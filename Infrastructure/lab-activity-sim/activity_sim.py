#!/usr/bin/env python3
"""Workstation activity simulator — fakes the human + cron baseline.

Without this, Waystar Royco's Linux workstations are silent except when
the attack chain touches them. john_ws, luke_ws, and vinzenz_ws have
zero shell history, zero outbound SSH, zero psql queries, zero sudo —
so when the attacker fires ``Accepted publickey for john.stravidis``
or ``vinzenz.fedora`` SSHes anywhere, that single event lights up
against a flat-zero baseline. Detection becomes trivial.

This daemon runs inside each workstation as that workstation's user
(via ``runuser -u`` from the entrypoint) and periodically executes
realistic everyday commands for that user persona. The commands write
to ``~/.bash_history`` (so the attacker's ``cat ~/.bash_history`` finds
real history, not an empty file), generate ``auth.log`` entries (sudo,
ssh-out, login), touch FIM-watched paths, and query db-internal — all
of which gives the SOC trainee a baseline to filter the attacker's
activity OUT of, rather than a single anomaly to spot in silence.

Pattern mirrors ``Infrastructure/noise_user_sim/noise.py``: a PERSONAS
dict, env-var-selected persona, ACTIVITY_ENABLED gate, signal-based
shutdown. Sparse cadence (300-900s between commands per workstation)
keeps log volume modest — three workstations together produce ~1
command every 20-60s lab-wide.

Environment variables (read at startup)
=======================================
- ``ACTIVITY_ENABLED``  — "1" to run; anything else → sleep forever.
                          Set to "1" by tools/run.sh when --pacing realistic,
                          "0" otherwise.
- ``ACTIVITY_PERSONA``  — one of {developer,clinical,sysadmin}.
                          Selects which user's command list to draw from.
- ``ACTIVITY_HOME``     — the home directory whose ~/.bash_history to
                          append to (default: $HOME). The daemon may be
                          invoked via runuser, in which case $HOME is
                          set correctly; pass explicitly for safety.
"""
from __future__ import annotations

import logging
import os
import random
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


# ─────────────────────────────────────────────────────────── Personas

# Each command is a tuple (label, shell_string). The label is what gets
# appended to ~/.bash_history (so it looks like what the human actually
# typed); the shell_string is what subprocess actually runs (may be
# differently quoted, may include flags that suppress noise output).

PERSONAS: dict[str, dict] = {
    # ───── john.stravidis @ ubuntu_workstation ─────
    # Frontend dev working on waystar-connect. Mix of git/npm activity,
    # occasional vim edits, sudo for package updates.
    "developer": {
        "min_interval": 300,
        "max_interval": 900,
        "commands": [
            ("cd ~/projects/waystar-connect && git status",
             "cd ~/projects/waystar-connect && git status >/dev/null 2>&1"),
            ("cd ~/projects/waystar-connect && git log --oneline | head -5",
             "cd ~/projects/waystar-connect && git log --oneline 2>/dev/null | head -5 >/dev/null"),
            ("cat ~/projects/waystar-connect/package.json | head -20",
             "head -20 ~/projects/waystar-connect/package.json >/dev/null 2>&1"),
            ("ls -la ~/projects/waystar-connect/node_modules | head -10",
             "ls -la ~/projects/waystar-connect/node_modules 2>/dev/null | head -10 >/dev/null"),
            ("node -v",
             "node -v >/dev/null 2>&1"),
            ("npm -v",
             "npm -v >/dev/null 2>&1"),
            ("cd ~/projects/waystar-connect && npm test",
             "cd ~/projects/waystar-connect && npm test --silent >/dev/null 2>&1 || true"),
            # vim edit — touch the dev.db's mtime; lab-fim may pick this up.
            ("vim ~/projects/waystar-connect/src/app.js",
             "touch ~/projects/waystar-connect/src/app.js"),
            ("less ~/.bashrc",
             "cat ~/.bashrc >/dev/null 2>&1"),
            ("df -h",
             "df -h >/dev/null 2>&1"),
            ("free -h",
             "free -h >/dev/null 2>&1"),
            # Sudo — generates auth.log entries; uses non-interactive -n flag
            # so it can't hang waiting for password (won't actually elevate
            # without ~/.sudo cookie, but the failed sudo attempt IS itself
            # an auth.log line that builds baseline).
            ("sudo apt update",
             "sudo -n apt update >/dev/null 2>&1 || true"),
        ],
    },
    # ───── luke.smith @ luke_ws ─────
    # Psychiatrist; spends time in psql querying his patient session notes
    # plus occasional file ops. NO sudo (Luke has no sudo group).
    "clinical": {
        "min_interval": 300,
        "max_interval": 900,
        "commands": [
            # Real workflow per scenario_story.md — psql to db-internal for
            # his patient queries. ~/.pgpass provides the credentials.
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT COUNT(*) FROM session_notes WHERE therapist='Luke Smith'\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT COUNT(*) FROM session_notes WHERE therapist='Luke Smith'\" "
             ">/dev/null 2>&1"),
            # Schema: session_notes(id, patient_id, therapist, session_date,
            # session_type, duration_min, content, created_at)
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT id, patient_id, session_date FROM session_notes "
             "WHERE therapist='Luke Smith' ORDER BY session_date DESC LIMIT 5\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT id, patient_id, session_date FROM session_notes "
             "WHERE therapist='Luke Smith' ORDER BY session_date DESC LIMIT 5\" "
             ">/dev/null 2>&1"),
            # Schema: patients(id, first_name, last_name, dob, gender,
            # ins_number, phone, ...). No primary_therapist column — join
            # via session_notes if Luke wants "his" patients.
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT p.id, p.first_name, p.last_name FROM patients p "
             "JOIN session_notes sn ON sn.patient_id=p.id "
             "WHERE sn.therapist='Luke Smith' GROUP BY p.id LIMIT 10\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT p.id, p.first_name, p.last_name FROM patients p "
             "JOIN session_notes sn ON sn.patient_id=p.id "
             "WHERE sn.therapist='Luke Smith' GROUP BY p.id LIMIT 10\" "
             ">/dev/null 2>&1"),
            # SQLite local cache lookup.
            ("sqlite3 ~/patient-cache.sqlite \"SELECT COUNT(*) FROM patients\"",
             "sqlite3 ~/patient-cache.sqlite 'SELECT COUNT(*) FROM patients' "
             ">/dev/null 2>&1 || true"),
            ("ls ~/Documents/",
             "ls ~/Documents/ >/dev/null 2>&1"),
            ("ls ~/Documents/notes/ 2>/dev/null || mkdir -p ~/Documents/notes",
             "mkdir -p ~/Documents/notes >/dev/null 2>&1"),
            # vim a session note — lab-fim should pick up MODIFY on ~/Documents.
            ("vim ~/Documents/notes/$(date +%Y-%m-%d).md",
             "touch ~/Documents/notes/$(date +%Y-%m-%d).md"),
            ("cat ~/.pgpass",
             "cat ~/.pgpass >/dev/null 2>&1"),
            ("df -h",
             "df -h >/dev/null 2>&1"),
        ],
    },
    # ───── vinzenz.fedora @ vinzenz_ws ─────
    # Sysadmin doing fleet maintenance. The CRUCIAL persona: his cross-host
    # SSH activity creates the baseline of "Accepted publickey for
    # vinzenz.fedora" entries on apache + ubuntu_workstation + luke_ws.
    # Without that baseline, the attacker's stolen-key SSH activity (in
    # the advanced chain) lights up trivially against zero. With it,
    # the trainee must find the off-pattern session.
    "sysadmin": {
        "min_interval": 300,
        "max_interval": 900,
        "commands": [
            # Cross-host SSH — uses ~/.ssh/config aliases (apache/john/luke).
            ("ssh apache 'uptime'",
             "ssh -o BatchMode=yes apache 'uptime' >/dev/null 2>&1 || true"),
            ("ssh john 'uptime'",
             "ssh -o BatchMode=yes john 'uptime' >/dev/null 2>&1 || true"),
            ("ssh luke 'uptime'",
             "ssh -o BatchMode=yes luke 'uptime' >/dev/null 2>&1 || true"),
            ("ssh apache 'df -h | head -5'",
             "ssh -o BatchMode=yes apache 'df -h | head -5' >/dev/null 2>&1 || true"),
            ("ssh john 'df -h | head -5'",
             "ssh -o BatchMode=yes john 'df -h | head -5' >/dev/null 2>&1 || true"),
            ("ssh apache 'tail -3 /var/log/apt/history.log 2>/dev/null'",
             "ssh -o BatchMode=yes apache 'tail -3 /var/log/apt/history.log 2>/dev/null' "
             ">/dev/null 2>&1 || true"),
            # Ansible fleet check — needs ansible installed; fall back to a
            # plain loop if not. The command runs from sysadmin's home.
            ("ansible -i ~/inventory.ini workstations -m ping",
             "(command -v ansible >/dev/null && "
             " ansible -i ~/inventory.ini workstations -m ping >/dev/null 2>&1) || true"),
            # Local maintenance.
            ("cat ~/inventory.ini",
             "cat ~/inventory.ini >/dev/null 2>&1"),
            ("sudo apt update",
             "sudo -n apt update >/dev/null 2>&1 || true"),
            ("journalctl -u sshd | tail -3",
             "(journalctl -u sshd 2>/dev/null | tail -3 >/dev/null) || true"),
            ("ls ~/runbooks/",
             "ls ~/runbooks/ >/dev/null 2>&1 || true"),
            ("df -h",
             "df -h >/dev/null 2>&1"),
            # Postgres superuser maintenance (Vinzenz has the privileged
            # creds per scenario_story.md ~vinzenz/.pgpass — generates the
            # legit-baseline of postgres connections from the sysadmin
            # account that the attacker's eventual exfil queries hide in).
            ("psql -h db-internal -U waystar -d waystar "
             "-c 'SELECT count(*) FROM pg_stat_activity'",
             "psql -h db-internal -U waystar -d waystar "
             "-c 'SELECT count(*) FROM pg_stat_activity' >/dev/null 2>&1 || true"),
        ],
    },
}

DEFAULT_PERSONA = "developer"

log = logging.getLogger("activity")


def _append_history(home: Path, label: str) -> None:
    """Append the command label to ~/.bash_history with a current timestamp.

    Bash writes history in the format::

        #<unix_ts>
        <command>

    when HISTTIMEFORMAT is set. We mimic that so the attacker's
    ``cat ~/.bash_history`` shows realistic timestamped output.
    """
    histfile = home / ".bash_history"
    line = f"#{int(time.time())}\n{label}\n"
    try:
        # Use append-only to avoid lock contention if bash itself ever
        # writes here (it shouldn't — daemon runs via runuser, never an
        # interactive shell — but be defensive).
        with histfile.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        log.debug("could not append to %s: %s", histfile, exc)


def _run_one(label: str, cmd: str, home: Path) -> None:
    """Execute one command via /bin/bash, with a generous timeout."""
    log.debug("running: %s", label)
    try:
        subprocess.run(
            ["/bin/bash", "-c", cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(home),
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        log.debug("timed out: %s", label)
    except OSError as exc:
        log.debug("OSError running %s: %s", label, exc)


def _worker(stop_event: threading.Event, persona: dict, home: Path) -> None:
    """Single-threaded worker — each persona runs one stream of commands."""
    while not stop_event.is_set():
        delay = random.uniform(persona["min_interval"], persona["max_interval"])
        if stop_event.wait(timeout=delay):
            return
        label, cmd = random.choice(persona["commands"])
        _append_history(home, label)
        _run_one(label, cmd, home)


def main() -> int:
    persona_name = os.environ.get("ACTIVITY_PERSONA", DEFAULT_PERSONA).strip().lower()
    if persona_name not in PERSONAS:
        print(f"[activity] WARN: unknown persona {persona_name!r}, "
              f"falling back to {DEFAULT_PERSONA!r} (valid: {sorted(PERSONAS)})",
              file=sys.stderr)
        persona_name = DEFAULT_PERSONA

    logging.basicConfig(
        level=logging.INFO,
        format=f"[%(asctime)s] [activity:{persona_name}] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logging.Formatter.converter = time.gmtime

    persona = PERSONAS[persona_name]
    enabled = os.environ.get("ACTIVITY_ENABLED", "0") == "1"
    home = Path(os.environ.get("ACTIVITY_HOME", os.environ.get("HOME", "/tmp")))

    if not enabled:
        log.info("ACTIVITY_ENABLED=0 — sleeping forever "
                 "(no baseline activity generated)")
        signal.pause()
        return 0

    log.info("starting: persona=%s home=%s interval=%ds-%ds cmd_pool=%d",
             persona_name, home,
             persona["min_interval"], persona["max_interval"],
             len(persona["commands"]))

    stop_event = threading.Event()

    def _shutdown(signum, _frame) -> None:
        log.info("received signal %d — shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    t = threading.Thread(
        target=_worker, args=(stop_event, persona, home),
        name=f"activity-{persona_name}", daemon=True,
    )
    t.start()
    stop_event.wait()
    t.join(timeout=2.0)
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
