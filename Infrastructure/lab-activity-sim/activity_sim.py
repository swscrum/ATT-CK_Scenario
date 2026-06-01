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

Realism design decisions
========================
* **Persona pools are ≥20 commands each.** Smaller pools produce
  visibly synthetic distributions (a Tier 3 trainee plotting
  ``frequency by command`` over a 3 h run sees a flat 9-bucket
  distribution → recognisably artificial). 20+ commands per persona
  hides the underlying pool size.

* **Commands are tuples of (label_template, shell_template).** The
  template strings can contain ``{placeholders}`` which are filled at
  invocation time from per-persona variable generators below. This
  means the SAME logical command (e.g. "psql for Luke's patients")
  produces *different* SQL each time it runs — different LIMITs,
  different date ranges, different ORDER BYs — so the postgres log
  doesn't show a tight cluster of identical statements.

* **Bursts, not singletons.** Real shells fire 1–5 commands in quick
  succession (a person doing a coherent task) then idle for minutes.
  Our worker picks a burst size from a weighted distribution (heavily
  favouring 1–3), runs those commands with 1–3 s gaps, then sleeps the
  full ``min_interval..max_interval`` window. ``bash_history`` finally
  looks like real shell-session shape, not "one command every X
  minutes forever."

* **No time-of-day weighting.** Looked tempting but the diurnal
  rewriter already maps any wall-clock window onto a synthetic 09–17
  workday. Adding real-time work-hour gating here would actively
  conflict with the diurnal stretch (a 02:00 run with the gate ON
  produces zero events → empty SIEM dashboard despite anchor=09:00).

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
from datetime import date, timedelta
from pathlib import Path


# ─────────────────────────────────────────────────────────── Argument generators
#
# Each call returns a dict of placeholders that templates can ``.format(**)``
# with. Personas declare which generator they use (see PERSONAS entries).
# Generators must be pure functions so the same template re-evaluated at a
# later time produces different (but type-correct) values.


def _gen_developer() -> dict:
    """Arg pool for the developer persona — branches, files, dirs."""
    return {
        "branch": random.choice([
            "main", "main", "main",     # weighted: main appears more
            "dev", "feature/booking-ux", "fix/cron-perm", "hotfix/api-keys",
        ]),
        "src_file": random.choice([
            "src/app.js", "src/booking.js", "src/index.html",
            "src/styles.css", "src/components/Header.vue",
            "src/api/client.js", "package.json", "vite.config.js",
        ]),
        "log_tail_n": random.choice([10, 20, 30, 50]),
        "ls_dir": random.choice([
            "~/projects/waystar-connect",
            "~/projects/waystar-connect/src",
            "~/projects/waystar-connect/node_modules",
            "~/projects/waystar-connect/dist",
        ]),
    }


def _gen_clinical() -> dict:
    """Arg pool for the clinical persona — note dates, LIMITs, patient filters."""
    # Random note date in the last 30 days — Luke might be revising old notes.
    days_back = random.choice([0, 0, 0, 1, 2, 3, 7, 14, 21])  # weighted toward today
    note_date = (date.today() - timedelta(days=days_back)).isoformat()
    return {
        "note_date": note_date,
        "lim": random.choice([3, 5, 10, 10, 15, 20, 25]),  # weighted toward 5-10
        "session_lim": random.choice([5, 10, 20, 50]),
        "order": random.choice(["DESC", "ASC", "DESC", "DESC"]),  # DESC bias
        "session_type": random.choice([
            "'individual'", "'individual'", "'group'", "'follow-up'", "'intake'",
        ]),
        "month_offset": random.choice([1, 1, 2, 3, 6]),  # months back for date ranges
    }


def _gen_sysadmin() -> dict:
    """Arg pool for the sysadmin persona — hosts, commands, journal units."""
    return {
        "host": random.choice([
            "apache", "apache", "apache",  # apache most-visited
            "john", "luke",
        ]),
        "remote_check": random.choice([
            "uptime", "df -h | head -5", "free -h",
            "tail -3 /var/log/apt/history.log 2>/dev/null",
            "systemctl --no-pager status sshd 2>/dev/null | head -5",
            "last -n 5", "who",
        ]),
        "journal_unit": random.choice(["sshd", "cron", "rsyslog"]),
        "tail_n": random.choice([3, 5, 10, 20]),
        "inventory_group": random.choice([
            "workstations", "workstations", "web", "all",
        ]),
    }


# ─────────────────────────────────────────────────────────── Personas
#
# Commands are (label_template, shell_template) — templates may contain
# {placeholders} filled at invocation time from the persona's `gen` callable.
# Templates without placeholders work identically to old static commands.

PERSONAS: dict[str, dict] = {
    # ───── john.stravidis @ ubuntu_workstation ─────
    # Frontend dev working on waystar-connect. Mix of git/npm activity,
    # occasional vim edits, sudo for package updates.
    "developer": {
        "min_interval": 300,
        "max_interval": 900,
        "gen": _gen_developer,
        "commands": [
            # git operations
            ("cd ~/projects/waystar-connect && git status",
             "cd ~/projects/waystar-connect && git status >/dev/null 2>&1"),
            ("cd ~/projects/waystar-connect && git log --oneline | head -{log_tail_n}",
             "cd ~/projects/waystar-connect && git log --oneline 2>/dev/null | head -{log_tail_n} >/dev/null"),
            ("cd ~/projects/waystar-connect && git diff",
             "cd ~/projects/waystar-connect && git diff >/dev/null 2>&1"),
            ("cd ~/projects/waystar-connect && git diff --stat HEAD~1",
             "cd ~/projects/waystar-connect && git diff --stat HEAD~1 >/dev/null 2>&1 || true"),
            ("cd ~/projects/waystar-connect && git checkout {branch}",
             "cd ~/projects/waystar-connect && git checkout {branch} >/dev/null 2>&1 || true"),
            ("cd ~/projects/waystar-connect && git pull",
             "cd ~/projects/waystar-connect && git pull --no-edit >/dev/null 2>&1 || true"),
            ("cd ~/projects/waystar-connect && git branch",
             "cd ~/projects/waystar-connect && git branch >/dev/null 2>&1"),
            # file inspection
            ("cat ~/projects/waystar-connect/package.json | head -20",
             "head -20 ~/projects/waystar-connect/package.json >/dev/null 2>&1"),
            ("ls -la {ls_dir} | head -10",
             "ls -la {ls_dir} 2>/dev/null | head -10 >/dev/null"),
            ("du -sh ~/projects/waystar-connect/node_modules",
             "du -sh ~/projects/waystar-connect/node_modules >/dev/null 2>&1 || true"),
            ("wc -l ~/projects/waystar-connect/{src_file}",
             "wc -l ~/projects/waystar-connect/{src_file} >/dev/null 2>&1 || true"),
            ("grep -rn TODO ~/projects/waystar-connect/src | head -10",
             "grep -rn TODO ~/projects/waystar-connect/src 2>/dev/null | head -10 >/dev/null"),
            # node/npm
            ("node -v",
             "node -v >/dev/null 2>&1"),
            ("npm -v",
             "npm -v >/dev/null 2>&1"),
            ("cd ~/projects/waystar-connect && npm test",
             "cd ~/projects/waystar-connect && npm test --silent >/dev/null 2>&1 || true"),
            ("cd ~/projects/waystar-connect && npm list --depth=0",
             "cd ~/projects/waystar-connect && npm list --depth=0 >/dev/null 2>&1 || true"),
            ("cd ~/projects/waystar-connect && npm outdated",
             "cd ~/projects/waystar-connect && npm outdated >/dev/null 2>&1 || true"),
            # vim — touches the file's mtime; lab-fim picks this up.
            ("vim ~/projects/waystar-connect/{src_file}",
             "touch ~/projects/waystar-connect/{src_file} 2>/dev/null || true"),
            # system / shell
            ("less ~/.bashrc",
             "cat ~/.bashrc >/dev/null 2>&1"),
            ("df -h",
             "df -h >/dev/null 2>&1"),
            ("free -h",
             "free -h >/dev/null 2>&1"),
            ("ps aux | head -10",
             "ps aux 2>/dev/null | head -10 >/dev/null"),
            ("history | tail -20",
             "tail -20 ~/.bash_history 2>/dev/null >/dev/null"),
            # Sudo — generates auth.log entries; non-interactive -n flag
            # so it can't hang waiting for password. The failed-sudo line
            # itself is the auth.log baseline we want.
            ("sudo apt update",
             "sudo -n apt update >/dev/null 2>&1 || true"),
            ("sudo apt list --upgradable",
             "sudo -n apt list --upgradable >/dev/null 2>&1 || true"),
        ],
    },
    # ───── luke.smith @ luke_ws ─────
    # Psychiatrist; spends time in psql querying his patient session notes
    # plus occasional file ops. NO sudo (Luke has no sudo group).
    "clinical": {
        "min_interval": 300,
        "max_interval": 900,
        "gen": _gen_clinical,
        "commands": [
            # Schema: session_notes(id, patient_id, therapist, session_date,
            # session_type, duration_min, content, created_at)
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT COUNT(*) FROM session_notes WHERE therapist='Luke Smith'\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT COUNT(*) FROM session_notes WHERE therapist='Luke Smith'\" "
             ">/dev/null 2>&1"),
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT id, patient_id, session_date FROM session_notes "
             "WHERE therapist='Luke Smith' ORDER BY session_date {order} LIMIT {session_lim}\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT id, patient_id, session_date FROM session_notes "
             "WHERE therapist='Luke Smith' ORDER BY session_date {order} LIMIT {session_lim}\" "
             ">/dev/null 2>&1"),
            # Schema: patients(id, first_name, last_name, dob, gender,
            # ins_number, phone, ...). No primary_therapist column — join
            # via session_notes to find "his" patients.
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT p.id, p.first_name, p.last_name FROM patients p "
             "JOIN session_notes sn ON sn.patient_id=p.id "
             "WHERE sn.therapist='Luke Smith' GROUP BY p.id LIMIT {lim}\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT p.id, p.first_name, p.last_name FROM patients p "
             "JOIN session_notes sn ON sn.patient_id=p.id "
             "WHERE sn.therapist='Luke Smith' GROUP BY p.id LIMIT {lim}\" "
             ">/dev/null 2>&1"),
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT session_type, COUNT(*) FROM session_notes "
             "WHERE therapist='Luke Smith' GROUP BY session_type\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT session_type, COUNT(*) FROM session_notes "
             "WHERE therapist='Luke Smith' GROUP BY session_type\" "
             ">/dev/null 2>&1"),
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT id, session_date, duration_min FROM session_notes "
             "WHERE therapist='Luke Smith' AND session_type={session_type} LIMIT {lim}\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT id, session_date, duration_min FROM session_notes "
             "WHERE therapist='Luke Smith' AND session_type={session_type} LIMIT {lim}\" "
             ">/dev/null 2>&1"),
            ("psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT COUNT(DISTINCT patient_id) FROM session_notes "
             "WHERE therapist='Luke Smith' "
             "AND session_date > NOW() - INTERVAL '{month_offset} months'\"",
             "psql -h db-internal -U waystar-readonly -d waystar "
             "-c \"SELECT COUNT(DISTINCT patient_id) FROM session_notes "
             "WHERE therapist='Luke Smith' "
             "AND session_date > NOW() - INTERVAL '{month_offset} months'\" "
             ">/dev/null 2>&1"),
            # SQLite local cache lookups (Luke's offline patient list).
            ("sqlite3 ~/patient-cache.sqlite \"SELECT COUNT(*) FROM patients\"",
             "sqlite3 ~/patient-cache.sqlite 'SELECT COUNT(*) FROM patients' "
             ">/dev/null 2>&1 || true"),
            ("sqlite3 ~/patient-cache.sqlite \"SELECT * FROM patients LIMIT {lim}\"",
             "sqlite3 ~/patient-cache.sqlite 'SELECT * FROM patients LIMIT {lim}' "
             ">/dev/null 2>&1 || true"),
            # File operations on the notes directory.
            ("ls ~/Documents/",
             "ls ~/Documents/ >/dev/null 2>&1"),
            ("ls -la ~/Documents/notes/",
             "ls -la ~/Documents/notes/ >/dev/null 2>&1 || true"),
            ("ls ~/Documents/notes/ 2>/dev/null || mkdir -p ~/Documents/notes",
             "mkdir -p ~/Documents/notes >/dev/null 2>&1"),
            ("du -sh ~/Documents/notes/",
             "du -sh ~/Documents/notes/ >/dev/null 2>&1 || true"),
            # vim a session note — rotates dates, so lab-fim sees varying
            # paths and the trainee can't anchor on "Luke only edits one file".
            ("vim ~/Documents/notes/{note_date}.md",
             "mkdir -p ~/Documents/notes && touch ~/Documents/notes/{note_date}.md"),
            ("cat ~/Documents/notes/{note_date}.md",
             "cat ~/Documents/notes/{note_date}.md >/dev/null 2>&1 || true"),
            ("head -20 ~/Documents/notes/{note_date}.md",
             "head -20 ~/Documents/notes/{note_date}.md >/dev/null 2>&1 || true"),
            # Local file inspection (Luke might read his own creds file).
            ("cat ~/.pgpass",
             "cat ~/.pgpass >/dev/null 2>&1"),
            ("cat ~/.bashrc | head -20",
             "head -20 ~/.bashrc >/dev/null 2>&1"),
            ("history | tail -10",
             "tail -10 ~/.bash_history 2>/dev/null >/dev/null"),
            # System checks (clinical end-user; rarely but happens).
            ("df -h",
             "df -h >/dev/null 2>&1"),
            ("date",
             "date >/dev/null 2>&1"),
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
        "gen": _gen_sysadmin,
        "commands": [
            # Cross-host SSH — parameterised host + check command. Variety
            # here is critical: a fixed "ssh apache uptime" repeating would
            # be a recognisable signature. Real sysadmins ssh into many
            # hosts for many reasons.
            ("ssh {host} '{remote_check}'",
             "ssh -o BatchMode=yes {host} '{remote_check}' >/dev/null 2>&1 || true"),
            ("ssh {host} 'cat /etc/os-release | head -5'",
             "ssh -o BatchMode=yes {host} 'cat /etc/os-release | head -5' "
             ">/dev/null 2>&1 || true"),
            ("ssh {host} 'free -h'",
             "ssh -o BatchMode=yes {host} 'free -h' >/dev/null 2>&1 || true"),
            ("ssh apache 'tail -{tail_n} /var/log/apt/history.log 2>/dev/null'",
             "ssh -o BatchMode=yes apache 'tail -{tail_n} /var/log/apt/history.log "
             "2>/dev/null' >/dev/null 2>&1 || true"),
            ("ssh john 'ls -la ~john.stravidis/projects/waystar-connect | head -10'",
             "ssh -o BatchMode=yes john 'ls -la ~john.stravidis/projects/waystar-connect "
             "2>/dev/null | head -10' >/dev/null 2>&1 || true"),
            ("ssh luke 'systemctl --user --no-pager status 2>/dev/null | head'",
             "ssh -o BatchMode=yes luke 'systemctl --user --no-pager status 2>/dev/null "
             "| head' >/dev/null 2>&1 || true"),
            # Ansible fleet checks — different inventory groups so the
            # ansible-related auth-log fanout varies.
            ("ansible -i ~/inventory.ini {inventory_group} -m ping",
             "(command -v ansible >/dev/null && "
             " ansible -i ~/inventory.ini {inventory_group} -m ping >/dev/null 2>&1) "
             "|| true"),
            ("ansible -i ~/inventory.ini {inventory_group} -m shell -a 'uptime'",
             "(command -v ansible >/dev/null && "
             " ansible -i ~/inventory.ini {inventory_group} -m shell -a 'uptime' "
             " >/dev/null 2>&1) || true"),
            # Local file/config inspection.
            ("cat ~/inventory.ini",
             "cat ~/inventory.ini >/dev/null 2>&1"),
            ("ls ~/runbooks/",
             "ls ~/runbooks/ >/dev/null 2>&1 || true"),
            ("ls ~/notes/",
             "ls ~/notes/ >/dev/null 2>&1 || true"),
            ("history | tail -{tail_n}",
             "tail -{tail_n} ~/.bash_history 2>/dev/null >/dev/null"),
            # Sudo — generates auth.log entries on his own box.
            ("sudo apt update",
             "sudo -n apt update >/dev/null 2>&1 || true"),
            ("sudo apt list --upgradable",
             "sudo -n apt list --upgradable >/dev/null 2>&1 || true"),
            ("sudo journalctl -u {journal_unit} -n {tail_n}",
             "sudo -n journalctl -u {journal_unit} -n {tail_n} >/dev/null 2>&1 || true"),
            # journalctl (non-sudo) — may or may not work in container,
            # but the command appears in bash_history regardless.
            ("journalctl -u {journal_unit} | tail -{tail_n}",
             "(journalctl -u {journal_unit} 2>/dev/null | tail -{tail_n} >/dev/null) "
             "|| true"),
            # System checks.
            ("df -h",
             "df -h >/dev/null 2>&1"),
            ("free -h",
             "free -h >/dev/null 2>&1"),
            ("ip a",
             "ip a >/dev/null 2>&1"),
            # Postgres superuser maintenance — Vinzenz has the privileged
            # creds in ~/.pgpass; varied admin queries.
            ("psql -h db-internal -U waystar -d waystar "
             "-c 'SELECT count(*) FROM pg_stat_activity'",
             "psql -h db-internal -U waystar -d waystar "
             "-c 'SELECT count(*) FROM pg_stat_activity' >/dev/null 2>&1 || true"),
            ("psql -h db-internal -U waystar -d waystar "
             "-c 'SELECT pg_size_pretty(pg_database_size(current_database()))'",
             "psql -h db-internal -U waystar -d waystar "
             "-c 'SELECT pg_size_pretty(pg_database_size(current_database()))' "
             ">/dev/null 2>&1 || true"),
            ("psql -h db-internal -U waystar -d waystar -c '\\dt'",
             "psql -h db-internal -U waystar -d waystar -c '\\dt' "
             ">/dev/null 2>&1 || true"),
            ("psql -h db-internal -U waystar -d waystar "
             "-c \"SELECT datname, numbackends FROM pg_stat_database\"",
             "psql -h db-internal -U waystar -d waystar "
             "-c \"SELECT datname, numbackends FROM pg_stat_database\" "
             ">/dev/null 2>&1 || true"),
            # rsync log archive (per the seeded bash_history Vinzenz does this).
            ("rsync -av luke:/var/log/persist/auth.log /tmp/ 2>/dev/null",
             "rsync -av -e 'ssh -o BatchMode=yes' luke:/var/log/persist/auth.log "
             "/tmp/ >/dev/null 2>&1 || true"),
        ],
    },
}

DEFAULT_PERSONA = "developer"

# Burst sizing: weighted distribution favouring 1-3 commands per burst,
# rarely up to 5. Modelled on real shell sessions where bursts of a few
# related commands are typical and bursts of >5 are unusual outside
# scripted operations.
_BURST_WEIGHTS = [
    (1, 35),  # 35% — single command (quick check, one-off)
    (2, 28),  # 28% — pair (cd + ls, or grep + head, etc.)
    (3, 20),  # 20% — short coherent sequence
    (4, 11),  # 11%
    (5, 6),   # 6%  — long burst, less common
]
_BURST_INTRA_GAP_MIN_SEC = 1.0
_BURST_INTRA_GAP_MAX_SEC = 3.5


log = logging.getLogger("activity")


def _pick_burst_size() -> int:
    """Weighted random burst length."""
    rolls = [n for n, w in _BURST_WEIGHTS for _ in range(w)]
    return random.choice(rolls)


def _render(template: str, args: dict) -> str:
    """str.format with safety net — if a template references a placeholder
    the generator didn't supply, fall back to the raw template rather than
    crash the daemon."""
    try:
        return template.format(**args)
    except (KeyError, IndexError) as exc:
        log.debug("template render fallback (%s): %s", exc, template)
        return template


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


def _fire_burst(persona: dict, home: Path, stop_event: threading.Event) -> None:
    """Fire one burst of 1-5 commands with small intra-burst gaps."""
    n = _pick_burst_size()
    gen = persona["gen"]
    for i in range(n):
        if stop_event.is_set():
            return
        label_t, shell_t = random.choice(persona["commands"])
        args = gen()
        label = _render(label_t, args)
        shell = _render(shell_t, args)
        _append_history(home, label)
        _run_one(label, shell, home)
        if i < n - 1:  # gap after every command except the last
            gap = random.uniform(_BURST_INTRA_GAP_MIN_SEC, _BURST_INTRA_GAP_MAX_SEC)
            if stop_event.wait(timeout=gap):
                return
    log.debug("burst of %d complete", n)


def _worker(stop_event: threading.Event, persona: dict, home: Path) -> None:
    """Single-threaded worker — bursts of commands separated by long idles."""
    while not stop_event.is_set():
        delay = random.uniform(persona["min_interval"], persona["max_interval"])
        if stop_event.wait(timeout=delay):
            return
        _fire_burst(persona, home, stop_event)


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

    log.info("starting: persona=%s home=%s interval=%ds-%ds cmd_pool=%d "
             "burst_dist=%s",
             persona_name, home,
             persona["min_interval"], persona["max_interval"],
             len(persona["commands"]),
             ",".join(f"{n}:{w}%" for n, w in _BURST_WEIGHTS))

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
