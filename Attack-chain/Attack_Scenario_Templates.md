# Initiale Ideen zum Attack Scenario

---

1. Reconnaissance: Intruder selects target, researches it, and attempts to identify vulnerabilities in the target network.
2. Weaponization: Intruder creates remote access malware weapon, such as a virus or worm, tailored to one or more vulnerabilities.
3. Delivery: Intruder transmits weapon to target (e.g., via e-mail attachments, websites or USB drives)
4. Exploitation: Malware weapon's program code triggers, which takes action on target network to exploit vulnerability.
5. Installation: Malware weapon installs an access point (e.g., "backdoor") usable by the intruder.
6. Command and Control: Malware enables intruder to have "hands on the keyboard" persistent access to the target network.
7. Actions on Objective: Intruder takes action to achieve their goals, such as data exfiltration, data destruction, or encryption for ransom.

---

### 1. Web App SQL Injection

```
Control Node (Orchestrator) ──HTTP/SSH──> Linux Target (Nginx + vuln PHP-App, Port 80)
                                           │
                                           └─> Payload: Custom Python SQLi-Skript (curl + sqlmap-ähnlich)
```

**Voll-Szenario (Config: initial_access=web_sqli):**

1. Recon: Nmap-Scan.
2. Weaponization: Payload bauen.
3. Delivery: HTTP-Request.
4. Exploit: SQLi → RCE.
5. Install: Cron-Job.
6. C2: Reverse Shell.
7. Actions: Data Exfil.
8. Cleanup: Cron rm + DB reset. / einfach Container neustarten

cve2docker (github.com/NS-unina/cve2docker)
-> to auto generate Docker based vulnerable WordPress environments from ExploitDB
 
### 2. RDP Brute Force

```
Control Node ──TCP 3389──> Windows Target (RDP enabled, weak PW)
                      │
                      └─> Payload: Bash + Hydra/Winexe für Brute + PS-Shell
```

**Voll-Szenario (Config: initial_access=rdp_brute):**

1. Recon: Port-Scan.
2. Weaponization: Wortliste generieren.
3. Delivery: Brute-Attack.
4. Exploit: RDP-Login.
5. Install: Scheduled Task.
6. C2: Netcat Listener.
7. Actions: LSASS Dump.
8. Cleanup: Taskkill + Eventlog clear. / einfach Container neustarten

### 3. SSH Key Exposure

```
Control Node ──TCP 22──> Linux Target (~/.ssh/id_rsa world-readable)
                     │
                     └─> Payload: Bash scp + key-copy + cron
```

**Voll-Szenario (Config: initial_access=ssh_key):**

1. Recon: SSH-Enum. Bruteforce or public exposure
2. Weaponization: Key-Exploit-Skript.
3. Delivery: Weak PW/Key.
4. Exploit: SSH-Login.
5. Install: Authorized_keys + Cron
6. C2: Persistent SSH-Tunnel.
7. Actions: Config Exfil
8. Cleanup: Key perms fix + Cron rm. / einfach Container neustarten
