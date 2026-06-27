# Attack chain — Cyber Kill Chain & MITRE ATT&CK mappings

Phase numbering matches `attack_plan.md`.

## Cyber Kill Chain coverage

| Kill Chain phase | Lab-side coverage |
|---|---|
| **Reconnaissance** | Pre-foothold: existing `initial_recon_1.py` (nmap, gobuster, ffuf, nikto). Post-foothold: phases 6, 8, 10. |
| **Weaponization** | Mostly attacker-side and not modelled in the lab. The variant-walk addition to phase 1 (per 2026-04-27 protocol) gives a *visible* weaponization beat. |
| **Delivery** | Phases 1, 11 (HTTP traversal payload; spearphishing attachment). |
| **Exploitation** | Phase 1 (CVE-2021-42013), phase 11 (attachment execution). |
| **Installation** | Phase 5 (persistence + encrypted C2 tunnel — the real Kill Chain phase 5 the lab currently skips). |
| **Command & Control** | Phase 5 establishes the tunnel; subsequent phases ride it. |
| **Actions on Objectives** | Phases 13–15 (Collection, Exfiltration, Impact). |

All seven phases are covered with substance, satisfying the customer brief's "Durchlauf aller Schritte der Cyber Kill Chain."

## MITRE ATT&CK technique mapping

Per phase, in chain order. ATT&CK technique IDs are linked to mitre.org; sub-techniques use the `T<id>.<sub>` format.

### Group A — Public-facing entry

| Phase | Technique | Where it bites |
|---|---|---|
| 1 | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | CVE-2021-42013 path traversal |
| 1 | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Command and Scripting Interpreter: Unix Shell | bash reverse shell payload |
| 2 | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Scheduled Task/Job: Cron | overwriting `/opt/cleanup.sh` so the root cron runs the attacker's payload |
| 2 | [T1068](https://attack.mitre.org/techniques/T1068/) Exploitation for Privilege Escalation | the chmod-777-cron-as-root chain itself |

### Group B — Foothold expansion

| Phase | Technique | Where it bites |
|---|---|---|
| 3 | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | reading `/opt/waystar-connect/`, `/root/.ssh/` |
| 3 | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files | deploy log + private key on apache, plus John's `~/.env` (mode 600, john.stravidis-owned — not accessible to www-data, readable after root privesc) |
| 3 | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) Unsecured Credentials: Private Keys | the deploy SSH private key |
| 3.5 | [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery | nmap sweep of 10.30.0.0/24 from apache enumerates live workstation hosts |
| 3.5 | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | the `-p 22 --open` portion of the same scan — apache fingerprints which internal hosts run sshd |
| 3.5 | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) Brute Force: Credential Stuffing | reuse of John's `~/.env` password across every discovered SSH host — auths against `john_ws`, denied on Luke/Vinzenz |
| 4 | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH | SSH from apache (or attacker via apache) to John's workstation |
| 4 | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts | john.stravidis is a real user on the workstation |
| 5 | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) Account Manipulation: SSH Authorized Keys | append attacker's public key to `~/.ssh/authorized_keys` |
| 5 | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Create or Modify System Process: Systemd Service | hidden systemd user-unit for re-connect on boot |
| 5 | [T1572](https://attack.mitre.org/techniques/T1572/) Protocol Tunneling | encrypted tunnel back to attacker (autossh / WireGuard / etc.) |
| 5 | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Application Layer Protocol: Web Protocols | if the C2 tunnel uses HTTPS framing |

### Group C — Internal recon

| Phase | Technique | Where it bites |
|---|---|---|
| 6 | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) Credentials from Password Stores: Credentials from Web Browsers | dump Firefox/Chrome saved passwords |
| 6 | [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie | browser cookie store |
| 6 | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | bash history, recents, project tree |
| 6 | [T1518](https://attack.mitre.org/techniques/T1518/) Software Discovery | installed packages, group membership |
| 7 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying | spray against hardened workstations |
| 7 | [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery | the actual workstation enumeration |
| 7 | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | port-scanning the internal subnet from John's box |
| 8 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying | spray against `luke.smith` from John's box — denied + logged |
| 8 | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts | reuse of John's stolen credentials against Luke — denied (different account) |
| 8 | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH | SSH attempt vector itself — sshd `LogLevel VERBOSE` records each fingerprint |

### Group D — Deep lateral movement

| Phase | Technique | Where it bites |
|---|---|---|
| 9 | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH | SSH to Luke's NEW workstation |
| 9 | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts | luke.smith is a real user; key reuse is the OPSEC failure |
| 10 | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) Email Collection: Local Email Collection | reading Luke's `~/Maildir` |
| 10 | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) Account Discovery: Local Account | identifying the sysadmin from email |
| 11 | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Phishing: Spearphishing Attachment | malicious attachment from Luke to Vinzenz |
| 11 | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File | mail-processor sim "opens" the attachment |
| 11 | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Command and Scripting Interpreter: Unix Shell | the attachment's payload |
| 12 | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files | DB conn string in `/etc/waystar/db.conf`, backup keys, `.pgpass` |
| 12 | [T1555](https://attack.mitre.org/techniques/T1555/) Credentials from Password Stores | sysadmin keyring / pass(1) |
| 12 | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | scoping out reachable file shares |

### Group E — Objectives

| Phase | Step | Technique | Where it bites |
|---|---|---|---|
| 13 | `advanced_exfiltration` | [T1005](https://attack.mitre.org/techniques/T1005/) Data from Local System | session-notes file tree and home directories |
| 13 | `advanced_exfiltration` | [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories | the patient DB |
| 13 | `advanced_exfiltration` | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) Archive Collected Data: Archive via Utility | tar/gzip/AES-pack of harvested files |
| 13 | `advanced_exfiltration` | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel | patient DB + home dirs exfil over HTTP POST to kali receiver |
| 13 | `advanced_exfiltration` | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service | one-shot HTTP staging server on kali |
| 14 | `exfiltrate` (basic) | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) Exfiltration Over Unencrypted Non-C2 Protocol | (basic mode) HTTP POST directly to kali without established C2 tunnel |
| 14 | `exfiltrate` (basic) | [T1030](https://attack.mitre.org/techniques/T1030/) Data Transfer Size Limits | chunking the upload |
| 15 | `advanced_cleanup_backdoor` | [T1070.002](https://attack.mitre.org/techniques/T1070/002/) Indicator Removal: Clear Linux/Mac System Logs | selective grep-out of attacker entries from auth logs (not truncation) |
| 15 | `advanced_cleanup_backdoor` | [T1070.003](https://attack.mitre.org/techniques/T1070/003/) Indicator Removal: Clear Command History | history rotation with plausible vinzenz commands (not deletion) |
| 15 | `advanced_cleanup_backdoor` | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) Indicator Removal: File Deletion | `shred -n 3` of staged artefacts + free-space fill |
| 15 | `advanced_cleanup_backdoor` | [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction | secure wipe of /tmp staged files on apache and vinzenz_ws |
| 15 | `advanced_cleanup_backdoor` | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) Data Manipulation: Stored Data Manipulation | false-flag artefacts: Lazarus AppleJeus bytes (apache), APT28 Cyrillic taunt (vinzenz_ws), FIN7 staging script |
| 15 | `advanced_cleanup_backdoor` | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) Account Manipulation: SSH Authorized Keys | single extra ed25519 entry in `~vinzenz.fedora/.ssh/authorized_keys`, masquerading as `ansible-deploy@cm-prod` |
| 15 | `advanced_cleanup_backdoor` | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) Defacement: Internal Defacement | `ran_wall.jpg` uploaded kali→vinzenz_ws→john_ws via Sliver+SCP; set as XFCE4 wallpaper via xfconf-query on John's VNC desktop `:5901` |
| 16 | `advanced_restoration` | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery | reversed — openssl CMS decryption of all `.enc` files network-wide + DB restoration (lab-reset path) |
| 16 | `advanced_restoration` | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) Defacement: Internal Defacement | reversed — XFCE4 wallpaper reset to default after successful decryption |

## Detection notes per technique

For SOC training and customer SIEM/EDR demos, what *should* fire on each technique. Implementation of the actual detection pipeline (Wazuh / Sigma / Suricata rules) is out of scope here. Persistent log volumes — the customer ask in `intern/Protokolle/Protokoll - 27.04.26.md:20` — landed in PR #58: every signal below now writes to a host-mounted file under `Infrastructure/logs/` so an external SIEM can ingest them.

| Technique(s) | Detection source | Signature / behaviour | Lab log path (PR #58) |
|---|---|---|---|
| T1190 (CVE-2021-42013) | Apache access log + NIDS | URL pattern `cgi-bin/.%32%65/.../bin/sh` is unmistakeable; ETOPEN Suricata rules ship for this CVE | `logs/apache/access.log`, `logs/apache/forensic_log`; router NFLOG `FW-NEW: SRC=10.10.0.2 DST=10.40.0.2 DPT=80` in `logs/router/ulog-iptables.log` |
| T1059.004 reverse-shell payload | EDR (auditd execve) | `bash -i >& /dev/tcp/...` is a textbook signature | router NFLOG `FW-NEW: SRC=10.40.0.2 DST=10.10.0.2 DPT={4444,5555}` in `logs/router/ulog-iptables.log` (apache calling back to kali) |
| T1053.003 cron discovery + tampering | auditd file watch on `/opt/cleanup.sh`; cron logs | discovery: `cat /etc/crontab`, `ls -la /etc/cron.*/`, `crontab -l`, `ls /etc/cron.d/` — all silent (bash history suppressed by the chain, no lab-fim watch on these paths); tampering: content change of `/opt/cleanup.sh`, run as root every minute, fires lab-fim | `/var/log/lab-fim.log` line `tag=lab_fim path=/opt/cleanup.sh event=MODIFY` (inside the apache container; inotify substitute for auditd — see implementation note below) |
| T1552.001 / .004 credential discovery | auditd file watch on `/root/.ssh/`, `/opt/waystar-connect/`; scenario log | unusual reads from www-data / root after foothold; **noise searches** for `passwords.txt`, `secrets.json`, `config.backup`, `credentials.txt`, `.passwd`, `db_password.txt` across `/home /root /tmp /var/www /opt /etc` appear in the scenario log and apache shell history before the real `.env` read — six `find` commands all returning empty, making the attacker's file-hunting visible to defenders | scenario log (`[-] '…' not found in …` lines from `_search_noise_files`); apache shell history (bash stores the `find` commands); lab-fim does not trigger (no matching watch path) |
| T1018 / T1046 internal scan from DMZ | router NFLOG + workstation auth.log | bursts of SYN/connect probes from apache (10.40.0.2) to every host in 10.30.0.0/24 :22 | `logs/router/ulog-iptables.log` (every probe gets `FW-NEW`); `logs/workstation/auth.log` (sshd opens then immediately disconnects for hosts where credentials don't match) |
| T1110.004 credential stuffing | sshd auth.log on each target | one password attempt per host from the same source IP within seconds; failures on Luke/Vinzenz, success on John | `logs/luke_ws/auth.log`, `logs/vinzenz_ws/auth.log` (`Failed password for john.stravidis`); `logs/workstation/auth.log` (`Accepted password for john.stravidis`) |
| T1021.004 SSH lateral | sshd auth.log | new login from apache→workstation IP, principal `john.stravidis`, no prior session pattern | `logs/workstation/auth.log` (sshd `LogLevel VERBOSE` records key fingerprints) |
| T1021.004 SSH lateral | router NFLOG | `FW-NEW: SRC=10.40.0.2 DST=10.30.0.5 DPT=22` — DMZ-to-Internal SSH crosses the router and gets a network-layer log line | `logs/router/ulog-iptables.log` (since PR #79: apache split off `internal_net` onto `dmz_net`, so the lateral pivot is no longer same-subnet) |
| T1098.004 authorized_keys append | EDR file watch on `~/.ssh/authorized_keys` | append events outside normal user sessions | `logs/workstation/lab-fim.log` once `john.stravidis` user lands (lab-fim already watches `~john.stravidis/.ssh`) |
| T1543.002 systemd persistence | auditd file watch on `~/.config/systemd/user/` and `/etc/systemd/`; systemd journal | new unit creation / enable | extend `Infrastructure/ubuntu_workstation/lab-fim.sh` watch list when this slice lands |
| T1572 / T1071.001 C2 tunnel | NIDS + flow logs | long-lived outbound TLS / SSH to non-routable / unusual destination; periodic keepalive cadence | `logs/router/ulog-iptables.log` — every NEW flow is captured with full 5-tuple |
| T1555.003 browser cred dump | EDR | unusual process accessing browser profile DBs | not yet implemented (post-foothold phase) |
| T1110.003 password spray (phase 7) | sshd auth.log + fail2ban | repeated auth failures from the same source IP across multiple accounts | `logs/workstation/auth.log` |
| T1018 / T1046 internal scanning | NetFlow / NIDS | bursts of SYN to many hosts/ports on internal subnet originating from a non-scanner host | `logs/router/ulog-iptables.log` (every SYN crosses FORWARD and gets NFLOG-tagged) |
| T1114.001 mail collection | auditd file watch on `/var/mail/`, `~/Maildir/` | unusual reads of mail files outside the user's normal MUA process | `logs/workstation/lab-fim.log` (lab-fim watches `/var/mail`) |
| T1566.001 + T1204.002 spearphishing chain | mail server logs + EDR (process spawn) | mail with executable attachment; process spawn of attachment payload from mail-processor / MUA | not yet implemented |
| T1070.002/.003/.004 log scrubbing + history rotation | auditd file watch on `/var/log/auth.log`, `~/.bash_history` | selective line deletions from auth log (diff against known-good baseline); history file rewritten within seconds of login | `logs/workstation/auth.log`, `logs/vinzenz_ws/auth.log` (scrubbed lines absent from attacker ground-truth window) |
| T1485 data destruction | EDR (file syscalls) + lab-fim | `shred` on /tmp files; `dd if=/dev/urandom` free-space fill | `logs/workstation/lab-fim.log` (lab-fim watches `/tmp` for the implant drops); attacker ground truth JSON records which files were wiped |
| T1565.001 false-flag artefacts | threat intel correlation | Lazarus/APT28/FIN7 signatures appearing simultaneously at breach time on unrelated hosts | attacker ground truth JSON names each dropped file and its false attribution |
| T1098.004 SSH authorized_keys | EDR file watch on `~/.ssh/authorized_keys` | extra entry appended outside provisioning; comment format (`ansible-deploy@cm-prod`) inconsistent with real provisioning key | `logs/vinzenz_ws/lab-fim.log` (lab-fim watches `~vinzenz.fedora/.ssh/`) |
| T1491.001 internal defacement | EDR / VNC session capture | wallpaper change via xfconf-query at unusual hour; `/tmp/ran_wall.jpg` file on john_ws | `logs/workstation/lab-fim.log` (lab-fim watches `/tmp`); VNC session at `localhost:5901` shows ransom image |
| T1490 inhibit recovery (reversed) | — | not a detection target — this is the lab-reset path for repeat demo runs | — |

These are minimum-viable detection signals — in a fuller implementation each would map to a concrete Wazuh rule, Sigma rule, or Suricata signature. That mapping is step-4 work; this table is the input.

### Ground-truth correlation

Each chain run creates a timestamped subdirectory `Attack-chain/results/run-<ISO8601>/` containing `chain-<ISO8601>.json` — a per-step record with `started` / `ended` UTC timestamps, tactic + technique IDs, and ok/elapsed. SOC analysts can match each detection-tool alert against the corresponding step's window to verify coverage and measure detection latency.

### Implementation note: auditd → inotify substitution

The detection design above calls for `auditd` file-watches on the apache and workstation containers. In practice, the kernel audit subsystem refuses `audit_set_enabled` from inside an unprivileged Docker container on this host (and even with `privileged: true` + `seccomp=unconfined` + `apparmor=unconfined` it remains locked at boot). Rather than mandate a host-side `audit=1`/`audit=2` kernel-cmdline change, the lab uses `inotify-tools` to produce an equivalent SIEM-ingestible signal:

```
2026-05-10T14:49:12+0000 tag=lab_fim path=/opt/cleanup.sh event=MODIFY
```

Wazuh's File Integrity Monitoring module uses inotify under the hood when auditd isn't available, so this matches what a real Linux EDR sees. The watch lists live in `Infrastructure/{apache,ubuntu_workstation}/lab-fim.sh` — same paths an `auditctl -w` rule file would name.

## Coverage summary

- **Cyber Kill Chain phases**: 7 of 7 covered.
- **ATT&CK Tactics touched**: Reconnaissance, Resource Development (implicit), Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact — all 14 enterprise tactics covered. Defense Evasion is now substantive: selective log scrubbing, history rotation, artefact shredding, and false-flag attribution misdirection are all implemented in `advanced_cleanup_backdoor`.
- **Distinct ATT&CK techniques referenced**: ~35, spanning common SOC training territory (cron persistence, SSH lateral, browser-cred theft, spearphishing, log scrubbing, false-flag attribution, ransomware-style impact, defacement).
- **Single stealthy backdoor**: the advanced chain plants exactly one persistence mechanism — an SSH authorized_keys entry on vinzenz_ws masquerading as an Ansible deploy key (T1098.004). Three-backdoor designs were reduced to one for realism: a disciplined APT minimises footprint.

This is enough breadth to genuinely exercise EDR + SIEM + NIDS, which is the customer brief's stated rationale (slide 5, "EDR & SIEM & NIDS & …").
