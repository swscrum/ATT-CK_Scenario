# Attack chain — Cyber Kill Chain & MITRE ATT&CK mappings

Phase numbering matches `attack_plan.md`.

## Cyber Kill Chain coverage

| Kill Chain phase | Lab-side coverage |
|---|---|
| **Reconnaissance** | Pre-foothold: existing `initial_recon_1.py` (nmap, gobuster, ffuf, nikto). Post-foothold: phases 6, 8, 10. |
| **Weaponization** | Mostly attacker-side and not modelled in the lab. The variant-walk addition to phase 1 (per 2026-04-27 protocol) gives a *visible* weaponization beat. |
| **Delivery** | Phases 1, 11 (HTTP traversal payload; spearphishing attachment). |
| **Exploitation** | Phase 1 (CVE-2021-41773), phase 11 (attachment execution). |
| **Installation** | Phase 5 (persistence + encrypted C2 tunnel — the real Kill Chain phase 5 the lab currently skips). |
| **Command & Control** | Phase 5 establishes the tunnel; subsequent phases ride it. |
| **Actions on Objectives** | Phases 13–15 (Collection, Exfiltration, Impact). |

All seven phases are covered with substance, satisfying the customer brief's "Durchlauf aller Schritte der Cyber Kill Chain."

## MITRE ATT&CK technique mapping

Per phase, in chain order. ATT&CK technique IDs are linked to mitre.org; sub-techniques use the `T<id>.<sub>` format.

### Group A — Public-facing entry

| Phase | Technique | Where it bites |
|---|---|---|
| 1 | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | CVE-2021-41773 path traversal |
| 1 | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Command and Scripting Interpreter: Unix Shell | bash reverse shell payload |
| 2 | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Scheduled Task/Job: Cron | overwriting `/opt/cleanup.sh` so the root cron runs the attacker's payload |
| 2 | [T1068](https://attack.mitre.org/techniques/T1068/) Exploitation for Privilege Escalation | the chmod-777-cron-as-root chain itself |

### Group B — Foothold expansion

| Phase | Technique | Where it bites |
|---|---|---|
| 3 | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | reading `/opt/waystar-connect/`, `/root/.ssh/` |
| 3 | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files | deploy log + private key on apache |
| 3 | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) Unsecured Credentials: Private Keys | the deploy SSH private key |
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
| 8 | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | finding `/var/log/migration/`, `/home/luke.smith.bak/` |
| 8 | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) Account Discovery: Local Account | identifying the previous user |
| 8 | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) Unsecured Credentials: Private Keys | Luke's stale personal SSH key |

### Group D — Deep lateral movement

| Phase | Technique | Where it bites |
|---|---|---|
| 9 | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH | SSH to Luke's NEW workstation |
| 9 | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts | luke.smith is a real user; key reuse is the OPSEC failure |
| 10 | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) Email Collection: Local Email Collection | reading Luke's `~/Maildir` |
| 10 | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) Account Discovery: Local Account | identifying the sysadmin from email |
| 11 | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Phishing: Spearphishing Attachment | malicious attachment from Luke to Hans |
| 11 | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File | mail-processor sim "opens" the attachment |
| 11 | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Command and Scripting Interpreter: Unix Shell | the attachment's payload |
| 12 | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files | DB conn string in `/etc/waystar/db.conf`, backup keys, `.pgpass` |
| 12 | [T1555](https://attack.mitre.org/techniques/T1555/) Credentials from Password Stores | sysadmin keyring / pass(1) |
| 12 | [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery | scoping out reachable file shares |

### Group E — Objectives

| Phase | Technique | Where it bites |
|---|---|---|
| 13 | [T1005](https://attack.mitre.org/techniques/T1005/) Data from Local System | session-notes file tree |
| 13 | [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories | the patient DB |
| 13 | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) Archive Collected Data: Archive via Utility | tar/gzip/AES-pack |
| 14 | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel | piped through the tunnel from phase 5 |
| 14 | [T1030](https://attack.mitre.org/techniques/T1030/) Data Transfer Size Limits | chunking the upload |
| 15 | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery | revoke backup keys, kill backup timers, delete recent snapshots |
| 15 | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | the actual ransomware encryption |
| 15 | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) Defacement: Internal Defacement | ransom note dropped per host / per directory |

## Detection notes per technique

For SOC training and customer SIEM/EDR demos, what *should* fire on each technique. Implementation of the actual detection pipeline (Wazuh / Sigma / Suricata rules) is out of scope here. Persistent log volumes — the customer ask in `intern/Protokolle/Protokoll - 27.04.26.md:20` — landed in PR #58: every signal below now writes to a host-mounted file under `Infrastructure/logs/` so an external SIEM can ingest them.

| Technique(s) | Detection source | Signature / behaviour | Lab log path (PR #58) |
|---|---|---|---|
| T1190 (CVE-2021-41773) | Apache access log + NIDS | URL pattern `cgi-bin/.%32%65/.../bin/sh` is unmistakeable; ETOPEN Suricata rules ship for this CVE | `logs/apache/access.log`, `logs/apache/forensic_log`; router NFLOG `FW-NEW: SRC=10.10.0.2 DST=10.30.0.2 DPT=80` in `logs/router/ulog-iptables.log` |
| T1059.004 reverse-shell payload | EDR (auditd execve) | `bash -i >& /dev/tcp/...` is a textbook signature | router NFLOG `FW-NEW: SRC=10.30.0.2 DST=10.10.0.2 DPT={4444,5555}` in `logs/router/ulog-iptables.log` (apache calling back to kali) |
| T1053.003 cron tampering | auditd file watch on `/opt/cleanup.sh`; cron logs | content change of a script run as root every minute | `/var/log/lab-fim.log` line `tag=lab_fim path=/opt/cleanup.sh event=MODIFY` (inside the apache container; inotify substitute for auditd — see implementation note below) |
| T1552.001 / .004 credential discovery | auditd file watch on `/root/.ssh/`, `/opt/waystar-connect/` | unusual reads from www-data / root after foothold | not yet implemented (post-foothold phase) |
| T1021.004 SSH lateral | sshd auth.log | new login from apache→workstation IP, principal `john.stravidis`, no prior session pattern | `logs/workstation/auth.log` (sshd `LogLevel VERBOSE` records key fingerprints) |
| T1098.004 authorized_keys append | EDR file watch on `~/.ssh/authorized_keys` | append events outside normal user sessions | `logs/workstation/lab-fim.log` once `john.stravidis` user lands (lab-fim already watches `~john.stravidis/.ssh`) |
| T1543.002 systemd persistence | auditd file watch on `~/.config/systemd/user/` and `/etc/systemd/`; systemd journal | new unit creation / enable | extend `Infrastructure/ubuntu_workstation/lab-fim.sh` watch list when this slice lands |
| T1572 / T1071.001 C2 tunnel | NIDS + flow logs | long-lived outbound TLS / SSH to non-routable / unusual destination; periodic keepalive cadence | `logs/router/ulog-iptables.log` — every NEW flow is captured with full 5-tuple |
| T1555.003 browser cred dump | EDR | unusual process accessing browser profile DBs | not yet implemented (post-foothold phase) |
| T1110.003 password spray (phase 7) | sshd auth.log + fail2ban | repeated auth failures from the same source IP across multiple accounts | `logs/workstation/auth.log` |
| T1018 / T1046 internal scanning | NetFlow / NIDS | bursts of SYN to many hosts/ports on internal subnet originating from a non-scanner host | `logs/router/ulog-iptables.log` (every SYN crosses FORWARD and gets NFLOG-tagged) |
| T1114.001 mail collection | auditd file watch on `/var/mail/`, `~/Maildir/` | unusual reads of mail files outside the user's normal MUA process | `logs/workstation/lab-fim.log` (lab-fim watches `/var/mail`) |
| T1566.001 + T1204.002 spearphishing chain | mail server logs + EDR (process spawn) | mail with executable attachment; process spawn of attachment payload from mail-processor / MUA | not yet implemented |
| T1486 ransomware encryption | EDR (file syscalls) + filesystem audit | high-rate file rename + size-similar rewrites across many directories; ransom-note file pattern | not yet implemented |
| T1490 inhibit recovery | auditd | systemd timer/service disable; deletion of backup files | not yet implemented |

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
- **ATT&CK Tactics touched**: Reconnaissance, Resource Development (implicit), Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion (light), Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact — 12 of 14 enterprise tactics. (Resource Development and Defense Evasion are the lighter ones; Defense Evasion grows naturally as the chain matures.)
- **Distinct ATT&CK techniques referenced**: ~30, spanning common SOC training territory (cron persistence, SSH lateral, browser-cred theft, spearphishing, ransomware impact).

This is enough breadth to genuinely exercise EDR + SIEM + NIDS, which is the customer brief's stated rationale (slide 5, "EDR & SIEM & NIDS & …").
