# Attack scenario — full attack plan

This document specifies the *technical* chain — what the attacker does, in what order, against which host. The story explains *why*; the mappings explain *what to detect*.

## Overview

The attacker is the same crew that breached Waystar Royco eighteen months ago (see `scenario_story.md`). Their goal on this second pass is two-stage: (1) full patient-data exfiltration, (2) ransomware-style impact on production data. The chain progresses through five logical groups, fifteen distinct phases:

| Group | Phases | Outcome |
|---|---|---|
| A — Public-facing entry | 1–2 | Root on Apache (Waystar Connect webserver) |
| B — Foothold expansion | 3–5 | Persistent, C2-enabled foothold on John Stravidis's (freelance webdev) workstation |
| C — Internal recon | 6–8 | Map the Linux fleet, attempt lateral to Luke Smith (psychiatrist) |
| D — Deep lateral movement | 9–12 | Sysadmin (Vinzenz Fedora) shell via SSH key theft → cross-fleet reach |
| E — Objectives | 13–15 | Patient DB exfil + ransomware impact |

**Hybrid TTP profile** (carried over from the story design): noisy at the edge (groups A–C are loud, signature-able, and meant to be detected), quiet from the foothold inward (groups D–E use encrypted channels, careful pacing, and clean persistence — the work for the EDR/behavioural side of the SOC training).

## Modes: basic vs advanced

The chain ships in two operator-selectable shapes that share groups A–B and diverge after John's workstation:

### Basic mode — messy, loud, exfil what you have

1. Groups A–B as below: CVE on apache, privesc to root, lateral to John.
2. **Failed lateral to Luke Smith.** Attacker attempts SSH from John's box → Luke's (`10.30.0.7`) using credentials and keys harvested from John. Luke's box doesn't trust those credentials → sshd denies; with fail2ban or rate-limited retries the attempts become a clear T1110 detection signature. Attacker gives up on Luke.
3. **Exfil what's on John's box** (Documents, browser profile, `.bash_history`, the dev SQLite cache) and leave. Messy: no cleanup, no persistence beyond what apache's poisoned `/opt/cleanup.sh` already provides. SOC sees a noisy, opportunistic intrusion.

What the SOC trainee gets to detect: the CVE attack path, the cron-poison privesc, the lateral SSH to John, the *failed* attempts on Luke, and unstructured exfil from John.

### Advanced mode — sysadmin pivot, then patient data

1. Groups A–B identical to basic.
2. **Same failed attempt on Luke** — same loud T1110 signature; the attacker can't reach Luke directly.
3. **Pivot to Vinzenz Fedora (sysadmin).** From John's box, the attacker enumerates the fleet and identifies `vinzenz_ws` (`10.30.0.8`). They reach Vinzenz via a credential left on John's box (a stale ssh config, a documented `vinzenz.fedora@*` SSH alias in `~/.ssh/config`, or a captured password) and SSH in. On Vinzenz's box they find `~/.ssh/id_ed25519` — the cross-fleet master key (T1552.004 — unsecured private key).
4. **Lateral to Luke via the sysadmin's account.** Using Vinzenz's key, the attacker SSHes into Luke's box as `vinzenz.fedora` (a real sudoer account on Luke's host, installed during fleet provisioning). They're now root-equivalent on Luke's box without ever having Luke's password.
5. **Read Luke's `.pgpass` + query the patient DB.** With Luke's `waystar-readonly` credentials they run `psql` from his box and pull everything in `patients`, `session_notes`, and `appointments`. Same query a legitimate SOC analyst would write — but from the wrong identity at the wrong time.
6. **Exfil + impact (groups D–E).** Tunnel the patient data out over the existing C2 channel; with Vinzenz's superuser `.pgpass` (full RW on `db-internal`) optionally proceed to T1490/T1486 (inhibit recovery, encrypt for impact).

What advanced adds for the SOC trainee: the **sysadmin-key-theft** detection beat (lab-fim on `~vinzenz.fedora/.ssh/id_ed25519`), the **lateral via sysadmin account** beat (sshd log shows `vinzenz.fedora` logging into Luke's box from `vinzenz_ws` IP — legitimate sysadmin behaviour, but possibly at off-hours from the wrong source IP if the attacker is sloppy), and the **patient-DB exfiltration** beat (postgres query log shows large `SELECT *` against `patients` + `session_notes` issued by `waystar-readonly` from Luke's host).

## Chain summary

| Phase | Step | ATT&CK |
|---|---|---|
| Recon | (existing) external scanning | T1592, T1595 |
| Recon | post-foothold network scan | T1018, T1046 |
| Initial Access | (existing) CVE-2021-41773 | T1190 |
| Execution | (existing) reverse shell | T1059.004 |
| Privilege Escalation | (existing) cron + chmod 777 | T1053.003 |
| Credential Access | deploy creds in files on apache | T1552.001 |
| Discovery + Credential Access | nmap sweep + sshpass spray from apache | T1018, T1046, T1110.004 |
| Lateral Movement | SSH to John | T1021.004, T1078 |
| Persistence | authorized_keys + systemd user unit | T1098.004, T1543.002 |
| Command & Control | encrypted reverse tunnel | T1572, T1071.001 |
| Discovery | files, accounts, history on John's box | T1083, T1087, T1518 |
| Lateral (failed) | brute force on hardened boxes | T1110 (detected/denied) |
| Discovery | Luke artefacts | T1083, T1087 |
| Credential Access | Luke's personal SSH key | T1552.004 |
| Lateral Movement | SSH to Luke | T1021.004, T1078 |
| Collection | mail mining for sysadmin coords | T1114.001 |
| Initial Access (phase 2) | spearphishing attachment to Vinzenz | T1566.001 |
| Execution | user opens attachment (sim) | T1204.002 |
| Lateral / Privesc | sysadmin shell | T1078 |
| Defense Evasion | inhibit backups before ransomware | T1490 |
| Collection | DB + session notes | T1005, T1213 |
| Exfiltration | over C2 tunnel | T1041 |
| Impact | ransomware encryption | T1486 |

## Sequence diagram (UML)

```mermaid
sequenceDiagram
    actor Att as Attacker
    participant Web as Apache (Waystar Connect)
    participant J as John's WS
    participant H as Hardened WS (×2)
    participant R as Luke's WS
    participant S as Sysadmin WS

    Note over Att,Web: Group A — Public-facing entry (already implemented)
    Att->>Web: 1. CVE-2021-41773 path traversal
    Web-->>Att: www-data reverse shell
    Att->>Web: 2. Overwrite chmod-777 /opt/cleanup.sh
    Web-->>Att: root shell via cron

    Note over Att,J: Group B — Foothold expansion
    Att->>Web: 3. Read /opt/waystar-connect/deploy.log + ~/.ssh/
    Web-->>Att: john.stravidis identity + deploy SSH key
    Att->>J: 4. SSH with stolen deploy key
    J-->>Att: shell as john.stravidis
    Att->>J: 5. Install authorized_keys + systemd user unit
    Att-->>J: 5. Establish encrypted C2 tunnel
    
    Note over Att,J: Group C — Internal recon
    Att->>J: 6. Dump browser creds, bash history, mail, recents
    Att->>H: 7. SSH attempts (password spray, john's key)
    H-->>Att: 7. auth failures + fail2ban (visible to SIEM later)
    Att->>J: 8. Read /var/log/migration/, /home/luke.smith.bak/.ssh/
    J-->>Att: 8. Luke's old personal SSH key

    Note over Att,R: Group D — Deep lateral movement
    Att->>R: 9. SSH with Luke's personal key
    R-->>Att: shell as luke.smith
    Att->>R: 10. Read ~/Maildir
    R-->>Att: 10. emails identifying vinzenz.fedora (sysadmin)
    Att->>R: 11. Compose + send spearphishing email to Vinzenz
    R->>S: 11. SMTP attachment
    Note right of S: mail-processor sim opens attachment
    S-->>Att: 11. reverse shell as vinzenz.fedora
    Att->>S: 12. Harvest DB creds, backup keys, fleet SSH keys

    Note over Att,S: Group E — Objectives
    Att->>S: 13. Dump patient DB, tarball session notes
    S-->>Att: 13. data
    Att->>Att: 14. Receive exfil chunks (over C2 tunnel from step 5)
    Att->>S: 15. Disable backups (T1490)
    Att->>S: 15. Encrypt files in place + drop ransom note
```

## Per-phase detail

### Group A — Public-facing entry *(already implemented)*

#### Phase 1 — Initial Access via CVE-2021-41773

Status: ✓ implemented in `Attack-chain/initial_access.py`.
- Attacker sends double-encoded path-traversal POST to `http://router/cgi-bin/.%32%65/.../bin/sh` containing a bash reverse-shell payload.
- Apache 2.4.50 mis-handles the encoding, executes `/bin/sh` with the POST body as input.
- Result: `www-data` reverse shell from apache to attacker on TCP/4444.

**Discovery beat** (per 2026-04-27 protocol): ✓ implemented. Before the working request, `fire_exploit` walks through three plausible-but-failing variants — un-encoded `../` traversal (normalised away by Apache), a too-shallow traversal that never reaches a binary, and a GET against the correct path (no body, so no stdin for the CGI shell). Each one reaches the server and lands in the Apache access log, mirroring an attacker fine-tuning the exploit, before the working double-encoded POST lands. The loop carries an `attempt_delay` parameter (default 0, wired through `get_www_shell`) so a scenario operator can later pace the attacker.

#### Phase 2 — Privilege Escalation via writable cron

Status: ✓ implemented in `Attack-chain/privesc.py`.
- Attacker overwrites `/opt/cleanup.sh` (chmod 777, run by root cron every minute) with a reverse-shell payload.
- Within ≤60 s, cron fires and connects back: root reverse shell from apache to attacker on TCP/5555.

### Group B — Foothold expansion *(new)*

#### Phase 3 — Credential discovery on apache

Find Stravidis's deploy credentials, which were left behind during MVP delivery:
- `/opt/waystar-connect/deploy.log` containing rsync/scp lines like `rsync -avz john.stravidis@10.30.0.5:/proj/waystar-connect/dist/ /var/www/html/`
- `/root/.ssh/authorized_keys` and `/root/.ssh/known_hosts` referencing `john.stravidis@10.30.0.5`
- A deploy SSH private key the attacker can copy out (most realistic location: `/root/.ssh/id_ed25519_deploy` or in a `.deploy_config` Stravidis dropped to make `make deploy` work)
- John's interim password in `/home/john.stravidis/.env` (mode 600, owned by john.stravidis — not readable by www-data pre-privesc, but accessible once root is obtained). The file is the vibecoded MVP's dev-env helper that was never removed before go-live; the same `waystar2026!` the transition team set on the workstation account is sitting next to deploy-host metadata.

Lab seeding requirement: bake these into `Infrastructure/apache/`.

#### Phase 3.5 — Internal host discovery + credential stuffing

Status: ✓ implemented across two chain steps — step 1 below (reading john's `.env`, Credential Access / T1552.001) lives in `Attack-chain/credential_access.py`; steps 2–3 (internal nmap sweep and the password spray / credential stuffing, T1018 / T1046 / T1110.004) live in `Attack-chain/lateral_movement.py`.

Before the attacker has any IP for John's workstation in hand, they:

1. Read `/home/john.stravidis/.env` (mode 600, john.stravidis-owned — only accessible after privesc to root) and pull `WS_PASS=waystar2026!`. T1552.001 — Credentials In Files.
2. Run `nmap -Pn -n -p 22 --open 10.30.0.0/24` from inside apache to enumerate live SSH hosts on the internal subnet. T1018 / T1046. Apache→Internal :22 is the only zone-crossing that the router's FORWARD policy permits, so this scan is the cheapest legitimate discovery path open from a DMZ foothold.
3. For each discovered host, attempt password-only SSH as `john.stravidis` using `sshpass`. T1110.004 — Credential Stuffing (reuse of one known credential pair against many endpoints). The spray succeeds on John's workstation only; the other accounts (Luke, Vinzenz) reject the password.

The orchestrator runs this from Kali but executes the actual scan + spray FROM apache via the existing root reverse shell — Kali itself has no FORWARD-permitted path to internal_net :22. The "what an operator would actually type" command is `nxc ssh 10.30.0.0/24 -u john.stravidis -p 'waystar2026!'` — [netexec](https://www.netexec.wiki/) is installed in the kali image for that manual demo. It cannot drive the automated chain end-to-end because (a) the router blocks External→Internal :22, and (b) the apache base image (Debian Buster, Python 3.7) is below netexec's minimum Python version.

Output of this step seeds `ctx.state["john_ip"]` so the lateral-movement step skips deploy.log parsing.

#### Phase 4 — Lateral movement to John's workstation

- SSH from attacker (or proxied through apache) to `10.30.0.5` using the stolen deploy key, principal `john.stravidis`.
- "Advanced TTP" upgrade begins here — attacker uses an SSH client wrapped in a TLS proxy / SSH multiplexing to reduce signal.

#### Phase 5 — Foothold establishment

Three things, in order:
1. **Persistence**: append a new public key to `~/.ssh/authorized_keys`; install a hidden `~/.config/systemd/user/<service>.service` providing a re-connect-on-boot daemon.
2. **Encrypted C2 tunnel**: bring up an autossh + TLS-wrapped reverse tunnel back to attacker infrastructure. Subsequent steps' traffic flows through this rather than touching the open Internet.
3. **Light cleanup**: prune obvious bash-history entries, set `HISTFILE=/dev/null` in the spawned shells.

### Group C — Internal recon *(new)*

#### Phase 6 — Discovery on John's workstation

What's harvested:
- Browser-stored credentials (Firefox/Chrome profile: `key4.db` + `logins.json`)
- `~/.bash_history`, `~/.ssh/known_hosts`, `~/.ssh/config`
- Mail client configuration (Thunderbird profile or local `Maildir`)
- Recent files, project trees in `~/projects/`
- Sudo membership, installed package list

#### Phase 7 — Failed lateral attempts (visible)

This phase is **deliberately noisy** — its purpose is to leave clean evidence in `auth.log` for the SIEM-side of the demo. Two hardened workstations (let's call them WS-3 and WS-4 in the lab) are tried:
- WS-3: password-auth disabled, SSH-key-only with a key John doesn't have. Attacker tries Stravidis's key, common-password spray, gets nothing.
- WS-4: same plus `fail2ban`. After ~5 failed attempts the attacker's IP gets banned for 1h. Visible auth-log + fail2ban-action evidence.

The point of two hardened boxes: shows that "the company *did* invest post-breach, but unevenly" — exactly the story's claim about the in-progress Linux transition.

#### Phase 8 — Failed lateral attempt against Luke Smith

The attacker enumerates the fleet from John's box and identifies Luke Smith's workstation (`luke_ws`, `10.30.0.7`) as the obvious next employee target. They attempt to log in:

- with John's stolen credentials — fails, different account
- with John's SSH key (in case Luke trusts it) — fails, key not in `authorized_keys`
- with common-password spray against `luke.smith` — fails, sshd `LogLevel VERBOSE` records each attempt

This is **deliberately noisy** and is the central detection beat of the **basic** mode. sshd auth.log + fail2ban (if configured) tells the SOC story clearly: "external attacker pivoted onto John, attempted lateral to Luke, was denied."

In **basic mode** the attacker gives up here and proceeds to messy exfil from John's box (Phase 13 / 14 collapsed into a single tarball-and-leave step).

In **advanced mode** the attacker does NOT proceed directly to Luke at all — they pivot to the sysadmin first (Phase 9), then use the sysadmin's account to land on Luke as a sudoer (Phase 11), bypassing the lateral problem.

### Group D — Deep lateral movement *(advanced mode)*

#### Phase 9 — Pivot to the sysadmin's workstation

From John's box, the attacker finds breadcrumbs pointing at Vinzenz Fedora — IT's sysadmin:

- `~/.ssh/known_hosts` entries for `vinzenz_ws` (10.30.0.8)
- a stale SSH config alias `vinzenz` in John's `.ssh/config`
- a password Vinzenz once emailed to John (or wrote to a shared chat log) that's still in scrollback

Using whichever of these works, the attacker SSHes into `vinzenz_ws` as `vinzenz.fedora`. Once on the sysadmin's box they find the central loot artefact: `~/.ssh/id_ed25519`, the unencrypted cross-fleet master key (T1552.004).

#### Phase 10 — Cross-fleet key reach + exfiltrating the master key

With Vinzenz's private key copied out to attacker infrastructure, the attacker can now SSH as `vinzenz.fedora` into:

- `apache` (DMZ) — root-equivalent via sudo
- `john_ws` (already owned, but now as sudoer rather than via the cron poisoning)
- `luke_ws` — the lateral the attacker couldn't get directly in Phase 8

This is the moment the chain pivots from "messy" to "owns the network". sshd auth.log shows `vinzenz.fedora` logins from `vinzenz_ws`'s IP — *that* part looks legitimate; the SOC has to detect on timing, frequency, or out-of-hours patterns.

#### Phase 11 — Lateral to Luke as the sysadmin

The attacker SSHes into `luke_ws` as `vinzenz.fedora` (a real sudoer account on Luke's host, installed by IT during fleet provisioning so that admin can manage the box). They sudo to luke.smith (or just stay as root via sudo) and now have full read of Luke's home directory.

Specifically they read:

- `~luke.smith/.pgpass` — `db-internal:5432:waystar:waystar-readonly:ChangeMe!2026`
- `~luke.smith/.bash_history` — the queries Luke routinely runs against the patient DB
- `~luke.smith/Documents/notes/` — local therapy notes (if seeded by the realistic-content slice)
- `~luke.smith/.local/share/waystar-psyc/patients.sqlite` — local patient cache (if seeded)

#### Phase 12 — Patient data exfiltration via Luke's identity

Using the credentials from Luke's `.pgpass` the attacker runs `psql -h db-internal -U waystar-readonly -d waystar` *from Luke's host*. They dump:

- `SELECT * FROM patients` — full PII roster
- `SELECT * FROM session_notes` — clinical content with diagnoses and contact info
- `SELECT * FROM appointments` — booking pipeline (less sensitive but rounds out the haul)

Tarball + exfil over the existing C2 tunnel. Postgres logs will show the query — but they'll show it coming from Luke's host with Luke's credentials, looking exactly like normal clinical work.

#### Phase 10 — Email mining

Luke's `~/Maildir` (or `/var/mail/luke.smith`) contains:
- An old thread with sysadmin **Vinzenz Fedora** (`vinzenz.fedora@waystar-royco.example`) about a service-account password reset — exposes Vinzenz's email and role
- Calendar invites / chat backlog confirming Vinzenz's identity
- Possibly a thread where Vinzenz asked Luke for help, exposing that Luke had break-glass dev access at one point

#### Phase 11 — Spearphishing the sysadmin

The chain's only "user simulation" beat. Two implementation choices (decision deferred to step 3):

- **Option A (recommended)**: A `mail-processor` daemon runs on Vinzenz's workstation that periodically polls his mailbox and "opens" attachments from senders in his contact list. The processor *is* the simulated user — defensible to mark out-of-scope for detection (we model user behaviour, not the user's decision). Demo lands as: attacker sends → ~30 s later sysadmin shell appears.
- **Option B**: skip the phishing; Luke's mail archive contains an old plaintext password Vinzenz once emailed to him. Attacker reads → SSHes in. Simpler to implement; loses the phishing-detection beat.

Either way, attacker gets a reverse shell as `vinzenz.fedora`.

#### Phase 12 — Sysadmin credential harvest

Vinzenz is the prize because he holds the keys:
- Patient-DB connection string (in `/etc/waystar/db.conf` or his `~/.pgpass`)
- Backup encryption keys (`~/keys/backup-*.key` or in `pass`/keyring)
- Fleet SSH keys (he can reach every Linux host)
- Sudo rights on file shares where session notes are stored

### Group E — Objectives *(new)*

#### Phase 13 — Collection

- Dump full patient DB (`pg_dump`-equivalent against the seeded patient DB) into a local tarball
- `tar` the session-notes directory tree
- Pack into chunked AES-encrypted archives ready for staged exfil

#### Phase 14 — Exfiltration

- Push chunks over the encrypted C2 tunnel established in phase 5 — *not* a pastebin, *not* bare HTTP. The exfil rides the same tunnel that's already been used for command traffic.
- Pace the upload to avoid burst-volume detection; spread over minutes/hours in a real engagement, compressed for demo.
- ATT&CK: Exfiltration over C2 channel.

#### Phase 15 — Impact

In strict order (this matters for realism — backups go first):
1. **Disable backups**: revoke or corrupt backup credentials, kill the systemd timer that runs incremental backups, delete the most recent local backup snapshots. (T1490 Inhibit System Recovery.)
2. **Encrypt files in place**: walk reachable file trees, AES-encrypt session notes / DB exports / any reachable Waystar Connect data. Custom binary preferred over shipping an off-the-shelf ransomware family (the project rules forbid known malware).
3. **Drop ransom note**: a `RANSOM.txt` (or themed Markdown) in each affected directory and on each compromised host's desktop.

## Lab artifacts that need to exist for this plan

Items marked **NEW** are not in the lab today. Items in *italics* are configuration changes to existing components.

### Network zones

Three-tier segmentation enforced by the `router` container's iptables FORWARD
chain. All cross-zone traffic must traverse the router, where it gets a
NFLOG line in `Infrastructure/logs/router/ulog-iptables.log`.

```
                ┌──── public_net  10.10.0.0/24 ────┐
                │                                   │
            [kali]                            [router]
            10.10.0.2          public_if .10.10.0.3 │
                                  dmz_if  10.40.0.4 │
                              internal_if 10.30.0.4 │
                                                    │
                ┌──── dmz_net     10.40.0.0/24 ─────┤
                │                                   │
            [apache]                                │
            10.40.0.2                               │
                                                    │
                ┌──── internal_net 10.30.0.0/24 ────┘
                │                       │
        [john's workstation]      (future: luke_ws,
        10.30.0.5                  hardened_ws_*,
                                   sysadmin_ws, ...)
```

Allowed flows (everything else dropped by `FORWARD` policy):

| From → To | Ports | Use |
|---|---|---|
| External → DMZ | tcp 80 (via DNAT) | the CVE-2021-41773 entry path |
| DMZ → External | any | apache's reverse shells dial back to kali :4444 / :5555 |
| DMZ → Internal | tcp 22 | Phase 4 lateral SSH (apache → john.stravidis) — **now loggable** |
| Internal → DMZ | tcp 22 | deploy path (john pushing back to apache) |
| Internal → External | any | future C2 / outbound from workstation |

### Containers
- ✓ Existing: `kali` (attacker), `router`, `apache`, `ubuntu_workstation`
- **NEW**: rename `ubuntu_workstation` → `john_ws` (or add a workstation service per role). The current single workstation becomes John's.
- **NEW**: `luke_ws` — Luke's current workstation, on `internal_net`
- **NEW**: `hardened_ws_1`, `hardened_ws_2` — properly-hardened boxes that fail the lateral attempts (key-only, fail2ban)
- **NEW**: `sysadmin_ws` — Vinzenz Fedora's box; mail-processor daemon; database client; backup-control reach
- **NEW (optional, step 4 follow-up)**: `freeipa` — FreeIPA / SSSD domain controller, partial enrollment of the fleet (see `scenario_story.md` open items)
- **NEW**: a small mail relay (or local sendmail with SSH-based delivery) connecting Luke → Vinzenz
- **NEW**: a "patient DB" service (could be a SQLite in `/var/lib/waystar/db/patients.sqlite` on Vinzenz's box, or a separate `postgres` container)

### Seeded files (per host)

**On apache**:
- `/opt/waystar-connect/deploy.log` referencing John's workstation
- `/root/.ssh/id_ed25519_deploy` (Stravidis's private deploy key)
- `/root/.deploy_config`

**On John's workstation**:
- `/var/log/migration/2024-12-15-luke-to-john.log`
- `/home/luke.smith.bak/.ssh/id_rsa` (Luke's personal SSH key)
- Browser profile with stored creds
- Plausible bash history, recent files, project tree

**On Luke's workstation**:
- Luke's personal SSH key in `~/.ssh/authorized_keys`
- `/var/mail/luke.smith` with a seeded `Maildir` containing the Vinzenz correspondence
- A trace amount of "still has dev access" evidence (sudo group + a residual SSH config)

**On Vinzenz's workstation**:
- The `mail-processor` daemon (option A from phase 11)
- DB connection string in `/etc/waystar/db.conf`
- Backup keys in `~/keys/`
- SSH keys to the fleet in `~/.ssh/`
- Patient DB and `notes/` directory (or a connection to the DB container) — these are the targets for phases 13/15

### New scripts in `Attack-chain/`

- `credential_access_apache.py` — phase 3
- `lateral_to_john.py` — phase 4
- `installation.py` — phase 5 (persistence + C2 tunnel setup)
- `discovery_john.py` — phase 6
- `failed_lateral.py` — phase 7 (the deliberate noise)
- `luke_breadcrumb.py` — phase 8
- `lateral_to_luke.py` — phase 9
- `mail_mining.py` — phase 10
- `spearphish.py` — phase 11
- `credential_harvest_sysadmin.py` — phase 12
- `collection.py` — phase 13
- `exfiltration.py` — phase 14
- `impact_ransomware.py` — phase 15

Many will be slim (one or two `send_command` calls plus state plumbing); some will need real implementation effort (the C2 tunnel setup, the ransomware encryption walk).

### Orchestrator changes (`Attack-chain/main.py`)

Each phase becomes a `Step(...)` in a chain (`CHAIN_BASIC` / `CHAIN_ADVANCED`, selected at runtime via `--mode {basic,advanced}`), with proper `requires=` plumbing so the orchestrator can refuse to run a step whose state inputs are missing. The hybrid TTP model means several steps will set up shared state objects that persist across multiple subsequent steps (the C2 tunnel handle, the various per-host `Connection` objects). Advanced mode currently mirrors basic; stealthier per-step variants are swapped into `CHAIN_ADVANCED` as they're implemented.

## Open questions (deferred to step 3 implementation)

1. **C2 tunnel implementation** — autossh + TLS wrapper, or WireGuard, or a bespoke binary? Affects detection signature on the wire.
2. **Phishing path** — option A (mail-processor sim) or option B (plaintext password in archive). Recommendation: A, but parking the call.
3. **OS family for the workstation containers** — Ubuntu (today) or Rocky 9 / RHEL family (per the story discussion). RHEL family enables SELinux + auditd as native telemetry. Half-day swap.
4. **FreeIPA integration** — defer to phase 4 follow-up. The story explicitly supports a partial rollout, so adding it later is non-breaking.
5. **Patient DB technology** — SQLite (simplest) vs. PostgreSQL container (most realistic). Demo richness vs. infrastructure cost.
6. **Hardened workstations** — do they need to actually exist in the demo, or can phase 7 simulate the failed attempts against fictional addresses? Real containers are more honest but cost startup overhead.
