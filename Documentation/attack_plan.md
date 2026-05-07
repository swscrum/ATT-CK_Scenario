# Attack scenario — full attack plan

This document specifies the *technical* chain — what the attacker does, in what order, against which host. The story explains *why*; the mappings explain *what to detect*.

## Overview

The attacker is the same crew that breached Waystar Royco eighteen months ago (see `scenario_story.md`). Their goal on this second pass is two-stage: (1) full patient-data exfiltration, (2) ransomware-style impact on production data. The chain progresses through five logical groups, fifteen distinct phases:

| Group | Phases | Outcome |
|---|---|---|
| A — Public-facing entry | 1–2 | Root on Apache (Waystar Connect webserver) |
| B — Foothold expansion | 3–5 | Persistent, C2-enabled foothold on John Stravidis's workstation |
| C — Internal recon | 6–8 | Map the Linux fleet, find Reiner Hermann breadcrumb |
| D — Deep lateral movement | 9–12 | Sysadmin (Hans Müller) shell via Reiner → spearphishing chain |
| E — Objectives | 13–15 | Patient DB exfil + ransomware impact |

**Hybrid TTP profile** (carried over from the story design): noisy at the edge (groups A–C are loud, signature-able, and meant to be detected), quiet from the foothold inward (groups D–E use encrypted channels, careful pacing, and clean persistence — the work for the EDR/behavioural side of the SOC training).

## Pivot graph (host-level overview)

```mermaid
graph LR
    A[Attacker]
    Router[Router<br/>10.10.0.3 / 10.30.0.4]
    Web[Apache<br/>Waystar Connect<br/>10.30.0.2]
    J[John's WS<br/>john.stravidis<br/>10.30.0.5]
    H1[Hardened WS #1]
    H2[Hardened WS #2]
    Rn[Reiner's WS<br/>reiner.hermann]
    Hn[Sysadmin WS<br/>hans.mueller]
    DB[(Patient DB)]
    BK[(Backups)]

    A -->|"1. CVE-2021-41773"| Router --> Web
    Web -->|"4. SSH stolen deploy key"| J
    J -.x|"7. SSH key-only"| H1
    J -.x|"7. fail2ban"| H2
    J -->|"9. Reiner's reused personal key"| Rn
    Rn -->|"11. spearphish attachment"| Hn
    Hn -->|"13. DB conn"| DB
    Hn -->|"15. inhibit"| BK
    A <-->|"5. encrypted C2 tunnel"| J
    A <-->|"14. exfil over tunnel"| Hn
```

## Sequence diagram (UML)

```mermaid
sequenceDiagram
    actor Att as Attacker
    participant Web as Apache (Waystar Connect)
    participant J as John's WS
    participant H as Hardened WS (×2)
    participant R as Reiner's WS
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
    Att->>J: 8. Read /var/log/migration/, /home/reiner.hermann.bak/.ssh/
    J-->>Att: 8. Reiner's old personal SSH key

    Note over Att,R: Group D — Deep lateral movement
    Att->>R: 9. SSH with Reiner's personal key
    R-->>Att: shell as reiner.hermann
    Att->>R: 10. Read ~/Maildir
    R-->>Att: 10. emails identifying hans.mueller (sysadmin)
    Att->>R: 11. Compose + send spearphishing email to Hans
    R->>S: 11. SMTP attachment
    Note right of S: mail-processor sim opens attachment
    S-->>Att: 11. reverse shell as hans.mueller
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

**Story-required addition** (per 2026-04-27 protocol): a *discovery beat* — attacker tries several payload variants (single-encoded, alternative CGI-base paths) before the working one lands. Currently the working payload is sent directly. To honour: extend `initial_access.py` with a small variant-walk loop.

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

Lab seeding requirement: bake these into `Infrastructure/apache/`.

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

#### Phase 8 — Reiner Hermann breadcrumb

Attacker pokes around John's workstation more carefully and finds artefacts of the previous user:
- `/var/log/migration/2024-12-15-reiner-to-john.log` — explicit migration log naming both users
- `/home/reiner.hermann.bak/` — old home dir parked "for audit purposes" by IT, never deleted
- `/home/reiner.hermann.bak/.ssh/id_rsa` — Reiner's *personal* SSH key pair (not work-issued, didn't get rotated post-breach because IT only rotated the work keys)
- Old `bash_history` showing Reiner SSHing to internal hosts

Story payoff: the attacker recognises "Reiner Hermann" — they had his name from the prior breach. (Optional heavyweight version: Reiner *was* the previously-compromised account; he was fired in the aftermath, his workstation reissued to John.)

### Group D — Deep lateral movement *(new)*

#### Phase 9 — Lateral movement to Reiner's NEW workstation

Reiner is still employed (or rehired post-breach) and is now on a new workstation. **His personal SSH key is authorized on the new box** — when migrating he copied his dotfiles (`~/.ssh/`) from his old box, which is the OPSEC failure that makes this work. Attacker uses the key from phase 8.

#### Phase 10 — Email mining

Reiner's `~/Maildir` (or `/var/mail/reiner.hermann`) contains:
- An old thread with sysadmin **Hans Müller** (`hans.mueller@waystar-royco.example`) about a service-account password reset — exposes Hans's email and role
- Calendar invites / chat backlog confirming Hans's identity
- Possibly a thread where Hans asked Reiner for help, exposing that Reiner had break-glass dev access at one point

#### Phase 11 — Spearphishing the sysadmin

The chain's only "user simulation" beat. Two implementation choices (decision deferred to step 3):

- **Option A (recommended)**: A `mail-processor` daemon runs on Hans's workstation that periodically polls his mailbox and "opens" attachments from senders in his contact list. The processor *is* the simulated user — defensible to mark out-of-scope for detection (we model user behaviour, not the user's decision). Demo lands as: attacker sends → ~30 s later sysadmin shell appears.
- **Option B**: skip the phishing; Reiner's mail archive contains an old plaintext password Hans once emailed to him. Attacker reads → SSHes in. Simpler to implement; loses the phishing-detection beat.

Either way, attacker gets a reverse shell as `hans.mueller`.

#### Phase 12 — Sysadmin credential harvest

Hans is the prize because he holds the keys:
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

### Containers
- ✓ Existing: `kali` (attacker), `router`, `apache`, `ubuntu_workstation`
- **NEW**: rename `ubuntu_workstation` → `john_ws` (or add a workstation service per role). The current single workstation becomes John's.
- **NEW**: `reiner_ws` — Reiner's current workstation, on `internal_net`
- **NEW**: `hardened_ws_1`, `hardened_ws_2` — properly-hardened boxes that fail the lateral attempts (key-only, fail2ban)
- **NEW**: `sysadmin_ws` — Hans Müller's box; mail-processor daemon; database client; backup-control reach
- **NEW (optional, step 4 follow-up)**: `freeipa` — FreeIPA / SSSD domain controller, partial enrollment of the fleet (see `scenario_story.md` open items)
- **NEW**: a small mail relay (or local sendmail with SSH-based delivery) connecting Reiner → Hans
- **NEW**: a "patient DB" service (could be a SQLite in `/var/lib/waystar/db/patients.sqlite` on Hans's box, or a separate `postgres` container)

### Seeded files (per host)

**On apache**:
- `/opt/waystar-connect/deploy.log` referencing John's workstation
- `/root/.ssh/id_ed25519_deploy` (Stravidis's private deploy key)
- `/root/.deploy_config`

**On John's workstation**:
- `/var/log/migration/2024-12-15-reiner-to-john.log`
- `/home/reiner.hermann.bak/.ssh/id_rsa` (Reiner's personal SSH key)
- Browser profile with stored creds
- Plausible bash history, recent files, project tree

**On Reiner's workstation**:
- Reiner's personal SSH key in `~/.ssh/authorized_keys`
- `/var/mail/reiner.hermann` with a seeded `Maildir` containing the Hans correspondence
- A trace amount of "still has dev access" evidence (sudo group + a residual SSH config)

**On Hans's workstation**:
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
- `reiner_breadcrumb.py` — phase 8
- `lateral_to_reiner.py` — phase 9
- `mail_mining.py` — phase 10
- `spearphish.py` — phase 11
- `credential_harvest_sysadmin.py` — phase 12
- `collection.py` — phase 13
- `exfiltration.py` — phase 14
- `impact_ransomware.py` — phase 15

Many will be slim (one or two `send_command` calls plus state plumbing); some will need real implementation effort (the C2 tunnel setup, the ransomware encryption walk).

### Orchestrator changes (`Attack-chain/main.py`)

Each phase becomes a `Step(...)` in `CHAIN`, with proper `requires=` plumbing so the orchestrator can refuse to run a step whose state inputs are missing. The hybrid TTP model means several steps will set up shared state objects that persist across multiple subsequent steps (the C2 tunnel handle, the various per-host `Connection` objects).

## Open questions (deferred to step 3 implementation)

1. **C2 tunnel implementation** — autossh + TLS wrapper, or WireGuard, or a bespoke binary? Affects detection signature on the wire.
2. **Phishing path** — option A (mail-processor sim) or option B (plaintext password in archive). Recommendation: A, but parking the call.
3. **OS family for the workstation containers** — Ubuntu (today) or Rocky 9 / RHEL family (per the story discussion). RHEL family enables SELinux + auditd as native telemetry. Half-day swap.
4. **FreeIPA integration** — defer to phase 4 follow-up. The story explicitly supports a partial rollout, so adding it later is non-breaking.
5. **Patient DB technology** — SQLite (simplest) vs. PostgreSQL container (most realistic). Demo richness vs. infrastructure cost.
6. **Hardened workstations** — do they need to actually exist in the demo, or can phase 7 simulate the failed attempts against fictional addresses? Real containers are more honest but cost startup overhead.

These are step-3 calls, not blockers for the plan.

## Out of scope for this plan

- The full pre-foothold reconnaissance phase (recon over the public internet) is documented in the existing `Attack-chain/Concepts/Recon_Scenarios.md` and `initial_recon_1.py`; not duplicated here.
- The May 11 customer demo logistics — how the chain is presented, which phases get the spotlight — are not covered here. Story doc plus this attack plan are the inputs to that.
- Detection rules / Sigma signatures / Wazuh policies — see `mappings.md` for technique-level detection notes; concrete rules are step-4 work.
