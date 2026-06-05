# Infrastructure workflows — how sensitive artefacts got there

## 1. Purpose

This document explains, for each sensitive artefact in the lab, **which person
left it there through which everyday workflow** — not "it was seeded because the
attack chain needs it". Audience: simulation builders, pentesters, and defenders
(what "normal" looks like, so the attack stands out against it).

Cross-references, not duplicated here:
[scenario_story.md](./scenario_story.md) (setting + personas),
[attack_plan.md](./attack_plan.md) (the attack chain),
[mappings.md](./mappings.md) (MITRE technique mapping).

**Snapshot note.** Point-in-time snapshot as of **2026-06-05**, not maintained as
a live inventory. If the Dockerfiles or home templates change, re-verify against
`Infrastructure/`.

**Background personas (context only).** Three off-stage roles explain most
artefact *origins* without being attack targets:

- **Transition team / IT helpdesk** — provisions every workstation, sets the
  interim passwords, authorizes deploy keys. Trail in
  `ubuntu_workstation/john_home/Documents/`.
- **Dr. M. Roy (CTO) + turnaround consultancy** — set scope and the four-week
  deadline; appear only as names in `.../Documents/Useful contacts.md`, touch no
  host.
- **Key-distribution mechanism** — SSH keys are injected at build time via `COPY`
  from `Infrastructure/shared-lab-keys/`, modeling Vinzenz's provisioning (§3.3).
  No key is a static home file; home templates carry only `.ssh/config` and
  `.ssh/known_hosts`.

## 2. Container inventory

| Container | Network(s) | IP(s) | Role | Who touches it |
|---|---|---|---|---|
| `router` | public / dmz / internal | 10.10.0.3 / 10.40.0.4 / 10.30.0.4 | Zone-crossing iptables router | Vinzenz (config), attacker (transit) |
| `apache` | dmz | 10.40.0.2 | Waystar Connect webserver (CVE-2021-41773) | John (deploys), `www-data` (CGI), Vinzenz (fleet), Luke (note backups) |
| `ubuntu_workstation` | internal | 10.30.0.5 | John's dev/staging box | John (daily), Vinzenz (fleet) |
| `luke_ws` | internal | 10.30.0.7 | Luke's clinical box | Luke (daily), Vinzenz (fleet) |
| `vinzenz_ws` | internal | 10.30.0.8 | Sysadmin master box | Vinzenz (exclusive) |
| `db-internal` | internal | 10.30.0.6 | Postgres patient DB (no sshd) | web-app (INSERT), Luke (SELECT readonly), Vinzenz (superuser, via psql) |
| `kali` | public | 10.10.0.2 | Attacker host | not part of the company model |

## 3. User stories per persona

Each story: what the person does, the artefacts it leaves (in-container path +
repo `file:line`), and — where not self-evident — why it is realistic.

### 3.1 John Stravidis

Contracted frontend freelancer who built Waystar Connect. Works from
`ubuntu_workstation` (`10.30.0.5`), deploys to `apache` (`10.40.0.2`). Competent
and non-malicious; every shortcut traces back to the four-week deadline. His two
boxes are where the attack chain begins.

#### 3.1.1 Onboarded and given deploy access to apache

Per the transition team's checklist (`Documents/Your first few days.md`), John
picks up the provisioned Linux box, keeps the interim password "for now",
generates an ed25519 keypair, and sends the pubkey to IT so they authorize him on
the deploy host.

**Artefacts left behind:**
- `~/.ssh/id_ed25519` + `.pub` on the workstation — `ubuntu_workstation/Dockerfile:68-69`
- `john.stravidis@apache` `authorized_keys` — `apache/Dockerfile:53`
- `Host apache` deploy entry — `ubuntu_workstation/john_home/.ssh/config:1-5`
- Unrotated interim password `waystar2026!` — `ubuntu_workstation/Dockerfile:58`; open reset TODO in `Documents/Your first few days.md:9-12`

*Why realistic:* the interim password that "is fine for now" and never gets
rotated is the most common small-shop credential-hygiene failure.

#### 3.1.2 Clones the repo and runs the first pipeline test deploy

Clones `git@apache:waystar-connect.git`, runs `npm install` / `npm run dev`, and
ships a hello-world bundle via `rsync` to prove the pipeline end-to-end before
real code.

**Artefacts left behind:**
- Project working tree incl. `node_modules/` — `ubuntu_workstation/john_home/projects/waystar-connect/`
- Deploy procedure doc (exact rsync line) — `.../waystar-connect/docs/deploy.md:18-21`
- First deploy timestamp — `apache/john_home/projects/waystar-connect/deploy.log:1-2`
- Command trail — `ubuntu_workstation/john_home/.bash_history:19-50`

*Why realistic:* proving the deploy path with a throwaway page is standard practice.

#### 3.1.3 Runs the daily build-and-deploy loop

Edits, `npm run build`, `npm run deploy` (aliased) — which is just
`rsync -avz --delete dist/ john.stravidis@apache:/opt/waystar-connect/dist/`.

**Artefacts left behind:**
- `deploy` alias + `PGPASSFILE` export — `ubuntu_workstation/john_home/.bashrc:23-26`
- Deploy history, declining file counts (polished MVP, then small fixes) — `apache/john_home/projects/waystar-connect/deploy.log:1-10`
- Served bundle on apache — `/opt/waystar-connect/dist/` (`apache/Dockerfile:52`)
- Command trail both boxes — `ubuntu_workstation/john_home/.bash_history:49,89`; `apache/john_home/.bash_history:1-17`

*Why realistic:* a `--delete` rsync deploy with no CI is what a solo dev under
deadline reaches for.

#### 3.1.4 Chmod 777s the cron maintenance script while debugging

Working a deploy-permission issue with IT helpdesk — the per-minute `cleanup.sh`
cron job keeps overwriting the files he is testing — the fix that lands is a
`chmod 777` on `/opt/cleanup.sh` so `www-data` can also trigger it from a
browser-reachable test endpoint. John leaves a revert TODO, gets pulled into a UI
fix, and never reverts. (He has no sudo on apache himself; the privileged change
rode in on the helpdesk ticket.)

**Artefacts left behind:**
- `/opt/cleanup.sh` mode `777`, root-owned — `apache/Dockerfile:37-38`
- In-file TODO matching John's identity + `Last edit: John Stravidis` header — `apache/cleanup.sh:11-17`
- Per-minute root cron entry — `apache/Dockerfile:41-42`
- Corroboration in onboarding note ("permissions looser than they should be") — `Documents/Your first few days.md:53-56`

*Why realistic:* time-pressure debugging shortcuts that survive into production
are the most-cited root cause in incident post-mortems; the TODO is the artefact
of the intention to fix it. This is the privilege-escalation vector of the chain
(see [attack_plan.md](./attack_plan.md)).

#### 3.1.5 Wires up read-only DB access to inspect real data shapes

Connects with `psql -h db-internal -U waystar-readonly`, then hand-writes a
`.pgpass` line so `psql` stops prompting. Separately, the project shipped with a
`.env` of vibecoded boilerplate — AI-generated alongside the MVP — that carries
the workstation password as a "convenience" value; no script reads it, and it was
never audited or removed.

**Artefacts left behind:**
- Read-only DB cred, self-created via `echo ... >> .pgpass` — `ubuntu_workstation/john_home/.bash_history:78-79`; file at `.../waystar-connect/.pgpass`
- `PGPASSFILE` pointing at it — `ubuntu_workstation/john_home/.bashrc:26`
- `.env` carrying `WS_PASS=waystar2026!`, unused boilerplate, never removed — `apache/john_home/.env:9-18`
- `waystar-app` DB creds for the booking CGI (separate, app-owned) — `apache/Dockerfile:74-78`

*Why realistic:* a developer self-creating a `.pgpass` to stop prompts is
everyday convenience; the credential lands on disk as a direct result. The
plaintext `WS_PASS` is the "vibecoded code, never reviewed" line from
[scenario_story.md](./scenario_story.md) made literal — the file's own comment
admits it was "meant to be removed before go-live".

#### 3.1.6 Probes what else his deploy key can reach during onboarding

Tries his key against other internal hosts out of curiosity, finds only `apache`
accepts him, and notes in his config that "the rest are key-only and centrally
managed."

**Artefacts left behind:**
- Probe entries for `luke_ws` / `vinzenz_ws` with explaining comment — `ubuntu_workstation/john_home/.ssh/config:7-18`
- Failed-reach command noise (incl. hosts not in the current fleet) — `ubuntu_workstation/john_home/.bash_history:65-71`

*Why realistic:* the denied attempts are themselves a SOC signal (failed
`T1021.004` / `T1078`), and the stale config entries model how access notes
accumulate.
