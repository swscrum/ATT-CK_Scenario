# Analyst session briefing — Waystar Royco SOC exercise

> **Hand this to the analyst at session start.** All they need to know is in
> here. Pair with [`analyst_findings_template.yaml`](analyst_findings_template.yaml)
> (the submission form) and, depending on tier, the cheat sheet at the bottom.

---

## The scenario (60 seconds)

**Waystar Royco** is a regional mental-health franchise. Eighteen months ago
they were breached — partial patient-record leak, public scrutiny, leadership
change. Today they relaunched: **Waystar Connect**, an online-therapy
platform built in four weeks by a single freelancer (**John Stravidis**). The
launch announcement hit LinkedIn this morning. Within hours, the **same crew
that breached them eighteen months ago** — who never went away — came back.

Your SIEM has been ingesting today's logs from Waystar Connect's web server
(`apache`, DMZ), the edge router, three internal Linux workstations (John's,
plus a clinician `luke_ws` and a sysadmin `vinzenz_ws`), and the patient
database. The day looks normal at a glance. It isn't.

**Find out what happened.**

---

## Your mission

Investigate the day's activity, build a timeline of the attack, and submit
your findings in [`analyst_findings_template.yaml`](analyst_findings_template.yaml).
For each attack beat you identify, you must record:

- **Tactic** (MITRE ATT&CK ID, e.g. `TA0001`)
- **Technique** (MITRE ATT&CK ID, e.g. `T1190`)
- **Detected at** (ISO 8601 UTC timestamp from the log line that gave it
  away — use the SIEM dashboard's clock, not wall-clock)
- **Evidence** (path:line OR query that surfaced it)
- **Notes** (one sentence on why this is what you think it is)

A clean chain has on the order of **6 distinct beats** — recon, initial
access, post-foothold enumeration, privilege escalation, credential access,
lateral movement. Don't anchor to that number — find what's there.

---

## Access

| Surface | How to reach it | Credentials |
|---|---|---|
| **SIEM dashboard** | _(filled in by instructor at session start)_ | _(filled in by instructor)_ |
| **Raw log snapshot** | `Infrastructure/logs/run-<ts>/` on the lab host | (read-only files) |
| **Diurnal-stretched logs** | `*.diurnal.log` siblings in the same dir | ingest these into your SIEM |
| **Live lab — apache shell** | `docker exec -it apache bash` | (root inside container) |
| **Live lab — John's workstation desktop** | `vncviewer localhost:5901` | _(no password — lab)_ |
| **Live lab — Postgres** | `docker exec -it db-internal psql -U waystar` | `WaystarDB!Secure2024` |
| **Live lab — any container** | `docker compose -f Infrastructure/docker-compose.yml exec <name> sh` | varies |

The lab is **kept up** for the duration of your session — feel free to
`docker exec` into any host to verify a finding (e.g., "is the file the
attacker dropped still there?"). It's a static snapshot of the moment the
chain finished, so things you touch don't change the logs you've already
ingested.

### Reading the SIEM clock

The SIEM dashboard shows events spanning a normal **9am–5pm workday**. The
actual chain ran in roughly 30 min to 6 h wall-clock; the diurnal rewriter
stretched the timestamps onto a synthetic business day so the dashboard
reads naturally. The mapping is recorded in
`Infrastructure/logs/run-<ts>/diurnal_manifest.json` if you need to convert
back to wall-clock (you usually won't).

---

## Useful starting points

You'll do better if you triangulate **two vantage points**:

1. **Edge view** — `logs/router/ulog-iptables.log`. Pre-NAT source IPs. Every
   FORWARD-crossing flow has a `FW-NEW` marker. This is where "who connected
   to what" lives.
2. **Host view** — `logs/apache/access.log`, `logs/workstation/auth.log`,
   `logs/db-internal/postgresql-*.log`, the `lab-fim.log` files. Post-NAT,
   application-level detail. This is where "what they did once they got in"
   lives.

A finding usually appears in **both** — start at the edge to spot anomalies,
pivot to host logs to confirm. If a beat only shows up in one of them, you
might be looking at false positives or noise.

Speaking of noise: **four distinct kinds of legitimate-looking background
traffic are hitting the web server all day**, each from its own pre-NAT
source IP:

- a **general human browsing pattern** (rotating desktop browser UAs, hits
  `/`, `/about.html`, the booking flow's static assets)
- an **uptime monitor** (predictable ~60s cadence, single endpoint, single
  monitor UA — easiest to identify in time-series views)
- an **internet background scanner** (404-yielding probes like
  `/wp-login.php`, `/.env`, `/phpmyadmin/`, with bot UAs like
  `python-requests`, `masscan`, `curl`)
- a **mobile browsing pattern** (mobile UAs, sparse cadence — minutes
  apart, not seconds)

Each noise source is *monomorphic* — it consistently exhibits one of those
four behaviors. The **attacker's traffic is the one that doesn't fit any
of them**: a single pre-NAT IP doing recon scanning, then exploit POSTs to
`/cgi-bin/...`, then internal-network SSH probes — a *mixed-behavior*
signature no legitimate source would produce. All sources arrive at apache
as the same post-NAT address; go look at the router to see the real source
IPs.

Hint that's fair to give Tier 1: the bot-looking probes are NOT the
attacker. The scanner probes are real-internet-noise; the attacker's CGI
traversal is something else entirely.

### Workstation-side baseline

The three internal workstations are **not idle**. Each runs a small daily-
user activity loop while the lab is in `--pacing realistic`:

- **John's workstation** — developer activity: `git status`, `npm` commands,
  occasional `sudo apt update`, `vim` edits on `~/projects/waystar-connect/`.
  Writes to `~/.bash_history` and `logs/workstation/auth.log` (sudo).
- **Luke's workstation** — clinical activity: `psql` queries to
  `db-internal` against his patient list, `vim` on `~/Documents/notes/`.
  Writes to `~/.bash_history`, `logs/luke_ws/auth.log`, AND
  `logs/db-internal/postgresql-*.log` (legitimate read-only queries from
  `waystar-readonly`).
- **Vinzenz's workstation** — sysadmin activity: SSHes out to apache,
  John's, Luke's boxes for routine maintenance (`uptime`, `df -h`),
  occasional sudo. Writes auth.log entries on his OWN box AND on the
  remote hosts (`Accepted publickey for vinzenz.fedora` from 10.30.0.8).

This means **finding "a sudo from john.stravidis" or "a vinzenz.fedora SSH
to apache" is NOT the attacker** — those happen routinely. The attacker
distinguishes themselves by: timing (off-hours), command sequences (recon
+ exploit + lateral in minutes), or by performing actions inconsistent
with the user's normal pattern (e.g., vinzenz.fedora SSHing to a host he
doesn't normally touch, OR doing it twice in 30 seconds when he usually
spaces sessions 10+ minutes apart).

---

## Deliverable

Fill in [`analyst_findings_template.yaml`](analyst_findings_template.yaml)
and hand it back to the instructor. **Save your work-in-progress as you
go** — most sessions are time-boxed and you'll want partial credit for
beats you spotted even if you didn't get to write them up.

---

## Tier-specific addendums

### Tier 1 — Junior (onboarding)
You also receive the **detection cheat sheet** at the bottom of this doc.
Use it to anchor what kinds of evidence to look for per technique. Your
goal is to find every beat in the cheat sheet that the run actually
contains.

### Tier 2 — Intermediate (working SOC)
No cheat sheet. You're given [`scenario_story.md`](scenario_story.md) and
[`attack_plan.md`](attack_plan.md) but **not** the per-technique mappings
or the per-step ground truth. Your goal is to find the beats yourself,
using the scenario for context and your own SIEM queries for evidence.

### Tier 3 — Senior (threat hunter)
You receive [`scenario_story.md`](scenario_story.md) and nothing else. The
SIEM is blank — write your own queries. Your goal includes the quiet
later-phase beats (key theft, exfil staging, C2 cadence) that don't trip
signature rules.

### Tier 4 — Red team (adversary emulation)
The lab is your target. The auto-chain has already run and seeded
breadcrumbs (John's `.env`, Vinzenz's keys, etc.). Your goal is to land
your own follow-on attacks — privilege chains, alternate exfil paths,
detection evasion — and document the blue-team-visible signal of each.

---

## For instructors — how to grade

Open `Attack-chain/results/run-<ts>/chain-<ts>.json` side-by-side with the
analyst's submitted `findings.yaml`. The JSON contains one entry per
ground-truth step with `name`, `started`, `ended`, `tactic`, `techniques`.

For each ground-truth step, ask:

1. Did the analyst submit a finding whose `tactic` + `technique` matches?
2. Is the finding's `detected_at` within `[step.started, step.ended + 30 min]`
   on the **wall-clock** scale? (If they're working from the diurnal SIEM,
   convert back via the `stretch_factor` in `diurnal_manifest.json`:
   `wall_t = run_start + (siem_t - anchor) / stretch_factor`.)
3. Does their `evidence` field point at a real log line that actually
   supports the claim?

Coverage = (beats correctly detected) / (total ground-truth beats).
Anything in the analyst's `findings.yaml` that doesn't map to a
ground-truth step is a false positive — usually it's them flagging the
noise traffic. False positives aren't necessarily wrong (they show
hunting instinct) but they shouldn't count toward coverage.

A passing junior session typically lands ≥4/6 beats with one false
positive. A passing senior session lands ≥5/6 with no false positives
plus a write-up of the quiet phases.

---

## Cheat sheet — Tier 1 only

Per-technique detection signal pointers. This is the subset of
[`mappings.md`](mappings.md) most relevant to the basic chain.

| Technique | Where to look | What to look for |
|---|---|---|
| **T1190** Exploit Public-Facing App (CVE-2021-41773) | `logs/apache/access.log` | `POST /cgi-bin/.%32%65/.../bin/sh` — double-URL-encoded path traversal |
| **T1059.004** Reverse Shell | `logs/router/ulog-iptables.log` | `FW-NEW: SRC=10.40.0.2 DST=10.10.0.2 DPT=4444` — apache calling back to kali |
| **T1053.003** Cron Tampering | `logs/apache/lab-fim.log` | `tag=lab_fim path=/opt/cleanup.sh event=MODIFY` |
| **T1552.001** Credentials in Files | `logs/apache/lab-fim.log` + bash history | `cat /home/john.stravidis/.env` reads |
| **T1018/T1046** Internal Scan | `logs/router/ulog-iptables.log` | Burst of `FW-NEW: SRC=10.40.0.2 DST=10.30.0.0/24 DPT=22` |
| **T1110.004** Credential Stuffing | `logs/luke_ws/auth.log`, `logs/vinzenz_ws/auth.log`, `logs/workstation/auth.log` | Same source IP, one password per host within seconds; failures on Luke/Vinzenz, success on John |
| **T1021.004** SSH Lateral | `logs/workstation/auth.log` + `logs/router/ulog-iptables.log` | `Accepted publickey for john.stravidis` from apache; `FW-NEW: SRC=10.40.0.2 DST=10.30.0.5 DPT=22` |
| **T1078** Valid Accounts | `logs/workstation/auth.log` | John's account used from a host he doesn't normally connect from |

---

*Document version: 1.0 — see [snuggly-roaming-rose.md](/home/joe/.claude/plans/snuggly-roaming-rose.md) for the workflow design.*
