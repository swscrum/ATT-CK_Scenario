# Attack scenario — base story


## Elevator pitch

Waystar Royco is a well-known regional mental-health practice — a franchise that's actively expanding, decades-old, traditionally in-person, with a long patient list and a stable therapist roster. Eighteen months ago they were breached: a portion of their patient records leaked, the press cycle was brutal and caused public scrutiny and financial losses, and a leadership change followed — a new CTO, alongside help from a turnaround consultancy. The consultancy's plan: in order to stabilise financially after the breach and stay relevant and strong in the coming years, expand the portfolio — adding online therapy alongside the existing on-site practice — to defend against BetterHelp, Talkspace, and the rest of the venture-funded competition that's eating Waystar's younger-patient pipeline. Alongside the digital pivot, the board approves a phased migration of all employee workstations off Microsoft to Linux: partly to save licensing costs, partly a post-breach *decouple-from-Big-Tech* move toward a more privacy-focused ecosystem (which doubles as positive PR) — a position the new CTO is publicly committed to. Alongside the effort to pivot online and reach a younger demographic, a single freelancer — **John Stravidis**, a frontend specialist — is contracted to build the new online platform: *Waystar Connect*. Original timeline: six weeks. Cut to four when Q3 revenue lands worse than projected. Stravidis ships an MVP that looks polished, runs on an outdated Apache base image, and leaves a maintenance script world-writable from a debugging session. Waystar announces the launch on LinkedIn. Within hours, the same threat actor that breached them eighteen months ago — who never went away — comes back for the rest.

## Setting: Waystar Royco

A mid-sized franchise mental-health practice, multiple offices, a panel of therapists, decades in operation, recognisable name in their region. Currently in active expansion mode — adding new locations and (now) an online arm. The relevant facts:

- **The eighteen-month-ago breach.** Attackers exfiltrated a portion of the patient database — names tied to therapist assignments, intake summaries, and (in some cases) session notes. Waystar paid for incident response, notified regulators, weathered the press cycle, and absorbed substantial financial losses. The CEO who was in post during the breach was replaced; a new CTO was appointed as part of the reset. Waystar believes the attacker is gone. They are wrong.
- **Financial pressure.** Online competitors — BetterHelp, Talkspace, Cerebral, and a long tail of venture-funded entrants — are cheap, frictionless, and aggressively marketed. Waystar's new-patient acquisition has been declining for three years, especially in the under-30 demographic. Q3 was bad. Q4 needs to look different.
- **Strategic reset.** The new CTO and a turnaround consultancy jointly drafted the recovery plan. It rests on three pillars:
  1. **Portfolio expansion** — add online therapy alongside the existing on-site practice. This is *Waystar Connect*.
  2. **Demographic recovery** — reach the younger patients on-site therapy is losing.
  3. **Linux transition** — phased migration of all employee workstations off Microsoft to Linux. Three motivations: licensing-cost savings, a post-breach *decouple-from-Big-Tech* / privacy-focused ecosystem position, and PR value (the new CTO has publicly committed to the position; it polls well).
- **Linux transition is in progress, not complete.** Waystar's IT team has very limited Linux experience; security engineering has even less. Several gaps in the new stack exist that nobody on the team is currently positioned to see. Additionally most of the staff are non-technical: therapists, assistants... so they are not security-savvy.
(a "therapy" company has major easter-egg potential :) )

The combination — fresh from a major breach, mid-transition, financially squeezed, and now publicly relaunching with younger-demographic-targeted marketing — is what makes Waystar plausible as a target *now* and not last year.

## Product: Waystar Connect

The new online-therapy platform, positioned to compete directly with BetterHelp and similar:

- **Patient-facing portal** — booking, intake forms, video sessions, secure messaging with therapists, payment.
- **Therapist-facing portal** — caseload management, session notes, scheduling.
- **Differentiator vs. faceless competitors** — backed by Waystar's existing roster of credentialed, established therapists. The marketing pitch is "real therapists you can actually meet, available online."

The shipped MVP covers the patient-facing flow end-to-end. Therapist tooling is partial. Several second-tier features were "vibecoded" by Stravidis using AI assistance under deadline pressure, work as intended, and were never reviewed by anyone with security exposure. None of them introduce additional exploitable surface in the lab — the bug that gets exploited remains the Apache 2.4.50 path traversal. *Vibecoding* is the **narrative explanation** for why nobody caught it.

## The relaunch project

### The consultancy

Hired post-breach to draft and shepherd the turnaround. They are not directly responsible for engineering — they recommend the digital pivot, define scope, and approve the freelancer hire on Waystar's behalf. When Q3 numbers miss, they recommend pulling the launch forward by two weeks to coincide with a planned investor presentation. The board agrees. Stravidis is told. Six weeks becomes four.

### The freelancer — John Stravidis

Solo frontend specialist. Hired to build Waystar Connect's web presence end-to-end. Waystar has historically not needed an in-house dev team and doesn't have one to back him up. His response under pressure:

- Reaches for a familiar Docker base image — Apache 2.4.50, the version that ships CVE-2021-41773. He's a frontend specialist; infrastructure auditing isn't his strength and nobody in his contract chain is positioned to ask the right question.
- "Vibecodes" the bulk of the rest with AI assistance. Output ships without review.
- Sets the scheduled-maintenance script `/opt/cleanup.sh` to `chmod 777` while debugging a permissions issue. Plans to revert before go-live, gets pulled into the timeline cut, never reverts. The TODO comment he left in the script ("set back to 700 before go-live") is still there, exactly as written.
- Uses a Linux workstation provisioned for him by IT with throwaway credentials (`labuser` / `labpass` initially, later `john.stravidis` / `waystar2026!`) that were meant to be rotated before go-live — never were.
- Ships on the new deadline. The consultancy is satisfied. The board is satisfied. Waystar Connect goes live.

Stravidis is competent, not malicious. Every shortcut traces back to the four-week clock and to him being asked to do two-thirds of a job he was originally hired to do.

### Luke Smith — psychiatrist, Waystar Royco clinical team

Clinician on the Waystar Royco mental-health franchise. Sees patients during the day, writes session notes in the central patient DB (`db-internal`) in the evening, has a thin local SQLite cache of "his patients" he uses offline at home. His workstation (`luke_ws`, `10.30.0.7`) is configured the way most clinical end-user boxes are: a password account, broad outbound network access, a credentials file (`~/.pgpass`) so `psql` Just Works without typing the password every time. Patient data is his daily work, not a special asset.

Luke is **not** the immediate post-John pivot in the **basic** mode of the chain. The attacker who lands on John's box will *try* to reach Luke (Luke is the obvious next employee target) but **fail** — Luke's box doesn't trust John's SSH key, his account doesn't share John's password, and there's no credential left behind on John's box that lets the attacker into Luke's. The visible noise of the failed attempt is its own SOC-training signal (T1110 / T1078 brute-force attempts that get denied + logged). In the basic flow, the attacker gives up on Luke and exfiltrates what they have from John's box.

In the **advanced** mode the attacker reaches Luke a different way: by first pivoting from John to **Vinzenz Fedora** (the sysadmin) and using Vinzenz's cross-fleet SSH key to log into Luke as `vinzenz.fedora` (a sysadmin account that exists on every host). Once on Luke's box as a sudoer, the attacker can read his `.pgpass`, run his queries against `db-internal`, and exfiltrate the patient data Luke routinely accesses.

### Vinzenz Fedora — sysadmin, Waystar Royco IT

The only person at Waystar Royco with SSH reach into every Linux host: the public web server (`apache`), John's workstation, Luke's workstation, and the patient database server (`db-internal`, via `psql` superuser). He has a dedicated `vinzenz.fedora` sudoer account on each managed box; his public key is in each `~vinzenz.fedora/.ssh/authorized_keys`; his private key lives unencrypted in his own workstation's `~/.ssh/id_ed25519`.

That private key file is the central loot artefact of the **advanced** chain. Anyone who steals it owns the whole fleet — the same way it works in real enterprise networks where the SOC's worst-case scenario is a compromised sysadmin laptop.

Vinzenz's workstation (`vinzenz_ws`, `10.30.0.8`) also stores:

- a `~/.pgpass` with the **superuser** Postgres credentials for `db-internal` (full read+write on the patient DB)
- an Ansible-style `inventory.ini` listing every managed host — a useful breadcrumb to an attacker mapping the fleet
- a fleet-wide `~/.ssh/config` with friendly aliases (`apache`, `john`, `luke`, `db-internal`) that point at the right IPs and use the right key automatically

Vinzenz is competent — his hygiene is fine for the size of the team — but the lab models a realistic small-shop sysadmin: one account, one key, no break-glass account, no key rotation cadence. Once the attacker is on his box, they have the keys to the kingdom.

## The trigger

Waystar posts a LinkedIn announcement: *"Excited to launch Waystar Connect — therapy that meets you where you are."* The post links to the new patient portal.

The post is the **trigger**, not the attacker's discovery. The attacker has known about Waystar Royco for eighteen months. What the LinkedIn post tells them is *the new attack surface is live*.

## The attacker

The same crew that breached Waystar eighteen months ago. They never went away. Specifically:

- **Lingering organisational knowledge** from the prior breach — therapist names, internal naming conventions, infra patterns, and credentials Waystar never realised were burned.
- **Standing alerts** on Waystar's domains and key employees' public profiles. The LinkedIn post is what fires the alert.
- **Operationally advanced but pragmatic.** When an obvious vulnerability exists at the entry, they use it — speed beats stealth at the edge. Once entrenched, they shift to careful, low-signal TTPs (encrypted channels, deliberate command pacing, clean persistence).
- **Returning to finish the job.** The first breach was sloppy. They tripped a detection too early, exfiltrated only a partial dataset, and were forced to abort before they got everything. They've spent the last eighteen months reviewing what went wrong. This time they intend to be patient, methodical, and complete: **full patient-data exfiltration, then ransomware on the encrypted-at-rest production data** — monetise twice, finish what they started, make Waystar's "we've fixed our security" public commitment look like the lie it now is.

This profile justifies the *advanced threat actor* framing without forcing every entry-point TTP to be covert. SOC analysts get **both** detection regimes to exercise: signature-heavy IDS work on the noisy entry, behavioural / EDR-driven hunting on the quiet later phases.

## What's at stake

Mental-health patient data is among the most sensitive categories of personal information. Specifically:

- **Therapy notes** tied to identifiable patients — direct extortion material.
- **Diagnoses and prescription histories** — employer/insurer leverage if leaked, regulatory consequences if disclosed.
- **Patient intake forms** — lifetime histories of mental-health concerns, often written without filter on the assumption of confidentiality.
- **Therapist-patient assignments** — useful for targeted blackmail and impersonation.

A second breach, eighteen months after the first, after a public commitment to "we've fixed our security," is unsurvivable for Waystar Royco at its current cash position. The attacker knows this; their leverage is correspondingly large.

The eventual end-state for the lab is **exfiltration plus ransomware** (parked for now — to be defined in step 2 and built in step 3). Lab content seeded during implementation should be shaped with both in mind: a real (dummy) patient DB to extract, real session-note files to encrypt.

## Story ↔ lab artifact mapping

| Lab artifact | What it is in the story |
|---|---|
| Apache 2.4.50 (vulnerable to CVE-2021-41773) | Stravidis's go-to Docker base image, never audited under time pressure |
| `/opt/cleanup.sh` set to `chmod 777` with the TODO comment | Literal artifact of Stravidis's debugging session — the in-script TODO already says exactly this |
| Ubuntu workstation on the internal network | Dev/staging box Stravidis used during the project, sitting on Waystar's in-progress Linux fleet |
| `labuser` / `labpass` SSH credentials | The transition team's interim credentials — meant to be rotated, never were |
| VNC server on `:5901` with no authentication | Dev convenience set up by the overwhelmed transition team |
| Absence of SIEM / EDR / NIDS on Linux hosts | Waystar's security team's Linux stack is incomplete; the visibility gap is real |
| (To be seeded in step 3) prior-breach evidence on the workstation | Justifies the *returning crew* framing — older log entries, dormant account named after a previously-compromised therapist or admin, reused naming patterns |
| (To be seeded in step 3) patient DB and `notes/` directory | The crown jewels — exfiltration target now, ransomware target later |


__________________________________________________________________
## Still Open 

- **Region / regulatory regime** — kept neutral. Specifying later (HIPAA / GDPR / national health-data law) sharpens the regulatory consequences of the breach but is not load-bearing for the chain.
- **Prior-breach details**: when exactly within the eighteen-month window, scope of the leak, what the public response was. Specifying these later supplies the "evidence" the lab will seed.
- **Consultancy name**:flavor only.
- **Therapist / patient names used in seeded data**:generate during step 3; ensure they are obviously fictional.
