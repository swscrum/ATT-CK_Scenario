# Attack scenario — base story


## Elevator pitch

Waystar Royco is a well-known regional mental-health practice — a franchise that's actively expanding, decades-old, traditionally in-person, with a long patient list and a stable therapist roster. Over the past few years, they have suffered a slow, steady decline in new patients due to cheap, venture-funded online competitors like BetterHelp. In response, the board hired a new CTO to execute a digital pivot: expanding the portfolio by adding online therapy (*Waystar Connect*) and migrating all employee workstations from Windows to Linux as a privacy-focused marketing stunt and to save licensing costs.

Under intense timeline pressure (cut from six weeks to four), the solo frontend freelancer **John Stravidis** builds the new portal. While the application code itself is cleanly written, the time constraint forces him to take shortcuts in configuration — deploying an outdated Apache 2.4.50 Docker base image (carrying CVE-2021-42013) and leaving default credentials. Meanwhile, sysadmin **Vinzenz Fedora** is under equal pressure to deploy the web server. To quickly debug cron job permission issues, Vinzenz runs `chmod 777` on the maintenance script `/opt/cleanup.sh` and forgets to lock it down before go-live. Waystar announces the launch on LinkedIn. 

In the **basic scenario**, the launch is noticed by **Tommy (16)**, a student who got into hacking through online forums and wants to steal classmates' data for fun after seeing Waystar Connect at a school awareness day. In the **advanced scenario**, the launch triggers an alert for **ByteLocker**, a professional ransomware group that passively harvests Shodan feeds and Wayback Machine data for vulnerable targets, executing a stealthy, multi-stage extortion operation.

## Setting: Waystar Royco

A mid-sized franchise mental-health practice, multiple offices, a panel of therapists, decades in operation, recognisable name in their region. Currently in active expansion mode — adding new locations and (now) an online arm. The relevant facts:

- **Financial decline.** Online competitors — BetterHelp, Talkspace, Cerebral, and a long tail of venture-funded entrants — are cheap, frictionless, and aggressively marketed. Waystar's new-patient acquisition has been declining for three years, especially in the under-30 demographic. Q3 was bad. Q4 needs to look different.
- **Strategic reset.** The new CTO and a turnaround consultancy jointly drafted the recovery plan. It rests on three pillars:
  1. **Portfolio expansion** — add online therapy alongside the existing on-site practice. This is *Waystar Connect*.
  2. **Demographic recovery** — reach the younger patients on-site therapy is losing.
  3. **Linux transition** — phased migration of all employee workstations off Microsoft to Linux. Three motivations: licensing-cost savings, a privacy-focused ecosystem position, and PR/marketing value (the new CTO has publicly committed to the position; it polls well).
- **Linux transition is in progress, not complete.** Waystar's IT team has very limited Linux experience; security engineering has even less. Several gaps in the new stack exist that nobody on the team is currently positioned to see. Additionally most of the staff are non-technical: therapists, assistants... so they are not security-savvy.

The combination — a slow decline, a rushed migration, financially squeezed, and now publicly relaunching with younger-demographic-targeted marketing — is what makes Waystar plausible as a target.

## Product: Waystar Connect

The new online-therapy platform, positioned to compete directly with BetterHelp and similar:

- **Patient-facing portal** — booking, intake forms, video sessions, secure messaging with therapists, payment.
- **Therapist-facing portal** — caseload management, session notes, scheduling.
- **Differentiator vs. faceless competitors** — backed by Waystar's existing roster of credentialed, established therapists. The marketing pitch is "real therapists you can actually meet, available online."

The shipped MVP covers the patient-facing flow end-to-end. Therapist tooling is partial. Stravidis programmed the application code cleanly, but took shortcuts in the container deployment due to the compressed timeline.

## The relaunch project

### The consultancy

Hired to draft and shepherd the turnaround. When Q3 numbers miss, they recommend pulling the launch forward by two weeks to coincide with a planned investor presentation. The board agrees. Stravidis is told. Six weeks becomes four.

### The freelancer — John Stravidis

Solo frontend specialist. Hired to build Waystar Connect's web presence end-to-end. Waystar has historically not needed an in-house dev team and doesn't have one to back him up. His response under pressure:

- Reaches for a familiar Docker base image — Apache 2.4.50, the version that ships CVE-2021-42013. He's a frontend specialist; infrastructure auditing isn't his strength and nobody in his contract chain is positioned to ask the right question.
- Programs the application cleanly but leaves test credentials (`john.stravidis` / `waystar2026!`) and configuration files behind.
- Ships on the new deadline. The consultancy is satisfied. The board is satisfied. Waystar Connect goes live.

### Luke Smith — psychiatrist, Waystar Royco clinical team

Clinician on the Waystar Royco mental-health franchise. Sees patients during the day, writes session notes in the central patient DB (`db-internal`) in the evening, has a thin local SQLite cache of "his patients" he uses offline at home. His workstation (`luke_ws`, `10.30.0.7`) is configured the way most clinical end-user boxes are: a password account, broad outbound network access, a credentials file (`~/.pgpass`) so `psql` Just Works without typing the password every time.

In the **basic** mode of the chain, Tommy lands on John's box and tries to reach Luke but **fails** — Luke's box doesn't trust John's SSH key, his account doesn't share John's password, and there's no credential left behind on John's box that lets him into Luke's. The visible noise of the failed attempt generates T1110 brute-force logs for training.

In the **advanced** mode, ByteLocker pivots from the web server to **Vinzenz Fedora** (the sysadmin) and uses Vinzenz's cross-fleet SSH key to log into Luke as `vinzenz.fedora` (a sysadmin account that exists on every host). Once on Luke's box, they read his `.pgpass`, run his queries against `db-internal`, and exfiltrate the patient data.

### Vinzenz Fedora — sysadmin, Waystar Royco IT

The only person at Waystar Royco with SSH reach into every Linux host. Under equal pressure to deploy the web server and configure automated backups, Vinzenz runs `chmod 777` on `/opt/cleanup.sh` to quickly debug cron permissions and forgets to lock it down before go-live. 

His workstation (`vinzenz_ws`, `10.30.0.8`) is the central target of the advanced chain, storing:
- An unencrypted cross-fleet SSH private key (`~/.ssh/id_ed25519`).
- A `~/.pgpass` with the superuser Postgres credentials for `db-internal`.
- An Ansible-style `inventory.ini` listing every managed host.

## The trigger

Waystar posts a LinkedIn announcement: *"Excited to launch Waystar Connect — therapy that meets you where you are."* The post links to the new patient portal. This public launch announcement is what triggers both attackers.

## The attackers

### Tommy (Basic Scenario)
*   **Profile**: A 16-year-old student who got into hacking through online forums.
*   **Trigger**: His school hosted a "Mental Health Awareness Day" where Waystar Connect was presented as a new digital resource for students.
*   **Motivation**: Tommy thinks it would be funny to access his classmates' data to show off. He logs onto online forums, finds basic penetration testing guides, and runs them against the domain on gut luck.
*   **TTPs**: Highly visible, noisy, script-heavy scans (Nmap full scans, Gobuster dir bruteforce, Nikto vulnerability scanners) and simple reverse shells.

### ByteLocker (Advanced Scenario)
*   **Profile**: A smaller but highly organized professional ransomware group targeting mid-to-small enterprises without dedicated security fleets.
*   **Operation**: Rather than running noisy active port sweeps, ByteLocker continuously ingests passive, internet-wide data feeds (Shodan, Censys, Cert Transparency logs, Wayback Machine crawling snapshots). Their tooling flags Waystar Connect's domain launch as running a vulnerable Apache 2.4.50 instance with `/cgi-bin/` exposed.
*   **Stealth Recon**: To verify the vulnerability without triggering EDR or firewall alerts, they execute exactly three targeted HTTP checks (GET /, HEAD /cgi-bin/, robots.txt) spoofed under a normal desktop browser User-Agent to confirm their exploit will succeed.
*   **Motivation**: Asymmetric database encryption, data exfiltration over C2 (Sliver C2), SQL data shredding, and Monero-based extortion.

## Story ↔ lab artifact mapping

| Lab artifact | What it is in the story |
|---|---|
| Apache 2.4.50 (vulnerable to CVE-2021-42013) | Stravidis's go-to Docker base image, never audited under time pressure |
| `/opt/cleanup.sh` set to `chmod 777` | Left behind by Vinzenz Fedora during a rushed debugging session of the cron job |
| Ubuntu workstation on the internal network | Dev/staging box Stravidis used during the project |
| `john.stravidis` / `waystar2026!` SSH credentials | Test credentials John used, never rotated before go-live |
| VNC server on `:5901` with no authentication | Dev convenience set up by the overwhelmed transition team |
| Absence of SIEM / EDR / NIDS on Linux hosts | Waystar's security team's Linux migration is incomplete; visibility gaps are real |
| Patient DB and `notes/` directory | The database John connected to, targeted for exfiltration (Tommy) and encryption (ByteLocker) |
