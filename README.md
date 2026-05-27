# Attack scenario

This project is about an custom attack scenario to showcase IT security demonstrations.

Currently, it consists of an attacker client (Kali Linux), a router container that simulates the edge of the network, a victim webserver, a victim Ubuntu workstation with an XFCE desktop, and an internal PostgreSQL database server (`db-internal`). The webserver, workstation, and database share an internal docker network. The workstation also uses an egress network so it can communicate outward. The router connects the internal network to the public side and forwards only port 80 to the webserver.

## Network topology

![Network topology](intern/Bilder/network-topology.jpg)

The Ubuntu workstation exposes its desktop on host port 5901 — connect with any VNC client (e.g. `vinagre`, `remmina`, `tigervnc-viewer`) to `localhost:5901`. No VNC password is set; this is a placeholder lab host. SSH (port 22) and the VNC server run side-by-side inside the container.

**Lab SSH credentials (intentionally weak — isolated lab use only):** `labuser` / `labpass`

```bash
ssh labuser@<ubuntu_workstation-IP>
```

## Services

| Container | Image | Network | Purpose |
|---|---|---|---|
| `router` | Ubuntu 22.04 | `public_net` + `internal_net` | Edge router; forwards port 80 to apache |
| `apache` | httpd:2.4.50 (vulnerable) | `internal_net` + `egress_net` | Waystar Connect webserver; CVE-2021-41773 target |
| `ubuntu_workstation` | Ubuntu 24.04 | `internal_net` + `egress_net` | John Stravidis's dev workstation (VNC on port 5901) |
| `luke_ws` | Ubuntu 24.04 | `internal_net` | Luke Smith's workstation (psychiatrist, 10.30.0.7); read-only patient-DB client |
| `vinzenz_ws` | Ubuntu 24.04 | `internal_net` | Vinzenz Fedora's sysadmin workstation (10.30.0.8); cross-fleet SSH reach + superuser DB credentials |
| `db-internal` | postgres:16 | `internal_net` only | Waystar Royco patient database; Phase 12–13 target |
| `kali` | kali-rolling | `public_net` | Attacker machine |

## db-internal — patient database

`db-internal` runs PostgreSQL 16 on `internal_net` (10.30.0.6) with no outbound connectivity.

**Database:** `waystar`  
**Tables:** `patients` (80 records), `session_notes` (~100 records of fictional therapy sessions), `appointments` (inbound booking requests from the public-facing site; filled at runtime by the waystar-connect web form)

| User | Password | Access |
|---|---|---|
| `waystar` | *(privileged; stored on Vinzenz's workstation, `~/.pgpass`)* | Full owner |
| `waystar-readonly` | `ChangeMe!2026` | SELECT on all tables — breadcrumbed in John's `~/.pgpass` |
| `waystar-app` | `AppBooking!2026` | INSERT on `appointments` only (no patient data); used by the apache booking endpoint, stored in `apache:/etc/waystar/db.env` |

**Connecting from the workstation:**
```bash
# Credentials are picked up automatically from ~/.pgpass
psql -h db-internal -U waystar-readonly -d waystar
```

**Public-facing booking endpoint:**
The Waystar Connect site (served by `apache`) ships a Python CGI at `/cgi-bin/book.py`. It accepts a JSON booking payload, validates it server-side, and inserts a row into `appointments` as `waystar-app`. Patient data is **not** exposed through this surface — a compromised webserver lands on a least-privilege account.

**Logs** are written to `Infrastructure/logs/db/postgresql-YYYY-MM-DD.log` and persist across container restarts. Connection attempts, failed authentications, and data-modification statements are all logged — useful for SIEM/NIDS demo scenarios.

**Attack-chain role:** John's bash history and `~/.pgpass` breadcrumb the existence of this host (Phase 6 discovery). Phase 12 harvests the `waystar` privileged credentials from Vinzenz Fedora's sysadmin workstation (`vinzenz_ws`). Phase 13 exfiltrates the patient records via `pg_dump`. The `waystar-app` credentials on apache are an *additional* lateral surface but only reach `appointments`.

## Prerequisites

1. Docker needs to be installed on the system
2. Navigate into the `Infrastructure` folder

## How to run this project

```bash
docker compose up -d --build
```

The workstation keeps outbound connectivity through its egress network, while inbound access from the attacker side reaches the webserver only through the router's forwarded port 80.

To add more internal clients later, connect them to `internal_net` and `egress_net` as well. Do not attach Kali to those internal networks.

## Running the recon phase

The Kali container ships with `nmap`, `gobuster`, `ffuf`, `nikto`, `python3`, `sshpass`, and [`netexec`](https://www.netexec.wiki/) (manual-use credential-stuffing tool referenced from the `creds` chain step), plus `wget` and `curl`. The `Attack-chain/` directory is mounted into the container at `/Attack-chain`, so `initial_recon_1.py` is runnable from inside.

```bash
# Option 1)
#Automated Orchestration of all phases and automated cleanup:
tools/run.sh                       # defaults to --mode basic
tools/run.sh --mode advanced       # stealthier variant (placeholder, mirrors basic for now)

# Option 2)
# Running the phases one by one:
# Full recon flow against the default target (router)
docker compose exec kali python3 /Attack-chain/initial_recon_1.py

# Override the target to the internal webserver instead of the default router
docker compose exec kali python3 /Attack-chain/initial_recon_1.py --target webserver

# Run a single phase
docker compose exec kali python3 /Attack-chain/initial_recon_1.py --phase gobuster

# Override the gobuster wordlist
docker compose exec kali python3 /Attack-chain/initial_recon_1.py --wordlist /usr/share/wordlists/dirb/small.txt
```

Results land in `Attack-chain/results/` (bind-mounted, persisted on the host):

| File | Source |
|---|---|
| `nmap-fullscan.txt` | `nmap -Pn -sS -p-` |
| `nmap-services.txt` | `nmap -Pn -sS -sV -sC -p <open-ports>` |
| `gobuster.txt` | `gobuster dir` against `dirb/common.txt` (override via `--wordlist`) |
| `ffuf.json` | extension fuzz on `/index<ext>` (JSON output from ffuf `-of json`) |
| `nikto.txt` | `nikto -Tuning b` |


