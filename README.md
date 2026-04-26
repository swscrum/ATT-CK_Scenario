# Attack scenario

This project is about an custom attack scenario to showcase IT security demonstrations.

Currently, it consists of an attacker client (Kali Linux), a router container that simulates the edge of the network, a victim webserver, and a victim Linux workstation. The webserver and the workstation share an internal docker network. The workstation also uses an egress network so it can communicate outward. The router connects the internal network to the public side and forwards only port 80 to the webserver.

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

The Kali container ships with `nmap`, `gobuster`, `ffuf`, `nikto`, `python3`, plus `wget` and `curl`. The `Attack-chain/` directory is mounted into the container at `/recon`, so `initial_recon_1.py` is runnable from inside.

```bash
# Full recon flow against the default target (router)
docker compose exec kali python3 /recon/initial_recon_1.py

# Override the target
docker compose exec kali python3 /recon/initial_recon_1.py --target router

# Run a single phase
docker compose exec kali python3 /recon/initial_recon_1.py --phase gobuster

# Override the gobuster wordlist
docker compose exec kali python3 /recon/initial_recon_1.py --wordlist /usr/share/wordlists/dirb/small.txt
```

Results land in `Attack-chain/results/` (bind-mounted, persisted on the host):

| File | Source |
|---|---|
| `nmap-fullscan.txt` | `nmap -Pn -sS -p-` |
| `nmap-services.txt` | `nmap -Pn -sS -sV -sC -p<open-ports>` |
| `gobuster.txt` | `gobuster dir` against `dirb/common.txt` (override via `--wordlist`) |
| `ffuf.txt` | extension fuzz on `/index<ext>` (JSON) |
| `nikto.txt` | `nikto -Tuning b` |
