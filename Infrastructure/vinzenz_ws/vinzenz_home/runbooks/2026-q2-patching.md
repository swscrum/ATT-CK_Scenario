# Q2 2026 — Fleet patching playbook

Owner: vinzenz.fedora@waystar-royco.example
Last revised: 2026-04-02
Patching window: every Tuesday 10:00–11:00 UTC (weekly cycle).

## Scope

| Host | Role | OS | Patch class |
|---|---|---|---|
| apache (10.40.0.2) | DMZ webserver — Waystar Connect | Debian Buster (httpd:2.4.50 base) | security only — DO NOT auto-upgrade httpd (legacy CGI dependency) |
| john (10.30.0.5) | dev workstation — John Stravidis | Ubuntu 24.04 | unattended-upgrades + manual review on kernel |
| luke (10.30.0.7) | clinical workstation — Luke Smith | Ubuntu 24.04 | same |
| vinzenz_ws (10.30.0.8) | this host | Ubuntu 24.04 | manual — sysadmin self-managed |
| db-internal (10.30.0.6) | postgres 16 | (managed image, follow upstream tag) | quarterly major-version review only |

## Weekly cycle (Tuesdays)

Run from this workstation. Do not patch from inside the affected host.

```bash
# 1. Snapshot current state across the fleet (uptime + kernel)
ansible all -i ~/inventory.ini -m shell -a 'uname -r; uptime'

# 2. Pull lists of available upgrades (dry-run, no changes yet)
ansible all -i ~/inventory.ini -b -m shell -a 'apt update >/dev/null && apt list --upgradable 2>/dev/null'

# 3. Review the list. If a security upgrade touches openssh-server, sudo,
#    libcap2-bin, or anything in /usr/sbin, FLAG it for individual review.

# 4. Apply (interactive — do NOT use ansible apt module in mass mode here).
for h in apache john luke; do
    echo "--- $h ---"
    ssh "$h" 'sudo apt -y upgrade'
done

# 5. Reboot only if kernel changed.
for h in apache john luke; do
    if ssh "$h" 'ls /var/run/reboot-required >/dev/null 2>&1'; then
        echo "$h needs reboot — schedule in maintenance window"
    fi
done
```

## Apache special case

Apache runs `httpd:2.4.50` from upstream because we deliberately pinned that
version (CGI-dependent staging path that breaks on 2.4.51+). DO NOT
`apt upgrade apache2` — there is no Debian apache2 on this host. The
upstream Docker image gets reviewed quarterly on a separate schedule.

What we DO patch on apache: openssh-server, sudo, libcap2-bin, ca-certificates,
the cron daemon, anything in the base Debian Buster security pocket. The
custom `/opt/cleanup.sh` script is a separate concern (see TODO: should
audit its perms next sweep — John chmod 777'd it during dev and we never
caught it).

## DB special case

Postgres lives in a stock `postgres:16` image. We don't `apt upgrade` it
in-place — we bump the image tag in `docker-compose.yml` and rebuild
during the quarterly review window. Out-of-cycle CVEs follow the
emergency procedure (see `incident-response.md`).

## Out-of-cycle (emergency)

Trigger conditions: CVE with public PoC affecting one of {openssh-server,
sudo, kernel, libssl, libapache2-mod-security2}, AND CVSS ≥ 7.5.

1. Page on-call (me, currently).
2. Open `~/notes/<date>_oncall.md`, record the CVE + advisory URL.
3. Apply to vinzenz_ws first as canary.
4. Apply to the rest in order: john → luke → apache.
5. Postgres last (via image bump if needed).
6. Update this runbook with any new exclusion/special-case.

## Known dead trees / DO NOT patch

- `apache` `mod_php5` — not installed, but appears in some advisories
- `john`/`luke` `chromium-browser` — XFCE has Firefox not Chromium
- Any `linux-image-*` kernel package on the `apache` container — it's
  using the host kernel; `apt upgrade linux-image-*` is a no-op there.
