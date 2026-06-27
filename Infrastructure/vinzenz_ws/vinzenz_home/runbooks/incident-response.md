# Incident response runbook

Owner: vinzenz.fedora@waystar-royco.example
Last revised: 2026-02-14 (post-tabletop review)
Related: `~/notes/` (on-call session notes), `~/runbooks/2026-q2-patching.md`

## Context

We were breached ~18 months ago. The forensic write-up never went past
"lateral movement via a freelancer's stale workstation." The transition
to Linux that followed (this current fleet) was supposed to put us in a
better posture — but most of the SOC tooling investment got deferred.
Practically, this runbook is what we have.

## Phase 0 — When something looks off

Triggers worth a `notes/<date>_oncall.md` entry:

- `lab-fim` event on `/opt/cleanup.sh`, `/etc/cron.d/*`, `/etc/sudoers.d/*`,
  `~/.ssh/authorized_keys` on any fleet host
- Unexpected `Accepted publickey for vinzenz.fedora` from a source IP that
  isn't `10.30.0.8` (my workstation)
- Apache `error.log` showing `mod_cgi` invocations from `/cgi-bin/.%32%65/...`
  (CVE-2021-42013 fingerprint — we are still on 2.4.50)
- Postgres `log_statement=all` entries from a client IP that isn't a
  known workstation (10.30.0.5/.7/.8 or apache 10.40.0.2)
- Any sudo by `www-data` in `/var/log/auth.log` on apache (should never happen)

## Phase 1 — Triage (first 15 minutes)

Do not start blocking yet. Establish what's happening.

```bash
# Snapshot the suspect host (do not log in interactively — use ansible)
ssh -o BatchMode=yes <host> 'who; w; last -20; ps auxfww | head -50'
ssh <host> 'sudo journalctl -u sshd -n 100'
ssh <host> 'sudo tail -200 /var/log/auth.log'
ssh <host> 'sudo tail -200 /usr/local/apache2/logs/access_log'  # apache only
ssh <host> 'sudo tail -200 /var/log/lab-fim.log'

# DB side
psql -h db-internal -U waystar -d waystar -c \
    "SELECT pid, usename, application_name, client_addr, state, query_start, query \
     FROM pg_stat_activity WHERE state != 'idle';"
```

Drop everything into `~/notes/<today>_oncall.md` as you go. Verbatim
output is fine; commentary in parens.

## Phase 2 — Containment (next 15–30 minutes)

If confirmed unauthorised access:

```bash
# Cut the affected host off from the internal net at the router.
# THIS DROPS LIVE WORKSTATION CONNECTIONS — call the user first.
ssh router 'iptables -I FORWARD 1 -s <attacker_ip> -j DROP'

# Rotate the master cross-fleet key (current: ~/.ssh/id_ed25519, used by
# vinzenz.fedora on every host). New key generated locally, pushed by
# overwriting authorized_keys on every host. Old key revoked.
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_NEW -N ''
for h in apache john luke; do
    scp ~/.ssh/id_ed25519_NEW.pub "$h:/tmp/new.pub"
    ssh "$h" 'cat /tmp/new.pub > ~/.ssh/authorized_keys && rm /tmp/new.pub'
done
mv ~/.ssh/id_ed25519{,_OLD}
mv ~/.ssh/id_ed25519_NEW ~/.ssh/id_ed25519
mv ~/.ssh/id_ed25519_NEW.pub ~/.ssh/id_ed25519.pub
```

DB user rotation if `waystar` or `waystar-readonly` creds may be exposed:

```bash
psql -h db-internal -U waystar -d waystar
\password waystar-readonly
\password waystar-app
# (Update apache's /etc/waystar/db.env afterward.)
```

## Phase 3 — Evidence preservation

Before any container restart:

```bash
# Pull all logs into the archive (this workstation's /srv/log-archive/).
for h in apache john luke; do
    rsync -avz "$h:/var/log/persist/" "/srv/log-archive/$h-incident-$(date +%Y%m%d-%H%M)/"
done
ssh apache 'sudo tar czf /tmp/apache-evidence.tgz /usr/local/apache2/logs /var/log /etc/cron.d /opt'
scp apache:/tmp/apache-evidence.tgz /srv/log-archive/
```

## Phase 4 — Postmortem

After the immediate fire is out, schedule a writeup. Don't repeat the
2024 mistake of "the forensic report never landed." See
`~/notes/2025-Q3-tabletop-takeaways.md` (if it exists; I keep meaning to
write it).

## TODO list (perpetual)

- Audit `/opt/cleanup.sh` perms on apache — John's `chmod 777` from 2024 is still there
- Stop sharing the same key across the fleet — move to per-host keypairs
- Get someone other than me a sudoer account on at least apache (bus factor)
- Centralise auth logs to a real SIEM (currently we rsync auth.log to
  /srv/log-archive/ and hope someone reads it)
