#!/bin/bash
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Cross-zone routes via the router (10.30.0.4 is its internal_net leg):
#   - 10.10.0.0/24 (External) — outbound to kali, future C2
#   - 10.40.0.0/24 (DMZ)      — SSH to apache as vinzenz.fedora (sysadmin reach)
ip route add 10.10.0.0/24 via 10.30.0.4 || true
ip route add 10.40.0.0/24 via 10.30.0.4 || true

# /var/log/persist is bind-mounted from the host; rsyslog runs as syslog
# user and needs write access. Match ownership/perm to what rsyslog
# expects on a stock Ubuntu box.
mkdir -p /var/log/persist
chown root:syslog /var/log/persist
chmod 0775 /var/log/persist

# Start rsyslog so /var/log/{syslog,auth.log} populate normally inside the
# container; the 40-lab-persist.conf snippet mirrors them to the
# host-visible /var/log/persist.
rsyslogd \
    || log "[entrypoint] rsyslogd failed to start"

# Lab File Integrity Monitor — inotify watcher for sysadmin-critical paths.
touch /var/log/persist/lab-fim.log
chmod 0644 /var/log/persist/lab-fim.log
nohup /usr/local/bin/lab-fim.sh >> /var/log/persist/lab-fim.log 2>&1 &
log "[entrypoint] lab-fim watcher PID $!"

# Activity simulator — runs as vinzenz.fedora (the daily-user persona) when
# ACTIVITY_ENABLED=1 (set by tools/run.sh in --pacing realistic). This is
# the BIGGEST realism win: Vinzenz's ssh-out commands generate the baseline
# of "Accepted publickey for vinzenz.fedora" entries on apache, john_ws,
# luke_ws — so the attacker's eventual stolen-key SSH activity (advanced
# chain) has a non-zero baseline to hide in, instead of being the ONLY
# vinzenz.fedora session anywhere on the fleet.
nohup runuser -u vinzenz.fedora -- \
    env ACTIVITY_ENABLED="${ACTIVITY_ENABLED:-0}" \
        ACTIVITY_PERSONA=sysadmin \
        ACTIVITY_HOME=/home/vinzenz.fedora \
        HOME=/home/vinzenz.fedora \
    python3 -u /usr/local/bin/activity_sim.py \
        >> /var/log/persist/activity_sim.log 2>&1 &
log "[entrypoint] activity_sim (sysadmin) PID $!"

# sshd in the foreground — keeps PID 1 alive.
exec /usr/sbin/sshd -D
