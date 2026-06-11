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

# Reactive Sysadmin Simulation
touch /var/log/persist/simulate_admin.log
chown vinzenz.fedora:vinzenz.fedora /var/log/persist/simulate_admin.log
nohup su - vinzenz.fedora -c "/usr/local/bin/simulate_admin.sh" >> /var/log/persist/simulate_admin.log 2>&1 &
log "[entrypoint] simulate_admin.sh watcher PID $!"

# sshd in the foreground — keeps PID 1 alive.
exec /usr/sbin/sshd -D
