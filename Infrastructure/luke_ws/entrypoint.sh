#!/bin/bash
set -e

# Cross-zone routes via the router (10.30.0.4 is its internal_net leg):
#   - 10.10.0.0/24 (External) — any future C2 / outbound traffic
#   - 10.40.0.0/24 (DMZ)      — Luke browsing the Waystar Connect intranet
ip route add 10.10.0.0/24 via 10.30.0.4 || true
ip route add 10.40.0.0/24 via 10.30.0.4 || true

# /var/log/persist is bind-mounted from the host; rsyslog runs as syslog
# user and needs write access. Match ownership/perm to what rsyslog
# expects on a stock Ubuntu box.
mkdir -p /var/log/persist
chown root:syslog /var/log/persist
chmod 0775 /var/log/persist

# Start rsyslog so /var/log/{syslog,auth.log} populate normally inside the
# container, and the 40-lab-persist.conf snippet mirrors them to the
# host-visible /var/log/persist.
rsyslogd \
    || echo "[entrypoint] rsyslogd failed to start"

# Lab File Integrity Monitor — inotify watcher for Luke-relevant paths.
touch /var/log/persist/lab-fim.log
chmod 0644 /var/log/persist/lab-fim.log
nohup /usr/local/bin/lab-fim.sh >> /var/log/persist/lab-fim.log 2>&1 &
echo "[entrypoint] lab-fim watcher PID $!"

# sshd in the foreground — keeps PID 1 alive without needing wait/tail tricks.
exec /usr/sbin/sshd -D
