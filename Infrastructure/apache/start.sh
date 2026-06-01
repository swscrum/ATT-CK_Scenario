#!/bin/sh
# Apache container start script. Invoked from /entrypoint.sh after the
# routing setup. Brings up cron + the FIM watcher, then hands off to
# httpd in the foreground so the container stays alive.
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# rsyslog — must start BEFORE sshd so the very first SSH attempt is
# captured. The 40-lab-persist.conf snippet (added to /etc/rsyslog.d/)
# mirrors auth.log and syslog into /usr/local/apache2/logs/ which is
# bind-mounted to host, so the SIEM can ingest them.
service rsyslog start

# Cron daemon — fires /opt/cleanup.sh every minute as root (the
# intentional misconfiguration that drives the lab privesc).
service cron start

# SSH daemon — apache hosts named accounts for luke.smith (backup pushes
# per scenario_story.md) and vinzenz.fedora (sysadmin maintenance via the
# shared vincent_admin_key). Both need inbound SSH on this container.
# Without this, the activity simulator's `ssh apache 'uptime'` from
# vinzenz_ws is refused, and no apache/auth.log baseline exists for
# vinzenz.fedora to hide the attacker's stolen-key activity in (advanced
# chain).
service ssh start

# Lab File Integrity Monitor — see lab-fim.sh for the watched paths.
# Output goes to /usr/local/apache2/logs/lab-fim.log so it persists via
# the apache logs bind mount.
nohup /usr/local/bin/lab-fim.sh >> /usr/local/apache2/logs/lab-fim.log 2>&1 &
log "[start] lab-fim watcher PID $!"

exec httpd-foreground
