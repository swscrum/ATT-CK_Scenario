#!/bin/sh
# Apache container start script. Invoked from /entrypoint.sh after the
# routing setup. Brings up cron + the FIM watcher, then hands off to
# httpd in the foreground so the container stays alive.
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Cron daemon — fires /opt/cleanup.sh every minute as root (the
# intentional misconfiguration that drives the lab privesc).
service cron start

# Lab File Integrity Monitor — see lab-fim.sh for the watched paths.
# Output goes to /usr/local/apache2/logs/lab-fim.log so it persists via
# the apache logs bind mount.
nohup /usr/local/bin/lab-fim.sh >> /usr/local/apache2/logs/lab-fim.log 2>&1 &
log "[start] lab-fim watcher PID $!"

exec httpd-foreground
