#!/bin/sh
# Apache container start script. Invoked from /entrypoint.sh after the
# routing setup. Brings up cron + the FIM watcher, then hands off to
# httpd in the foreground so the container stays alive.
set -e

# Cron daemon — fires /opt/cleanup.sh every minute as root (the
# intentional misconfiguration that drives the lab privesc).
service cron start

# Lab File Integrity Monitor — see lab-fim.sh for the watched paths.
# Output goes to /var/log/lab-fim.log inside the container.
nohup /usr/local/bin/lab-fim.sh >> /var/log/lab-fim.log 2>&1 &
echo "[start] lab-fim watcher PID $!"

exec httpd-foreground
