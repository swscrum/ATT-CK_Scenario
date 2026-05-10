#!/bin/bash
set -e

# /var/log is bind-mounted from the host. Ownership inherits from the host
# (uid 1000), so rsyslog (running as `syslog` user) cannot write here.
# Restore the standard ubuntu ownership/permissions inside the container.
chown root:syslog /var/log
chmod 0775 /var/log

# Start rsyslog so /var/log/{syslog,auth.log,kern.log} get written. /var/log
# is bind-mounted to Infrastructure/logs/workstation on the host so SOC tools
# can ingest them after the container exits. ubuntu:24.04 ships systemd-only
# unit files so we invoke the daemon binary directly.
rsyslogd \
    || echo "[entrypoint] rsyslogd failed to start"

# Start the lab file integrity monitor (inotify-based). Output goes to
# /var/log/lab-fim.log on host. See lab-fim.sh for the watched paths and
# the MITRE technique mapping.
touch /var/log/lab-fim.log
chmod 0644 /var/log/lab-fim.log
nohup /usr/local/bin/lab-fim.sh >> /var/log/lab-fim.log 2>&1 &
echo "[entrypoint] lab-fim watcher PID $!"

# Start sshd in the background so the container has a remote shell.
/usr/sbin/sshd

# Start the Xtigervnc server on display :1 with no auth (placeholder lab).
Xtigervnc :1 \
    -geometry 1280x720 \
    -depth 24 \
    -SecurityTypes None \
    -localhost no \
    -rfbport 5901 &

# Wait briefly for the X server to be ready, then launch the XFCE session
# inside that display. `wait` blocks PID 1 on the X server (foreground for
# Docker), so the container stays alive as long as VNC is running.
sleep 2
DISPLAY=:1 startxfce4 &

wait -n
