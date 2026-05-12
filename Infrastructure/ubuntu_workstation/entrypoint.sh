#!/bin/bash
set -e

# /var/log/persist is bind-mounted from Infrastructure/logs/workstation on the
# host. We only create the directory (in case docker didn't pre-create it) and
# touch the log files so rsyslog can open them. We deliberately do NOT chown
# /var/log itself — that would change host-side directory ownership and make
# cleanup require sudo.
mkdir -p /var/log/persist
touch /var/log/persist/syslog /var/log/persist/auth.log /var/log/persist/lab-fim.log
chmod 0640 /var/log/persist/syslog /var/log/persist/auth.log /var/log/persist/lab-fim.log

# Start rsyslog so /var/log/{syslog,auth.log} get written inside the container.
# The 40-lab-persist.conf drop-in additionally mirrors those streams to
# /var/log/persist so SOC tools on the host can ingest them after the
# container exits. ubuntu:24.04 ships systemd-only unit files so we invoke
# the daemon binary directly.
rsyslogd \
    || echo "[entrypoint] rsyslogd failed to start"

# Start the lab file integrity monitor (inotify-based). Output goes to
# /var/log/persist/lab-fim.log on host. See lab-fim.sh for the watched paths
# and the MITRE technique mapping.
nohup /usr/local/bin/lab-fim.sh >> /var/log/persist/lab-fim.log 2>&1 &
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
