#!/bin/bash
set -e

# Allow reverse shells spawned on this host to reach kali — same route apache adds
ip route add 10.10.0.0/24 via 10.30.0.4 || true

# Clean any stale X server locks left behind by a previous container start
# (matters when Docker restarts the container without recreating it — the
# overlay /tmp can keep /tmp/.X1-lock around even though the X server is gone).
rm -f /tmp/.X*-lock
rm -rf /tmp/.X11-unix
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix

# /var/log is bind-mounted from the host (./logs/workstation on host); the
# mount inherits host ownership (uid 1000), so we restore the standard
# Ubuntu root:syslog ownership before rsyslog tries to write. /var/log/audit
# is set up in advance for any future auditd plugin even though the lab
# currently uses inotify for FIM.
chown root:syslog /var/log
chmod 0775 /var/log
mkdir -p /var/log/audit
chown root:adm /var/log/audit
chmod 0750 /var/log/audit

# Start the real Linux logging daemon so /var/log/{syslog,auth.log,kern.log}
# populate the way they would on a production Ubuntu box. Ubuntu 24.04 ships
# systemd-only unit files inside the image, so we invoke the binary directly.
rsyslogd \
    || echo "[entrypoint] rsyslogd failed to start"

# inotify-based File Integrity Monitor. Writes one structured line per
# filesystem event on the watched paths (john's ~/.ssh, ~/.bash_history,
# /var/mail, /etc/{passwd,shadow,sudoers,…}) to /var/log/lab-fim.log.
# Stands in for auditd, which can't register with the kernel audit
# subsystem inside this Docker host. Wazuh-FIM uses inotify the same way
# when auditd is unavailable, so the SIEM-side experience matches a real
# Linux EDR.
touch /var/log/lab-fim.log && chmod 0644 /var/log/lab-fim.log
nohup /usr/local/bin/lab-fim.sh >> /var/log/lab-fim.log 2>&1 &
echo "[entrypoint] lab-fim watcher PID $!"

# Start sshd in the background so the container has a remote shell.
/usr/sbin/sshd

# Start Xtigervnc on display :1 with no auth (placeholder lab) — running as
# john.stravidis so the desktop the user sees on localhost:5901 is John's,
# not root's.
runuser -u john.stravidis -- Xtigervnc :1 \
    -geometry 1280x720 \
    -depth 24 \
    -SecurityTypes None \
    -localhost no \
    -rfbport 5901 &

# Wait briefly for the X server to be ready, then launch the XFCE session
# inside that display (also as john.stravidis). `wait` blocks PID 1 on the
# X server (foreground for Docker), so the container stays alive as long as
# VNC is running.
sleep 2
runuser -u john.stravidis -- env DISPLAY=:1 startxfce4 &

wait -n
