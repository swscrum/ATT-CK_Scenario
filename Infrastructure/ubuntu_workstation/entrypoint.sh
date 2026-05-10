#!/bin/bash
set -e

# /var/log is bind-mounted from the host. Ownership inherits from the host
# (uid 1000), so rsyslog (running as `syslog` user) cannot write here.
# Restore the standard ubuntu ownership/permissions inside the container.
chown root:syslog /var/log
chmod 0775 /var/log
mkdir -p /var/log/audit
chown root:adm /var/log/audit
chmod 0750 /var/log/audit

# Start rsyslog so /var/log/{syslog,auth.log,kern.log} get written. /var/log
# is bind-mounted to Infrastructure/logs/workstation on the host so SOC tools
# can ingest them after the container exits. ubuntu:24.04 ships systemd-only
# unit files so we invoke the daemon binary directly.
rsyslogd \
    || echo "[entrypoint] rsyslogd failed to start"

# auditd's default priority_boost=4 requires CAP_SYS_NICE which we don't
# grant. Drop the boost so auditd can start under just AUDIT_CONTROL/READ.
sed -i 's/^priority_boost.*/priority_boost = 0/' /etc/audit/auditd.conf

# Start auditd. The kernel audit netlink socket is host-wide; in this lab the
# host's auditd is inactive so the container can claim it. Requires
# CAP_AUDIT_CONTROL plus seccomp=unconfined (set in docker-compose.yml) so
# the audit_* syscalls aren't blocked by Docker's default seccomp profile.
auditd \
    || echo "[entrypoint] auditd failed to start"
# Give auditd a beat to grab the netlink socket before loading rules.
sleep 1
auditctl -R /etc/audit/rules.d/lab.rules \
    || echo "[entrypoint] auditctl rule load failed"

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
