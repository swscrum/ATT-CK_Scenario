#!/bin/bash
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Cross-zone routes via the router (10.30.0.4 is its internal_net leg):
#   - 10.10.0.0/24 (External) — reverse shells from this host to kali
#   - 10.40.0.0/24 (DMZ)      — deploy path to apache (rsync john.stravidis@apache:...)
ip route add 10.10.0.0/24 via 10.30.0.4 || true
ip route add 10.40.0.0/24 via 10.30.0.4 || true

# Clean any stale X/ICE state left behind by a previous container start
# (matters when Docker restarts the container without recreating it — the
# overlay /tmp can keep /tmp/.X1-lock or /tmp/.ICE-unix around even though
# the processes are gone). Pre-creating /tmp/.ICE-unix with 1777 silences the
#   _IceTransmkdir: ERROR: euid != 0, directory /tmp/.ICE-unix will not be created
# message when xfce4-session opens its session socket.
rm -f /tmp/.X*-lock
rm -rf /tmp/.X11-unix /tmp/.ICE-unix
mkdir -p /tmp/.X11-unix /tmp/.ICE-unix
chmod 1777 /tmp/.X11-unix /tmp/.ICE-unix

# John's XDG runtime dir — used by dbus-launch and a few XFCE plugins.
JOHN_UID=$(id -u john.stravidis)
mkdir -p /run/user/${JOHN_UID}
chown john.stravidis:john.stravidis /run/user/${JOHN_UID}
chmod 700 /run/user/${JOHN_UID}

# Pre-create ICEauthority so iceauth doesn't log "creating new authority file".
touch /run/user/${JOHN_UID}/ICEauthority
chown john.stravidis:john.stravidis /run/user/${JOHN_UID}/ICEauthority
chmod 600 /run/user/${JOHN_UID}/ICEauthority

# Start the D-Bus system bus so that services like upower, logind, and
# xfdesktop's system-bus clients can connect and suppress their "Could not
# connect" warnings.
mkdir -p /run/dbus
dbus-daemon --system --fork 2>/dev/null \
    || log "[entrypoint] dbus-daemon --system unavailable (non-fatal)"

# Register a minimal org.freedesktop.login1 stub on the system bus.
# xfce4-panel's clock plugin (libclock) probes this interface at startup to
# subscribe to PrepareForSleep signals. Without it the panel logs:
#   libclock-Message: logind not active
#   libclock-WARNING: could not instantiate a sleep monitor
# The stub is a no-op (the container never sleeps); it just makes the probe
# succeed. Run in background; failures are non-fatal.
python3 /usr/local/bin/logind-stub.py 2>/dev/null &
# disown removes the stub from the shell's job table so that wait -n (used
# at the end of this script to keep PID 1 alive on the VNC server) does not
# pick it up and exit the container if the stub ever terminates.
disown

# /var/log is bind-mounted from the host (./logs/workstation on host); the
# mount inherits host ownership (uid 1000), so we restore the standard
# Ubuntu root:syslog ownership before rsyslog tries to write. /var/log/audit
# is set up in advance for any future auditd plugin even though the lab
# currently uses inotify for FIM.
chown root:syslog /var/log
chmod 0775 /var/log
# Also reset ownership on existing log FILES inside /var/log — bind mounts
# preserve old ownership across container restarts, and rsyslog (running as
# user `syslog`) silently fails to append to files it can't open for write.
# Without this, auth.log / syslog stay frozen at whatever the last run wrote
# and no new sshd events are recorded. The `|| true` keeps existing files
# we don't recognise alone.
chown -R syslog:adm /var/log/*.log /var/log/syslog 2>/dev/null || true
chmod 0640 /var/log/*.log /var/log/syslog 2>/dev/null || true
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

# Activity simulator — runs as john.stravidis (the daily-user persona) when
# ACTIVITY_ENABLED=1 (set by tools/run.sh in --pacing realistic). Generates
# the developer baseline (git, npm, vim, occasional sudo) so the attacker's
# post-foothold enumeration walk has actual prior shell history to land in,
# instead of an empty ~/.bash_history that itself screams "this account
# isn't used."
nohup runuser -u john.stravidis -- \
    env ACTIVITY_ENABLED="${ACTIVITY_ENABLED:-0}" \
        ACTIVITY_PERSONA=developer \
        ACTIVITY_HOME=/home/john.stravidis \
        HOME=/home/john.stravidis \
    python3 -u /usr/local/bin/activity_sim.py \
        >> /var/log/activity_sim.log 2>&1 &
echo "[entrypoint] activity_sim (developer) PID $!"

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

# Wait briefly for the X server to be ready, then start John's XFCE session
# inside that display. We invoke `xfce4-session` directly instead of
# `startxfce4`: startxfce4 is a wrapper that tries to spawn its own X server
# (logging the misleading "X server already running on display :1" warning
# on every boot) before falling through to xfce4-session. Calling
# xfce4-session through `dbus-launch --exit-with-session` also gives the
# desktop a session bus.
#
# NO_AT_BRIDGE=1  — tells GTK/ATK not to probe for the AT-SPI accessibility
#   bus at all, eliminating the flood of "Error retrieving accessibility bus
#   address: org.a11y.Bus was not provided" dbind-WARNINGs from every XFCE
#   component on startup. AT-SPI is unused in this container lab.
sleep 2
# Start the XFCE session.  dbus-launch --exit-with-session creates the
# session D-Bus and ties its lifetime to the child process.  Instead of
# launching xfce4-session directly, we pass a small shell fragment that:
#   1. starts tumblerd in the background (it registers on the session bus
#      immediately, before xfce4-session's components start)
#   2. sleeps briefly so tumblerd is fully registered
#   3. exec-replaces the shell with xfce4-session so the dbus session bus
#      lifetime remains tied to xfce4-session
#
# Without the pre-start, xfdesktop calls tumbler's GetFlavors interface
# before D-Bus has had time to auto-activate tumblerd, producing:
#   xfdesktop WARNING: Thumbnailer failed calling GetFlavors
#   GLib-GObject-CRITICAL: g_object_unref: assertion 'G_IS_OBJECT' failed
TUMBLERD=/usr/lib/x86_64-linux-gnu/tumbler-1/tumblerd
runuser -u john.stravidis -- \
    env DISPLAY=:1 \
        HOME=/home/john.stravidis \
        XDG_RUNTIME_DIR=/run/user/${JOHN_UID} \
        NO_AT_BRIDGE=1 \
    dbus-launch --exit-with-session \
        sh -c "$TUMBLERD & sleep 1 && exec xfce4-session" &

# Block PID 1 on the X server (foreground for Docker), so the container stays
# alive as long as VNC is running.
wait -n
