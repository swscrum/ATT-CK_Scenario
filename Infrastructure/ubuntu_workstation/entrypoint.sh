#!/bin/bash
set -e

# Allow reverse shells spawned on this host to reach kali — same route apache adds
ip route add 10.10.0.0/24 via 10.30.0.4 || true

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
    || echo "[entrypoint] dbus-daemon --system unavailable (non-fatal)"

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
runuser -u john.stravidis -- \
    env DISPLAY=:1 \
        HOME=/home/john.stravidis \
        XDG_RUNTIME_DIR=/run/user/${JOHN_UID} \
        NO_AT_BRIDGE=1 \
    dbus-launch --exit-with-session xfce4-session &

# Block PID 1 on the X server (foreground for Docker), so the container stays
# alive as long as VNC is running.
wait -n
