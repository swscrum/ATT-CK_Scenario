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
