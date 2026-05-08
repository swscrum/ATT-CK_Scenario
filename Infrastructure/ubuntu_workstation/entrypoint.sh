#!/bin/bash
set -e

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
