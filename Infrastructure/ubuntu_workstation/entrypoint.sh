#!/bin/bash
set -e

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
