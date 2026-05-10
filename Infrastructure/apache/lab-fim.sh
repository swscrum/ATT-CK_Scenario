#!/bin/bash
# Apache File Integrity Monitor — produces SIEM-ingestible log lines
# whenever the watched paths change. The central detection point is
# /opt/cleanup.sh: it is world-writable and runs as root every minute via
# cron, so a write to it (T1053.003 + T1068) is the moment the attack
# pivots from www-data to root. Any line tagged `lab_fim` referencing
# /opt/cleanup.sh in this lab IS a privesc.
#
# Replaces auditd, which can't register with the kernel audit subsystem
# inside Docker on this host.
set -u

WATCH_PATHS=(
    /opt/cleanup.sh                       # T1053.003 — privesc tripwire
    /etc/cron.d/cleanup                   # T1053.003 — cron schedule tamper
    /usr/local/apache2/cgi-bin            # T1190 / T1505.003 — webshell drop
)

EXISTING=()
for p in "${WATCH_PATHS[@]}"; do
    [ -e "$p" ] && EXISTING+=("$p")
done

if [ ${#EXISTING[@]} -eq 0 ]; then
    echo "[lab-fim] no watch paths exist yet, exiting" >&2
    exit 0
fi

exec inotifywait -m -r \
    --timefmt '%Y-%m-%dT%H:%M:%S%z' \
    --format '%T tag=lab_fim path=%w%f event=%e' \
    -e modify -e attrib -e move -e create -e delete -e delete_self \
    "${EXISTING[@]}"
