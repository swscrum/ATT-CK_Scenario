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
    /opt/cleanup.sh                       # T1053.003 — basic-mode privesc tripwire
    /etc/cron.d/cleanup                   # T1053.003 — cron schedule tamper
    /etc/sudoers                          # T1548.003 — sudo policy tamper (future-proof)
    /etc/sudoers.d                        # T1548.003 — sudoers.d drop-in (future-proof)
    /usr/local/apache2/cgi-bin            # T1190 / T1505.003 — webshell drop
)
# Note: file capabilities (T1548.001) are stored as extended attributes and
# are not reliably surfaced by inotify event masks; the start.sh capability
# baseline + diff is the right tool for that detection class, not FIM.

EXISTING=()
for p in "${WATCH_PATHS[@]}"; do
    [ -e "$p" ] && EXISTING+=("$p")
done

if [ ${#EXISTING[@]} -eq 0 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [lab-fim] no watch paths exist yet, exiting" >&2
    exit 0
fi

exec inotifywait -m -r \
    --timefmt '%Y-%m-%dT%H:%M:%S%z' \
    --format '%T tag=lab_fim host=apache path=%w%f event=%e' \
    -e modify -e attrib -e move -e create -e delete -e delete_self \
    "${EXISTING[@]}"
