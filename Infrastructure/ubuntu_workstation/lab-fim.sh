#!/bin/bash
# Lab File Integrity Monitor — produces SIEM-ingestible log lines whenever
# any of the watched paths is created/modified/deleted/moved. Replaces
# auditd in this lab because the kernel audit subsystem can't be enabled
# from inside an unprivileged Docker container on this host.
#
# This script writes event lines to stdout; in this lab, the entrypoint
# redirects that output to /var/log/lab-fim.log so SOC analysts can write
# Sigma / Wazuh-FIM rules against the same paths the auditd-based design
# called out in Documentation/mappings.md.
#
# Watched paths map to MITRE techniques:
#   ~/.ssh/                T1098.004 — SSH key persistence
#   ~/.bash_history        T1070.003 — clear shell history
#   /var/mail/             T1114.001 — local email collection
#   /etc/{passwd,shadow,group,sudoers,sudoers.d}  T1136 / T1098 — account ops
set -u

WATCH_PATHS=(
    /home/john.stravidis/.ssh
    /home/john.stravidis/.bash_history
    /var/mail
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/sudoers
    /etc/sudoers.d
)

# Drop paths that don't exist yet so inotifywait doesn't error.
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
    --format '%T tag=lab_fim host=john_ws path=%w%f event=%e' \
    -e modify -e attrib -e move -e create -e delete -e delete_self \
    "${EXISTING[@]}"
