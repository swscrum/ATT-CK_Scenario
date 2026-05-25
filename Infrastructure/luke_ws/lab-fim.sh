#!/bin/bash
# Lab File Integrity Monitor — Luke Smith's workstation.
#
# Watched paths map to MITRE techniques the SOC should be able to detect
# when an attacker pivots onto Luke's box:
#   ~/.ssh/                  T1098.004 — SSH key persistence
#   ~/.bash_history          T1070.003 — clear/edit shell history
#   ~/.pgpass                T1552.001 — credentials in files (DB creds!)
#   ~/Documents/             T1005    — data from local system (patient notes)
#   ~/.local/share/...sqlite T1005    — local patient cache (the juicy local DB)
#   /var/mail/               T1114.001 — local email collection
#   /etc/{passwd,...}        T1136 / T1098 — account ops
#   ~vinzenz.fedora/.ssh/authorized_keys — sysadmin key tampering
set -u

WATCH_PATHS=(
    /home/luke.smith/.ssh
    /home/luke.smith/.bash_history
    /home/luke.smith/.pgpass
    /home/luke.smith/Documents
    /home/luke.smith/.local/share/waystar-psyc
    /var/mail
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/sudoers
    /etc/sudoers.d
    /home/vinzenz.fedora/.ssh/authorized_keys
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
