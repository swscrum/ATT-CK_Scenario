#!/bin/bash
# Lab File Integrity Monitor — Vinzenz Fedora's workstation.
#
# Sysadmin box — the central pivot. Most-important watch is on
# ~/.ssh/id_ed25519 because that's the cross-fleet master key; any
# touch is a five-alarm event.
#
# Watched paths map to MITRE techniques:
#   ~/.ssh/                  T1098.004 — SSH key persistence
#   ~/.ssh/id_ed25519        T1552.004 — unsecured private key theft
#   ~/.bash_history          T1070.003 — clear shell history
#   ~/.pgpass                T1552.001 — credentials in files (DB superuser!)
#   ~/inventory.ini          T1018    — remote system discovery breadcrumb
#   /var/mail/               T1114.001 — local email collection
#   /etc/{passwd,...}        T1136 / T1098 — account ops
set -u

WATCH_PATHS=(
    /home/vinzenz.fedora/.ssh
    /home/vinzenz.fedora/.bash_history
    /home/vinzenz.fedora/.pgpass
    /home/vinzenz.fedora/inventory.ini
    /home/vinzenz.fedora/runbooks
    /home/vinzenz.fedora/notes
    /home/vinzenz.fedora/Documents
    /var/mail
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/sudoers
    /etc/sudoers.d
)

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
    --format '%T tag=lab_fim path=%w%f event=%e' \
    -e modify -e attrib -e move -e create -e delete -e delete_self \
    "${EXISTING[@]}"
