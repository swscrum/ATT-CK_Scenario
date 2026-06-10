#!/bin/bash
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Cross-zone routes via the router (10.30.0.4 is its internal_net leg):
#   - 10.10.0.0/24 (External) — outbound to kali, future C2
#   - 10.40.0.0/24 (DMZ)      — SSH to apache as vinzenz.fedora (sysadmin reach)
ip route add 10.10.0.0/24 via 10.30.0.4 || true
ip route add 10.40.0.0/24 via 10.30.0.4 || true

# /var/log/persist is bind-mounted from the host; rsyslog runs as syslog
# user and needs write access. Match ownership/perm to what rsyslog
# expects on a stock Ubuntu box.
mkdir -p /var/log/persist
chown root:syslog /var/log/persist
chmod 0775 /var/log/persist

# Pre-seed /var/log/* with realistic past activity (sysadmin persona).
# Must run BEFORE rsyslog + lab-fim so the baseline entries are in place
# before any watcher could surface them as runtime modifications.
BASELINE_PERSONA=sysadmin /usr/local/bin/hydrate-baseline.sh 2>&1 \
    | while read -r line; do log "$line"; done \
    || log "[entrypoint] hydrate-baseline failed (non-fatal)"

# Start rsyslog so /var/log/{syslog,auth.log} populate normally inside the
# container; the 40-lab-persist.conf snippet mirrors them to the
# host-visible /var/log/persist.
rsyslogd \
    || log "[entrypoint] rsyslogd failed to start"

# Mirror the baseline-written /var/log/{auth.log,syslog} into the
# persist mount so a SIEM ingesting from the host sees them. rsyslog
# itself only mirrors NEW lines after it starts; the baseline was
# written before rsyslog started.
for f in auth.log syslog; do
    [ -f "/var/log/$f" ] && cp -a "/var/log/$f" "/var/log/persist/$f.baseline" || true
done

# Hydrate ~/.ssh/known_hosts with REAL fleet host keys so Vinzenz's SSH
# out actually works (the source-tree known_hosts has only an instructional
# header comment; without this step, accept-new would silently re-populate
# the file on each connection). Best-effort: if a host isn't ready yet,
# accept-new still covers us on first real SSH attempt.
hydrate_vinzenz_known_hosts() {
    local kh=/home/vinzenz.fedora/.ssh/known_hosts
    # Wait for all three fleet hosts to be sshd-reachable in parallel, then
    # keyscan each with name+IP so subsequent SSH-by-name AND SSH-by-IP both
    # hit cached entries (no accept-new prompt). Parallel is critical: if we
    # serialise, the first host's retry budget can starve the others before
    # the user lands a manual SSH that triggers accept-new and races us.
    keyscan_one() {
        local pair="$1" name ip tmp
        name="${pair%:*}"
        ip="${pair#*:}"
        tmp=$(mktemp)
        for attempt in $(seq 1 25); do
            if ssh-keyscan -T 3 -t ed25519,ecdsa-sha2-nistp256,ssh-rsa "$ip" 2>/dev/null > "$tmp" \
                && grep -q ssh-ed25519 "$tmp"; then
                # Re-scan with combined name,IP tag so both lookup paths
                # match the cached entry.
                ssh-keyscan -T 3 -t ed25519,ecdsa-sha2-nistp256,ssh-rsa "$name,$ip" 2>/dev/null \
                    > "$tmp"
                # Append atomically.
                flock -x "$kh" sh -c "cat '$tmp' >> '$kh'"
                rm -f "$tmp"
                return 0
            fi
            sleep 1
        done
        rm -f "$tmp"
        return 1
    }
    keyscan_one "apache:10.40.0.2" &
    keyscan_one "john:10.30.0.5" &
    keyscan_one "luke:10.30.0.7" &
    wait
    chown vinzenz.fedora:vinzenz.fedora "$kh"
    chmod 644 "$kh"
}
hydrate_vinzenz_known_hosts &
log "[entrypoint] vinzenz known_hosts hydrator launched in background"

# Lab File Integrity Monitor — inotify watcher for sysadmin-critical paths.
touch /var/log/persist/lab-fim.log
chmod 0644 /var/log/persist/lab-fim.log
nohup /usr/local/bin/lab-fim.sh >> /var/log/persist/lab-fim.log 2>&1 &
log "[entrypoint] lab-fim watcher PID $!"

# sshd in the foreground — keeps PID 1 alive.
exec /usr/sbin/sshd -D
