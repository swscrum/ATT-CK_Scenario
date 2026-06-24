#!/bin/bash
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Cross-zone routes via the router (10.30.0.4 is its internal_net leg):
#   - 10.10.0.0/24 (External) — any future C2 / outbound traffic
#   - 10.40.0.0/24 (DMZ)      — Luke browsing the Waystar Connect intranet
ip route add 10.10.0.0/24 via 10.30.0.4 || true
ip route add 10.40.0.0/24 via 10.30.0.4 || true

# Pin DNS resolution to lab_dns (10.30.0.10) instead of Docker's embedded
# resolver. Luke's clinical activity hits real-looking external domains
# (slack.com, intranet.waystar.local) and lab DNS is the only resolver
# that knows about them. Other container names (apache, db-internal,
# kali, router) are mirrored into lab_dns's hostfile.
cat > /etc/resolv.conf <<EOF
nameserver 10.30.0.10
options edns0 timeout:2 attempts:2
EOF

# /var/log/persist is bind-mounted from the host; rsyslog runs as syslog
# user and needs write access. Match ownership/perm to what rsyslog
# expects on a stock Ubuntu box.
mkdir -p /var/log/persist
chown root:syslog /var/log/persist
chmod 0775 /var/log/persist

# Pre-seed /var/log/* with realistic past activity (clinical persona).
# Must run BEFORE rsyslog + lab-fim so the baseline entries are in place
# before any watcher could surface them as runtime modifications.
BASELINE_PERSONA=clinical /usr/local/bin/hydrate-baseline.sh 2>&1 \
    | while read -r line; do log "$line"; done \
    || log "[entrypoint] hydrate-baseline failed (non-fatal)"

# Start rsyslog so /var/log/{syslog,auth.log} populate normally inside the
# container, and the 40-lab-persist.conf snippet mirrors them to the
# host-visible /var/log/persist.
rsyslogd \
    || log "[entrypoint] rsyslogd failed to start"

# Mirror the baseline-written /var/log/{auth.log,syslog} into the persist
# mount so a SIEM ingesting from the host sees them (rsyslog only mirrors
# NEW lines after it starts).
for f in auth.log syslog; do
    [ -f "/var/log/$f" ] && cp -a "/var/log/$f" "/var/log/persist/$f.baseline" || true
done

# Lab File Integrity Monitor — inotify watcher for Luke-relevant paths.
touch /var/log/persist/lab-fim.log
chmod 0644 /var/log/persist/lab-fim.log
nohup /usr/local/bin/lab-fim.sh >> /var/log/persist/lab-fim.log 2>&1 &
log "[entrypoint] lab-fim watcher PID $!"

# Hydrate ~/.ssh/known_hosts with REAL apache host key so Luke's rsync
# backups work without accept-new prompts. Best-effort, background.
hydrate_luke_known_hosts() {
    local kh=/home/luke.smith/.ssh/known_hosts
    local tmp
    tmp=$(mktemp)
    for attempt in $(seq 1 25); do
        if ssh-keyscan -T 3 -t ed25519,ecdsa-sha2-nistp256,ssh-rsa 10.40.0.2 2>/dev/null > "$tmp" \
            && grep -q ssh-ed25519 "$tmp"; then
            ssh-keyscan -T 3 -t ed25519,ecdsa-sha2-nistp256,ssh-rsa "apache,10.40.0.2" 2>/dev/null > "$tmp"
            cat "$tmp" >> "$kh"
            rm -f "$tmp"
            chown luke.smith:luke.smith "$kh"
            chmod 644 "$kh"
            return 0
        fi
        sleep 1
    done
    rm -f "$tmp"
}
hydrate_luke_known_hosts &
log "[entrypoint] luke known_hosts hydrator launched in background"

# Activity simulator — runs as luke.smith (the daily-user persona) when
# ACTIVITY_ENABLED=1 (set by tools/run.sh in --pacing realistic). Generates
# the legitimate-baseline of psql queries to db-internal + vim/ls on
# ~/Documents/notes so the attacker's eventual exfil queries have history
# to hide in. Runs in background so sshd takes PID 1.
nohup runuser -u luke.smith -- \
    env ACTIVITY_ENABLED="${ACTIVITY_ENABLED:-0}" \
        ACTIVITY_PERSONA=clinical \
        ACTIVITY_HOME=/home/luke.smith \
        HOME=/home/luke.smith \
    python3 -u /usr/local/bin/activity_sim.py \
        >> /var/log/persist/activity_sim.log 2>&1 &
log "[entrypoint] activity_sim (clinical) PID $!"

# sshd in the foreground — keeps PID 1 alive without needing wait/tail tricks.
exec /usr/sbin/sshd -D
