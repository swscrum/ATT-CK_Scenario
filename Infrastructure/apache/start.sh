#!/bin/sh
# Apache container start script. Invoked from /entrypoint.sh after the
# routing setup. Brings up cron + the FIM watcher, then hands off to
# httpd in the foreground so the container stays alive.
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Build-time activity baseline — render persona-keyed log templates into
# /var/log/{auth.log,dpkg.log,apt/history.log,cleanup.log} so the host
# comes up with 14-60 days of believable past activity. Idempotent across
# restarts via /var/lib/baseline-hydrated. Must run BEFORE cron + lab-fim
# so the baseline entries are in place before any watcher could surface
# them as runtime modifications. See Infrastructure/shared-baseline/README.md.
BASELINE_PERSONA=apache /usr/local/bin/hydrate-baseline.sh 2>&1 \
    | while read -r line; do log "$line"; done \
    || log "[start] hydrate-baseline failed (non-fatal)"

# Cron daemon — fires /opt/cleanup.sh every minute as root (the
# intentional misconfiguration that drives the basic-mode lab privesc).
service cron start

# SSH daemon — john.stravidis deploys into apache from his workstation, and
# vinzenz.fedora SSHes in for sysadmin work. Both are used by the chain
# (basic-mode deploy artefacts, advanced-mode lateral pivots).
service ssh start

# Capability baseline — single snapshot at startup so blue-team teams have
# a reference point for diff-based T1548.001 detection. The advanced-mode
# privesc relies on cap_setuid,cap_setgid+ep being baked onto /usr/bin/python3
# at build time (see Dockerfile); any *runtime* change to file capabilities
# (a real attacker adding caps to another binary post-exploitation) would
# diff against this file.
CAP_BASELINE=/usr/local/apache2/logs/capability-baseline.txt
getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null > "$CAP_BASELINE" || true
log "[start] capability baseline written ($(wc -l < "$CAP_BASELINE") entries)"

# Lab File Integrity Monitor — see lab-fim.sh for the watched paths.
# Output goes to /usr/local/apache2/logs/lab-fim.log so it persists via
# the apache logs bind mount.
nohup /usr/local/bin/lab-fim.sh >> /usr/local/apache2/logs/lab-fim.log 2>&1 &
log "[start] lab-fim watcher PID $!"

exec httpd-foreground
