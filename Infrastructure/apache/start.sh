#!/bin/sh
# Apache container start script. Invoked from /entrypoint.sh after the
# routing setup. Brings up cron + the FIM watcher, then hands off to
# httpd in the foreground so the container stays alive.
set -e

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

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
