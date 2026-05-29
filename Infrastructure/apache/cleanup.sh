#!/bin/bash
# ============================================================================
#  cleanup.sh - Apache webserver housekeeping (Waystar Connect host)
# ----------------------------------------------------------------------------
#  Keeps the public webserver tidy: rotates Apache logs, sweeps stale
#  tempfiles and old rotated logs, and drops a disk-usage snapshot for
#  monitoring. Runs via /etc/cron.d/cleanup once a minute as root. Every
#  step is threshold-based, so the script is a no-op most of the time and
#  cheap to run that often.
#
#  Author:    Vinzenz Fedora (vinzenz.fedora@waystar-royco.example) - IT/sysadmin
#  Last edit: John Stravidis (Waystar Connect freelancer), 2024-08-12
#
#  TODO(js 2024-08): set the permissions back!! Only chmod 777'd this so
#       www-data could trigger the script itself while I was chasing down a
#       deploy permission issue. Revert to 700 before go-live:
#       chmod 700 /opt/cleanup.sh
#  TODO(vf 2024-09): replace this per-minute cron hack with a proper
#       logrotate(8) config once the Linux transition settles down.
# ============================================================================

set -u

LOGFILE="/var/log/cleanup.log"
APACHE_LOGDIR="/usr/local/apache2/logs"
STATUS_FILE="/var/log/diskusage.status"
MAX_LOG_SIZE=$((1024 * 1024))   # 1 MiB
MAX_LOG_AGE_DAYS=14
ROTATED_LOG_AGE_DAYS=30
TMP_AGE_MIN=60

log() {
    echo "[cleanup $(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}

# 1) Rotate Apache logs: compress large *.log, delete old *.log.gz
if [ -d "$APACHE_LOGDIR" ]; then
    find "$APACHE_LOGDIR" -type f -name "*.log" -size +${MAX_LOG_SIZE}c \
        -exec gzip -f {} \; 2>/dev/null
    find "$APACHE_LOGDIR" -type f -name "*.log.gz" -mtime +${MAX_LOG_AGE_DAYS} \
        -delete 2>/dev/null
fi

# 2) Rotate cleanup.log itself when it grows too big (otherwise the FS fills)
if [ -f "$LOGFILE" ]; then
    size=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)
    if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
        mv "$LOGFILE" "${LOGFILE}.1"
        : > "$LOGFILE"
        log "rotated cleanup.log (was ${size} bytes)"
    fi
fi

# 3) Drop the previous cleanup.log.1 once it's stale, so old rotations don't
#    pile up forever between go-lives.
if [ -f "${LOGFILE}.1" ]; then
    find "$LOGFILE.1" -mtime +${ROTATED_LOG_AGE_DAYS} -delete 2>/dev/null
fi

# 4) Sweep stale tempfiles (PHP sessions, Apache tempfiles, generic .tmp)
find /tmp -maxdepth 1 -type f \
    \( -name "sess_*" -o -name "apache_*" -o -name "*.tmp" \) \
    -mmin +${TMP_AGE_MIN} -delete 2>/dev/null

# 5) Clear leftover core dumps from the webroot/CGI dir — Apache children can
#    drop these on a crash and they're never useful in production.
find /usr/local/apache2 -maxdepth 2 -type f -name "core*" \
    -mmin +${TMP_AGE_MIN} -delete 2>/dev/null

# 6) Snapshot disk usage for monitoring
df -h / > "$STATUS_FILE" 2>/dev/null

# 7) Heartbeat - keeps existing timestamp-grepping tests green
echo "[cleanup] $(date)" >> "$LOGFILE"
