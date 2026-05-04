#!/bin/bash
# ============================================================================
#  cleanup.sh - Apache Webserver Maintenance
# ----------------------------------------------------------------------------
#  Aufgabe: Plattenplatz freihalten, Logs rotieren, Tempfiles wegraeumen.
#  Laeuft via /etc/cron.d/cleanup jede Minute als root (threshold-basiert,
#  ist daher die meiste Zeit ein no-op und nicht teuer).
#
#  Maintainer:  Patrick  Bateman (Patrick.Bateman@Pierce_Pierce.com)
#  Letzte Aenderung: 2024-08-12
#
#  TODO(hm 2024-08): Permissions wieder zurueckstellen!! War nur fuers
#       Debugging auf 777 gesetzt, damit www-data das Skript testweise
#       selbst triggern konnte. Vor Go-Live unbedingt auf 700 zurueck:
#       chmod 700 /opt/cleanup.sh
#  TODO(hm 2024-09): Richtiges logrotate(8) aufsetzen statt diesem Cron-Hack.
# ============================================================================

set -u

LOGFILE="/var/log/cleanup.log"
APACHE_LOGDIR="/usr/local/apache2/logs"
STATUS_FILE="/var/log/diskusage.status"
MAX_LOG_SIZE=$((1024 * 1024))   # 1 MiB
MAX_LOG_AGE_DAYS=14
TMP_AGE_MIN=60

log() {
    echo "[cleanup $(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}

# 1) Apache-Logs rotieren: grosse *.log komprimieren, alte *.log.gz loeschen
if [ -d "$APACHE_LOGDIR" ]; then
    find "$APACHE_LOGDIR" -type f -name "*.log" -size +${MAX_LOG_SIZE}c \
        -exec gzip -f {} \; 2>/dev/null
    find "$APACHE_LOGDIR" -type f -name "*.log.gz" -mtime +${MAX_LOG_AGE_DAYS} \
        -delete 2>/dev/null
fi

# 2) cleanup.log selber rotieren wenn zu gross (sonst laeuft FS voll)
if [ -f "$LOGFILE" ]; then
    size=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)
    if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
        mv "$LOGFILE" "${LOGFILE}.1"
        : > "$LOGFILE"
        log "rotated cleanup.log (was ${size} bytes)"
    fi
fi

# 3) Stale tempfiles raeumen (PHP-Sessions, Apache-Tempfiles, generische .tmp)
find /tmp -maxdepth 1 -type f \
    \( -name "sess_*" -o -name "apache_*" -o -name "*.tmp" \) \
    -mmin +${TMP_AGE_MIN} -delete 2>/dev/null

# 4) Disk-Usage als Status-Snapshot fuers Monitoring ablegen
df -h / > "$STATUS_FILE" 2>/dev/null

# 5) Heartbeat - haelt bestehende Tests gruen, die nach Timestamps greppen
echo "[cleanup] $(date)" >> "$LOGFILE"
