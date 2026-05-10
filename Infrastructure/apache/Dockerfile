# Basis-Image enthaelt  verwundbare Apache-Version (CVE-2021-41773)
FROM httpd:2.4.50

# Debian Buster ist End of life --> kein apt update geht --> kein cron installieren --> rip xd 
# updates weg sonst fehler 
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /buster-updates/d' /etc/apt/sources.list \
    #mirror archiv von debian 2019
    && apt-get -o Acquire::Check-Valid-Until=false update \
    # wegen veraltetetn paketen
    # inotify-tools backs the lab File Integrity Monitor that watches
    # /opt/cleanup.sh — the central privesc detection point.
    && apt-get install -y --no-install-recommends cron iproute2 dnsutils inotify-tools \
    # online empfehlung zum abschalten als best practice damit image klein bleibt
    && rm -rf /var/lib/apt/lists/*
#cleanup kann auch weggelassen werden 


# man könte auch Apache 2.4.49 selbst bauen aber wieso?? schneller so 






# ============================================================================
#  FEHLKONFIGURATION__-_-__-_-__MITRE ATT&CK T1053.003 (Cron )
# ----------------------------------------------------------------------------
# /opt/cleanup.sh wird per Cron jede Minute als root ausgefuehrt UND ist
# world-writable (chmod 777) JEDER  Nutzer im Container
# kann damit den Skript-Inhalt ueberschreiben und beliebigen Code als
# root ausfuehren lassen -> Privilege Escalation -> boom
# ==========================================================================

#somit alle Acceptance Criteria: Issue 23 erfüllt 

# Maintenance-Skript des "Admin"  
#macht echte Wartung (Logrotation,
# Tempfile-Cleanup, Disk-Usage-Snapshot)
# eines TODO-Kommentars im Skript ("nur fuers Debugging"  nie
# zurueckgebaut )
COPY cleanup.sh /opt/cleanup.sh
RUN chmod 777 /opt/cleanup.sh
#wichtig: rwxrwxrwx  jeder kann ueberschreiben -> www-data kann root-Code droppen

RUN printf '* * * * * root /opt/cleanup.sh\n' > /etc/cron.d/cleanup \
    && chmod 644 /etc/cron.d/cleanup 
# cron ist richtig konfiguriert --> skript aber nicht 

# Start script — brings up cron + the File Integrity Monitor, then hands
# off to httpd in the foreground. See start.sh for the detail.
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# File Integrity Monitor — inotify-based. Watches /opt/cleanup.sh and
# friends; replaces auditd which can't register inside an unprivileged
# Docker container on this host.
COPY lab-fim.sh /usr/local/bin/lab-fim.sh
RUN chmod +x /usr/local/bin/lab-fim.sh
#

CMD ["/usr/local/bin/start.sh"]

# ============================================================================
#  Reverse-Routing Setup einschleußen
# ============================================================================
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Wir überschreiben das Entrypoint. Dadurch läuft unser Routing-Skipt 
# VOR dem CMD. Unser Skript ruft danach ganz brav "/usr/local/bin/start.sh" auf!
ENTRYPOINT ["/entrypoint.sh"]


# run build with docker compose up -d --build apache router
#Test with docker compose exec apache cat /etc/cron.d/cleanup or sleep 63 && docker compose exec apache cat /var/log/cleanup.log --> should be new timestamps 