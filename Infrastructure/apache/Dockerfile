# Basis-Image enthaelt  verwundbare Apache-Version (CVE-2021-41773)
FROM httpd:2.4.49

# Debian Buster ist End of life --> kein apt update geht --> kein cron installieren --> rip xd 
# updates weg sonst fehler 
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /buster-updates/d' /etc/apt/sources.list \
#mirror archiv von debian 2019
    && apt-get -o Acquire::Check-Valid-Until=false update \
    # wegen veraltetetn paketen 
    && apt-get install -y --no-install-recommends cron \
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

RUN printf '#!/bin/sh\necho "[cleanup] $(date)" >> /var/log/cleanup.log\n' > /opt/cleanup.sh \
    && chmod 777 /opt/cleanup.sh 
    #cleanup timestamp extra minimal gehalten und wichtig rwxrwxrwx  jeder kanns schreiben!!!

RUN printf '* * * * * root /opt/cleanup.sh\n' > /etc/cron.d/cleanup \
    && chmod 644 /etc/cron.d/cleanup 
    # cron ist richtig konfiguriert --> skript aber nicht 

# Startskript: Cron-Daemon starten, dann Apache im Vordergrund damit der sich nicht beendet nach dem start
RUN printf '#!/bin/sh\nservice cron start\nexec httpd-foreground\n' > /usr/local/bin/start.sh \
    && chmod +x /usr/local/bin/start.sh
    #

CMD ["/usr/local/bin/start.sh"]


# run build with docker compose up -d --build apache router
#Test with docker compose exec apache cat /etc/cron.d/cleanup or sleep 63 && docker compose exec apache cat /var/log/cleanup.log --> should be new timestamps 