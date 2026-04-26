#!/bin/bash

# ================================
#  UNSERE AUFGABE: Reverse-Routing
# ================================
ROUTER_IP=""
RETRIES=10
for i in $(seq 1 $RETRIES); do
    ROUTER_IP=$(dig +short router | tail -n 1)
    if [ -n "$ROUTER_IP" ]; then
        break
    fi
    echo "Warte auf DNS-Auflösung für 'router' (Versuch $i/$RETRIES)..."
    sleep 2
done

if [ -n "$ROUTER_IP" ]; then
    echo "Füge Route zum Public Net (172.22.0.0/16) über Router ($ROUTER_IP) hinzu..."
    ip route add 172.22.0.0/16 via $ROUTER_IP || true
else
    echo "ERROR: Konnte Router IP nicht finden, Reverse-Shell Routing könnte fehlschlagen."
fi

# ================================
#  TEAM-AUFGABE: Cron Start
# ================================
echo "Starte Cron Service..."
service cron start

# ================================
#  MAIN: Apache Start
# ================================
echo "Starte Apache..."
exec httpd-foreground
