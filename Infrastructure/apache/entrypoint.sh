#!/bin/bash

# ================================
#  UNSERE AUFGABE: Reverse-Routing
# ================================
DEFAULT_ROUTER_IP="10.30.0.4"
ROUTER_IP="${ROUTER_IP:-$DEFAULT_ROUTER_IP}"
RESOLVED_ROUTER_IP=""
RETRIES=10

if [ "$ROUTER_IP" = "$DEFAULT_ROUTER_IP" ]; then
    for i in $(seq 1 $RETRIES); do
        RESOLVED_ROUTER_IP=$(dig +short router | tail -n 1)
        if [ -n "$RESOLVED_ROUTER_IP" ]; then
            ROUTER_IP="$RESOLVED_ROUTER_IP"
            break
        fi
        echo "Warte auf DNS-Auflösung für 'router' (Versuch $i/$RETRIES)..."
        sleep 2
    done
fi

if [ -n "$ROUTER_IP" ]; then
    if [ -n "$RESOLVED_ROUTER_IP" ]; then
        echo "Füge Route zum Public Net (10.10.0.0/24) über Router ($ROUTER_IP) hinzu..."
    else
        echo "DNS-Auflösung für 'router' fehlgeschlagen, verwende Fallback Router-IP ($ROUTER_IP)..."
    fi
    ip route add 10.10.0.0/24 via "$ROUTER_IP" || true
else
    echo "ERROR: Konnte Router IP nicht finden, Reverse-Shell Routing könnte fehlschlagen."
fi

# ================================
#  TEAM-AUFGABE: CMD ausführen
# ================================
echo "Übergebe an das originale Startskript: $@"
exec "$@"
