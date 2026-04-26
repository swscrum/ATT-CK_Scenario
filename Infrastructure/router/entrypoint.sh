#!/bin/bash

# IP-Forwarding aktivieren (falls sysctl per compose fehlschlägt, versuchen wir es hier)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "IP Forwarding per sysctl vom Host übernommen."

# Hole die IP des Apache-Containers mit Retry-Loop (DNS ist nach Start ggf. noch nicht verfügbar)
APACHE_IP=""
RETRIES=10
for i in $(seq 1 $RETRIES); do
    APACHE_IP=$(dig +short apache | tail -n 1)
    if [ -n "$APACHE_IP" ]; then
        break
    fi
    echo "Warte auf DNS-Auflösung für 'apache' (Versuch $i/$RETRIES)..."
    sleep 2
done

echo "Gefundene Apache IP: $APACHE_IP"

# Existierende Regeln löschen
iptables -F
iptables -t nat -F

if [ -n "$APACHE_IP" ]; then
    echo "Aktiviere Port Forwarding (DNAT) auf Port 80 zu $APACHE_IP:80"
    
    # 1. PREROUTING: Allen Traffic, der auf Port 80 an diesen Router-Container geht, auf Apache umleiten
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $APACHE_IP:80
    
    # 2. POSTROUTING: Generelles NAT (Masquerading) für ausgehenden Traffic über die Router-Interfaces
    # Die spezielle MASQUERADE-Regel für $APACHE_IP:80 ist redundant, da der Traffic bereits
    # durch die Interface-basierten POSTROUTING-Regeln abgedeckt wird.
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
else
    echo "ERROR: Konnte 'apache' Container im DNS nicht finden."
    exit 1
fi

echo "Router aktiv! Warte auf Traffic..."
# Endlosschleife, um Container am Leben zu halten
tail -f /dev/null
