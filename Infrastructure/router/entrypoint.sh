#!/bin/bash

# IP-Forwarding aktivieren (falls sysctl per compose fehlschlägt, versuchen wir es hier)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "IP Forwarding per sysctl vom Host übernommen."

# Hole die IP des Apache-Containers BEVOR wir iptables flushen (Da iptables-Flushes Docker-DNS zerstören)
APACHE_IP=$(dig +short apache | tail -n 1)

echo "Gefundene Apache IP: $APACHE_IP"

# Existierende Regeln löschen
iptables -F
iptables -t nat -F

if [ -n "$APACHE_IP" ]; then
    echo "Aktiviere Port Forwarding (DNAT) auf Port 80 zu $APACHE_IP:80"
    
    # 1. PREROUTING: Allen Traffic, der auf Port 80 an diesen Router-Container geht, auf Apache umleiten
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $APACHE_IP:80
    
    # 2. POSTROUTING: Mache NAT (Masquerading), damit Apache den Traffic beantworten kann 
    # (Ohne SNAT wüsste Apache nicht, wie er über diesen Container als Gateway zurückfunken soll)
    iptables -t nat -A POSTROUTING -p tcp -d $APACHE_IP --dport 80 -j MASQUERADE
    
    # 3. Falls Traffic fürs Internet oder Kali bestimmt ist (späteres Szenario)
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
else
    echo "ERROR: Konnte 'apache' Container im DNS nicht finden."
fi

echo "Router aktiv! Warte auf Traffic..."
# Endlosschleife, um Container am Leben zu halten
tail -f /dev/null
