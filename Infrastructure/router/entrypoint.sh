#!/bin/bash

# IP-Forwarding und RP-Filter
sysctl -w net.ipv4.ip_forward=1 2>/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null

# Hole die IP des Apache-Containers
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

# ============================================================
# Dynamische Interface-Erkennung
# Feste Subnetze: public_net=10.10.0.0/24, internal_net=10.30.0.0/24
# ============================================================
INTERNAL_IF=""
PUBLIC_IF=""

while read -r line; do
    iface=$(echo "$line" | awk '{print $2}')
    ip_addr=$(echo "$line" | grep -oP 'inet \K[\d.]+')

    if echo "$ip_addr" | grep -q "^10\.30\."; then
        INTERNAL_IF="$iface"
        echo "Internal interface: $iface ($ip_addr)"
    elif echo "$ip_addr" | grep -q "^10\.10\."; then
        PUBLIC_IF="$iface"
        echo "Public interface: $iface ($ip_addr)"
    fi
done < <(ip -4 -o addr show scope global)

echo "INTERNAL_IF=$INTERNAL_IF  PUBLIC_IF=$PUBLIC_IF"

# Existierende Regeln löschen
iptables -F
iptables -t nat -F

if [ -n "$APACHE_IP" ] && [ -n "$INTERNAL_IF" ] && [ -n "$PUBLIC_IF" ]; then
    echo "Konfiguriere Routing und NAT..."

    # 1. DNAT: Port 80 Traffic von außen an Apache weiterleiten
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $APACHE_IP:80

    # 2. MASQUERADE: Ausgehenden Traffic auf BEIDEN Interfaces maskieren
    iptables -t nat -A POSTROUTING -o $PUBLIC_IF -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $INTERNAL_IF -j MASQUERADE

    # 3. FORWARD: Stateful Firewall
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF -j ACCEPT
    iptables -A FORWARD -i $PUBLIC_IF -o $INTERNAL_IF -j ACCEPT

    echo ""
    echo "=== Finale iptables Konfiguration ==="
    iptables -nvL FORWARD
    echo ""
    iptables -t nat -nvL
else
    echo "WARNUNG: Konnte Interfaces oder Apache IP nicht ermitteln."
    echo "  APACHE_IP=$APACHE_IP INTERNAL_IF=$INTERNAL_IF PUBLIC_IF=$PUBLIC_IF"
    echo "  Fallback: Erlaube generelles Forwarding..."

    if [ -n "$APACHE_IP" ]; then
        iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $APACHE_IP:80
    fi
    iptables -t nat -A POSTROUTING -j MASQUERADE
    iptables -A FORWARD -j ACCEPT
fi

echo ""
echo "Router aktiv!"
tail -f /dev/null
