#!/bin/bash

# IP-Forwarding und RP-Filter
sysctl -w net.ipv4.ip_forward=1 2>/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null

# Start ulogd2 in the background so NFLOG events from iptables get written
# to /var/log/ulog-iptables.log (bind-mounted for SIEM ingest).
mkdir -p /var/log
ulogd -d -c /etc/ulogd.conf \
    || echo "[entrypoint] ulogd failed to start"

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
# Fixed subnets: public_net=10.10.0.0/24, dmz_net=10.40.0.0/24,
#                internal_net=10.30.0.0/24
# ============================================================
PUBLIC_IF=""
DMZ_IF=""
INTERNAL_IF=""

while read -r line; do
    iface=$(echo "$line" | awk '{print $2}')
    ip_addr=$(echo "$line" | grep -oP 'inet \K[\d.]+')

    if echo "$ip_addr" | grep -q "^10\.30\."; then
        INTERNAL_IF="$iface"
        echo "Internal interface: $iface ($ip_addr)"
    elif echo "$ip_addr" | grep -q "^10\.40\."; then
        DMZ_IF="$iface"
        echo "DMZ interface:      $iface ($ip_addr)"
    elif echo "$ip_addr" | grep -q "^10\.10\."; then
        PUBLIC_IF="$iface"
        echo "Public interface:   $iface ($ip_addr)"
    fi
done < <(ip -4 -o addr show scope global)

echo "PUBLIC_IF=$PUBLIC_IF  DMZ_IF=$DMZ_IF  INTERNAL_IF=$INTERNAL_IF"

# Existierende Regeln löschen
iptables -F
iptables -t nat -F

if [ -n "$APACHE_IP" ] && [ -n "$INTERNAL_IF" ] && [ -n "$DMZ_IF" ] && [ -n "$PUBLIC_IF" ]; then
    echo "Konfiguriere Routing und NAT..."

    # 1. DNAT: external :80 → apache (now living in DMZ).
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $APACHE_IP:80

    # 2. MASQUERADE: outgoing traffic on every interface gets source-rewritten.
    iptables -t nat -A POSTROUTING -o $PUBLIC_IF   -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $DMZ_IF      -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $INTERNAL_IF -j MASQUERADE

    # 3. FORWARD: zone-aware stateful firewall.
    iptables -P FORWARD DROP
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # External → DMZ: only the CVE-2021-41773 attack path (HTTP to apache).
    iptables -A FORWARD -i $PUBLIC_IF   -o $DMZ_IF      -p tcp -d $APACHE_IP --dport 80 -j ACCEPT

    # DMZ → External: lets apache's reverse shells dial back to kali
    # (Phase 2 :4444 www-data callback and Phase 3 :5555 root callback).
    iptables -A FORWARD -i $DMZ_IF      -o $PUBLIC_IF   -j ACCEPT

    # DMZ → Internal: only SSH. This is the Phase 4 lateral movement
    # (apache → john.stravidis@workstation). Now traverses the router and
    # gets logged at the network layer instead of bypassing it via a shared
    # subnet — the central SOC-training win of this segmentation slice.
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 22 -j ACCEPT

    # DMZ → Internal: apache's booking CGI talks to db-internal on Postgres.
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 5432 -j ACCEPT

    # Internal → External: workstation outbound (future C2 / phases 5+).
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF   -j ACCEPT

    # Internal → DMZ: SSH-only deploy path (e.g. john pushing from his
    # workstation back to apache).
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 22 -j ACCEPT

    # 4. NFLOG: tap NEW flows at the head of FORWARD and unmatched drops at
    #    the tail. ulogd2 catches both via group 1 and writes to
    #    /var/log/ulog-iptables.log (bind-mounted to host for SIEM ingest).
    iptables -I FORWARD 1 -m conntrack --ctstate NEW \
        -j NFLOG --nflog-prefix "FW-NEW: " --nflog-group 1
    iptables -A FORWARD \
        -j NFLOG --nflog-prefix "FW-DROP: " --nflog-group 1

    echo ""
    echo "=== Finale iptables Konfiguration ==="
    iptables -nvL FORWARD
    echo ""
    iptables -t nat -nvL
else
    echo "FEHLER: Konnte Interfaces oder Apache IP nicht ermitteln."
    echo "  APACHE_IP=$APACHE_IP PUBLIC_IF=$PUBLIC_IF DMZ_IF=$DMZ_IF INTERNAL_IF=$INTERNAL_IF"
    echo "  Breche ab, um fail-closed zu bleiben und kein generelles Forwarding zu erlauben."

    # Fail-closed: Kein unspezifisches NAT/Forwarding aktivieren
    iptables -P FORWARD DROP
    exit 1
fi

echo ""
echo "Router aktiv!"
tail -f /dev/null
