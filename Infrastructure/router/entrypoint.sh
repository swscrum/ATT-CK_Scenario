#!/bin/bash

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# IP-Forwarding und RP-Filter
sysctl -w net.ipv4.ip_forward=1 2>/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null

# Start ulogd2 in the background so NFLOG events from iptables get written
# to /var/log/ulog-iptables.log (bind-mounted for SIEM ingest).
mkdir -p /var/log
ulogd -d -c /etc/ulogd.conf \
    || log "[entrypoint] ulogd failed to start"

# Hole die IP des Apache-Containers
APACHE_IP=""
RETRIES=10
for i in $(seq 1 $RETRIES); do
    APACHE_IP=$(dig +short apache | tail -n 1)
    if [ -n "$APACHE_IP" ]; then
        break
    fi
    log "Warte auf DNS-Auflösung für 'apache' (Versuch $i/$RETRIES)..."
    sleep 2
done

log "Gefundene Apache IP: $APACHE_IP"

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
        log "Internal interface: $iface ($ip_addr)"
    elif echo "$ip_addr" | grep -q "^10\.40\."; then
        DMZ_IF="$iface"
        log "DMZ interface:      $iface ($ip_addr)"
    elif echo "$ip_addr" | grep -q "^10\.10\."; then
        PUBLIC_IF="$iface"
        log "Public interface:   $iface ($ip_addr)"
    fi
done < <(ip -4 -o addr show scope global)

log "PUBLIC_IF=$PUBLIC_IF  DMZ_IF=$DMZ_IF  INTERNAL_IF=$INTERNAL_IF"

# Existierende Regeln löschen
iptables -F
iptables -t nat -F

if [ -n "$APACHE_IP" ] && [ -n "$INTERNAL_IF" ] && [ -n "$DMZ_IF" ] && [ -n "$PUBLIC_IF" ]; then
    log "Konfiguriere Routing und NAT..."

    # 1. DNAT: only PUBLIC-facing :80 / :443 → apache. Scoped to `-i PUBLIC_IF`
    # so it only fires for traffic ARRIVING from the external zone (kali,
    # noise_* containers). Without this scope the rule also catches
    # Internal→External flows (workstation → fake_internet on :443),
    # silently rewriting them to apache and breaking the simulated
    # outbound-internet baseline.
    iptables -t nat -A PREROUTING -i $PUBLIC_IF -p tcp --dport 80  -j DNAT --to-destination $APACHE_IP:80
    iptables -t nat -A PREROUTING -i $PUBLIC_IF -p tcp --dport 443 -j DNAT --to-destination $APACHE_IP:443

    # 2. MASQUERADE: outgoing traffic on every interface gets source-rewritten.
    iptables -t nat -A POSTROUTING -o $PUBLIC_IF   -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $DMZ_IF      -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $INTERNAL_IF -j MASQUERADE

    # 3. FORWARD: zone-aware stateful firewall.
    iptables -P FORWARD DROP
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # External → DMZ: the CVE-2021-42013 attack path. HTTP for legacy
    # clients (apache redirects to HTTPS for non-cgi-bin paths), HTTPS
    # for the production-realistic transport. Both terminate at apache.
    iptables -A FORWARD -i $PUBLIC_IF   -o $DMZ_IF      -p tcp -d $APACHE_IP --dport 80  -j ACCEPT
    iptables -A FORWARD -i $PUBLIC_IF   -o $DMZ_IF      -p tcp -d $APACHE_IP --dport 443 -j ACCEPT

    # External → Internal: realistic perimeter posture. The current attack
    # chain pivots in via apache (External → DMZ → Internal) and does NOT
    # need a direct External → Internal path. A real edge firewall would
    # still WRITE explicit rules covering this direction so the SOC has
    # named-prefix log entries for the most common probe types instead of
    # everything collapsing into the generic FW-DROP tail rule.
    #
    # ICMP echo is left open — common operational convenience in many real
    # networks (helps admins debug, also helps attackers map; visible to
    # SOC via the head FW-NEW NFLOG either way).
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF \
        -p icmp --icmp-type echo-request -j ACCEPT
    # Common scanned ports — tag with named NFLOG prefixes so SOC training
    # rules can fire on specifically "external-to-internal probe of X"
    # rather than the generic tail FW-DROP. Each rule is non-terminating
    # (NFLOG continues the chain); the explicit DROP below ends the chain.
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF -p tcp --dport 22 \
        -j NFLOG --nflog-prefix "FW-EXT-PROBE-SSH: "   --nflog-group 1
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF -p tcp --dport 3389 \
        -j NFLOG --nflog-prefix "FW-EXT-PROBE-RDP: "   --nflog-group 1
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF -p tcp --dport 5432 \
        -j NFLOG --nflog-prefix "FW-EXT-PROBE-DB: "    --nflog-group 1
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF -p tcp --dport 5901 \
        -j NFLOG --nflog-prefix "FW-EXT-PROBE-VNC: "   --nflog-group 1
    # HTTPS probes — external scanners regularly fingerprint :443 looking
    # for misconfigured internal services. Apache itself lives on dmz_net
    # not internal_net, so any External→Internal :443 attempt is anomalous.
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF -p tcp --dport 443 \
        -j NFLOG --nflog-prefix "FW-EXT-PROBE-HTTPS: " --nflog-group 1
    # Explicit DROP for everything else External → Internal. Catches the
    # remaining probes (other ports, UDP, weird protocols) AND makes the
    # firewall intent visible in `iptables -nvL` packet counters.
    iptables -A FORWARD -i $PUBLIC_IF   -o $INTERNAL_IF -j DROP

    # DMZ → External: lets apache's reverse shells dial back to kali
    # (Phase 2 :4444 www-data callback and Phase 3 :5555 root callback).
    iptables -A FORWARD -i $DMZ_IF      -o $PUBLIC_IF   -j ACCEPT

    # DMZ → Internal: permissive baseline. One rule per service so each
    # port shows up with its own packet counter in `iptables -nvL` (handy
    # for ops + SOC training). Tighten by deleting specific lines as the
    # chain matures and named detections need cleaner signal.
    #     22       SSH       — Phase 4 lateral (apache → workstation)
    #     53       DNS       — name resolution (TCP + UDP)
    #     80/443   HTTP/S    — web (intranet API, internal admin panels)
    #     3389     RDP       — Windows remote desktop
    #     1433/3306/5432/27017  — MSSQL / MySQL / Postgres / MongoDB
    #                           Postgres covers the existing booking-CGI path.
    #     5900-5901 VNC       — covers canonical :5900 and the lab's :5901
    #     icmp     ping      — ops debugging
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 22        -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 53        -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p udp --dport 53        -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 80        -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 443       -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 3389      -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 1433      -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 3306      -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 5432      -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 27017     -j ACCEPT
    iptables -A FORWARD -i $DMZ_IF      -o $INTERNAL_IF -p tcp --dport 5900:5901 -j ACCEPT

    # Internal → External: workstation outbound. Tagged with named NFLOG
    # prefixes per port so the SIEM can see the WORKSTATION BASELINE
    # (DNS to lab_dns, HTTPS to fake_internet, plain HTTP for apt repos)
    # AS DISTINCT FROM the future attacker C2 (which would be one of
    # these same ports — same tag — but to a non-baseline destination IP
    # or carrying a non-baseline payload). Each NFLOG rule is
    # non-terminating; the ACCEPT below ends the chain.
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF -p udp --dport 53 \
        -j NFLOG --nflog-prefix "FW-INT-OUT-DNS: "   --nflog-group 1
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF -p tcp --dport 53 \
        -j NFLOG --nflog-prefix "FW-INT-OUT-DNS: "   --nflog-group 1
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF -p tcp --dport 443 \
        -j NFLOG --nflog-prefix "FW-INT-OUT-HTTPS: " --nflog-group 1
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF -p tcp --dport 80 \
        -j NFLOG --nflog-prefix "FW-INT-OUT-HTTP: "  --nflog-group 1
    iptables -A FORWARD -i $INTERNAL_IF -o $PUBLIC_IF   -j ACCEPT

    # Internal → DMZ: symmetric mirror of the DMZ → Internal block above.
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 22        -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 53        -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p udp --dport 53        -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 80        -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 443       -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 3389      -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 1433      -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 3306      -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 5432      -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 27017     -j ACCEPT
    iptables -A FORWARD -i $INTERNAL_IF -o $DMZ_IF      -p tcp --dport 5900:5901 -j ACCEPT

    # 4. NFLOG: tap NEW flows at the head of FORWARD and unmatched drops at
    #    the tail. ulogd2 catches both via group 1 and writes to
    #    /var/log/ulog-iptables.log (bind-mounted to host for SIEM ingest).
    iptables -I FORWARD 1 -m conntrack --ctstate NEW \
        -j NFLOG --nflog-prefix "FW-NEW: " --nflog-group 1
    iptables -A FORWARD \
        -j NFLOG --nflog-prefix "FW-DROP: " --nflog-group 1

    echo ""
    log "=== Finale iptables Konfiguration ==="
    iptables -nvL FORWARD
    echo ""
    iptables -t nat -nvL
else
    log "FEHLER: Konnte Interfaces oder Apache IP nicht ermitteln."
    log "  APACHE_IP=$APACHE_IP PUBLIC_IF=$PUBLIC_IF DMZ_IF=$DMZ_IF INTERNAL_IF=$INTERNAL_IF"
    log "  Breche ab, um fail-closed zu bleiben und kein generelles Forwarding zu erlauben."

    # Fail-closed: Kein unspezifisches NAT/Forwarding aktivieren
    iptables -P FORWARD DROP
    exit 1
fi

echo ""
log "Router aktiv!"
tail -f /dev/null
