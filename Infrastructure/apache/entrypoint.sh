#!/bin/bash

# Timestamped console logging (UTC ISO-8601, matches the attack-chain output).
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# ================================
#  Cross-zone routing setup
# ================================
# Apache lives on dmz_net (10.40.0.0/24). The router has a leg on the same
# subnet at 10.40.0.4 and is the only path out of the DMZ:
#   - 10.10.0.0/24 (External) — Phase 2/3 reverse-shell callbacks to kali
#   - 10.30.0.0/24 (Internal) — Phase 4 lateral SSH to john.stravidis@workstation
# Both routes go via the router's DMZ-side IP.
DEFAULT_ROUTER_IP="10.40.0.4"
ROUTER_IP="${ROUTER_IP:-$DEFAULT_ROUTER_IP}"
RESOLVED_ROUTER_IP=""
RETRIES=10

if [ "$ROUTER_IP" = "$DEFAULT_ROUTER_IP" ]; then
    for i in $(seq 1 $RETRIES); do
        # dig returns all three router IPs (public/dmz/internal); we want
        # the one on our own subnet so packets actually have a next hop.
        RESOLVED_ROUTER_IP=$(dig +short router | grep '^10\.40\.' | head -n 1)
        if [ -n "$RESOLVED_ROUTER_IP" ]; then
            ROUTER_IP="$RESOLVED_ROUTER_IP"
            break
        fi
        log "Waiting for DNS resolution of 'router' (attempt $i/$RETRIES)..."
        sleep 2
    done
fi

if [ -n "$ROUTER_IP" ]; then
    if [ -n "$RESOLVED_ROUTER_IP" ]; then
        log "Adding cross-zone routes via router ($ROUTER_IP)..."
    else
        log "DNS resolution for 'router' failed, falling back to default router IP ($ROUTER_IP)..."
    fi
    ip route add 10.10.0.0/24 via "$ROUTER_IP" || true   # External (kali)
    ip route add 10.30.0.0/24 via "$ROUTER_IP" || true   # Internal (workstations)
else
    log "ERROR: could not determine router IP; reverse-shell and lateral routing may fail."
fi

# ================================
#  Hand off to the original CMD
# ================================
log "Handing off to the original start script: $@"
exec "$@"
