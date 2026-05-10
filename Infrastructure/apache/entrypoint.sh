#!/bin/bash

# ================================
#  Reverse-routing setup
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
        echo "Waiting for DNS resolution of 'router' (attempt $i/$RETRIES)..."
        sleep 2
    done
fi

if [ -n "$ROUTER_IP" ]; then
    if [ -n "$RESOLVED_ROUTER_IP" ]; then
        echo "Adding route to public_net (10.10.0.0/24) via router ($ROUTER_IP)..."
    else
        echo "DNS resolution for 'router' failed, falling back to default router IP ($ROUTER_IP)..."
    fi
    ip route add 10.10.0.0/24 via "$ROUTER_IP" || true
else
    echo "ERROR: could not determine router IP; reverse-shell routing may fail."
fi

# ================================
#  Hand off to the original CMD
# ================================
echo "Handing off to the original start script: $@"
exec "$@"
