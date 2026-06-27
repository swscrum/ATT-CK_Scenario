#!/bin/sh
# noise_user_sim entrypoint.
#
# Apache lives in dmz_net (10.40.0.2). This container lives in public_net
# (10.10.0.5). Without a static route to 10.40.0.0/24 via the router, packets
# would go out Docker's public_net bridge gateway (10.10.0.1) which doesn't
# know about the DMZ subnet → silent black-hole.
#
# We hit apache by its hostname via the router's :80 DNAT instead, so the
# route is not strictly needed for the default --target=router, BUT we add
# it anyway so a future --target=10.40.0.2 (direct-to-apache) would still
# work without code changes.
set -e

command -v ip >/dev/null 2>&1 && ip route add 10.40.0.0/24 via 10.10.0.3 2>/dev/null || true

# Pass through to noise.py — it reads its config from env vars
# (NOISE_ENABLED, NOISE_TARGET, NOISE_THREADS, NOISE_PROBE_PCT).
exec python3 -u /usr/local/bin/noise.py
