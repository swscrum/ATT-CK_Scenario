# ============================================================================
#  noise_user_sim — simulates ambient internet/legit user traffic to apache.
# ----------------------------------------------------------------------------
#  Lives on public_net (10.10.0.5), separate from kali (10.10.0.2), so the
#  source IP of noise traffic is different from the attacker's. Without this
#  separation a SOC trainee could trivially filter the attacker via
#  ``src_ip != 10.10.0.2`` and detection becomes a non-exercise.
#
#  Reaches apache (10.40.0.2, dmz_net) via the router's DNAT on :80 — the
#  same path real external users use. Static route to 10.40.0.0/24 added at
#  startup so packets to apache go through the router instead of being
#  black-holed by Docker's public_net bridge.
#
#  LAB ONLY.
# ============================================================================
FROM python:3.12-alpine

# iproute2 for `ip route add` at startup (we model an internet host whose
# default gw points at our router). ca-certificates so urllib has a trust
# store even though we only do HTTP today — costs almost nothing and makes
# the image future-proof for HTTPS noise.
RUN apk add --no-cache iproute2 ca-certificates

COPY noise.py /usr/local/bin/noise.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/noise.py /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
