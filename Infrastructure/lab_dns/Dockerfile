# ============================================================================
#  lab_dns — workstation DNS resolver (dnsmasq) for the Waystar lab.
# ----------------------------------------------------------------------------
#  Replaces Docker's embedded DNS for the three internal workstations
#  (ubuntu_workstation, luke_ws, vinzenz_ws) so their lookups for
#  "archive.ubuntu.com" / "github.com" / "registry.npmjs.org" / etc.
#  resolve to fake_internet (10.10.0.11) instead of failing or hitting
#  the real internet.
#
#  Equally important — dnsmasq logs EVERY query it serves (`log-queries`).
#  Those logs are the new SIEM source for detecting attacker C2: the
#  attacker either has to use a domain that's NOT on our baseline list
#  (visible as an "unfamiliar domain" alert) or skip DNS entirely and
#  use a raw IP (visible as DNS-bypass behaviour at the router NFLOG).
#
#  Hostfile (dnsmasq.hosts) is the canonical "what resolves to what"
#  list. Workstations and other containers reachable by hostname
#  (apache, db-internal, kali, router, the fake_internet domains)
#  all live there.
#
#  LAB ONLY.
# ============================================================================
FROM alpine:3.20

RUN apk add --no-cache dnsmasq iproute2

COPY dnsmasq.conf  /etc/dnsmasq.conf
COPY dnsmasq.hosts /etc/dnsmasq.hosts
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/entrypoint.sh"]
