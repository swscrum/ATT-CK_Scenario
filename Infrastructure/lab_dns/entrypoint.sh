#!/bin/sh
# lab_dns entrypoint.
#
# dnsmasq doesn't need any pre-startup setup beyond what's already in
# dnsmasq.conf, but we wrap it so we can run startup banners and add
# an explicit log line before handing off — useful for `docker logs`.
set -e

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [lab_dns] starting dnsmasq (resolver for workstations)"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [lab_dns] entries in /etc/dnsmasq.hosts:"
grep -vE '^\s*(#|$)' /etc/dnsmasq.hosts | head -20

exec dnsmasq --conf-file=/etc/dnsmasq.conf
