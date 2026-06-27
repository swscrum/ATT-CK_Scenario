# ============================================================================
#  fake_internet — single-IP simulation of "the internet" for workstation
#                  outbound traffic.
# ----------------------------------------------------------------------------
#  All the public-looking domains dnsmasq points here (github.com,
#  archive.ubuntu.com, registry.npmjs.org, slack.com, …) terminate at
#  this nginx instance. nginx routes by `Host:` header to return a
#  realistic-shaped response per "domain":
#    - apt mirrors return /InRelease + /Packages metadata
#    - github API returns JSON
#    - npm registry returns package JSON
#    - slack returns {"ok":true}
#    - connectivity-check returns 204 Not-Authorized (NetworkManager's
#      expected payload)
#
#  Cert: server.crt is signed by the lab CA (shared-lab-keys/lab-ca.crt)
#  at build time, with a SAN covering every domain dnsmasq.hosts points
#  here. Workstations trust the lab CA, so `curl https://github.com`
#  succeeds without -k.
#
#  Logs: nginx writes access.log + error.log to /var/log/nginx, bind-
#  mounted to ./logs/fake_internet on the host. Captures Host header,
#  path, status, client IP per request — second-richest log source in
#  the lab after apache.
#
#  LAB ONLY.
# ============================================================================
FROM nginx:alpine

# server.key + server.crt are generated on the host by tools/generate-lab-ca.sh,
# which tools/run.sh invokes before every build — so a fresh clone builds with
# no manual step. Both are gitignored (the cert is re-derivable from the
# committed lab CA, so it isn't tracked). The lab CA .crt is committed.
# To regenerate by hand: delete Infrastructure/fake_internet/ssl/server.{key,crt}
# and rerun tools/generate-lab-ca.sh.
COPY shared-lab-keys/lab-ca.crt      /etc/nginx/ssl/lab-ca.crt
COPY fake_internet/ssl/server.crt    /etc/nginx/ssl/server.crt
COPY fake_internet/ssl/server.key    /etc/nginx/ssl/server.key

RUN mkdir -p /var/log/nginx /usr/share/nginx/html/fixtures \
    && chmod 600 /etc/nginx/ssl/server.key \
    && chmod 644 /etc/nginx/ssl/server.crt /etc/nginx/ssl/lab-ca.crt

COPY fake_internet/nginx.conf      /etc/nginx/nginx.conf
COPY fake_internet/fixtures/       /usr/share/nginx/html/fixtures/

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
