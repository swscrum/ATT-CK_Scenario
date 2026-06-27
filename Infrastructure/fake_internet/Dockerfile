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

# Cert pre-generated on the host by tools/generate-lab-ca.sh (or manually with openssl).
# The lab CA cert is committed; server.key is gitignored (private key).
# Regenerate with: cd Infrastructure/fake_internet/ssl && openssl req -new -newkey rsa:2048
#   -nodes -keyout server.key -out server.csr -subj '/C=US/O=Waystar Royco/CN=lab-internet'
#   && openssl x509 -req -in server.csr -CA ../../shared-lab-keys/lab-ca.crt
#   -CAkey ../../shared-lab-keys/lab-ca.key -CAcreateserial -days 730
#   -extfile <(printf 'subjectAltName=DNS:github.com,...') -out server.crt
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
