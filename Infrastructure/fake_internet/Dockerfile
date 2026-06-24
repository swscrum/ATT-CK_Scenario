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

RUN apk add --no-cache openssl ca-certificates

# Workstation cert chain anchors: copy the lab CA + use it to sign the
# multi-SAN server cert. The lab CA cert is committed (public); the key
# only lives on the dev host (see tools/generate-lab-ca.sh) and is mounted
# into the build at build time via a build-arg-driven COPY.
#
# Build context is Infrastructure/ so we can reach into shared-lab-keys.
COPY shared-lab-keys/lab-ca.crt /etc/nginx/ssl/lab-ca.crt
COPY shared-lab-keys/lab-ca.key /etc/nginx/ssl/lab-ca.key

RUN mkdir -p /etc/nginx/ssl /var/log/nginx /usr/share/nginx/html/fixtures \
    && cd /etc/nginx/ssl \
    && openssl req -new -newkey rsa:2048 -nodes \
        -keyout server.key \
        -out    server.csr \
        -subj '/C=US/O=Waystar Royco/CN=lab-internet' \
    && SAN='subjectAltName=DNS:archive.ubuntu.com,DNS:security.ubuntu.com,DNS:registry.npmjs.org,DNS:github.com,DNS:api.github.com,DNS:raw.githubusercontent.com,DNS:slack.com,DNS:api.slack.com,DNS:time.cloudflare.com,DNS:connectivity-check.ubuntu.com' \
    && printf "%s\n" "$SAN" > san.ext \
    && openssl x509 -req -in server.csr \
        -CA lab-ca.crt -CAkey lab-ca.key -CAcreateserial \
        -days 730 -extfile san.ext \
        -out server.crt \
    && chmod 600 server.key lab-ca.key \
    && chmod 644 server.crt lab-ca.crt \
    && rm -f server.csr san.ext lab-ca.key
    # Delete the CA key right after signing — fake_internet never needs it
    # again, and we don't want it sitting inside an image.

COPY fake_internet/nginx.conf      /etc/nginx/nginx.conf
COPY fake_internet/fixtures/       /usr/share/nginx/html/fixtures/

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
