#!/usr/bin/env bash
# Generate the Waystar lab internal CA.
#
# Used by:
#   - fake_internet container (signs its multi-SAN server cert with this CA)
#   - all three workstation containers (trust this CA so `curl https://github.com`
#     against fake_internet succeeds without -k)
#
# Output:
#   Infrastructure/shared-lab-keys/lab-ca.crt   (public, committed)
#   Infrastructure/shared-lab-keys/lab-ca.key   (private, gitignored)
#
# Run this ONCE during initial setup OR whenever you want to rotate the CA.
# The key never leaves the dev host; only the .crt is shipped into images.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_DIR="Infrastructure/shared-lab-keys"
CA_KEY="$OUT_DIR/lab-ca.key"
CA_CRT="$OUT_DIR/lab-ca.crt"

mkdir -p "$OUT_DIR"

if [ -f "$CA_KEY" ] && [ -f "$CA_CRT" ]; then
    echo "[lab-ca] already exists — skipping CA generation."
    echo "  $CA_CRT"
    echo "  $CA_KEY"
    echo "[lab-ca] delete both files to rotate the CA."
else
    echo "[lab-ca] generating fresh CA (RSA 2048, 10 year validity)..."
    openssl req -x509 -nodes -newkey rsa:2048 \
        -days 3650 \
        -keyout "$CA_KEY" \
        -out    "$CA_CRT" \
        -subj '/C=US/O=Waystar Royco/CN=Waystar Lab Internal CA' \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>&1 | grep -vE '^---|^\.\.\.|^Generating' || true

    chmod 600 "$CA_KEY"
    chmod 644 "$CA_CRT"

    echo "[lab-ca] generated:"
    ls -la "$OUT_DIR"/lab-ca.*
    echo "[lab-ca] Subject:    $(openssl x509 -in "$CA_CRT" -noout -subject)"
    echo "[lab-ca] Valid:      $(openssl x509 -in "$CA_CRT" -noout -dates | tr '\n' ' ')"
    echo "[lab-ca] Commit lab-ca.crt; lab-ca.key is gitignored (see .gitignore)."
fi

# ---------------------------------------------------------------------------
# fake_internet server cert — multi-SAN TLS cert for the nginx "internet"
# simulation, signed by the lab CA above. Both files are gitignored and
# (re)generated here when missing, so a fresh clone builds without anyone
# running openssl by hand. The SAN list must cover every domain dnsmasq
# points at fake_internet (keep in sync with lab_dns / nginx.conf).
# ---------------------------------------------------------------------------
SSL_DIR="Infrastructure/fake_internet/ssl"
SRV_KEY="$SSL_DIR/server.key"
SRV_CRT="$SSL_DIR/server.crt"
SRV_SAN="subjectAltName=DNS:archive.ubuntu.com,DNS:security.ubuntu.com,DNS:registry.npmjs.org,DNS:github.com,DNS:api.github.com,DNS:raw.githubusercontent.com,DNS:slack.com,DNS:api.slack.com,DNS:time.cloudflare.com,DNS:connectivity-check.ubuntu.com"

mkdir -p "$SSL_DIR"

if [ -f "$SRV_KEY" ] && [ -f "$SRV_CRT" ]; then
    echo "[fake_internet] server cert already exists — skipping."
    echo "[fake_internet] delete $SSL_DIR/server.{key,crt} to regenerate."
else
    echo "[fake_internet] generating multi-SAN server cert (signed by lab CA)..."
    SRV_CSR="$(mktemp)"
    trap 'rm -f "$SRV_CSR"' EXIT
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$SRV_KEY" -out "$SRV_CSR" \
        -subj '/C=US/O=Waystar Royco/CN=lab-internet' 2>/dev/null
    openssl x509 -req -in "$SRV_CSR" \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -days 730 \
        -extfile <(printf '%s\n' "$SRV_SAN") \
        -out "$SRV_CRT" 2>/dev/null
    rm -f "$SRV_CSR"; trap - EXIT

    chmod 600 "$SRV_KEY"
    chmod 644 "$SRV_CRT"

    echo "[fake_internet] generated:"
    ls -la "$SRV_KEY" "$SRV_CRT"
    echo "[fake_internet] Issuer: $(openssl x509 -in "$SRV_CRT" -noout -issuer)"
    echo "[fake_internet] SAN:    $(openssl x509 -in "$SRV_CRT" -noout -ext subjectAltName | tail -n1 | sed 's/^[[:space:]]*//')"
    echo "[fake_internet] both files are gitignored (see .gitignore)."
fi
