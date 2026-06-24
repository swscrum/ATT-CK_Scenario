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
    echo "[lab-ca] already exists:"
    echo "  $CA_CRT"
    echo "  $CA_KEY"
    echo "[lab-ca] delete both files to regenerate."
    exit 0
fi

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
echo ""
echo "[lab-ca] Subject:    $(openssl x509 -in "$CA_CRT" -noout -subject)"
echo "[lab-ca] Valid:      $(openssl x509 -in "$CA_CRT" -noout -dates | tr '\n' ' ')"
echo ""
echo "[lab-ca] Commit lab-ca.crt; lab-ca.key is gitignored (see .gitignore)."
