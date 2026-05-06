#!/usr/bin/env bash
# Operator wrapper for the automated attack scenario.
#
# Runs the chain inside the kali container, then recreates apache so its
# in-container state (notably /opt/cleanup.sh) returns to the image baseline.
# `restart` is not enough — it stop+starts the same container with the same
# writable layer, so privesc's overwrite of /opt/cleanup.sh persists. We need
# --force-recreate to actually replace the container from the image.
# The recreate is in a trap so the lab is left clean even if main.py crashes.
#
# Pre-req: lab already up via `docker compose up -d --build`. See README.
#
# Usage:
#   tools/run.sh                    # full chain
#   tools/run.sh --only recon       # forward args to main.py
#   tools/run.sh --target webserver
set -euo pipefail

cd "$(dirname "$0")/../Infrastructure"

trap 'docker compose up -d --force-recreate --no-deps apache' EXIT

docker compose exec kali python3 /Attack-chain/main.py "$@"
