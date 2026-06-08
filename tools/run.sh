#!/usr/bin/env bash
# Operator wrapper for the automated attack scenario.
#
# Each invocation:
#   1. Brings the lab up if not already running (idempotent — `compose up -d`
#      no-ops if everything matches the spec).
#   2. Runs the chain inside the kali container (any extra args are
#      forwarded to main.py).
#   3. On exit (success, failure, or Ctrl-C), snapshots each container's
#      log directory into Infrastructure/logs/run-<ISO8601>Z/<container>/
#      so a SIEM / SOC analyst can ingest them after the run.
#   4. Tears the lab down with `docker compose down`, which removes the
#      veth* pairs and the br-<hash> compose bridges from the host's
#      `ip a` output. Only `docker0` survives (daemon-level).
#
# Logs preserved on host after teardown:
#   Infrastructure/logs/run-<ts>/apache/{access.log,error.log,...}
#   Infrastructure/logs/run-<ts>/router/{kern.log,...}
#   Infrastructure/logs/run-<ts>/workstation/{auth.log,syslog,...}
#   Attack-chain/results/                       (already bind-mounted via kali)
#
# Pre-req: images built once via `docker compose build` (or first run after
# a Dockerfile change). The default `up -d` does NOT pass `--build`, to keep
# startup fast. Pass --build whenever a Dockerfile or a seeded file changed
# (e.g. after pulling new breadcrumbs) — otherwise a stale image silently
# reuses the old contents and the chain can fail on missing seed data.
#
# Usage:
#   tools/run.sh                    # full chain, snapshot + teardown after
#   tools/run.sh --only recon       # forwarded to main.py
#   tools/run.sh --build            # rebuild images first, then run (use
#                                   # after a Dockerfile / seed change)
#   tools/run.sh --keep-up          # skip teardown so the lab stays running
#                                   # for follow-up exploration; tear down
#                                   # later with `docker compose down`
set -euo pipefail
cd "$(dirname "$0")/../Infrastructure"

# -------------------------------------------------------------------- args
KEEP_UP=0
BUILD=0
chain_args=()
for arg in "$@"; do
    case "$arg" in
        --keep-up) KEEP_UP=1 ;;
        --build)   BUILD=1 ;;
        *)         chain_args+=("$arg") ;;
    esac
done

# Snapshot destination for this run's logs.
RUN_DIR="$PWD/logs/run-$(date -u +%Y%m%dT%H%M%SZ)"

# -------------------------------------------------------------------- cleanup hook
# Runs on EXIT regardless of how the script ends. Order matters: snapshot
# BEFORE teardown so the writable layers still exist when docker cp reads.
cleanup() {
    echo ""
    echo "[run.sh] snapshotting container logs → $RUN_DIR"
    mkdir -p "$RUN_DIR/apache" "$RUN_DIR/router" "$RUN_DIR/workstation"
    # Best-effort: some paths exist only after later slices land (e.g.,
    # lab-fim.log, ulog-iptables.log) — `|| true` keeps the snapshot from
    # aborting if a source path is missing.
    # File-based logs (only present when the container app writes to disk).
    docker cp apache:/usr/local/apache2/logs/. "$RUN_DIR/apache/"      2>/dev/null || true
    docker cp router:/var/log/.                "$RUN_DIR/router/"      2>/dev/null || true
    docker cp ubuntu_workstation:/var/log/.    "$RUN_DIR/workstation/" 2>/dev/null || true
    # Stdout/stderr captured by Docker's logging driver — covers apache's
    # default httpd-foreground that pipes access/error to stdout/stderr.
    docker logs apache             >"$RUN_DIR/apache/stdout.log"      2>"$RUN_DIR/apache/stderr.log"      || true
    docker logs router             >"$RUN_DIR/router/stdout.log"      2>"$RUN_DIR/router/stderr.log"      || true
    docker logs ubuntu_workstation >"$RUN_DIR/workstation/stdout.log" 2>"$RUN_DIR/workstation/stderr.log" || true
    docker logs kali               >"$RUN_DIR/kali.stdout.log"        2>"$RUN_DIR/kali.stderr.log"        || true

    if [ "$KEEP_UP" -eq 0 ]; then
        echo "[run.sh] tearing down lab (removes veth* and br-* interfaces)"
        docker compose down
    else
        echo "[run.sh] --keep-up: lab still running. Tear down later with: docker compose down"
    fi

    echo "[run.sh] inspect:"
    echo "  $RUN_DIR/"
    echo "  $(cd .. && pwd)/Attack-chain/results/"
}
trap cleanup EXIT

# -------------------------------------------------------------------- run
echo "[run.sh] ensuring lab is up..."
if [ "$BUILD" -eq 1 ]; then
    echo "[run.sh] --build: rebuilding changed images (layer cache keeps this cheap)"
    docker compose up -d --build >/dev/null
else
    docker compose up -d >/dev/null
fi
sleep 3

docker compose exec -T kali python3 /Attack-chain/main.py "${chain_args[@]}"
