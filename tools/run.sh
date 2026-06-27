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
# Parsed out of the --pacing forwarded arg so we can set the noise container's
# env var BEFORE `docker compose up -d` brings it online. Defaults to fast →
# noise off, matching main.py's DEFAULT_PACING.
PACING=fast
chain_args=()
prev=""
for arg in "$@"; do
    case "$arg" in
        --keep-up) KEEP_UP=1 ;;
        --build)   BUILD=1 ;;
        --pacing=*)
            PACING="${arg#--pacing=}"
            chain_args+=("$arg")
            ;;
        *)
            # Catch `--pacing <value>` (space-separated form): when the
            # previous token was --pacing, this token is its value.
            if [ "$prev" = "--pacing" ]; then PACING="$arg"; fi
            chain_args+=("$arg")
            ;;
    esac
    prev="$arg"
done

# Wire NOISE_ENABLED + ACTIVITY_ENABLED based on --pacing so the noise
# containers AND the per-workstation activity simulators only generate
# baseline traffic in realistic mode. Exported so `docker compose up -d`
# picks both up via the ${VAR:-0} substitutions in docker-compose.yml.
# Same axis intentionally — there's no realistic scenario where you want
# one but not the other.
case "$PACING" in
    realistic) export NOISE_ENABLED=1 ACTIVITY_ENABLED=1 ;;
    fast)      export NOISE_ENABLED=0 ACTIVITY_ENABLED=0 ;;
    *)
        echo "[run.sh] ERROR: unknown --pacing value '${PACING}'. Valid values: fast, realistic" >&2
        exit 1
        ;;
esac

# Snapshot destination for this run's logs.
RUN_DIR="$PWD/logs/run-$(date -u +%Y%m%dT%H%M%SZ)"

# Captured BEFORE `docker compose up -d` so the diurnal rewriter's window
# filter is anchored to actual chain-launch time, not snapshot-collection
# time. Without this, lab-startup chatter (rsyslog daemon starts, kernel
# log noise, container boot lines) would fall inside the rewrite window
# and pollute the SIEM view.
RUN_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# -------------------------------------------------------------------- cleanup hook
# Runs on EXIT regardless of how the script ends. Order matters: snapshot
# BEFORE teardown so the writable layers still exist when docker cp reads.
cleanup() {
    echo ""
    echo "[run.sh] snapshotting container logs → $RUN_DIR"
    mkdir -p "$RUN_DIR"/{apache,router,workstation,luke_ws,vinzenz_ws,db-internal,noise_user_sim,noise_monitor,noise_scanner,noise_mobile,lab_dns,fake_internet}
    # Best-effort: some paths exist only after later slices land (e.g.,
    # lab-fim.log, ulog-iptables.log) — `|| true` keeps the snapshot from
    # aborting if a source path is missing.
    # File-based logs (only present when the container app writes to disk).
    docker cp apache:/usr/local/apache2/logs/.    "$RUN_DIR/apache/"      2>/dev/null || true
    docker cp router:/var/log/.                   "$RUN_DIR/router/"      2>/dev/null || true
    docker cp ubuntu_workstation:/var/log/.       "$RUN_DIR/workstation/" 2>/dev/null || true
    docker cp luke_ws:/var/log/.                  "$RUN_DIR/luke_ws/"     2>/dev/null || true
    docker cp vinzenz_ws:/var/log/.               "$RUN_DIR/vinzenz_ws/"  2>/dev/null || true
    docker cp db-internal:/var/log/postgres/.     "$RUN_DIR/db-internal/" 2>/dev/null || true
    # Stdout/stderr captured by Docker's logging driver — covers apache's
    # default httpd-foreground that pipes access/error to stdout/stderr.
    docker logs apache             >"$RUN_DIR/apache/stdout.log"      2>"$RUN_DIR/apache/stderr.log"      || true
    docker logs router             >"$RUN_DIR/router/stdout.log"      2>"$RUN_DIR/router/stderr.log"      || true
    docker logs ubuntu_workstation >"$RUN_DIR/workstation/stdout.log" 2>"$RUN_DIR/workstation/stderr.log" || true
    docker logs luke_ws            >"$RUN_DIR/luke_ws/stdout.log"     2>"$RUN_DIR/luke_ws/stderr.log"     || true
    docker logs vinzenz_ws         >"$RUN_DIR/vinzenz_ws/stdout.log"  2>"$RUN_DIR/vinzenz_ws/stderr.log"  || true
    docker logs db-internal        >"$RUN_DIR/db-internal/stdout.log" 2>"$RUN_DIR/db-internal/stderr.log" || true
    docker logs noise_user_sim     >"$RUN_DIR/noise_user_sim/stdout.log" 2>"$RUN_DIR/noise_user_sim/stderr.log" || true
    docker logs noise_monitor      >"$RUN_DIR/noise_monitor/stdout.log"  2>"$RUN_DIR/noise_monitor/stderr.log"  || true
    docker logs noise_scanner      >"$RUN_DIR/noise_scanner/stdout.log"  2>"$RUN_DIR/noise_scanner/stderr.log"  || true
    docker logs noise_mobile       >"$RUN_DIR/noise_mobile/stdout.log"   2>"$RUN_DIR/noise_mobile/stderr.log"   || true
    # lab_dns — the dnsmasq query log lives in stdout; that's the central
    # SIEM source for unfamiliar-domain detection (every workstation DNS
    # query is logged with src IP + queried name).
    docker logs lab_dns            >"$RUN_DIR/lab_dns/stdout.log"        2>"$RUN_DIR/lab_dns/stderr.log"        || true
    # fake_internet — nginx access logs are bind-mounted, but capture
    # stdout/stderr too in case nginx logs anything to those streams.
    docker cp fake_internet:/var/log/nginx/.        "$RUN_DIR/fake_internet/"  2>/dev/null || true
    docker logs fake_internet      >"$RUN_DIR/fake_internet/stdout.log" 2>"$RUN_DIR/fake_internet/stderr.log" || true
    docker logs kali               >"$RUN_DIR/kali.stdout.log"        2>"$RUN_DIR/kali.stderr.log"        || true

    # -------------------------------------------------------------------- diurnal stretch
    # Only in realistic pacing: rewrite each log file's timestamps so the
    # SIEM view spans a synthetic 8-hour workday (anchored at 09:00 UTC
    # today) instead of the ~30 min wall-clock the run actually took.
    # Preserves relative ordering and inter-event ratios. Originals are
    # untouched — companion ``*.diurnal.log`` files appear alongside them
    # and a ``diurnal_manifest.json`` records the stretch parameters.
    if [ "$PACING" = "realistic" ]; then
        RUN_END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "[run.sh] applying diurnal stretch to $RUN_DIR (anchor=today 09:00Z, window=8h)"
        python3 "$(cd .. && pwd)/Attack-chain/diurnal_rewriter.py" \
            --snapshot-dir "$RUN_DIR" \
            --run-start    "$RUN_START_ISO" \
            --run-end      "$RUN_END_ISO" \
            --window-hours 8 \
            || echo "[run.sh] WARN: diurnal rewriter failed (originals untouched)"
    fi

    if [ "$KEEP_UP" -eq 0 ]; then
        echo "[run.sh] tearing down lab (removes veth* and br-* interfaces)"
        docker compose down
    else
        echo "[run.sh] --keep-up: lab still running. Tear down later with: cd Infrastructure/ && docker compose down"
        echo ""
        echo "[run.sh] analyst entry points (lab is up — verify findings live):"
        echo "  Web app          curl http://localhost:80/"
        echo "  John's VNC       vncviewer localhost:5901   (no password — lab)"
        echo "  Apache shell     docker compose exec apache bash"
        echo "  John WS shell    docker compose exec ubuntu_workstation bash"
        echo "  Luke WS shell    docker compose exec luke_ws bash"
        echo "  Vinzenz WS shell docker compose exec vinzenz_ws bash"
        echo "  DB shell         docker compose exec db-internal psql -U waystar"
        echo "                   (password: WaystarDB!Secure2024)"
        echo "  Router shell     docker compose exec router sh"
        echo "  Kali shell       docker compose exec kali bash"
        echo ""
        echo "[run.sh] analyst-facing docs:"
        echo "  Briefing         $(cd .. && pwd)/Documentation/analyst_briefing.md"
        echo "  Findings form    $(cd .. && pwd)/Documentation/analyst_findings_template.yaml"
        echo "  Scenario story   $(cd .. && pwd)/Documentation/scenario_story.md"
    fi

    # Snapshot rotation — keep the most recent 5 run-* directories, prune
    # older ones. Real-prod log pipelines age/rotate; this is the lab
    # equivalent. Some files inside the snapshot are root-owned (docker cp
    # preserves uid/gid), so use a throwaway container with the dir mounted
    # to do the deletion without needing host sudo.
    KEEP=5
    old_dirs=$(ls -1dt "$PWD/logs"/run-* 2>/dev/null | tail -n +$((KEEP + 1)))
    if [ -n "$old_dirs" ]; then
        count=$(echo "$old_dirs" | wc -l)
        echo "[run.sh] pruning $count old snapshot(s) (keeping last $KEEP)"
        docker run --rm -v "$PWD/logs:/L" ubuntu:22.04 sh -c \
            "cd /L && rm -rf $(echo "$old_dirs" | xargs -n1 basename | tr '\n' ' ')" \
            2>/dev/null || true
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

# Wait for the lab to be fully wired before starting the chain. On a cold
# `compose up -d` the router still needs to: resolve apache via DNS, configure
# iptables (DNAT + FORWARD + NFLOG), start ulogd2; apache needs to add its
# cross-zone routes; kali's embedded-DNS cache needs to populate. A flat
# `sleep 3` is not enough on a cold start, so probe end-to-end reachability
# instead. The probe succeeds once kali → router DNS resolves AND HTTP
# returns a response (any status), which means the DNAT path is live.
echo "[run.sh] waiting for lab readiness (kali → http://router/ via DNAT)..."
ready=0
for i in $(seq 1 60); do
    # Probe components in order: (1) kali can resolve `router` via Docker's
    # embedded DNS, (2) kali can complete a TCP+HTTP exchange with router's
    # DNAT to apache. We accept any real HTTP status (200-599); a curl exit
    # 0 means the connection succeeded and an HTTP response was returned.
    if docker compose exec -T kali sh -c \
        'getent hosts router >/dev/null && \
         curl -s --max-time 2 -o /dev/null -w "%{http_code}" http://router/ 2>/dev/null \
            | grep -qE "^[1-5][0-9][0-9]$"' \
        ; then
        echo "[run.sh] lab ready after ${i}s"
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "[run.sh] ERROR: lab did not become reachable within 60s." >&2
    echo "[run.sh]        Likely causes:" >&2
    echo "[run.sh]          - container images are stale; rerun with 'tools/run.sh --build'" >&2
    echo "[run.sh]          - one of router/apache is crash-looping" >&2
    echo "[run.sh]        Check 'docker compose logs router apache kali' before retrying." >&2
    exit 1
fi

if ! docker compose exec -T kali python3 /Attack-chain/main.py "${chain_args[@]}"; then
    ec=$?
    echo "" >&2
    echo "[run.sh] ERROR: main.py exited $ec — scenario did not complete." >&2
    [ ${#chain_args[@]} -gt 0 ] && \
        echo "[run.sh]        args forwarded to main.py: ${chain_args[*]}" >&2
    exit $ec
fi
