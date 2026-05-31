#!/usr/bin/env bash
# Replay / cohort-distribution helper.
#
# Takes ONE existing snapshot (Infrastructure/logs/run-<ts>/) and a cohort
# anchor date, and produces a self-contained tarball ready to ship to
# multiple analysts:
#
#   1. Re-runs Attack-chain/diurnal_rewriter.py with the requested anchor
#      so the SIEM dashboard for cohort A reads as "today 09:00 → 17:00"
#      even though the underlying capture is months old. Originals
#      untouched; new *.diurnal.log siblings overwrite the previous ones.
#
#   2. Sanitizes the ground-truth JSON — drops per-step `tactic`,
#      `techniques`, `started`, `ended` so the cohort kit doesn't ship
#      the answer key. The full chain-*.json is COPIED ASIDE as
#      `chain-*.answer-key.json` next to the snapshot for the instructor
#      to keep.
#
#   3. Bundles into Infrastructure/logs/cohort-kits/<cohort_id>-<run_ts>.tar.gz
#      containing:
#         <run_ts>/
#           <containers>/*.diurnal.log         ← what the SIEM ingests
#           diurnal_manifest.json              ← stretch params
#           chain-<run_ts>.public.json         ← sanitized ground truth
#         Documentation/analyst_briefing.md    (copied in)
#         Documentation/analyst_findings_template.yaml
#         Documentation/scenario_story.md
#
# Usage:
#   tools/replay.sh --snapshot run-20260518T141116Z --anchor 2026-06-03T09:00:00Z --cohort cohort-A
#   tools/replay.sh --snapshot Infrastructure/logs/run-20260531T131346Z --anchor today
#
# Flags:
#   --snapshot <name|path>   the snapshot dir (basename under
#                            Infrastructure/logs/ OR absolute path)
#   --anchor   <iso|today>   SIEM-clock 09:00 anchor; `today` = today 09:00Z
#   --window-hours <n>       synthetic window length (default: 8)
#   --cohort   <id>          short label for the output tarball; default
#                            uses the host's user@hostname
#
# Required: python3 on PATH, tar.
set -euo pipefail
cd "$(dirname "$0")/.."

# ---------------------------------------------------------------- args
SNAPSHOT=""
ANCHOR="today"
WINDOW_HOURS=8
COHORT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --snapshot)     SNAPSHOT="$2"; shift 2 ;;
        --anchor)       ANCHOR="$2"; shift 2 ;;
        --window-hours) WINDOW_HOURS="$2"; shift 2 ;;
        --cohort)       COHORT="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//' | sed '$d'
            exit 0
            ;;
        *) echo "replay.sh: unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -n "$SNAPSHOT" ] || { echo "replay.sh: --snapshot is required" >&2; exit 2; }

# Resolve snapshot path — accept basename, relative path, or absolute path.
if [ -d "$SNAPSHOT" ]; then
    SNAP_DIR="$(cd "$SNAPSHOT" && pwd)"
elif [ -d "Infrastructure/logs/$SNAPSHOT" ]; then
    SNAP_DIR="$(cd "Infrastructure/logs/$SNAPSHOT" && pwd)"
else
    echo "replay.sh: no such snapshot: $SNAPSHOT" >&2
    echo "replay.sh: tried './$SNAPSHOT' and 'Infrastructure/logs/$SNAPSHOT'" >&2
    exit 1
fi

RUN_TS="$(basename "$SNAP_DIR" | sed 's/^run-//')"

# Resolve anchor — accept ISO 8601 directly or "today" shortcut.
if [ "$ANCHOR" = "today" ]; then
    ANCHOR_ISO="$(date -u +%Y-%m-%d)T09:00:00Z"
else
    ANCHOR_ISO="$ANCHOR"
fi

# Resolve cohort id.
if [ -z "$COHORT" ]; then
    COHORT="$(id -un)-$(hostname -s)"
fi

KIT_DIR="Infrastructure/logs/cohort-kits"
mkdir -p "$KIT_DIR"
KIT_TARBALL="$KIT_DIR/${COHORT}-${RUN_TS}.tar.gz"

echo "[replay.sh] snapshot : $SNAP_DIR"
echo "[replay.sh] run_ts   : $RUN_TS"
echo "[replay.sh] anchor   : $ANCHOR_ISO"
echo "[replay.sh] window   : ${WINDOW_HOURS}h"
echo "[replay.sh] cohort   : $COHORT"
echo "[replay.sh] tarball  : $KIT_TARBALL"

# ---------------------------------------------------------------- step 1: locate ground truth
# The ground-truth JSON for this run lives in Attack-chain/results/run-<ts>/
# (next to the snapshot, NOT inside it). Snapshot timestamps come from
# run.sh's start (pre `compose up -d`); results timestamps come from
# main.py starting inside kali — those clocks drift by 3–10 seconds.
# Pick the results dir whose ISO timestamp is CLOSEST to the snapshot's.
GROUND_TRUTH=""
RESULTS_DIR=""
if compgen -G "Attack-chain/results/run-*" > /dev/null; then
    RESULTS_DIR="$(python3 - <<PYEOF
import pathlib, re
snap_ts = "$RUN_TS"
def to_secs(ts):
    m = re.match(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z", ts)
    if not m: return 10**12
    y,mo,d,h,mi,se = (int(x) for x in m.groups())
    return ((y*12+mo)*31+d)*86400 + h*3600 + mi*60 + se
snap = to_secs(snap_ts)
best, best_diff = None, 10**12
for p in pathlib.Path("Attack-chain/results").glob("run-*"):
    ts = p.name.replace("run-", "")
    diff = abs(to_secs(ts) - snap)
    if diff < best_diff:
        best_diff, best = diff, p
if best and best_diff <= 60:
    print(best)
PYEOF
)"
fi
if [ -n "$RESULTS_DIR" ] && [ -d "$RESULTS_DIR" ]; then
    GROUND_TRUTH="$(ls -1 "$RESULTS_DIR"/chain-*.json 2>/dev/null | grep -v '\.public\.json' | grep -v '\.answer-key\.json' | head -1)"
    echo "[replay.sh] matched results dir (±$(( $(python3 -c "import os;print(int(abs(os.path.getmtime('$RESULTS_DIR')-os.path.getmtime('$SNAP_DIR'))))") ))s): $RESULTS_DIR"
fi

# ---------------------------------------------------------------- step 2: derive run window
# Try in order: manifest from a prior diurnal pass; first/last step from
# ground truth; min/max file mtimes inside the snapshot.
MANIFEST="$SNAP_DIR/diurnal_manifest.json"
if [ -f "$MANIFEST" ]; then
    RUN_START="$(python3 -c "import json;print(json.load(open('$MANIFEST'))['run_start'])")"
    RUN_END="$(python3   -c "import json;print(json.load(open('$MANIFEST'))['run_end'])")"
    echo "[replay.sh] reusing window from manifest: $RUN_START → $RUN_END"
elif [ -n "$GROUND_TRUTH" ] && [ -f "$GROUND_TRUTH" ]; then
    RUN_START="$(python3 -c "import json;s=json.load(open('$GROUND_TRUTH'))['steps'];print(s[0]['started'])")"
    RUN_END="$(python3   -c "import json;s=json.load(open('$GROUND_TRUTH'))['steps'];print(s[-1]['ended'])")"
    echo "[replay.sh] derived window from ground truth: $RUN_START → $RUN_END"
else
    echo "[replay.sh] no manifest or ground truth — using snapshot file mtime range"
    RUN_START="$(find "$SNAP_DIR" -type f -printf '%T@\n' | sort -n | head -1 | xargs -I{} date -u -d @{} +%Y-%m-%dT%H:%M:%SZ)"
    RUN_END="$(  find "$SNAP_DIR" -type f -printf '%T@\n' | sort -n | tail -1 | xargs -I{} date -u -d @{} +%Y-%m-%dT%H:%M:%SZ)"
fi

# ---------------------------------------------------------------- step 3: re-stretch
python3 Attack-chain/diurnal_rewriter.py \
    --snapshot-dir "$SNAP_DIR" \
    --run-start    "$RUN_START" \
    --run-end      "$RUN_END" \
    --anchor       "$ANCHOR_ISO" \
    --window-hours "$WINDOW_HOURS"

# ---------------------------------------------------------------- step 4: sanitize ground truth
if [ -n "$GROUND_TRUTH" ] && [ -f "$GROUND_TRUTH" ]; then
    # Stash the answer key in a joe-owned sibling dir, NOT next to the
    # root-owned chain-*.json (which docker exec wrote as root and the
    # operator can't cp into without sudo). Name it by snapshot timestamp
    # so the instructor can find it later by run.
    ANSWER_KEY_DIR="Infrastructure/logs/answer-keys"
    mkdir -p "$ANSWER_KEY_DIR"
    ANSWER_KEY="$ANSWER_KEY_DIR/chain-${RUN_TS}.answer-key.json"
    PUBLIC_JSON="$SNAP_DIR/chain-${RUN_TS}.public.json"
    cp "$GROUND_TRUTH" "$ANSWER_KEY" 2>/dev/null \
        || { echo "[replay.sh] WARN: could not stash answer key (perms?)"; ANSWER_KEY=""; }
    [ -n "$ANSWER_KEY" ] && echo "[replay.sh] answer key reserved: $ANSWER_KEY"
    python3 <<PYEOF
import json, pathlib
src = json.load(open("$GROUND_TRUTH"))
public = {k: src[k] for k in ("run_id", "target", "kali", "mode", "pacing") if k in src}
public["steps"] = [{"name": s["name"], "ok": s["ok"]} for s in src.get("steps", [])]
pathlib.Path("$PUBLIC_JSON").write_text(json.dumps(public, indent=2))
print(f"[replay.sh] sanitized public ground truth: $PUBLIC_JSON")
PYEOF
else
    echo "[replay.sh] WARN: no chain-*.json found under $RESULTS_DIR — skipping sanitization"
fi

# ---------------------------------------------------------------- step 3: bundle
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$STAGE_DIR/logs"
cp -a "$SNAP_DIR" "$STAGE_DIR/logs/"
# Strip the raw originals — analysts get the diurnal copies only. Keep
# manifest + public json + the *.diurnal.log files. (Without this the
# tarball would ship the answer key in postgres/auth.log timestamps.)
find "$STAGE_DIR/logs/$(basename "$SNAP_DIR")" -type f -name '*.log' \
    ! -name '*.diurnal.log' -delete
# Drop the answer key if it accidentally landed inside the snapshot dir
# (it shouldn't — it lives in Attack-chain/results/ — but be defensive).
find "$STAGE_DIR/logs/$(basename "$SNAP_DIR")" -name '*.answer-key.json' -delete

mkdir -p "$STAGE_DIR/Documentation"
cp Documentation/analyst_briefing.md            "$STAGE_DIR/Documentation/" 2>/dev/null || true
cp Documentation/analyst_findings_template.yaml "$STAGE_DIR/Documentation/" 2>/dev/null || true
cp Documentation/scenario_story.md              "$STAGE_DIR/Documentation/" 2>/dev/null || true

# tar from inside STAGE_DIR so the archive has a clean top-level layout.
tar -czf "$KIT_TARBALL" -C "$STAGE_DIR" .

# ---------------------------------------------------------------- done
SIZE="$(du -h "$KIT_TARBALL" | cut -f1)"
echo ""
echo "[replay.sh] cohort kit ready ($SIZE):"
echo "  $KIT_TARBALL"
echo ""
echo "[replay.sh] kit contents:"
tar -tzf "$KIT_TARBALL" | head -25
echo "  ... $(tar -tzf "$KIT_TARBALL" | wc -l) entries total"
echo ""
echo "[replay.sh] instructor — answer key kept at:"
if [ -n "${ANSWER_KEY:-}" ] && [ -f "$ANSWER_KEY" ]; then
    echo "  $(cd "$(dirname "$ANSWER_KEY")" && pwd)/$(basename "$ANSWER_KEY")"
else
    echo "  (none — no chain-*.json was found for this snapshot)"
fi
