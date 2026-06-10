#!/bin/bash
# ============================================================================
#  hydrate-baseline.sh — first-boot baseline log writer
# ----------------------------------------------------------------------------
#  Reads template files from /usr/local/share/baseline/<persona>/, substitutes
#  date-relative tokens with today-anchored UTC timestamps, and writes the
#  rendered output into the system log paths declared by each template's
#  `# TARGET: <path>` header line.
#
#  Runs ONCE per container lifetime; the marker file /var/lib/baseline-hydrated
#  short-circuits subsequent invocations so `docker compose restart` does not
#  double-write the baseline.
#
#  Invoked from each victim container's entrypoint.sh BEFORE rsyslogd and the
#  lab-fim watcher start, so the baseline entries are in place before any
#  inotify watcher could log them as runtime modifications.
#
#  Token grammar (in templates):
#      {D-N}            → YYYY-MM-DD, N days ago (UTC)
#      {D-N-Hh-Mm}      → ISO timestamp at H:M on day N-ago, e.g. 2026-05-27T10:23:00Z
#      {BSD-N-Hh-Mm}    → BSD syslog timestamp, e.g. "May 27 10:23:00"
#      {DPKG-N-Hh-Mm}   → dpkg.log timestamp, e.g. "2026-05-27 10:23:00"
#      {HOST}           → container hostname
#      {EPOCH-N-Hh-Mm}  → Unix epoch seconds at H:M on day N-ago
#  N is an integer (days ago); H and M are two-digit hour/minute.
#  Template first line declares the target file path:
#      # TARGET: /var/log/auth.log
# ============================================================================
set -u

MARKER=/var/lib/baseline-hydrated
PERSONA="${BASELINE_PERSONA:-developer}"
TPL_DIR="/usr/local/share/baseline/${PERSONA}"

# Idempotent on container restart.
if [ -f "$MARKER" ]; then
    exit 0
fi

if [ ! -d "$TPL_DIR" ]; then
    echo "[hydrate-baseline] no templates at $TPL_DIR (persona=$PERSONA); skipping" >&2
    mkdir -p "$(dirname "$MARKER")"
    touch "$MARKER"
    exit 0
fi

HOST="$(hostname)"
TODAY_EPOCH="$(date -u +%s)"

# render_tokens reads stdin, writes rendered output to stdout.
# Implemented in awk so we get GNU date arithmetic without spawning a
# subprocess for every token in every template line.
render_tokens() {
    awk -v today="$TODAY_EPOCH" -v host="$HOST" '
    function ymd(off,   t) {
        t = today - (off * 86400)
        return strftime("%Y-%m-%d", t, 1)
    }
    function iso(off, h, m,   t) {
        t = today - (off * 86400)
        # Truncate to midnight UTC of that day, then add H:M.
        t = t - (t % 86400) + (h * 3600) + (m * 60)
        return strftime("%Y-%m-%dT%H:%M:%SZ", t, 1)
    }
    function bsd(off, h, m,   t) {
        t = today - (off * 86400)
        t = t - (t % 86400) + (h * 3600) + (m * 60)
        return strftime("%b %e %H:%M:%S", t, 1)
    }
    function dpkg(off, h, m,   t) {
        t = today - (off * 86400)
        t = t - (t % 86400) + (h * 3600) + (m * 60)
        return strftime("%Y-%m-%d %H:%M:%S", t, 1)
    }
    function epoch(off, h, m,   t) {
        t = today - (off * 86400)
        t = t - (t % 86400) + (h * 3600) + (m * 60)
        return t
    }
    {
        line = $0
        # {HOST}
        gsub(/\{HOST\}/, host, line)
        # {D-N} — YYYY-MM-DD, N days ago
        while (match(line, /\{D-[0-9]+\}/)) {
            tok = substr(line, RSTART, RLENGTH)
            n = substr(tok, 4, length(tok) - 4) + 0
            sub(/\{D-[0-9]+\}/, ymd(n), line)
        }
        # {D-N-Hh-Mm} — ISO at H:M on day N-ago
        while (match(line, /\{D-[0-9]+-[0-9]+h-[0-9]+m\}/)) {
            tok = substr(line, RSTART, RLENGTH)
            split(tok, parts, /[-{}hm]/)
            # parts indices: 1=empty 2="D" 3=N 4="" 5=H 6="" 7=M 8=""
            n = parts[3] + 0; h = parts[4] + 0; m = parts[6] + 0
            sub(/\{D-[0-9]+-[0-9]+h-[0-9]+m\}/, iso(n, h, m), line)
        }
        # {BSD-N-Hh-Mm}
        while (match(line, /\{BSD-[0-9]+-[0-9]+h-[0-9]+m\}/)) {
            tok = substr(line, RSTART, RLENGTH)
            split(tok, parts, /[-{}hm]/)
            n = parts[3] + 0; h = parts[4] + 0; m = parts[6] + 0
            sub(/\{BSD-[0-9]+-[0-9]+h-[0-9]+m\}/, bsd(n, h, m), line)
        }
        # {DPKG-N-Hh-Mm}
        while (match(line, /\{DPKG-[0-9]+-[0-9]+h-[0-9]+m\}/)) {
            tok = substr(line, RSTART, RLENGTH)
            split(tok, parts, /[-{}hm]/)
            n = parts[3] + 0; h = parts[4] + 0; m = parts[6] + 0
            sub(/\{DPKG-[0-9]+-[0-9]+h-[0-9]+m\}/, dpkg(n, h, m), line)
        }
        # {EPOCH-N-Hh-Mm}
        while (match(line, /\{EPOCH-[0-9]+-[0-9]+h-[0-9]+m\}/)) {
            tok = substr(line, RSTART, RLENGTH)
            split(tok, parts, /[-{}hm]/)
            n = parts[3] + 0; h = parts[4] + 0; m = parts[6] + 0
            sub(/\{EPOCH-[0-9]+-[0-9]+h-[0-9]+m\}/, epoch(n, h, m), line)
        }
        print line
    }
    '
}

# Process every *.tpl in the persona dir.
shopt -s nullglob
for tpl in "$TPL_DIR"/*.tpl; do
    # Target path from "# TARGET: <path>" on the first line.
    target="$(awk 'NR==1 && /^# TARGET:/ { print $3; exit }' "$tpl")"
    if [ -z "$target" ]; then
        echo "[hydrate-baseline] $tpl: missing '# TARGET:' header; skipping" >&2
        continue
    fi

    # Ensure target dir exists, append-or-create.
    mkdir -p "$(dirname "$target")"
    # Strip the # TARGET: header line and the # comment marker rows that follow
    # it (any line where the FIRST character is '#' that appears BEFORE the
    # first non-comment line). After the first non-comment line, '#' lines are
    # part of the rendered output (dpkg/apt history files use '#' inside).
    awk '
        BEGIN { in_header = 1 }
        in_header && /^#/ { next }
        { in_header = 0; print }
    ' "$tpl" | render_tokens >> "$target"

    echo "[hydrate-baseline] persona=$PERSONA  tpl=$(basename "$tpl")  ->  $target" >&2
done

# Mark hydrated.
mkdir -p "$(dirname "$MARKER")"
touch "$MARKER"
echo "[hydrate-baseline] complete (persona=$PERSONA)" >&2
exit 0
