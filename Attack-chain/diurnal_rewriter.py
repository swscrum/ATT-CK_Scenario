#!/usr/bin/env python3
"""Diurnal timestamp rewriter for SIEM-friendly post-processing.

Given a snapshotted log directory from one chain run, produce ``*.diurnal.log``
companion files where every in-run timestamp has been stretched onto a
synthetic 8-hour business-day window starting at ``--anchor``.

The win: a 30-minute realistic chain run looks like a normal workday on the
SIEM dashboard — events are spread realistically apart, but relative ordering
and inter-event spacing ratios are preserved exactly (single linear stretch).
A trainee sees morning probes → midday exploit → afternoon lateral movement
spanning real business hours, instead of one tight cluster.

Output policy
=============
- For each ``*.log`` (and ``stdout.log`` / ``stderr.log``) under
  ``--snapshot-dir``, we write a sibling ``*.diurnal.log`` containing only
  the lines whose original timestamp falls inside ``[run_start, run_end]``.
- Lines without a timestamp are treated as continuations of the previous
  matched line (e.g. multi-line Python tracebacks, postgres CONTEXT blocks)
  and inherit that line's rewritten timestamp.
- Pre-existing log content (events from before run_start, including the
  daemon-startup chatter that lives in the bind mounts across runs) is
  excluded — the diurnal copy is "this run, viewed on the SIEM clock".
- Originals are NEVER modified — diurnal is purely additive.
- A ``diurnal_manifest.json`` lands at the snapshot-dir root so the SIEM
  dashboard can label the synthetic window with what was actually warped.

Supported timestamp formats (sniffed per-file via first-matching regex)
======================================================================
- ``apache_clf``        — ``[31/May/2026:12:48:13 +0000]`` (access.log)
- ``apache_error``      — ``[Sun May 31 12:41:18.118304 2026]`` (error.log)
- ``rsyslog_iso``       — ``2026-05-10T17:43:05.522955+00:00`` (modern syslog)
- ``rsyslog_bsd``       — ``May 10 17:43:18`` (no year — assumed = run year)
- ``postgres``          — ``2026-05-18 15:56:57 UTC``
- ``lab_fim``           — ``2026-05-17T18:46:02+0000`` (no-colon TZ ISO)
- ``chainlog``          — ``[2026-05-31T12:43:16Z] ...`` (kali stdout)

CLI
===
    python3 diurnal_rewriter.py \\
        --snapshot-dir /path/to/Infrastructure/logs/run-<ts> \\
        --run-start 2026-05-31T14:30:00Z \\
        --run-end   2026-05-31T14:54:00Z \\
        --anchor    2026-05-31T09:00:00Z \\
        --window-hours 8

``--run-end`` defaults to "now" if omitted (typical when called right after
the snapshot step). ``--anchor`` defaults to today 09:00 UTC.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Timestamp format registry
# ---------------------------------------------------------------------------


@dataclass
class TsFormat:
    name: str
    # Regex must capture exactly one group: the raw timestamp string.
    pattern: re.Pattern
    # Parse the captured string → aware UTC datetime. Receives the run year
    # for formats that don't include it (BSD syslog).
    parse: Callable[[str, int], datetime]
    # Render an aware UTC datetime back into the same shape so the rest of
    # the line stays byte-identical.
    render: Callable[[datetime], str]


def _parse_apache_clf(s: str, _yr: int) -> datetime:
    # 31/May/2026:12:48:13 +0000
    return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)


def _render_apache_clf(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def _parse_apache_error(s: str, _yr: int) -> datetime:
    # Sun May 31 12:41:18.118304 2026
    return datetime.strptime(s, "%a %b %d %H:%M:%S.%f %Y").replace(tzinfo=timezone.utc)


def _render_apache_error(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%a %b %d %H:%M:%S.%f %Y")


def _parse_rsyslog_iso(s: str, _yr: int) -> datetime:
    # 2026-05-10T17:43:05.522955+00:00 — fromisoformat handles this in 3.11+.
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def _render_rsyslog_iso(dt: datetime) -> str:
    # Same shape as the input (microseconds + +00:00 TZ).
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _parse_rsyslog_bsd(s: str, run_year: int) -> datetime:
    # "May 10 17:43:18" — no year. Use run year; caller's window filter
    # discards anything that lands outside the run window so a wrong-year
    # guess for stale lines simply means they get filtered out.
    dt = datetime.strptime(f"{run_year} {s}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def _render_rsyslog_bsd(dt: datetime) -> str:
    # "May 31 14:30:00" — strftime("%b %e ...") would left-pad day with
    # space, which matches rsyslog's actual output. %e is GNU; fall back
    # to manual padding for portability.
    u = dt.astimezone(timezone.utc)
    return f"{u.strftime('%b')} {u.day:>2} {u.strftime('%H:%M:%S')}"


def _parse_postgres(s: str, _yr: int) -> datetime:
    # "2026-05-18 15:56:57 UTC"
    base = s[:-4]  # strip " UTC"
    return datetime.strptime(base, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def _render_postgres(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_lab_fim(s: str, _yr: int) -> datetime:
    # "2026-05-17T18:46:02+0000" — no colon in TZ offset.
    # Normalize the offset so fromisoformat accepts it on older Pythons.
    normalized = s[:-5] + s[-5:-2] + ":" + s[-2:]
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def _render_lab_fim(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")


def _parse_chainlog(s: str, _yr: int) -> datetime:
    # "2026-05-31T12:43:16Z"
    return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc)


def _render_chainlog(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


FORMATS: list[TsFormat] = [
    TsFormat(
        "apache_clf",
        re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]"),
        _parse_apache_clf,
        _render_apache_clf,
    ),
    TsFormat(
        "apache_error",
        re.compile(r"\[([A-Za-z]{3} [A-Za-z]{3} [ \d]\d \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]"),
        _parse_apache_error,
        _render_apache_error,
    ),
    TsFormat(
        "rsyslog_iso",
        re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})"),
        _parse_rsyslog_iso,
        _render_rsyslog_iso,
    ),
    TsFormat(
        "postgres",
        re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)"),
        _parse_postgres,
        _render_postgres,
    ),
    TsFormat(
        "lab_fim",
        re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})"),
        _parse_lab_fim,
        _render_lab_fim,
    ),
    TsFormat(
        "chainlog",
        re.compile(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\]"),
        _parse_chainlog,
        _render_chainlog,
    ),
    # rsyslog_bsd is LAST because its pattern is the loosest (no year, no TZ)
    # — listing it after the more specific ISO formats avoids false positives
    # on lines that have both a leading BSD-style ts AND an embedded ISO one.
    TsFormat(
        "rsyslog_bsd",
        re.compile(r"^([A-Za-z]{3} [ \d]\d \d{2}:\d{2}:\d{2})\b"),
        _parse_rsyslog_bsd,
        _render_rsyslog_bsd,
    ),
]


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------


@dataclass
class FileStats:
    path: str
    format: Optional[str] = None
    lines_total: int = 0
    lines_in_window: int = 0
    lines_skipped: int = 0      # outside run window
    lines_no_ts: int = 0        # continuation lines inheriting prev ts


def _sniff_format(sample: list[str]) -> Optional[TsFormat]:
    """Return the first format whose pattern matches any line in ``sample``."""
    for fmt in FORMATS:
        for line in sample:
            if fmt.pattern.search(line):
                return fmt
    return None


def _process_file(
    src: Path,
    dst: Path,
    *,
    run_start: datetime,
    run_end: datetime,
    anchor: datetime,
    stretch: float,
    run_year: int,
) -> FileStats:
    stats = FileStats(path=str(src))
    try:
        raw = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        return stats
    if not raw:
        return stats

    # Sniff format from up to the first 200 lines so daemon-startup chatter
    # at the top of a file doesn't fool us into picking the wrong format.
    fmt = _sniff_format(raw[:200])
    if fmt is None:
        return stats
    stats.format = fmt.name

    out: list[str] = []
    last_new_dt: Optional[datetime] = None

    for line in raw:
        stats.lines_total += 1
        match = fmt.pattern.search(line)
        if not match:
            # Continuation line — keep it iff we're currently inside the run
            # window (i.e. previous matched line was kept).
            if last_new_dt is not None:
                out.append(line)
                stats.lines_no_ts += 1
            continue

        try:
            orig_dt = fmt.parse(match.group(1), run_year)
        except (ValueError, OverflowError):
            # Malformed/ambiguous timestamp — drop and reset continuation
            # anchor so subsequent unattached lines don't leak through.
            last_new_dt = None
            stats.lines_skipped += 1
            continue

        if not (run_start <= orig_dt <= run_end):
            last_new_dt = None
            stats.lines_skipped += 1
            continue

        delta = (orig_dt - run_start).total_seconds() * stretch
        new_dt = anchor + timedelta(seconds=delta)
        last_new_dt = new_dt

        # Replace only the matched span — preserves the rest of the line
        # (status code, source IP, message body, etc.) byte-for-byte.
        new_line = line[: match.start(1)] + fmt.render(new_dt) + line[match.end(1):]
        out.append(new_line)
        stats.lines_in_window += 1

    if out:
        dst.write_text("\n".join(out) + "\n", encoding="utf-8")
    return stats


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _iter_log_files(root: Path):
    """Yield every regular file under root that we'll try to rewrite.

    We process anything ending in ``.log`` plus the conventional
    stdout.log/stderr.log copies. Skip already-rewritten ``*.diurnal.log``
    files so re-running the rewriter is idempotent.
    """
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        name = p.name
        if name.endswith(".diurnal.log"):
            continue
        if name.endswith(".log"):
            yield p


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--snapshot-dir", required=True, type=Path,
                   help="Path to one Infrastructure/logs/run-<ts>/ snapshot.")
    p.add_argument("--run-start", required=True,
                   help="ISO 8601 UTC timestamp the chain started.")
    p.add_argument("--run-end", default=None,
                   help="ISO 8601 UTC timestamp the chain ended (default: now).")
    p.add_argument("--anchor", default=None,
                   help="ISO 8601 UTC start of the synthetic window "
                        "(default: today 09:00:00Z).")
    p.add_argument("--window-hours", type=float, default=8.0,
                   help="Length of the synthetic window in hours (default: 8).")
    args = p.parse_args(argv)

    snapshot = args.snapshot_dir
    if not snapshot.is_dir():
        print(f"diurnal: no such directory: {snapshot}", file=sys.stderr)
        return 1

    run_start = datetime.fromisoformat(args.run_start.replace("Z", "+00:00")).astimezone(timezone.utc)
    if args.run_end:
        run_end = datetime.fromisoformat(args.run_end.replace("Z", "+00:00")).astimezone(timezone.utc)
    else:
        run_end = datetime.now(timezone.utc)
    if args.anchor:
        anchor = datetime.fromisoformat(args.anchor.replace("Z", "+00:00")).astimezone(timezone.utc)
    else:
        today = datetime.now(timezone.utc).date()
        anchor = datetime(today.year, today.month, today.day, 9, 0, 0, tzinfo=timezone.utc)

    actual_sec = max((run_end - run_start).total_seconds(), 1.0)
    synthetic_sec = args.window_hours * 3600.0
    stretch = synthetic_sec / actual_sec
    run_year = run_start.year

    print(f"diurnal: snapshot={snapshot}")
    print(f"diurnal: run window {run_start.isoformat()} → {run_end.isoformat()} "
          f"({actual_sec:.0f}s)")
    print(f"diurnal: anchor {anchor.isoformat()}  stretch {stretch:.2f}× "
          f"(synthetic {synthetic_sec/3600:.1f}h)")

    files: list[dict] = []
    for src in _iter_log_files(snapshot):
        dst = src.with_name(src.stem + ".diurnal.log")
        stats = _process_file(
            src, dst,
            run_start=run_start, run_end=run_end,
            anchor=anchor, stretch=stretch, run_year=run_year,
        )
        rel = str(src.relative_to(snapshot))
        if stats.format is None:
            print(f"  · {rel}: no recognised timestamp format — skipped")
        else:
            print(f"  · {rel}: format={stats.format}  "
                  f"in_window={stats.lines_in_window}  "
                  f"skipped={stats.lines_skipped}  "
                  f"continuations={stats.lines_no_ts}  → {dst.name}")
        files.append({
            "path": rel,
            "format": stats.format,
            "lines_total": stats.lines_total,
            "lines_in_window": stats.lines_in_window,
            "lines_skipped": stats.lines_skipped,
            "lines_continuation": stats.lines_no_ts,
        })

    manifest = {
        "run_start": run_start.isoformat(),
        "run_end": run_end.isoformat(),
        "actual_window_sec": actual_sec,
        "anchor": anchor.isoformat(),
        "synthetic_window_sec": synthetic_sec,
        "stretch_factor": stretch,
        "files": files,
    }
    manifest_path = snapshot / "diurnal_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"diurnal: wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
