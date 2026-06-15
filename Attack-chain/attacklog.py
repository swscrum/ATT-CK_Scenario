"""Attacker-POV logger for the attack chain.

Creates two files per run in ``/Infrastructure/logs/attacker/``:

  attack_steps_<run_id>.md   — structured markdown with MITRE ATT&CK annotations,
                               command output, and a summary table.  For human review.
  attack_steps_<run_id>.log  — syslog-style key=value structured log, one line per
                               command.  Designed for ingestion into Splunk / SIEM tools.

Log line format (matches the lab's auth.log / syslog convention):
  2026-06-15T14:25:35.123456+00:00 kali attacker[<run_id>]: phase=RECON tactic="..." cmd="..."

Called from ``main.py``:
    import attacklog
    attacklog.open_log(path, meta)       # once before the step loop
    attacklog.begin_phase(name, ...)     # before each step
    attacklog.end_phase(name, ok, ...)   # after each step
    attacklog.close_log(results)         # once in the finally block
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

_fh: IO[str] | None = None        # markdown file handle
_log_fh: IO[str] | None = None    # structured .log file handle
_phase_count: int = 0
_run_id: str = ""
_current_phase: str = ""
_current_tactic: str = ""

_MAX_OUTPUT_LINES = 20


def _log_cmd(cmd: str) -> None:
    """Write one structured syslog-style entry to the .log file."""
    if _log_fh is None:
        return
    try:
        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        cmd_escaped = cmd.replace('"', '\\"')
        _log_fh.write(
            f'{ts} kali attacker[{_run_id}]: '
            f'phase={_current_phase} tactic="{_current_tactic}" cmd="{cmd_escaped}"\n'
        )
        _log_fh.flush()
    except OSError as exc:
        print(f"[attacklog] write error in _log_cmd: {exc}", file=sys.stderr)


def _append(line: str) -> None:
    """Write only command lines (containing '] $ ') to the attack log.

    Called by chainlog.log() for every console line.  Status messages
    ([*], [+], [-], [!]) and plain output are silently ignored here —
    command output is captured separately via _append_output().
    """
    if _fh is None:
        return
    try:
        for subline in line.split("\n"):
            if "] $ " in subline:
                _fh.write(f"`{subline}`\n")
                cmd = subline[subline.index("] $ ") + 4:]
                _log_cmd(cmd)
        _fh.flush()
    except OSError as exc:
        print(f"[attacklog] write error in _append: {exc}", file=sys.stderr)


def _append_output(output: str) -> None:
    """Write the captured output of the last command to the attack log.

    Called by chainlog.run_remote() after the output is captured.
    Output is 4-space indented (markdown code block) and capped at
    _MAX_OUTPUT_LINES lines to keep the file readable.
    """
    if _fh is None or not output:
        return
    try:
        lines = [l for l in output.splitlines() if l.strip()]
        if not lines:
            return
        for line in lines[:_MAX_OUTPUT_LINES]:
            _fh.write(f"    {line}\n")
        if len(lines) > _MAX_OUTPUT_LINES:
            _fh.write(f"    ... ({len(lines) - _MAX_OUTPUT_LINES} more lines truncated)\n")
        _fh.write("\n")
        _fh.flush()
    except OSError as exc:
        print(f"[attacklog] write error in _append_output: {exc}", file=sys.stderr)


def open_log(path: str | Path, meta: dict) -> None:
    """Create the markdown and structured log files and write the run header."""
    global _fh, _log_fh, _phase_count, _run_id, _current_phase, _current_tactic
    for fh in (_fh, _log_fh):
        if fh is not None:
            fh.close()
    _fh = _log_fh = None
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _fh = path.open("w", encoding="utf-8")
    _log_fh = path.with_suffix(".log").open("w", encoding="utf-8")
    _phase_count = 0
    _current_phase = ""
    _current_tactic = ""

    def _safe(v: object) -> str:
        return str(v).replace("\n", " ").replace("\r", " ").replace("|", "\\|")

    _run_id = _safe(meta.get("run_id", "?"))
    mode    = _safe(meta.get("mode",   "?"))
    target  = _safe(meta.get("target", "?"))
    kali    = _safe(meta.get("kali",   "?"))

    _fh.write(f"# Attack Log — {_run_id}\n\n")
    _fh.write(f"**Mode:** {mode} | **Target:** {target} | **Kali:** {kali}\n\n")
    _fh.write("---\n\n")
    _fh.flush()


def begin_phase(name: str, tactic: str, techniques: list[str], started: str) -> None:
    """Write the phase header section to the attack log."""
    global _phase_count, _current_phase, _current_tactic
    if _fh is None:
        return
    _phase_count += 1
    _current_phase = name.upper()
    _current_tactic = tactic
    tech_str = " · ".join(f"`{t}`" for t in techniques) if techniques else "—"
    _fh.write(f"## Phase {_phase_count} — {name.upper()}\n\n")
    _fh.write("| | |\n|---|---|\n")
    _fh.write(f"| **Tactic** | {tactic} |\n")
    _fh.write(f"| **Techniques** | {tech_str} |\n")
    _fh.write(f"| **Started** | {started} |\n\n")
    _fh.flush()


def end_phase(name: str, ok: bool, elapsed: float, ended: str) -> None:
    """Write the phase result line to the attack log."""
    if _fh is None:
        return
    icon   = "✓" if ok else "✗"
    status = "completed" if ok else "FAILED"
    _fh.write(f"\n**{icon} {status}** — {elapsed:.1f}s — ended {ended}\n\n---\n\n")
    _fh.flush()


def close_log(results: list[dict] | None = None) -> None:
    """Write the summary table and close both log files."""
    global _fh, _log_fh, _phase_count, _run_id, _current_phase, _current_tactic
    if _fh is None:
        return
    _fh.write("## Summary\n\n")
    if results:
        _fh.write("| Phase | Status | Duration | Tactic |\n")
        _fh.write("|---|---|---|---|\n")
        for r in results:
            icon = "✓" if r.get("ok") else "✗"
            _fh.write(
                f"| {r.get('name', '?').upper()} | {icon} | {r.get('elapsed', 0):.1f}s"
                f" | {r.get('tactic', '')} |\n"
            )
    else:
        _fh.write("*(run ended before any step completed)*\n")
    _fh.write("\n")
    _fh.flush()
    _fh.close()
    _fh = None
    if _log_fh is not None:
        _log_fh.close()
        _log_fh = None
    _phase_count = 0
    _run_id = ""
    _current_phase = ""
    _current_tactic = ""
