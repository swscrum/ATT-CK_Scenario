"""Attacker-POV markdown logger for the attack chain.

Creates one ``attack_steps_<run_id>.md`` file per run in
``/Infrastructure/logs/attacker/``.  Written in real-time: every ``log()``
call in the chain tees here via ``_append()``.  Structured by attack phase
with MITRE ATT&CK annotations.

Called from ``main.py``:
    import attacklog
    attacklog.open_log(path, meta)       # once before the step loop
    attacklog.begin_phase(name, ...)     # before each step
    attacklog.end_phase(name, ok, ...)   # after each step
    attacklog.close_log(results)         # once in the finally block
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO

_fh: IO[str] | None = None
_phase_count: int = 0


_MAX_OUTPUT_LINES = 20


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
    """Create the attack log file and write the run header."""
    global _fh, _phase_count
    if _fh is not None:
        _fh.close()
        _fh = None
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _fh = path.open("w", encoding="utf-8")
    _phase_count = 0

    def _safe(v: object) -> str:
        return str(v).replace("\n", " ").replace("\r", " ").replace("|", "\\|")

    run_id = _safe(meta.get("run_id", "?"))
    mode   = _safe(meta.get("mode",   "?"))
    target = _safe(meta.get("target", "?"))
    kali   = _safe(meta.get("kali",   "?"))

    _fh.write(f"# Attack Log — {run_id}\n\n")
    _fh.write(f"**Mode:** {mode} | **Target:** {target} | **Kali:** {kali}\n\n")
    _fh.write("---\n\n")
    _fh.flush()


def begin_phase(name: str, tactic: str, techniques: list[str], started: str) -> None:
    """Write the phase header section to the attack log."""
    global _phase_count
    if _fh is None:
        return
    _phase_count += 1
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
    """Write the summary table and close the file."""
    global _fh, _phase_count
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
    _phase_count = 0
