"""Shared console-logging helper for the attack chain.

Prepends a UTC ISO-8601 timestamp to each operator console line so the output
correlates to the second with the per-run ground-truth JSON written by
``main.py`` and with the blue-team SIEM logs (e.g. ``lab-fim.sh``), which all
use the same ISO-8601 / UTC convention.
"""

from __future__ import annotations

from datetime import datetime, timezone


def timestamp() -> str:
    """UTC ISO-8601, second precision, Z-suffixed (e.g. ``2026-05-29T14:30:00Z``)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log(msg: str = "", *, end: str = "\n", flush: bool = False) -> None:
    """``print`` a line prefixed with ``[<utc-iso>]``.

    Leading newlines in ``msg`` are emitted before the prefix so blank-line
    spacing between sections is preserved rather than timestamped.
    """
    stripped = msg.lstrip("\n")
    leading = msg[: len(msg) - len(stripped)]
    print(f"{leading}[{timestamp()}] {stripped}", end=end, flush=flush)
