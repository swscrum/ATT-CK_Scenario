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
    """``print`` ``msg`` with every line prefixed by ``[<utc-iso>]``.

    Multi-line messages (e.g. captured command output) get the same prefix on
    each line so every console line carries a timestamp. A single timestamp is
    sampled per call so all lines of one message share the same instant.

    Leading newlines in ``msg`` are emitted before the prefix so blank-line
    spacing between sections is preserved rather than timestamped. Blank lines
    inside the message are left empty for the same reason.
    """
    stripped = msg.lstrip("\n")
    leading = msg[: len(msg) - len(stripped)]
    prefix = f"[{timestamp()}] "
    prefixed = "\n".join(prefix + line if line else line for line in stripped.split("\n"))
    print(f"{leading}{prefixed}", end=end, flush=flush)
