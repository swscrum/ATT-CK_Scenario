"""Shared console-logging and shell helper utilities for the attack chain.

Prepends a UTC ISO-8601 timestamp to each operator console line so the output
correlates to the second with the per-run ground-truth JSON written by
``main.py`` and with the blue-team SIEM logs (e.g. ``lab-fim.sh``), which all
use the same ISO-8601 / UTC convention.

Also exports ``run_remote`` and ``send_command`` so all chain modules share
one implementation.  ``run_remote`` logs every command it sends (``$ cmd``)
through ``log()``, which in turn tees to the attack-log markdown file when
one is open.
"""

from __future__ import annotations

import re
import socket
import time
from datetime import datetime, timezone

import attacklog


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

    Every line is also teed to the attack-log markdown file when one is open.
    """
    stripped = msg.lstrip("\n")
    leading = msg[: len(msg) - len(stripped)]
    prefix = f"[{timestamp()}] "
    prefixed = "\n".join(prefix + line if line else line for line in stripped.split("\n"))
    full = f"{leading}{prefixed}"
    print(full, end=end, flush=flush)
    attacklog._append(full)


# ---------------------------------------------------------------------------
# Shared shell helpers — used by all chain modules that talk to a remote shell
# ---------------------------------------------------------------------------

_sentinel_seq = 0


def drain(shell: socket.socket) -> None:
    """Discard stale bytes left in the socket buffer from a previous command."""
    prev = shell.gettimeout()
    shell.settimeout(0.1)
    while True:
        try:
            if not shell.recv(4096):
                break
        except socket.timeout:
            break
    shell.settimeout(prev)


def run_remote(shell: socket.socket, cmd: str, timeout: float = 15) -> str:
    """Send ``cmd`` to ``shell``, capture and return the output.

    Logs the command via ``log()`` before sending so it appears in both the
    console output and the attack-log markdown file.  Uses a unique sentinel
    echo to delimit the real output from the shell prompt.
    """
    global _sentinel_seq
    log(f"$ {cmd}")
    _sentinel_seq += 1
    sentinel = f"SENTINEL_{_sentinel_seq:04X}_END"

    drain(shell)
    shell.sendall(f"{cmd}\n".encode())
    time.sleep(0.5)
    shell.sendall(f"echo {sentinel}\n".encode())

    prev_timeout = shell.gettimeout()
    shell.settimeout(2)
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = shell.recv(4096)
            if not chunk:
                break
            buf += chunk.decode(errors="replace")
        except socket.timeout:
            pass
        if sentinel in buf:
            break
    shell.settimeout(prev_timeout)

    if sentinel in buf:
        buf = buf[:buf.index(sentinel)]

    buf = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf)
    buf = buf.replace("\r", "")
    result = buf.strip()
    attacklog._append_output(result)
    return result


def send_command(shell: socket.socket, cmd: str) -> None:
    """Send ``cmd`` to ``shell`` without capturing output (fire-and-forget).

    Logs the command via ``log()`` before sending.
    """
    log(f"$ {cmd}")
    shell.sendall((cmd + "\n").encode())
    time.sleep(0.5)
