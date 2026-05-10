#!/usr/bin/env python3
"""Attack-chain orchestrator.

Wires individual chain modules (initial_recon_1, privesc, ...) into a single
runnable pipeline. Each module keeps its own ``run()`` signature and can still
be invoked standalone; the orchestrator talks to it through a thin per-step
adapter that reads from / writes to a shared ``Context``.

Add a new step by:
  1. Writing the module under ``Attack-chain/`` with a top-level entry function.
  2. Adding an ``_step_<name>`` adapter below.
  3. Appending a ``Step(...)`` entry to ``CHAIN``.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

console = Console(highlight=False)
log = logging.getLogger("chain")

DEFAULT_TARGET = "router"
DEFAULT_RESULTS_DIR = "/Attack-chain/results"
DEFAULT_KALI_HOST = "10.10.0.2"
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

STEP_META = {
    "recon":   {"tactic": "TA0043 · Reconnaissance",       "techniques": ["T1595", "T1592"],     "color": "cyan"},
    "exploit": {"tactic": "TA0001 · Initial Access",       "techniques": ["T1190", "T1059.004"], "color": "yellow"},
    "privesc": {"tactic": "TA0004 · Privilege Escalation", "techniques": ["T1053.003", "T1068"], "color": "red"},
    "lateral": {"tactic": "TA0008 · Lateral Movement",     "techniques": ["T1021.004", "T1078"], "color": "magenta"},
    "cleanup": {"tactic": "operator hygiene",              "techniques": [],                     "color": "green"},
}


@dataclass
class Context:
    """State carried between chain steps."""

    target: str = DEFAULT_TARGET
    results_dir: str = DEFAULT_RESULTS_DIR
    kali_host: str = DEFAULT_KALI_HOST
    wordlist: str = DEFAULT_WORDLIST
    state: dict[str, Any] = field(default_factory=dict)


@dataclass
class Step:
    name: str
    run: Callable[[Context], dict[str, Any] | None]
    requires: tuple[str, ...] = ()
    optional: bool = False
    teardown: Callable[[Context], None] | None = None


# ---------------------------------------------------------------------------
# Rich helpers
# ---------------------------------------------------------------------------

def _print_banner(ctx: Context, steps: list[Step]) -> None:
    title = Text("⛓  ATTACK CHAIN", style="bold white")
    meta = (
        f"[dim]Target:[/dim] [bold cyan]{ctx.target}[/bold cyan]   "
        f"[dim]Kali:[/dim] [bold cyan]{ctx.kali_host}[/bold cyan]   "
        f"[dim]Steps:[/dim] [bold white]{', '.join(s.name for s in steps)}[/bold white]"
    )
    console.print(Panel(meta, title=title, border_style="dim white", padding=(0, 2)))
    console.print()


def _print_step_header(step: Step, index: int, total: int) -> None:
    meta = STEP_META.get(step.name, {})
    color = meta.get("color", "white")
    tactic = meta.get("tactic", "")
    techniques = "  ".join(f"[dim]{t}[/dim]" for t in meta.get("techniques", []))

    progress = f"[dim]({index}/{total})[/dim]"
    header = (
        f"[bold {color}]{step.name.upper()}[/bold {color}]  "
        f"{progress}   [dim italic]{tactic}[/dim italic]   {techniques}"
    )
    console.print(Rule(header, style=color))
    console.print()


def _print_step_result(step: Step, elapsed: float, success: bool, error: str = "") -> None:
    console.print()
    meta = STEP_META.get(step.name, {})
    color = meta.get("color", "white")
    if success:
        msg = f"[bold green]✓[/bold green]  [bold {color}]{step.name}[/bold {color}]  [green]completed[/green]  [dim]{elapsed:.1f}s[/dim]"
    else:
        msg = f"[bold red]✗[/bold red]  [bold {color}]{step.name}[/bold {color}]  [red]failed[/red]  [dim]{elapsed:.1f}s[/dim]  [red]{error}[/red]"
    console.print(msg)
    console.print()


def _iso_utc() -> str:
    """Return current UTC time as ISO 8601 with second precision (Z-suffixed)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_ground_truth(ctx: Context, run_id: str, results: list[dict]) -> None:
    """Persist a structured per-run record for SIEM correlation.

    Writes ``<results_dir>/chain-<run_id>.json`` with per-step timestamps,
    Tactic/Technique IDs and ok/elapsed. Blue-team can match these windows
    against alerts fired in their SIEM/EDR.
    """
    out_dir = Path(ctx.results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_run_id = run_id.replace(":", "")
    out_path = out_dir / f"chain-{safe_run_id}.json"
    payload = {
        "run_id": run_id,
        "target": ctx.target,
        "kali": ctx.kali_host,
        "steps": results,
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    log.info("wrote ground truth: %s", out_path)


def _print_summary(results: list[dict]) -> None:
    console.print(Rule("[bold white]CHAIN SUMMARY[/bold white]", style="dim white"))
    console.print()

    table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 2))
    table.add_column("Step",      style="bold white",  no_wrap=True)
    table.add_column("Status",    no_wrap=True)
    table.add_column("Time",      style="dim",         no_wrap=True)
    table.add_column("Tactic",    style="dim italic")
    table.add_column("Techniques",style="dim")

    for r in results:
        meta = STEP_META.get(r["name"], {})
        color = meta.get("color", "white")
        status = (
            f"[green]✓ ok[/green]" if r["ok"]
            else f"[red]✗ failed[/red]"
        )
        techniques = " · ".join(meta.get("techniques", []))
        table.add_row(
            f"[{color}]{r['name']}[/{color}]",
            status,
            f"{r['elapsed']:.1f}s",
            meta.get("tactic", ""),
            techniques,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Per-step adapters
# ---------------------------------------------------------------------------

def _step_recon(ctx: Context) -> dict[str, Any]:
    from initial_recon_1 import run as recon_run
    recon_run(target=ctx.target, results_dir=ctx.results_dir, wordlist=ctx.wordlist)
    return {"recon_results": ctx.results_dir}


def _step_exploit(ctx: Context) -> dict[str, Any]:
    from initial_access import get_www_shell
    www_shell = get_www_shell(target_ip=ctx.target, kali_ip=ctx.kali_host)
    if www_shell is None:
        raise RuntimeError("exploit returned no www-data shell")
    return {"www_shell": www_shell}


def _step_privesc(ctx: Context) -> dict[str, Any]:
    from privesc import run as privesc_run
    root_shell = privesc_run(ctx.state["www_shell"], kali_host=ctx.kali_host)
    if root_shell is None:
        raise RuntimeError("privesc returned no root shell")
    return {"root_shell": root_shell}


def _teardown_close_socket(key: str) -> Callable[[Context], None]:
    def _close(ctx: Context) -> None:
        sock = ctx.state.get(key)
        if sock is not None:
            try:
                sock.close()
            except Exception as exc:
                log.warning("failed to close %s: %s", key, exc)
    return _close


# ---------------------------------------------------------------------------
# Chain definition
# ---------------------------------------------------------------------------

CHAIN: list[Step] = [
    Step("recon", _step_recon),
    Step("exploit", _step_exploit, teardown=_teardown_close_socket("www_shell")),
    Step("privesc", _step_privesc, requires=("www_shell",), teardown=_teardown_close_socket("root_shell")),
]


# ---------------------------------------------------------------------------
# Selection + execution
# ---------------------------------------------------------------------------

def _index_of(name: str, steps: list[Step]) -> int:
    for i, step in enumerate(steps):
        if step.name == name:
            return i
    valid = ", ".join(s.name for s in steps)
    raise SystemExit(f"unknown step {name!r}; choose one of: {valid}")


def _select(steps, *, only, start, stop) -> list[Step]:
    if only is not None:
        return [steps[_index_of(only, steps)]]
    lo = _index_of(start, steps) if start else 0
    hi = _index_of(stop, steps) + 1 if stop else len(steps)
    if lo >= hi:
        raise SystemExit(f"--from {start!r} comes after --to {stop!r}")
    return steps[lo:hi]


def _result_entry(step: Step, *, ok: bool, started: str, ended: str,
                  elapsed: float, err: str = "") -> dict:
    """Build one structured ground-truth record for a single step."""
    meta = STEP_META.get(step.name, {})
    entry = {
        "name": step.name,
        "ok": ok,
        "started": started,
        "ended": ended,
        "elapsed": elapsed,
        "tactic": meta.get("tactic", ""),
        "techniques": meta.get("techniques", []),
    }
    if err:
        entry["error"] = err
    return entry


def run_chain(ctx: Context, *, only=None, start=None, stop=None) -> Context:
    selected = _select(CHAIN, only=only, start=start, stop=stop)
    _print_banner(ctx, selected)

    run_id = _iso_utc()
    results: list[dict] = []
    executed: list[Step] = []

    try:
        for i, step in enumerate(selected, 1):
            missing = [k for k in step.requires if k not in ctx.state]
            if missing:
                msg = (
                    f"step {step.name!r} missing required state: {missing}. "
                    "Run an earlier step that produces it."
                )
                if step.optional:
                    log.warning(msg)
                    continue
                raise RuntimeError(msg)

            _print_step_header(step, i, len(selected))
            started = _iso_utc()
            t0 = time.perf_counter()
            ok = True
            err = ""
            try:
                delta = step.run(ctx) or {}
            except Exception as exc:
                ok = False
                err = str(exc)
                if not step.optional:
                    elapsed = time.perf_counter() - t0
                    ended = _iso_utc()
                    _print_step_result(step, elapsed, ok, err)
                    results.append(_result_entry(step, ok=ok, started=started,
                                                 ended=ended, elapsed=elapsed, err=err))
                    raise
            elapsed = time.perf_counter() - t0
            ended = _iso_utc()
            ctx.state.update(delta)
            executed.append(step)
            _print_step_result(step, elapsed, ok, err)
            results.append(_result_entry(step, ok=ok, started=started,
                                         ended=ended, elapsed=elapsed))
            time.sleep(0.5)

    finally:
        for step in reversed(executed):
            if step.teardown is None:
                continue
            try:
                step.teardown(ctx)
            except Exception as exc:
                log.warning("teardown %s failed: %s", step.name, exc)

        if results:
            _print_summary(results)
            try:
                _write_ground_truth(ctx, run_id, results)
            except Exception as exc:
                log.warning("failed to write ground-truth JSON: %s", exc)

    return ctx


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--target", default=DEFAULT_TARGET)
    p.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR)
    p.add_argument("--kali-host", default=DEFAULT_KALI_HOST)
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST)

    step_names = [s.name for s in CHAIN]
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("--only", choices=step_names)
    sel.add_argument("--from", dest="start", choices=step_names)
    p.add_argument("--to", dest="stop", choices=step_names)
    p.add_argument("--list", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")

    args = p.parse_args(argv)
    if args.only is not None and args.stop is not None:
        p.error("--only cannot be combined with --to")
    return args


def _list_steps() -> None:
    console.print(Rule("[dim]configured steps[/dim]", style="dim"))
    for step in CHAIN:
        meta = STEP_META.get(step.name, {})
        color = meta.get("color", "white")
        reqs = f"  [dim]requires: {', '.join(step.requires)}[/dim]" if step.requires else ""
        opt = "  [dim][optional][/dim]" if step.optional else ""
        techniques = "  ".join(f"[dim]{t}[/dim]" for t in meta.get("techniques", []))
        console.print(
            f"  [{color}]{step.name:<10}[/{color}]"
            f"  [dim italic]{meta.get('tactic', ''):<35}[/dim italic]"
            f"  {techniques}{reqs}{opt}"
        )
    console.print()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[dim][%(name)s][/dim] %(message)s",
    )
    if args.list:
        _list_steps()
        return 0

    ctx = Context(
        target=args.target,
        results_dir=args.results_dir,
        kali_host=args.kali_host,
        wordlist=args.wordlist,
    )
    run_chain(ctx, only=args.only, start=args.start, stop=args.stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
