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
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger("chain")

DEFAULT_TARGET = "router"
DEFAULT_RESULTS_DIR = "/Attack-chain/results"
DEFAULT_KALI_HOST = "10.10.0.2"
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


@dataclass
class Context:
    """State carried between chain steps.

    ``state`` holds runtime objects that can't be passed via CLI flags —
    sockets, parsed recon output, captured credentials. Steps read keys
    declared in ``Step.requires`` and write keys via the dict they return.
    """

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
# Per-step adapters. Each one is the seam between the orchestrator's Context
# and the module's native run() signature. Keep them small.
# ---------------------------------------------------------------------------


def _step_recon(ctx: Context) -> dict[str, Any]:
    from initial_recon_1 import run as recon_run

    recon_run(
        target=ctx.target,
        results_dir=ctx.results_dir,
        wordlist=ctx.wordlist,
    )
    return {"recon_results": ctx.results_dir}


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
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                log.warning("failed to close %s: %s", key, exc)

    return _close


# ---------------------------------------------------------------------------
# Chain definition. Order matters; ``requires`` declares the data dependency
# so a misconfigured chain fails pre-flight instead of mid-run.
# ---------------------------------------------------------------------------

CHAIN: list[Step] = [
    Step("recon", _step_recon),
    # Step("exploit", _step_exploit, requires=("recon_results",),
    #      teardown=_teardown_close_socket("www_shell")),
    Step(
        "privesc",
        _step_privesc,
        requires=("www_shell",),
        teardown=_teardown_close_socket("root_shell"),
    ),
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


def _select(
    steps: list[Step],
    *,
    only: str | None,
    start: str | None,
    stop: str | None,
) -> list[Step]:
    if only is not None:
        return [steps[_index_of(only, steps)]]
    lo = _index_of(start, steps) if start else 0
    hi = _index_of(stop, steps) + 1 if stop else len(steps)
    if lo >= hi:
        raise SystemExit(f"--from {start!r} comes after --to {stop!r}")
    return steps[lo:hi]


def run_chain(
    ctx: Context,
    *,
    only: str | None = None,
    start: str | None = None,
    stop: str | None = None,
) -> Context:
    selected = _select(CHAIN, only=only, start=start, stop=stop)
    executed: list[Step] = []
    try:
        for step in selected:
            missing = [k for k in step.requires if k not in ctx.state]
            if missing:
                msg = (
                    f"step {step.name!r} missing required state: {missing}. "
                    "Run an earlier step that produces it, or pre-populate "
                    "ctx.state when calling run_chain()."
                )
                if step.optional:
                    log.warning(msg)
                    continue
                raise RuntimeError(msg)

            log.info("=== step: %s ===", step.name)
            try:
                delta = step.run(ctx) or {}
            except Exception as exc:  # noqa: BLE001 — surfaced to caller below
                if step.optional:
                    log.warning("optional step %s failed: %s", step.name, exc)
                    continue
                raise
            ctx.state.update(delta)
            executed.append(step)
    finally:
        for step in reversed(executed):
            if step.teardown is None:
                continue
            try:
                step.teardown(ctx)
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                log.warning("teardown %s failed: %s", step.name, exc)
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
    sel.add_argument(
        "--only", choices=step_names, help="Run a single step by name."
    )
    sel.add_argument(
        "--from", dest="start", choices=step_names, help="Start at this step."
    )
    p.add_argument(
        "--to", dest="stop", choices=step_names, help="Stop after this step."
    )

    p.add_argument(
        "--list", action="store_true", help="List configured steps and exit."
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    if args.only is not None and args.stop is not None:
        p.error("--only cannot be combined with --to")
    return args


def _list_steps() -> None:
    for step in CHAIN:
        reqs = f" (requires: {', '.join(step.requires)})" if step.requires else ""
        opt = " [optional]" if step.optional else ""
        print(f"  {step.name}{opt}{reqs}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(name)s] %(message)s",
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
