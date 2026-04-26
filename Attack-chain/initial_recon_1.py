#!/usr/bin/env python3
"""Initial recon (chain step 1).

Runs nmap → gobuster → ffuf → nikto against a target and writes results to
RESULTS_DIR. Designed to be invoked from a future Attack-chain/main.py via
`from initial_recon_1 import run`, or standalone via the CLI below.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_TARGET = "router"
DEFAULT_RESULTS_DIR = "/Attack-chain/results"
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

EXT_LIST = [".php", ".html", ".txt", ".bak", ".sh", ".cgi", ".old"]


def _header(num: int, name: str) -> None:
    print(f"\n=== Phase {num}: {name} ===", flush=True)


def _run(cmd: list[str], *, check: bool = True) -> int:
    """Stream a subprocess to stdout/stderr; return its exit code."""
    print("$ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, check=False)
    if check and proc.returncode != 0:
        raise SystemExit(
            f"Command failed (exit {proc.returncode}): {' '.join(cmd)}"
        )
    return proc.returncode


def phase_nmap_full(target: str, results_dir: Path) -> Path:
    _header(1, f"nmap full TCP scan ({target})")
    out = results_dir / "nmap-fullscan.txt"
    _run(["nmap", "-Pn", "-sS", "-p-", target, "-oN", str(out)])
    return out


def phase_nmap_services(target: str, results_dir: Path) -> Path:
    _header(2, "nmap version + default scripts on open ports")
    out = results_dir / "nmap-services.txt"
    fullscan = results_dir / "nmap-fullscan.txt"
    if not fullscan.exists():
        print(f"No fullscan output at {fullscan} — skipping.")
        out.write_text("")
        return out

    ports = re.findall(
        r"^(\d+)/tcp\s+open", fullscan.read_text(), flags=re.MULTILINE
    )
    if not ports:
        print("No open ports from phase 1 — skipping.")
        out.write_text("")
        return out

    port_list = ",".join(ports)
    print(f"Open ports: {port_list}")
    _run(
        [
            "nmap", "-Pn", "-sS", "-sV", "-sC",
            "-p", port_list, target, "-oN", str(out),
        ]
    )
    return out


def phase_gobuster(target: str, results_dir: Path, wordlist: Path) -> Path:
    _header(3, "gobuster directory enumeration")
    out = results_dir / "gobuster.txt"
    if not wordlist.exists():
        print(f"Wordlist {wordlist} not found — skipping.")
        out.write_text("")
        return out
    _run(
        [
            "gobuster", "dir",
            "-u", f"http://{target}",
            "-w", str(wordlist),
            "-o", str(out),
            "-q",
        ]
    )
    return out


def phase_ffuf(target: str, results_dir: Path) -> Path:
    _header(4, "ffuf extension fuzz")
    out = results_dir / "ffuf.json"
    ext_file = results_dir / ".web-extensions.txt"
    ext_file.write_text("\n".join(EXT_LIST) + "\n")
    # ffuf can exit non-zero when no matches are found — don't make it fatal.
    _run(
        [
            "ffuf",
            "-w", f"{ext_file}:FUZZ",
            "-u", f"http://{target}/indexFUZZ",
            "-o", str(out),
            "-of", "json",
            "-s",
        ],
        check=False,
    )
    return out


def phase_nikto(target: str, results_dir: Path) -> Path:
    _header(5, "nikto vulnerability scan")
    # nikto's -o auto-appends a format extension; pass the basename without
    # .txt and force -Format txt so the result lands at nikto.txt.
    final = results_dir / "nikto.txt"
    final.unlink(missing_ok=True)
    (results_dir / "nikto.txt.txt").unlink(missing_ok=True)
    _run(
        [
            "nikto",
            "-h", f"http://{target}",
            "-Tuning", "b",
            "-Format", "txt",
            "-o", str(results_dir / "nikto"),
        ],
        check=False,
    )
    return final


PHASES = {
    "nmap_full": phase_nmap_full,
    "nmap_services": phase_nmap_services,
    "gobuster": phase_gobuster,
    "ffuf": phase_ffuf,
    "nikto": phase_nikto,
}


def run(
    target: str = DEFAULT_TARGET,
    results_dir: str | os.PathLike[str] = DEFAULT_RESULTS_DIR,
    wordlist: str | os.PathLike[str] = DEFAULT_WORDLIST,
    phase: str | None = None,
) -> None:
    """Run the recon flow. If phase is None, run all phases in order.

    Designed to be called from Attack-chain/main.py.
    """
    results = Path(results_dir)
    results.mkdir(parents=True, exist_ok=True)
    wl = Path(wordlist)

    def call(name: str) -> None:
        fn = PHASES[name]
        if name == "gobuster":
            fn(target, results, wl)
        else:
            fn(target, results)

    if phase is not None:
        if phase not in PHASES:
            raise SystemExit(
                f"Unknown phase {phase!r}; choose one of: "
                + ", ".join(PHASES)
            )
        call(phase)
        return

    for name in PHASES:
        call(name)

    print(f"\nRecon complete. Results in {results}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--target",
        default=os.environ.get("RECON_TARGET", DEFAULT_TARGET),
        help=f"Target hostname or IP (default: {DEFAULT_TARGET})",
    )
    p.add_argument(
        "--results-dir",
        default=os.environ.get("RECON_RESULTS_DIR", DEFAULT_RESULTS_DIR),
        help=f"Where scan output goes (default: {DEFAULT_RESULTS_DIR})",
    )
    p.add_argument(
        "--wordlist",
        default=os.environ.get("WORDLIST", DEFAULT_WORDLIST),
        help=f"Wordlist for gobuster (default: {DEFAULT_WORDLIST})",
    )
    p.add_argument(
        "--phase",
        choices=list(PHASES),
        help="Run a single phase instead of the full flow.",
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args(sys.argv[1:])
    run(
        target=args.target,
        results_dir=args.results_dir,
        wordlist=args.wordlist,
        phase=args.phase,
    )
