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

from chainlog import log

DEFAULT_TARGET = "router"
DEFAULT_RESULTS_DIR = "/Attack-chain/results"
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_PACING = "fast"

EXT_LIST = [".php", ".html", ".txt", ".bak", ".sh", ".cgi", ".old"]

# Per-pacing scan profiles. Only `realistic` slows scans down — `fast` keeps
# scans fast because the user-visible realism in that mode comes from
# inter-phase dwell, not intra-phase pacing.
SCAN_PROFILES = {
    "fast": {
        "nmap_T": "-T4",
        # `-p-` = all 65,535 TCP ports. At -T4 timing this takes ~30s
        # against our single-host targets — fine for dev/CI.
        "nmap_ports": ["-p-"],
        "gobuster_extra": [],
        "ffuf_extra": [],
    },
    "realistic": {
        "nmap_T": "-T2",
        # NOT `-p-` at -T2 — that's 65k ports × 400ms minimum scan-delay =
        # 7+ hours per host, which never finishes inside a session window.
        # Real "low-and-slow" attackers don't scan -p- either; they pick a
        # top-N port set so they finish before the SOC notices. Top-1000
        # covers every interesting service in this lab (22/80/443/3389/
        # 5432/5900-5901/27017/etc.) AND matches nmap's own default port
        # set when -p is omitted, which is what a realistic attacker
        # would actually run.
        "nmap_ports": ["--top-ports", "1000"],
        "gobuster_extra": ["--delay", "100ms", "-t", "5"],
        "ffuf_extra": ["-rate", "30"],
    },
}


def _header(num: int, name: str) -> None:
    log(f"\n=== Phase {num}: {name} ===", flush=True)


def _run(cmd: list[str], *, check: bool = True) -> int:
    """Stream a subprocess to stdout/stderr; return its exit code."""
    log("$ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, check=False)
    if check and proc.returncode != 0:
        raise SystemExit(
            f"Command failed (exit {proc.returncode}): {' '.join(cmd)}"
        )
    return proc.returncode


def phase_nmap_full(target: str, results_dir: Path, *, pacing: str = DEFAULT_PACING) -> Path:
    _header(1, f"nmap discovery scan ({target}, pacing={pacing})")
    out = results_dir / "nmap-fullscan.txt"
    profile = SCAN_PROFILES.get(pacing, SCAN_PROFILES[DEFAULT_PACING])
    _run(
        ["nmap", "-Pn", "-sS", profile["nmap_T"]]
        + profile["nmap_ports"]
        + [target, "-oN", str(out)]
    )
    return out


def phase_nmap_services(target: str, results_dir: Path, *, pacing: str = DEFAULT_PACING) -> Path:
    _header(2, "nmap version + default scripts on open ports")
    out = results_dir / "nmap-services.txt"
    fullscan = results_dir / "nmap-fullscan.txt"
    if not fullscan.exists():
        log(f"No fullscan output at {fullscan} — skipping.")
        out.write_text("")
        return out

    ports = re.findall(
        r"^(\d+)/tcp\s+open", fullscan.read_text(), flags=re.MULTILINE
    )
    if not ports:
        log("No open ports from phase 1 — skipping.")
        out.write_text("")
        return out

    port_list = ",".join(ports)
    log(f"Open ports: {port_list}")
    profile = SCAN_PROFILES.get(pacing, SCAN_PROFILES[DEFAULT_PACING])
    _run(
        [
            "nmap", "-Pn", "-sS", "-sV", "-sC", profile["nmap_T"],
            "-p", port_list, target, "-oN", str(out),
        ]
    )
    return out


def phase_gobuster(target: str, results_dir: Path, wordlist: Path,
                   *, pacing: str = DEFAULT_PACING) -> Path:
    _header(3, "gobuster directory enumeration")
    out = results_dir / "gobuster.txt"
    if not wordlist.exists():
        log(f"Wordlist {wordlist} not found — skipping.")
        out.write_text("")
        return out
    profile = SCAN_PROFILES.get(pacing, SCAN_PROFILES[DEFAULT_PACING])
    # Apache now redirects :80 → :443, so every URL on :80 returns 301.
    # gobuster's wildcard-detection bails out unless we either go directly
    # to :443 (with -k to ignore self-signed) or tell it to exclude 301.
    # Hitting :443 is more realistic for what a real recon would do.
    _run(
        [
            "gobuster", "dir",
            "-u", f"https://{target}",
            "-k",                      # accept self-signed cert
            "-w", str(wordlist),
            "-o", str(out),
            "-q",
            *profile["gobuster_extra"],
        ]
    )
    return out


def phase_ffuf(target: str, results_dir: Path, *, pacing: str = DEFAULT_PACING) -> Path:
    _header(4, "ffuf extension fuzz")
    out = results_dir / "ffuf.json"
    ext_file = results_dir / ".web-extensions.txt"
    ext_file.write_text("\n".join(EXT_LIST) + "\n")
    profile = SCAN_PROFILES.get(pacing, SCAN_PROFILES[DEFAULT_PACING])
    # ffuf can exit non-zero when no matches are found — don't make it fatal.
    # Hit :443 directly so ffuf doesn't trip on the :80 → :443 redirect.
    _run(
        [
            "ffuf",
            "-w", f"{ext_file}:FUZZ",
            "-u", f"https://{target}/indexFUZZ",
            "-k",                      # accept self-signed cert
            "-o", str(out),
            "-of", "json",
            "-s",
            *profile["ffuf_extra"],
        ],
        check=False,
    )
    return out


def phase_nikto(target: str, results_dir: Path, *, pacing: str = DEFAULT_PACING) -> Path:
    # nikto doesn't have a clean rate-limit knob; pacing is ignored here
    # but kept in the signature so the caller can pass it uniformly.
    _header(5, "nikto vulnerability scan")
    # nikto's -o auto-appends a format extension; pass the basename without
    # .txt and force -Format txt so the result lands at nikto.txt.
    final = results_dir / "nikto.txt"
    final.unlink(missing_ok=True)
    (results_dir / "nikto.txt.txt").unlink(missing_ok=True)
    _run(
        [
            "nikto",
            "-h", f"https://{target}",
            "-ssl",                    # explicit TLS (some nikto versions need this even with https://)
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
    *,
    pacing: str = DEFAULT_PACING,
) -> None:
    """Run the recon flow. If phase is None, run all phases in order.

    Designed to be called from Attack-chain/main.py.

    Pacing controls scan-tool timing:
      fast            — aggressive flags, full -p- port scan (~30 s total)
      realistic       — slow flags: nmap -T2 with --top-ports 1000 (NOT -p-,
                        which would take 7+ hours at -T2's 400 ms scan-delay),
                        gobuster --delay 100 ms, ffuf -rate 30. Produces the
                        low-and-slow probe pattern a real SOC sees from a
                        careful attacker, completing in ~10-15 minutes total.
    """
    results = Path(results_dir)
    results.mkdir(parents=True, exist_ok=True)
    wl = Path(wordlist)

    def call(name: str) -> None:
        fn = PHASES[name]
        if name == "gobuster":
            fn(target, results, wl, pacing=pacing)
        else:
            fn(target, results, pacing=pacing)

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

    log(f"\nRecon complete. Results in {results}")


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
    p.add_argument(
        "--pacing",
        choices=list(SCAN_PROFILES),
        default=DEFAULT_PACING,
        help="Scan-tool timing profile (fast/relative aggressive, realistic stealthy).",
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args(sys.argv[1:])
    run(
        target=args.target,
        results_dir=args.results_dir,
        wordlist=args.wordlist,
        phase=args.phase,
        pacing=args.pacing,
    )
