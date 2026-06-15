#!/usr/bin/env python3
"""Advanced initial reconnaissance (advanced chain step 1).

Replaces the loud ``initial_recon_1.py`` (nmap full-scan + gobuster + ffuf +
nikto) with an APT-style minimal probe: three HTTP requests that confirm the
Apache banner and the presence of ``mod_cgi`` -- the only two facts the
attacker actually needs before firing the CVE-2021-41773 exploit. No port
sweep, no directory bruteforce, no vulnerability scanner.

The narrative around the probes simulates prior OSINT (Shodan / Censys /
certificate transparency) -- log lines surface that context to the operator
console and to ``chain-<run_id>.json`` so the SOC analyst sees a recognisable
APT recon footprint instead of scanner noise.
"""
# MITRE ATT&CK:
#   T1595.002 - Active Scanning: Vulnerability Scanning  (single targeted probe)
#   T1592.002 - Gather Victim Host Information: Software  (Apache banner grab)
#   T1590.005 - Gather Victim Network Information: IP Addresses  (OSINT narrative)
#   T1583.006 - Acquire Infrastructure: Web Services  (Shodan / Censys mention)
# -----------------------------------------------------------------------------
# Detection trade-off: basic mode produces ~thousands of access.log entries
# with gobuster / nikto / ffuf User-Agents -- trivial to detect on UA alone.
# Advanced mode produces <= 3 GETs with a browser UA, blending into normal
# background traffic. The SOC training challenge moves from "spot the noisy
# scanner" to "time-correlate the one benign probe at T-5min with the
# exploit at T+0".
# =============================================================================

from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from chainlog import log

DEFAULT_TARGET = "router"
DEFAULT_RESULTS_DIR = "/Attack-chain/results"
DEFAULT_KALI_HOST = "10.10.0.2"

# Current-looking desktop browser UA so the probes blend into normal traffic
# in apache/access.log alongside genuine user requests.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
)

# Short per-request timeout: keeps the chain snappy but long enough that a
# slow apache start-up doesn't false-fail the recon step.
HTTP_TIMEOUT = 5.0


def _probe(url: str, *, method: str) -> tuple[int, dict[str, str], bytes]:
    """Issue one HTTP request with the browser UA, return (status, headers, body).        """
    req = urllib.request.Request(url, method=method, headers={"User-Agent": BROWSER_UA})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status, dict(resp.headers), resp.read(4096)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers) if exc.headers else {}, b""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log(f"[!] probe failed: {method} {url} -> {exc}")
        return 0, {}, b""


def _osint_narrative(target: str) -> None:
    log("[*] Phase 0 -- OSINT (no packets to target yet)")
    log(f"    Shodan match     : Apache httpd / port 80 on {target}")
    log(f"    Cert transparency: waystar-royco.example -> {target}")
    log(f"    Wayback snapshot : /cgi-bin/ present in 2024-Q4 crawl")
    log("    Conclusion       : Apache + mod_cgi, candidate for CVE-2021-41773")


def phase_banner_grab(target: str) -> tuple[int, str]:
    """Phase 1 -- one GET / with a browser UA; return ``(status, server_header)``."""
    log(f"\n=== Phase 1: banner grab GET http://{target}/ ===")
    status, headers, _ = _probe(f"http://{target}/", method="GET")
    server = headers.get("Server", "")
    log(f"[+] GET /  -> {status}  Server: {server!r}")
    return status, server


def phase_modcgi_probe(target: str) -> int:
    """Phase 2 -- HEAD /cgi-bin/ to confirm ``mod_cgi`` is loaded.
    """
    log(f"\n=== Phase 2: mod_cgi probe HEAD http://{target}/cgi-bin/ ===")
    status, _, _ = _probe(f"http://{target}/cgi-bin/", method="HEAD")
    if status == 403:
        log("[+] HEAD /cgi-bin/  -> 403 Forbidden  (mod_cgi loaded, listing denied)")
    elif status == 404:
        log("[-] HEAD /cgi-bin/  -> 404 Not Found  (mod_cgi NOT loaded -- exploit will fail)")
    else:
        log(f"[?] HEAD /cgi-bin/  -> {status}  (unexpected; proceeding optimistically)")
    return status


def phase_robots(target: str) -> int:
    """Phase 3 -- one GET /robots.txt to blend into normal crawler traffic."""
    log(f"\n=== Phase 3: cover-traffic GET http://{target}/robots.txt ===")
    status, _, _ = _probe(f"http://{target}/robots.txt", method="GET")
    log(f"[+] GET /robots.txt  -> {status}  (blends into normal crawler traffic)")
    return status


def _write_artefact(
    results_dir: Path,
    target: str,
    banner: str,
    banner_status: int,
    cgi_status: int,
    robots_status: int,
) -> Path:
    """Drop a small text artefact mirroring basic-mode's ``nmap-*.txt`` outputs."""
    out = results_dir / "advanced-recon.txt"
    out.write_text(
        f"# advanced_initial_recon -- {target}\n"
        f"# Three HTTP probes, browser UA, no scanner footprint.\n"
        f"phase_1_banner_grab    status={banner_status}  server={banner!r}\n"
        f"phase_2_cgi_probe      status={cgi_status}\n"
        f"phase_3_cover_traffic  status={robots_status}\n",
        encoding="utf-8",
    )
    log(f"[+] wrote {out}")
    return out


def run(
    target: str = DEFAULT_TARGET,
    results_dir: str | os.PathLike[str] = DEFAULT_RESULTS_DIR,
    kali_host: str = DEFAULT_KALI_HOST,
) -> None:
    """Run the advanced recon flow."""
    results = Path(results_dir)
    results.mkdir(parents=True, exist_ok=True)
    _ = kali_host  # accepted for adapter parity

    _osint_narrative(target)
    banner_status, banner = phase_banner_grab(target)
    cgi_status = phase_modcgi_probe(target)
    robots_status = phase_robots(target)

    _write_artefact(results, target, banner, banner_status, cgi_status, robots_status)
    log(f"\n[+] Advanced recon complete. Artefact in {results}")


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
        help=f"Where the recon artefact goes (default: {DEFAULT_RESULTS_DIR})",
    )
    p.add_argument(
        "--kali-host",
        default=os.environ.get("KALI_HOST", DEFAULT_KALI_HOST),
        help=(
            "Kali host (accepted for adapter parity; unused here) "
            f"(default: {DEFAULT_KALI_HOST})"
        ),
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args(sys.argv[1:])
    run(target=args.target, results_dir=args.results_dir, kali_host=args.kali_host)
