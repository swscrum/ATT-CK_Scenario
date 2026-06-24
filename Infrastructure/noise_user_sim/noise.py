#!/usr/bin/env python3
"""Background-noise generator for the lab.

One Docker image, four containers, each picks a *persona* via the
``NOISE_PERSONA`` env var (general / monitor / scanner / mobile). Each
persona is **monomorphic** — one consistent behavior class — which is
how real internet traffic actually looks at a public webserver:
desktop browsers don't suddenly probe ``/wp-login.php``; uptime monitors
don't hit anything except their one endpoint; etc.

This defeats the trivial SOC filter "exclude src_ip in {kali, noise}"
because there are now four noise IPs each doing something distinct, AND
defeats the lazy "anything with a bot UA is noise" heuristic because
behavioral patterns matter as much as User-Agent strings.

Personas (configured via PERSONAS dict below):

| persona  | typical IP   | paths           | UAs       | interval        | threads |
|----------|--------------|-----------------|-----------|-----------------|---------|
| general  | 10.10.0.5    | LEGIT_PATHS     | HUMAN_UAS | 30–120s         | 3       |
| monitor  | 10.10.0.6    | /api/health     | MONITOR_UA| 55–65s          | 1       |
| scanner  | 10.10.0.7    | PROBE_PATHS     | BOT_UAS   | 60–300s         | 2       |
| mobile   | 10.10.0.8    | LEGIT_PATHS     | MOBILE_UAS| 300–900s        | 1       |

Why no rate scaling
===================
Earlier iterations scaled the inter-request interval by a ``pacing_speed``
divisor so noise tempo matched chain tempo. With only ``fast`` and
``realistic`` pacing left, that's pointless: in ``fast`` the noise is
turned off entirely (chain runs in seconds — no point); in ``realistic``
the noise should run at *real wall-clock* rates because the diurnal
rewriter stretches everything (attack + noise) by the same factor at the
end, preserving the original noise:attack temporal ratio.

Lifecycle
=========
Runs forever until SIGTERM/SIGINT (the standard signals docker compose
sends on ``stop``). Workers shut down promptly via a shared
``threading.Event``.

Environment variables (read at startup)
=======================================
- ``NOISE_ENABLED``  — "1" to run; anything else → sleep forever (so the
                       container stays up but generates no traffic).
                       Set to "0" by tools/run.sh when ``--pacing fast``.
- ``NOISE_PERSONA``  — one of {general,monitor,scanner,mobile}; selects
                       the behavior class. Default: ``general``.
- ``NOISE_TARGET``   — hostname/IP to GET against (default: ``router``).
- ``NOISE_THREADS``  — override the persona's default thread count.
                       Rarely needed; default is per-persona.
"""
from __future__ import annotations

import logging
import os
import random
import signal
import sys
import threading
import time
import ssl
import urllib.error
import urllib.request


# Self-signed cert acceptance — apache's lab cert (CN=apache, SAN=DNS:apache,
# IP:10.40.0.2) won't validate against the system trust store. Real noise
# sources in the wild would either trust a CA-signed cert or run with
# certificate-skipping curl/wget; we model the latter (the practical reality
# for many monitor/scanner clients hitting public sites with weird CAs).
# One context shared across all workers — cheaper than building per-request.
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


# ─────────────────────────────────────────────────────────── Paths

# What a real human browsing waystar-connect would touch.
LEGIT_PATHS = [
    "/",
    "/api/health",
    "/api/version",
    "/static/css/main.css",
    "/static/js/app.js",
    "/favicon.ico",
    "/robots.txt",
    "/about.html",
    "/contact",
    "/assets/index-Cb9vdwyu.css",
    "/assets/index-CnI_Q0Cw.js",
]

# Paths random internet bots probe on every public webserver — all 404
# against our apache config. The scanner persona emits these and only
# these, modelling the ambient internet background scan.
PROBE_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/.env",
    "/.git/config",
    "/phpmyadmin/",
    "/admin/",
    "/xmlrpc.php",
    "/server-status",
    "/.aws/credentials",
]


# ─────────────────────────────────────────────────────────── User-Agents

# Desktop browsers — what general human traffic looks like.
HUMAN_UAS = [
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# What real uptime monitors send — Pingdom/UptimeRobot/etc. shape.
# Single UA per persona is realistic: a monitor doesn't rotate UAs.
MONITOR_UA = "WaystarMonitor/2.1 (+https://waystar.local/monitor) healthcheck"

# Mobile browsers — same paths as desktop humans but a different UA family
# and much sparser cadence (people pull their phones out, not constantly).
MOBILE_UAS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
]

# What internet scanners and exploit kits identify as. These ARE
# suspicious-looking strings — that's the point: teaches the SOC trainee
# that bot UA != attacker (the attacker's CGI POSTs come WITHOUT a UA).
BOT_UAS = [
    "Mozilla/5.0 (compatible; censys-go-scanner)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
]


# ─────────────────────────────────────────────────────────── Personas

PERSONAS: dict[str, dict] = {
    # General desktop browsing — the majority of real traffic.
    "general": {
        "paths": LEGIT_PATHS,
        "uas": HUMAN_UAS,
        "min_interval": 30,
        "max_interval": 120,
        "threads": 3,
    },
    # Uptime monitor: predictable cadence, single endpoint, single UA.
    # Distinctive shape in time-series views (hits exactly every ~60s).
    # Targets `/` (returns 200) rather than `/api/health` (returns 404 — the
    # booking site doesn't ship an API health endpoint), so the monitor
    # signal looks like a HEALTHY uptime check, not a broken one.
    "monitor": {
        "paths": ["/"],
        "uas": [MONITOR_UA],
        "min_interval": 55,
        "max_interval": 65,
        "threads": 1,
    },
    # Internet background scanner: bot UAs, 404-yielding probes.
    # Looks suspicious but is NOT the attacker — teaches "suspicious
    # surface anomaly != malicious"; SOC trainee must look at WHICH
    # suspicious path (the attacker hits /cgi-bin, scanners don't).
    "scanner": {
        "paths": PROBE_PATHS,
        "uas": BOT_UAS,
        "min_interval": 60,
        "max_interval": 300,
        "threads": 2,
    },
    # Mobile browsing: same paths as general but mobile UAs and a much
    # sparser cadence. Teaches that legit traffic has wildly varying
    # *interval* shapes, not just IPs.
    "mobile": {
        "paths": LEGIT_PATHS,
        "uas": MOBILE_UAS,
        "min_interval": 300,
        "max_interval": 900,
        "threads": 1,
    },
}
DEFAULT_PERSONA = "general"


log = logging.getLogger("noise")


def _worker(stop_event: threading.Event, target: str,
            paths: list[str], uas: list[str],
            min_interval: int, max_interval: int) -> None:
    """One thread; loops GETting random URLs from this persona's lists."""
    while not stop_event.is_set():
        delay = random.uniform(min_interval, max_interval)
        if stop_event.wait(timeout=delay):
            return
        path = random.choice(paths)
        ua = random.choice(uas)
        url = f"https://{target}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": ua, "Accept": "text/html,*/*;q=0.8"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5, context=_TLS_CTX) as resp:
                resp.read(64)
                log.debug("GET %s → %d", url, resp.status)
        except urllib.error.HTTPError as exc:
            # Expected for scanner persona — 404/403 is precisely the point.
            log.debug("GET %s → %d", url, exc.code)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            log.debug("GET failed for %s: %s", url, exc)


def main() -> int:
    persona_name = os.environ.get("NOISE_PERSONA", DEFAULT_PERSONA).strip().lower()
    if persona_name not in PERSONAS:
        # Fall back rather than crash — keeps the container up so compose
        # doesn't restart-loop on a typo. Log loudly.
        print(f"[noise] WARN: unknown persona {persona_name!r}, "
              f"falling back to {DEFAULT_PERSONA!r} (valid: {sorted(PERSONAS)})",
              file=sys.stderr)
        persona_name = DEFAULT_PERSONA

    logging.basicConfig(
        level=logging.INFO,
        format=f"[%(asctime)s] [noise:{persona_name}] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logging.Formatter.converter = time.gmtime

    persona = PERSONAS[persona_name]
    enabled = os.environ.get("NOISE_ENABLED", "0") == "1"
    target = os.environ.get("NOISE_TARGET", "router")
    # NOISE_THREADS override is rarely needed — defaults to persona-specified.
    threads_n = int(os.environ.get("NOISE_THREADS", str(persona["threads"])))

    if not enabled:
        log.info("NOISE_ENABLED=0 — sleeping forever (container stays up, no traffic)")
        # Keep the container alive so compose doesn't restart-loop it, but
        # generate no traffic.
        signal.pause()
        return 0

    log.info("starting: target=%s threads=%d interval=%ds-%ds paths=%d uas=%d",
             target, threads_n,
             persona["min_interval"], persona["max_interval"],
             len(persona["paths"]), len(persona["uas"]))

    stop_event = threading.Event()

    def _shutdown(signum, _frame) -> None:
        log.info("received signal %d — shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    workers = []
    for i in range(threads_n):
        t = threading.Thread(
            target=_worker,
            args=(stop_event, target,
                  persona["paths"], persona["uas"],
                  persona["min_interval"], persona["max_interval"]),
            name=f"{persona_name}-{i}",
            daemon=True,
        )
        t.start()
        workers.append(t)

    # Block PID 1 on the stop event; signals above flip it.
    stop_event.wait()
    for t in workers:
        t.join(timeout=2.0)
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
