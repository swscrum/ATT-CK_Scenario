#!/usr/bin/env python3
"""Background-noise generator for the lab.

Lives in its own container (``noise_user_sim``, public_net 10.10.0.5) so the
source IP of the noise is **different from the attacker's** (kali, 10.10.0.2).
A SOC trainee can no longer filter the attacker out by ``src_ip != 10.10.0.2``
alone — they must look at the actual request patterns, User-Agents, and paths.

Behaviour
=========
- Spawns ``NUM_THREADS`` workers, each looping a GET to a random "legit"
  path on ``--target`` (router, which DNATs :80 → apache in the DMZ) with a
  random "legit" User-Agent every ``MIN_INTERVAL_SEC..MAX_INTERVAL_SEC``
  real-time seconds.
- A small fraction of requests deliberately probe paths that 404, mimicking
  the ambient internet background scan that every public webserver gets
  (WordPress probes, ``.env`` discovery, etc.). These look suspicious but
  are *not* the attacker, so they teach the SOC trainee to look past
  surface anomalies.

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
- ``NOISE_ENABLED``      — "1" to run; anything else → sleep forever (so
                           the container stays up but generates no traffic).
                           Set to "0" by run.sh when ``--pacing fast``.
- ``NOISE_TARGET``       — hostname/IP to GET against (default: ``router``).
- ``NOISE_THREADS``      — worker thread count (default: 3).
- ``NOISE_PROBE_PCT``    — % chance per request of a 404-yielding probe
                           path (default: 10).
"""
from __future__ import annotations

import logging
import os
import random
import signal
import sys
import threading
import time
import urllib.error
import urllib.request


# Paths a legit user / health monitor would hit on the booking site.
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

# Paths that random internet bots probe on every public webserver — these
# all 404 against our apache config. Including them puts the attacker's
# real CGI probes (/cgi-bin/...) in a sea of similar-shaped suspicious
# noise so detection has to look at *which* suspicious path, not whether
# the source generated any 404s.
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

LEGIT_UAS = [
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "WaystarMonitor/2.1 (+https://waystar.local/monitor) healthcheck",
]

# UAs the bots / scanners typically send.
BOT_UAS = [
    "Mozilla/5.0 (compatible; censys-go-scanner)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
]

# Real-time bounds between hits per thread (seconds).
MIN_INTERVAL_SEC = 30
MAX_INTERVAL_SEC = 120
NUM_THREADS_DEFAULT = 3

log = logging.getLogger("noise")


def _pick_request(probe_pct: int) -> tuple[str, str]:
    """Return (path, user_agent) — a probe with probability ``probe_pct``%."""
    if random.randrange(100) < probe_pct:
        return random.choice(PROBE_PATHS), random.choice(BOT_UAS)
    return random.choice(LEGIT_PATHS), random.choice(LEGIT_UAS)


def _worker(stop_event: threading.Event, target: str, probe_pct: int) -> None:
    """One thread; loops GETting random URLs with realistic intervals."""
    while not stop_event.is_set():
        delay = random.uniform(MIN_INTERVAL_SEC, MAX_INTERVAL_SEC)
        if stop_event.wait(timeout=delay):
            return
        path, ua = _pick_request(probe_pct)
        url = f"http://{target}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": ua, "Accept": "text/html,*/*;q=0.8"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read(64)
                log.debug("noise GET %s → %d", url, resp.status)
        except urllib.error.HTTPError as exc:
            # Expected for PROBE_PATHS — 404/403/etc. is precisely the point.
            log.debug("noise GET %s → %d", url, exc.code)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            log.debug("noise GET failed for %s: %s", url, exc)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [noise] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logging.Formatter.converter = time.gmtime

    enabled = os.environ.get("NOISE_ENABLED", "0") == "1"
    target = os.environ.get("NOISE_TARGET", "router")
    threads_n = int(os.environ.get("NOISE_THREADS", str(NUM_THREADS_DEFAULT)))
    probe_pct = int(os.environ.get("NOISE_PROBE_PCT", "10"))

    if not enabled:
        log.info("NOISE_ENABLED=0 — sleeping forever (container stays up, no traffic)")
        # Keep the container alive so compose doesn't restart-loop it, but
        # generate no traffic.
        signal.pause()
        return 0

    log.info("starting: target=%s threads=%d probe_pct=%d interval=%ds-%ds",
             target, threads_n, probe_pct, MIN_INTERVAL_SEC, MAX_INTERVAL_SEC)

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
            args=(stop_event, target, probe_pct),
            name=f"noise-{i}",
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
