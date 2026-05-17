"""Background-noise daemons for realistic pacing mode.

Enabled only when ``PACING_MODES["realistic"]["noise"]`` is true. Spawns a
small pool of threads inside the kali container that issue legitimate-looking
HTTP requests to apache during the chain run. The SOC trainee then has to
*filter* attack traffic out of the noise instead of trivially spotting the
only events on the wire.

What the noise looks like:
  - GET to ordinary paths (``/``, ``/api/health``, ``/favicon.ico``, …)
  - friendly User-Agent strings (Firefox / Chrome / a fake monitor agent)
  - ``Accept: text/html`` headers
  - 30 – 120 s real-time intervals between hits, scaled by ``pacing_speed``

Limitation (documented, not fixed in this slice): traffic still originates
from the kali container's IP (10.10.0.2). A real-world SOC would whitelist
the legit *source* — not just the path. A future slice will add a
``noise_user_sim`` container on ``public_net`` so the source IP differs from
the attacker's; until then the User-Agent and path patterns are how a
detector tells noise from attack.
"""
from __future__ import annotations

import logging
import random
import threading
import urllib.error
import urllib.request
from typing import List, Tuple


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
]

LEGIT_UAS = [
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "WaystarMonitor/2.1 (+https://waystar.local/monitor) healthcheck",
]

# Real-time bounds between hits per thread (seconds). Divided by speed at run time.
MIN_INTERVAL_SEC = 30
MAX_INTERVAL_SEC = 120
NUM_THREADS = 3


def _worker(stop_event: threading.Event, target: str, speed: float,
            log: logging.Logger) -> None:
    """One thread; loops GETting random legitimate-looking URLs."""
    while not stop_event.is_set():
        delay = random.uniform(MIN_INTERVAL_SEC, MAX_INTERVAL_SEC) / speed
        # Use Event.wait so the thread can shut down promptly.
        if stop_event.wait(timeout=max(delay, 0.01)):
            return
        path = random.choice(LEGIT_PATHS)
        ua = random.choice(LEGIT_UAS)
        url = f"http://{target}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": ua, "Accept": "text/html,*/*;q=0.8"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read(64)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            log.debug("noise GET failed for %s: %s", url, exc)


def start(target: str, speed: float, log: logging.Logger
          ) -> Tuple[threading.Event, List[threading.Thread]]:
    """Spawn the noise pool. Caller is responsible for calling :func:`stop`.

    Returns the stop_event + thread list so the caller can shut them down
    cleanly at chain end (typically from a ``finally`` block).
    """
    stop_event = threading.Event()
    threads: List[threading.Thread] = []
    for i in range(NUM_THREADS):
        t = threading.Thread(
            target=_worker,
            args=(stop_event, target, speed, log),
            name=f"noise-{i}",
            daemon=True,
        )
        t.start()
        threads.append(t)
    log.info("noise: %d threads → http://%s (speed=%g×)", len(threads),
             target, speed)
    return stop_event, threads


def stop(stop_event: threading.Event, threads: List[threading.Thread],
         log: logging.Logger) -> None:
    """Signal stop, join with a short timeout (daemon threads exit anyway)."""
    stop_event.set()
    for t in threads:
        t.join(timeout=2.0)
    log.info("noise: stopped")
