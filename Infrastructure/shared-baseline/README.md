# shared-baseline/

Build-time activity baseline shared across every victim container.

## What this is

A small bash + awk hydrator (`hydrate-baseline.sh`) and a tree of persona
templates (`templates/{apache,developer,clinical,sysadmin}/`). Each
victim container's Dockerfile COPYs this directory in and its
`entrypoint.sh` calls the hydrator once at first boot, **before**
`rsyslogd` and `lab-fim.sh` start. The hydrator renders date-relative
tokens (today-anchored) and writes the result into the target log path
declared by each template's `# TARGET: <path>` header line.

The result is that every victim container comes up with 14–60 days of
believable past activity in `/var/log/auth.log`, `/var/log/dpkg.log`,
`/var/log/syslog`, and `/var/log/cleanup.log` (apache). No host has the
"clean slate" feel that defeats the SOC-training baseline.

This is **complementary** to PR #130's runtime `activity_sim.py` daemon
— hydrator writes pre-boot history; activity_sim appends present-day
activity during `--pacing realistic` runs. The two coexist cleanly.

## File layout

```
shared-baseline/
├── hydrate-baseline.sh          # bash + awk renderer, COPYed to /usr/local/bin/
├── README.md                    # this file
├── timeline.md                  # shared cross-host timestamp reference
└── templates/
    ├── apache/                  # persona: apache (DMZ webserver)
    │   ├── auth.log.tpl
    │   ├── cleanup.log.tpl
    │   ├── dpkg.log.tpl
    │   └── apt-history.log.tpl
    ├── developer/               # persona: john.stravidis on ubuntu_workstation
    │   ├── auth.log.tpl
    │   ├── dpkg.log.tpl
    │   └── apt-history.log.tpl
    ├── clinical/                # persona: luke.smith on luke_ws
    │   ├── auth.log.tpl
    │   ├── dpkg.log.tpl
    │   └── apt-history.log.tpl
    └── sysadmin/                # persona: vinzenz.fedora on vinzenz_ws
        ├── auth.log.tpl
        ├── dpkg.log.tpl
        ├── apt-history.log.tpl
        └── syslog.tpl
```

## Template format

First line declares the target log path:

```
# TARGET: /var/log/auth.log
```

Lines beginning with `#` BEFORE the first non-comment line are treated
as additional header comments (stripped). After the first non-comment
line, `#` characters are part of the rendered output (the dpkg /
apt-history log formats use `#` inside).

## Token grammar

| Token | Expands to | Example (today = 2026-06-10) |
|---|---|---|
| `{D-N}` | `YYYY-MM-DD`, N days ago, UTC | `{D-14}` → `2026-05-27` |
| `{D-N-Hh-Mm}` | ISO 8601 UTC at H:M on day N-ago | `{D-7-09h-15m}` → `2026-06-03T09:15:00Z` |
| `{BSD-N-Hh-Mm}` | rsyslog BSD timestamp | `{BSD-7-10h-23m}` → `Jun  3 10:23:00` |
| `{DPKG-N-Hh-Mm}` | dpkg.log timestamp | `{DPKG-3-14h-05m}` → `2026-06-07 14:05:00` |
| `{EPOCH-N-Hh-Mm}` | Unix epoch seconds | `{EPOCH-1-12h-00m}` → `1781006400` |
| `{HOST}` | container hostname (from `hostname`) | `vinzenz_ws` |

N is integer (days ago). H, M are two-digit hour, minute. All times
anchored to UTC midnight of the day-ago, plus the H:M offset.

## Adding a new template

1. Create `templates/<persona>/<file>.tpl`.
2. First line: `# TARGET: <absolute path>`.
3. Use the tokens above for any time-relative content. **Never** hard-code
   a year like `2026-05-15` — that decays.
4. If the template's events should correlate with another container's
   template (e.g. Vinzenz outbound matching John's inbound), use the
   **same exact token** in both places and add the slot to `timeline.md`.

## Idempotency

The hydrator touches `/var/lib/baseline-hydrated` after a successful run
and short-circuits on subsequent invocations. This prevents
`docker compose restart` from doubling the baseline. Container rebuild
(without the marker file in the new image) re-runs hydration as expected.

## Per-container wiring

Each victim container's Dockerfile gets:

```dockerfile
COPY shared-baseline/hydrate-baseline.sh        /usr/local/bin/hydrate-baseline.sh
COPY shared-baseline/templates/<persona>/       /usr/local/share/baseline/<persona>/
RUN chmod +x /usr/local/bin/hydrate-baseline.sh
```

Each `entrypoint.sh` gets a call before `rsyslogd`:

```bash
BASELINE_PERSONA=<persona> /usr/local/bin/hydrate-baseline.sh \
    || log "[entrypoint] hydrate-baseline failed (non-fatal)"
```
