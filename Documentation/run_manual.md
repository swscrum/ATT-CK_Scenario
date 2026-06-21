# Run manual

How to bring the lab up, run the attack chain, and where the resulting logs
land for SIEM ingestion. Network topology, service descriptions, and the
`db-internal` credential set are documented in the [README](../README.md);
this manual only covers what the README doesn't: orchestrator flags, chain
steps, and the full log inventory.

## Prerequisites

Docker and the Compose plugin. `cd Infrastructure` before any `docker
compose` command — all paths in `docker-compose.yml` (bind mounts, build
contexts) are relative to that directory. `tools/run.sh` does this `cd`
itself, so it can be invoked from the repo root. First run after a clone (or
after a `git pull` that touched a Dockerfile or seeded file) needs an image
build; every run after that reuses the cached layers.

## Quickstart

1. `cd Infrastructure && docker compose build`
2. `cd .. && tools/run.sh` — brings the lab up, runs the basic chain, snapshots logs, tears down
3. `cat Attack-chain/results/run-*/chain-*.json` — per-step ground truth for the run just finished
4. `ls Infrastructure/logs/run-*Z/` — apache/router/workstation log snapshot from that run
5. `tools/run.sh --keep-up` — rerun without teardown, e.g. to inspect a live container before tearing it down with `docker compose down`

## Container map

| Container | IP(s) | Networks | Host port |
|---|---|---|---|
| `kali` | 10.10.0.2 | `public_net` | — |
| `router` | 10.10.0.3 / 10.40.0.4 / 10.30.0.4 | `public_net` + `dmz_net` + `internal_net` | — |
| `apache` | 10.40.0.2 | `dmz_net` | 80 |
| `ubuntu_workstation` | 10.30.0.5 | `internal_net` | 5901 (VNC) |
| `luke_ws` | 10.30.0.7 | `internal_net` | — |
| `vinzenz_ws` | 10.30.0.8 | `internal_net` | — |
| `db-internal` | 10.30.0.6 | `internal_net` | — |

`kali` mounts `../Attack-chain` to `/Attack-chain` — the orchestrator and all
chain modules run from inside that container.

## Two ways to run

`tools/run.sh` is the default path: it brings the lab up, runs `main.py`
inside `kali` with whatever arguments you pass through, snapshots
apache/router/workstation logs into `Infrastructure/logs/run-<ISO8601>Z/`,
then tears the lab down. Use it for anything you'd report on or hand to a
SIEM demo, since it's the only path that produces that snapshot directory.

Run `main.py` directly via `docker compose exec kali python3
/Attack-chain/main.py ...` when the lab is already up and you're iterating
on a single step — no snapshot, no teardown, faster turnaround.

## Flag reference

### `tools/run.sh`

| Flag | Effect |
|---|---|
| `--build` | `docker compose up -d --build` instead of plain `up -d` — use after a Dockerfile or seed-data change |
| `--keep-up` | Skip `docker compose down` after the run; tear down later yourself |

Any other argument is forwarded verbatim to `main.py`.

### `Attack-chain/main.py`

| Flag | Effect |
|---|---|
| `--mode {basic,advanced}` | Aliases `b`/`basic`, `a`/`adv`/`advanced`. Default `basic`. |
| `--only <step>` | Run a single step. Mutually exclusive with `--from`/`--to`. |
| `--from <step> --to <step>` | Run an inclusive range of the chain. |
| `--no-linpeas` | Skip the LinPEAS drop, use targeted enumeration commands only. Default: LinPEAS enabled. |
| `--target` | Recon/exploit target host. Default `router`. |
| `--results-dir` | Default `/Attack-chain/results` (inside `kali`). |
| `--kali-host` | Default `10.10.0.2`. |
| `--wordlist` | Gobuster wordlist. Default `/usr/share/wordlists/dirb/common.txt`. |
| `--list` | Print the configured steps for `--mode` and exit. |
| `-v` / `--verbose` | Debug-level orchestrator logging. |

State produced by one step (a shell handle, a Sliver session ID, ...) lives
only in the running process's memory. `--only` or `--from` on a step that
isn't first in the chain raises `missing required state` unless you've just
run the earlier steps in the same `main.py` invocation — there is no
resume-from-disk.

## Chain steps

### `--mode basic`

| Step | Tactic · TTPs | Requires | Produces |
|---|---|---|---|
| `recon` | TA0043 · T1595, T1592 | — | — |
| `exploit` | TA0001 · T1190, T1059.004 | — | `www_shell` |
| `post_exploit_enumeration` | TA0007 · T1082, T1087.001, T1057, T1053.003, T1016, T1552.001 | `www_shell` | `cron_script` |
| `privesc` | TA0004 · T1053.003, T1068 | `www_shell`, `cron_script` | `root_shell` |
| `credential_access` | TA0006 · T1552.001 | `root_shell` | — |
| `lateral` | TA0007/TA0008 · T1018, T1046, T1110.004, T1021.004, T1078 | `root_shell` | `john_shell` |
| `enumeration_john_ws` | TA0007 · T1082, T1087.001, T1016, T1083, T1552.001, T1552.004 | `john_shell` | — |
| `exfiltrate` | TA0009/TA0010 · T1552.001, T1213, T1041 | `john_shell` | — |
| `defense_evasion` | TA0005 · T1070, T1070.001, T1070.003, T1070.004 | — | — |

`defense_evasion` runs with `optional=True` — its failures are logged but don't abort the chain.

### `--mode advanced`

| Step | Tactic · TTPs | Requires | Produces |
|---|---|---|---|
| `recon` | TA0043 · T1595.002, T1592.002, T1590.005, T1583.006 | — | — |
| `exploit` | TA0001 · T1190, T1059.006, T1620, T1036.005, T1071.001 | — | `sliver_session` |
| `webserver_post_exploit_enum` | TA0007 · T1082, T1087.001, T1057, T1083, T1548.001, T1016 | `sliver_session` | — |
| `webserver_privesc` | TA0004/TA0006 · T1548.001, T1068, T1620, T1036.005, T1552.001, T1552.004 | `sliver_session`, `cap_binary` | `root_sliver_session` |
| `webserver_persistence` | TA0003 · T1505.003 | `root_sliver_session` | — |
| `advanced_lateral_movement` | TA0008/TA0040 · T1021.004, T1556.003, T1499.004 | `root_sliver_session` | `vinzenz_beacon` |
| `advanced_vinzenzws_privesc` | TA0006 · T1546.004, T1140, T1078 | `vinzenz_beacon` | — |

Advanced mode has no `defense_evasion` step.

## Logs

| Path | Format | Ingest for |
|---|---|---|
| `Infrastructure/logs/apache/access.log`, `error.log`, `forensic_log` | Apache combined / error / forensic | `recon` (404 probe noise), `exploit` (CVE-2021-41773 traversal URI — T1190); `forensic_log` pairs `+id`/`-id` per request and captures truncated/aborted requests that never get a normal `access.log` line (useful for failed CVE-2021-41773 attempts) |
| `Infrastructure/logs/workstation/auth.log` | rsyslog ISO; sshd default `INFO` on `ubuntu_workstation` (no key fingerprint) | `Accepted publickey` for `john.stravidis` on `ubuntu_workstation` (T1021.004) |
| `Infrastructure/logs/luke_ws/auth.log`, `Infrastructure/logs/vinzenz_ws/auth.log` | rsyslog ISO; sshd `LogLevel VERBOSE` on `luke_ws` and `vinzenz_ws` (key fingerprint logged) | `Failed password` entries from the `lateral` credential-stuffing pass (T1110.004) |
| `Infrastructure/logs/db/postgresql-YYYY-MM-DD.log` | Postgres, `log_statement=all`, prefix `%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h` | every connect/disconnect and query against `waystar`, including the `pg_dump` exfil (T1213, T1041) |
| `Infrastructure/logs/attacker/attack_steps_<run_id>.log` | syslog-style key=value, one line per command: `<ts> kali attacker[<run_id>]: phase=<step> tactic="..." cmd="..."` | attacker-POV ground truth, correlate by `run_id` against defender logs |
| `Attack-chain/results/run-<run_id>/chain-<run_id>.json` | JSON, per step: `started`/`ended`/tactic/techniques/ok/elapsed | master timeline for matching SIEM alerts to chain steps |

`router` has no compose volume mount — its `/var/log` only reaches the host
via `tools/run.sh`'s teardown snapshot into
`Infrastructure/logs/run-<ISO8601>Z/router/`, alongside a duplicate copy of
the apache and workstation logs and `docker logs` stdout/stderr for `apache`,
`router`, `ubuntu_workstation`, and `kali`. Running `main.py` directly
without `run.sh` means router activity is only visible via `docker logs
router` or `docker exec router cat /var/log/...` while the container is
still up.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker compose exec kali` fails right after `tools/run.sh` starts, or the chain errors on a missing tool/file | Images built before a Dockerfile/seed-data change, so `up -d` reused stale layers | `tools/run.sh --build` |
| `missing required state: [...]` on `--only <step>` or `--from <step>` | The step needs state (`www_shell`, `root_shell`, ...) that only exists in the same process after running the earlier steps — nothing is resumed from disk | Run the chain from `recon` (or whichever step actually produces the missing key) in the same invocation |
| `--only X` combined with `--to Y` errors with "cannot be combined" | `--only` and `--from`/`--to` are mutually exclusive in `argparse` | Use either `--only <step>` or `--from <step> --to <step>` |
| Host port 5901 or 80 already bound | Another compose project, or a previous lab instance, still has the port | `docker compose down` the conflicting project, or check `docker ps` for a stray container |
| `Infrastructure/logs/attacker/` missing after a fresh clone | The directory is gitignored and only created on first `attacklog.open_log()` call, i.e. the first chain run | Run the chain once; the directory and `.log`/`.md` files appear afterward |
| Workstation/luke/vinzenz containers unreachable by hostname from inside another container | `apache` lives in `dmz_net`, so Docker's embedded DNS doesn't resolve it from `internal_net` hosts — they're pinned via `extra_hosts` in `docker-compose.yml` instead | Don't rely on DNS for `apache` from internal hosts; use the pinned IP or the existing `extra_hosts` entry |
