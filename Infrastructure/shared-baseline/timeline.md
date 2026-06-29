# Shared cross-host activity timeline

Vinzenz's outbound SSH sessions show up in **multiple** containers' log baselines:
- His own `/var/log/auth.log` on `vinzenz_ws` (outbound connection traces)
- The destination host's `/var/log/auth.log` on `apache` / `ubuntu_workstation` / `luke_ws` (matching `Accepted publickey for vinzenz.fedora from 10.30.0.8` lines)

The token timestamps below MUST match across all four `templates/<persona>/auth.log.tpl` files so a SOC analyst time-correlating across hosts sees a coherent fleet baseline.

## Vinzenz daily maintenance pattern (weekdays, past 14 days)

| Day offset | Slot | Token | Destination | Activity |
|---|---|---|---|---|
| D-1 | 10:00 | `{BSD-1-10h-00m}` | apache | `ssh apache 'uptime'` + `tail -f /usr/local/apache2/logs/error.log` |
| D-1 | 10:15 | `{BSD-1-10h-15m}` | john | `ssh john 'df -h /'` |
| D-1 | 10:22 | `{BSD-1-10h-22m}` | luke | `ssh luke 'df -h /'` |
| D-2 | 10:03 | `{BSD-2-10h-03m}` | apache | `ssh apache 'sudo apt update'` |
| D-2 | 10:18 | `{BSD-2-10h-18m}` | john | `ssh john 'sudo apt update'` |
| D-2 | 10:25 | `{BSD-2-10h-25m}` | luke | `ssh luke 'sudo apt update'` |
| D-3 | 10:05 | `{BSD-3-10h-05m}` | apache | uptime + cleanup.log check |
| D-3 | 10:19 | `{BSD-3-10h-19m}` | john | uptime + dev-env check |
| D-3 | 10:27 | `{BSD-3-10h-27m}` | luke | uptime check |
| D-4 | 10:01 | `{BSD-4-10h-01m}` | apache | quick health check |
| D-4 | 10:14 | `{BSD-4-10h-14m}` | john |  |
| D-4 | 10:21 | `{BSD-4-10h-21m}` | luke |  |
| D-7 | 10:02 | `{BSD-7-10h-02m}` | apache | weekly cycle (skipping weekend D-5, D-6) |
| D-7 | 10:17 | `{BSD-7-10h-17m}` | john |  |
| D-7 | 10:24 | `{BSD-7-10h-24m}` | luke |  |
| D-8 | 10:04 | `{BSD-8-10h-04m}` | apache |  |
| D-8 | 10:16 | `{BSD-8-10h-16m}` | john |  |
| D-8 | 10:23 | `{BSD-8-10h-23m}` | luke |  |
| D-9 | 10:06 | `{BSD-9-10h-06m}` | apache |  |
| D-9 | 10:20 | `{BSD-9-10h-20m}` | john |  |
| D-9 | 10:28 | `{BSD-9-10h-28m}` | luke |  |
| D-10 | 10:00 | `{BSD-10-10h-00m}` | apache |  |
| D-10 | 10:13 | `{BSD-10-10h-13m}` | john |  |
| D-10 | 10:26 | `{BSD-10-10h-26m}` | luke |  |
| D-11 | 10:08 | `{BSD-11-10h-08m}` | apache |  |
| D-11 | 10:19 | `{BSD-11-10h-19m}` | john |  |
| D-11 | 10:24 | `{BSD-11-10h-24m}` | luke |  |
| D-14 | 10:07 | `{BSD-14-10h-07m}` | apache | weekly cycle (skipping D-12, D-13) |
| D-14 | 10:18 | `{BSD-14-10h-18m}` | john |  |
| D-14 | 10:25 | `{BSD-14-10h-25m}` | luke |  |

(D-5, D-6, D-12, D-13 are weekend days — no maintenance pattern. Real
sysadmins don't SSH into prod on Saturday unless on-call paged them.)

## John's daily activity pattern (weekdays, past 14 days)

| Day offset | Token | Activity |
|---|---|---|
| D-1 | `{BSD-1-09h-12m}` | VNC login from 10.10.x.x (his own terminal) |
| D-1 | `{BSD-1-09h-35m}` | `ssh apache` for deploy verification |
| D-2 | `{BSD-2-09h-08m}` | VNC login |
| D-3 | `{BSD-3-09h-15m}` | VNC login + `sudo apt update` |
| D-4 | `{BSD-4-09h-10m}` | VNC login |
| D-7 | `{BSD-7-09h-22m}` | VNC login + `ssh apache` deploy |
| D-8 | `{BSD-8-09h-11m}` | VNC login |
| D-9 | `{BSD-9-09h-14m}` | VNC login |
| D-10 | `{BSD-10-09h-09m}` | VNC login + `sudo apt update` |
| D-11 | `{BSD-11-09h-18m}` | VNC login |
| D-14 | `{BSD-14-09h-13m}` | VNC login |

## Luke's daily activity pattern (weekdays, past 14 days)

| Day offset | Token | Activity |
|---|---|---|
| D-1 | `{BSD-1-08h-30m}` | VNC login (clinical day-start) |
| D-1 | `{BSD-1-08h-45m}` | psql sessions (db-internal connection) |
| D-2 | `{BSD-2-08h-32m}` | VNC + psql |
| D-3 | `{BSD-3-08h-28m}` | VNC + psql |
| D-4 | `{BSD-4-08h-35m}` | VNC + psql + rsync apache→workstation pull |
| D-7 | `{BSD-7-08h-31m}` | VNC + psql |
| D-8 | `{BSD-8-08h-29m}` | VNC + psql |
| D-9 | `{BSD-9-08h-33m}` | VNC + psql |
| D-10 | `{BSD-10-08h-28m}` | VNC + psql |
| D-11 | `{BSD-11-08h-30m}` | VNC + psql |
| D-14 | `{BSD-14-08h-34m}` | VNC + psql + rsync backup pull |

## apt/dpkg patching cadence (cross-host, sysadmin-driven)

| Day offset | Token | Hosts patched |
|---|---|---|
| D-3 | `{DPKG-3-10h-30m}` | apache: openssh-server, libcap2-bin |
| D-3 | `{DPKG-3-10h-47m}` | john: nodejs-lts, npm |
| D-3 | `{DPKG-3-11h-02m}` | luke: postgresql-client |
| D-10 | `{DPKG-10-10h-22m}` | apache: libapache2-mod-security2 |
| D-17 | `{DPKG-17-10h-15m}` | all: openssh-server CVE patch |
| D-24 | `{DPKG-24-10h-30m}` | all: kernel upgrade |
| D-31 | `{DPKG-31-10h-44m}` | apache: ssl-cert renewal |
| D-45 | `{DPKG-45-09h-58m}` | all: apt-utils, ca-certificates |

Any new pattern added by future template work should be appended here so
future maintainers (and PR reviewers) can verify cross-host consistency.
