# TARGET: /var/log/cleanup.log
# Baseline cleanup.log — 60 days of the per-minute cron heartbeat at fixed
# slots through each day. The script's own heartbeat line format matches
# cleanup.sh line 74 ("[cleanup] $(date)"). We seed 9 representative slots
# per day for 14 days so the file has structure without ballooning.
[cleanup] {D-14-08h-00m}
[cleanup] {D-14-10h-00m}
[cleanup] {D-14-12h-00m}
[cleanup] {D-14-14h-00m}
[cleanup] {D-14-16h-00m}
[cleanup] {D-13-08h-00m}
[cleanup] {D-13-10h-00m}
[cleanup] {D-13-12h-00m}
[cleanup] {D-13-14h-00m}
[cleanup] {D-13-16h-00m}
[cleanup] {D-11-08h-00m}
[cleanup] {D-11-10h-00m}
[cleanup] {D-11-12h-00m}
[cleanup] {D-11-14h-00m}
[cleanup] {D-11-16h-00m}
[cleanup 2026-05-25 03:14:00] rotated cleanup.log (was 1048593 bytes)
[cleanup] {D-10-08h-00m}
[cleanup] {D-10-10h-00m}
[cleanup] {D-10-12h-00m}
[cleanup] {D-10-14h-00m}
[cleanup] {D-10-16h-00m}
[cleanup] {D-9-08h-00m}
[cleanup] {D-9-10h-00m}
[cleanup] {D-9-12h-00m}
[cleanup] {D-9-14h-00m}
[cleanup] {D-9-16h-00m}
[cleanup] {D-8-10h-00m}
[cleanup] {D-8-14h-00m}
[cleanup] {D-7-08h-00m}
[cleanup] {D-7-10h-00m}
[cleanup] {D-7-12h-00m}
[cleanup] {D-7-14h-00m}
[cleanup] {D-7-16h-00m}
[cleanup] {D-4-08h-00m}
[cleanup] {D-4-10h-00m}
[cleanup] {D-4-12h-00m}
[cleanup] {D-4-14h-00m}
[cleanup] {D-4-16h-00m}
[cleanup] {D-3-08h-00m}
[cleanup] {D-3-10h-00m}
[cleanup] {D-3-12h-00m}
[cleanup] {D-3-14h-00m}
[cleanup] {D-3-16h-00m}
[cleanup] {D-2-08h-00m}
[cleanup] {D-2-10h-00m}
[cleanup] {D-2-12h-00m}
[cleanup] {D-2-14h-00m}
[cleanup] {D-2-16h-00m}
[cleanup] {D-1-08h-00m}
[cleanup] {D-1-10h-00m}
[cleanup] {D-1-12h-00m}
[cleanup] {D-1-14h-00m}
[cleanup] {D-1-16h-00m}
