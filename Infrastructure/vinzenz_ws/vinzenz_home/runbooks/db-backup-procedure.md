# DB backup procedure — waystar (postgres-16, db-internal)

Owner: vinzenz.fedora@waystar-royco.example
Schedule: weekly, every Sunday 02:00 UTC, via cron on this workstation
Last revised: 2026-03-08

## Quick-reference

```bash
# Run manually — same as the weekly cron
~/bin/waystar-backup.sh
```

The cron entry:

```
0 2 * * 0  /home/vinzenz.fedora/bin/waystar-backup.sh >> ~/.local/log/waystar-backup.log 2>&1
```

(That script just wraps the `pg_dump` + `rsync` invocations below.)

## What we actually do

1. **Connect to postgres as superuser `waystar`** (credentials in
   `~/.pgpass`, format `db-internal:5432:waystar:waystar:<password>`).
   We use the superuser intentionally for `pg_dump --clean` to round-trip
   sequence ownership, RLS policies, etc.

2. **Dump** the `waystar` DB with custom format (parallel-safe, restorable
   in any direction):

   ```bash
   pg_dump --host db-internal --username waystar \
           --format=custom --jobs=2 --no-owner \
           --file="/srv/db-backup/waystar-$(date -u +%Y%m%dT%H%M%SZ).pgdump" \
           waystar
   ```

3. **Verify** the dump opens (catches torn IO at write time):

   ```bash
   pg_restore --list "/srv/db-backup/waystar-...pgdump" > /dev/null
   ```

4. **Compress + checksum**:

   ```bash
   gzip /srv/db-backup/waystar-...pgdump
   sha256sum /srv/db-backup/waystar-...pgdump.gz >> /srv/db-backup/SHA256SUMS
   ```

5. **Off-site mirror** to (placeholder) `backup-host.waystar-royco.example`
   over rsync-via-SSH. In the lab this resolves to the void; in prod it
   would land on a separate physical host on a different subnet.

   ```bash
   rsync -avz --remove-source-files \
       /srv/db-backup/ backup-host:/srv/waystar/db/
   ```

6. **Rotate**: keep daily for 7 days, weekly for 4 weeks, monthly for 12 months.

## Restore (manual, not for prod without coordination)

```bash
# 1. STOP application writes (apache booking CGI, anything touching appointments)
ssh apache 'sudo systemctl stop httpd'

# 2. Snapshot the current state before restoring
pg_dump --format=custom --file=/srv/db-backup/PRE-RESTORE-$(date -u +%Y%m%dT%H%M%SZ).pgdump \
    --host db-internal --username waystar waystar

# 3. Drop + recreate from the chosen backup
psql -h db-internal -U waystar -c 'DROP DATABASE waystar'
psql -h db-internal -U waystar -c 'CREATE DATABASE waystar'
pg_restore --host db-internal --username waystar --dbname waystar \
    --clean --if-exists --jobs=2 /srv/db-backup/waystar-<TARGET>.pgdump

# 4. Re-verify the booking CGI works end-to-end before restarting apache
ssh apache 'sudo systemctl start httpd'
curl -fsS -X POST http://apache/cgi-bin/book.py -d 'full_name=Test&email=...'
```

## Known gaps

- We don't currently encrypt the dumps. Should be GPG-signed at minimum;
  the patient data in `patients` and `session_notes` is PHI. Open ticket.
- Off-site mirror is to a host that nobody has verified exists for at
  least 6 months. Worth checking.
- `pg_dump` with `--no-owner` drops the `waystar-readonly` and
  `waystar-app` role definitions — restore script has to recreate them
  from `init/01-schema.sql`. Documented separately in the runbook
  attachment (which doesn't exist yet, TODO).
