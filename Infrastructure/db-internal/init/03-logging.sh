#!/bin/bash
# Enable full statement logging for SIEM/Splunk ingest.
# ALTER SYSTEM writes to postgresql.auto.conf which is loaded on startup.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    ALTER SYSTEM SET log_statement = 'all';
    ALTER SYSTEM SET log_connections = on;
    ALTER SYSTEM SET log_disconnections = on;
    ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d ';
EOSQL
