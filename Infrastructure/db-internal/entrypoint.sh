#!/bin/bash
set -e

# Ensure the bind-mounted log directory exists and is writable by the postgres
# user before docker-entrypoint.sh drops root privileges.
mkdir -p /var/log/postgres
chown -R postgres:postgres /var/log/postgres

exec docker-entrypoint.sh "$@"
