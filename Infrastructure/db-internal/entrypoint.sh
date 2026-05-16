#!/bin/bash
set -e

# Ensure the bind-mounted log directory exists and is writable by the postgres
# user before docker-entrypoint.sh drops root privileges.
mkdir -p /var/log/postgres
chown -R postgres:postgres /var/log/postgres

# Enforce no container egress: keep same-subnet traffic but remove the default
# route before handing off to the official entrypoint.
ip route del default || true

exec docker-entrypoint.sh "$@"
