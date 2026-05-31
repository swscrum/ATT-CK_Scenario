FROM postgres:16

# ============================================================================
#  db-internal — Waystar Royco internal patient database (PostgreSQL 16).
#  Lives on internal_net only; no public exposure.
#
#  Users:
#    waystar          — privileged owner created by the official Postgres
#                       entrypoint from POSTGRES_USER (credentials on Vinzenz
#                       Fedora's workstation, ~/.pgpass)
#    waystar-readonly — read-only, created by init/01-schema.sql
#                       (credentials breadcrumbed on John's and Luke's boxes)
#
#  LAB ONLY — intentionally weak credentials for the attack-chain demo.
#  Do NOT use outside an isolated lab environment.
# ============================================================================

# The bind-mounted log directory lands as root-owned; this wrapper chowns it
# before postgres drops from root to the postgres user.
RUN apt-get update \
  && apt-get install -y --no-install-recommends iproute2 \
  && rm -rf /var/lib/apt/lists/*

COPY db-internal/entrypoint.sh /docker-entrypoint-wrapper.sh
RUN chmod +x /docker-entrypoint-wrapper.sh

# Init scripts execute in alphabetical order on first container start.
COPY db-internal/init/ /docker-entrypoint-initdb.d/

ENTRYPOINT ["/docker-entrypoint-wrapper.sh"]
CMD ["postgres"]
