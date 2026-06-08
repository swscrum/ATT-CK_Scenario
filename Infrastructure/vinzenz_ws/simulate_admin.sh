#!/bin/bash

# ============================================================================
# simulate_admin.sh
# ----------------------------------------------------------------------------
# Simulates the sysadmin (Vinzenz) monitoring the Waystar environment.
# When the DB goes down (simulated connection pool exhaustion by attacker),
# Vinzenz logs into the apache server using SSH Agent Forwarding to debug.
# ============================================================================

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [Admin-Sim] $*"; }

log "Starting reactive admin simulation. Monitoring db-internal..."

while true; do
    # Try to connect to the DB. A timeout means it's hanging (our attack bait).
    # We MUST use the regular app user (waystar-app) to test this! The superuser
    # 'waystar' has reserved connections and bypasses the connection exhaustion.
    if ! PGPASSWORD='AppBooking!2026' psql -h db-internal -U waystar-app -d waystar -c "SELECT 1" > /dev/null 2>&1; then
        log "ALERT: Database connection failed! Logging into webserver to investigate..."
        
        # Simulate Vinzenz SSHing into the webserver with agent forwarding (-A)
        # and running typical sysadmin debugging commands. We must start an ssh-agent
        # first so that we actually have a socket to forward!
        ssh-agent bash -c "ssh-add ~/.ssh/id_ed25519 > /dev/null 2>&1 && ssh -A -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null vinzenz.fedora@apache \
            \"echo '--- Admin debugging session ---'; \
             uptime; \
             tail -n 20 /usr/local/apache2/logs/error_log 2>/dev/null; \
             ps aux | grep httpd; \
             ping -c 3 db-internal; \
             echo 'Testing DB connection from webserver...'; \
             python3 -c \\\"import psycopg2; psycopg2.connect(host='db-internal', user='waystar-app', password='AppBooking!2026', dbname='waystar')\\\" 2>&1; \
             echo 'DB is hanging! Need to investigate further...'; \
             sleep 25\""
             
        log "Admin finished debugging session on webserver."
        
        # Wait a bit before checking again to avoid spamming connections
        sleep 30
    fi
    
    # Normal polling interval
    sleep 5
done
