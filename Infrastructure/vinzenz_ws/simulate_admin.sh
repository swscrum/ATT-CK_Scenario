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
             echo 'DB is hanging! Must be an application connection leak. Restarting Apache workers...'; \
             sleep 25; \
             sudo -S /usr/local/apache2/bin/apachectl graceful < /home/vinzenz.fedora/.config/.maint_token\""
             
        log "Admin finished debugging session on webserver."
        
        # Wait a bit before checking again to avoid spamming connections
        sleep 30
    fi
    
    # Normal polling interval. 15s strikes a balance: tight enough that the
    # advanced-privesc step's 90s sudo-phish window catches at least one
    # interactive-shell sudo on average (~6 cycles × 50% maintenance trigger
    # = 1.6% miss rate), loose enough that postgres.log and auth.log don't
    # get hammered with one psql probe + sudo entry every few seconds.
    sleep 15

    # Simulate occasional local sysadmin maintenance.
    # 50% per cycle -> ~2 sudo entries/min on auth.log. This is the bait that
    # triggers the advanced T1546.004 sudo() function in ~/.bashrc; the
    # bash -ic invocation below loads ~/.bashrc so the injected function
    # intercepts before /usr/bin/sudo runs.
    if [ $((RANDOM % 2)) -eq 0 ]; then
        log "Running periodic local maintenance task..."
        # Use an interactive shell to ensure ~/.bashrc (and thus our
        # malicious sudo function, if injected) is loaded. The sudo
        # password is read from a 0600-permissioned cache file rather
        # than piped from argv -- so it doesn't show up in `ps aux`.
        # The malicious sudo() function still captures it via stdin
        # exactly like the previous echo-pipe version did.
        bash -ic "sudo -S apt-get update < /home/vinzenz.fedora/.config/.maint_token" > /tmp/maintenance.log 2>&1
        log "Local maintenance complete. Log:"
        cat /tmp/maintenance.log >> /var/log/admin_sim.log
    fi
done
