FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ============================================================================
#  Luke Smith — psychiatrist at the Waystar Royco mental-health franchise.
#  Day-to-day workstation. Has a `psql` client + .pgpass with read access
#  to the central patient database (db-internal). Models the "credentialed
#  end-user" pivot target after John's box.
#
#  LAB ONLY — intentionally weak credentials for the attack-chain demo.
#  Do NOT use outside an isolated lab environment.
# ============================================================================

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        bash \
        nano \
        less \
        rsync \
        procps \
        iproute2 \
        iputils-ping \
        ca-certificates \
        rsyslog \
        inotify-tools \
        postgresql-client \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    # Reclaim UID 1000 if the base image ships an `ubuntu` user.
    && if id -u ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
    # luke.smith — primary user (UID 1000, sudoer, weak password).
    && useradd -m -s /bin/bash -G sudo luke.smith \
    && echo 'luke.smith:WaystarLuke!2026' | chpasswd \
    # vinzenz.fedora — the sysadmin's named account on this host. He logs
    # in via SSH using the shared vincent_admin_key. Sudoer.
    && useradd -m -s /bin/bash -G sudo vinzenz.fedora \
    && echo 'vinzenz.fedora:VinzenzAdmin!2026' | chpasswd \
    # sshd: password auth on (Luke uses password), key auth for Vinzenz.
    # LogLevel VERBOSE records public-key fingerprints — needed for
    # SOC detection of T1021.004 (Remote Services: SSH).
    && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Seed Luke's home directory.
COPY luke_ws/luke_home/ /home/luke.smith/

# Vinzenz's authorized_keys on this host — sysadmin reach via shared keypair.
RUN mkdir -p /home/vinzenz.fedora/.ssh
COPY shared-lab-keys/vincent_admin_key.pub /home/vinzenz.fedora/.ssh/authorized_keys

RUN chown -R luke.smith:luke.smith /home/luke.smith \
    && chmod 700 /home/luke.smith/.ssh \
    && find /home/luke.smith/.ssh -type f -exec chmod 600 {} + \
    && chmod 600 /home/luke.smith/.pgpass \
    && chown -R vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora \
    && chmod 700 /home/vinzenz.fedora/.ssh \
    && chmod 600 /home/vinzenz.fedora/.ssh/authorized_keys

# Build Luke's local SQLite patient cache from patient-cache.sql. The cache
# is referenced by ~/.bashrc (alias `localnotes`) and ~/.bash_history, and
# acts as the Phase 11 local-cache loot artefact (T1005). Materialised at
# build time so the file is present + watchable by lab-fim from boot.
COPY luke_ws/patient-cache.sql /tmp/patient-cache.sql
RUN mkdir -p /home/luke.smith/.local/share/waystar-psyc \
    && sqlite3 /home/luke.smith/.local/share/waystar-psyc/patients.sqlite < /tmp/patient-cache.sql \
    && rm /tmp/patient-cache.sql \
    && chown -R luke.smith:luke.smith /home/luke.smith/.local \
    && chmod 700 /home/luke.smith/.local \
    && chmod 600 /home/luke.smith/.local/share/waystar-psyc/patients.sqlite

# Lab File Integrity Monitor — inotify watcher, same pattern as john_ws.
# Writes to /var/log/persist/lab-fim.log (bind-mounted host path).
COPY luke_ws/lab-fim.sh         /usr/local/bin/lab-fim.sh
COPY luke_ws/40-lab-persist.conf /etc/rsyslog.d/40-lab-persist.conf
RUN chmod +x /usr/local/bin/lab-fim.sh

COPY luke_ws/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
