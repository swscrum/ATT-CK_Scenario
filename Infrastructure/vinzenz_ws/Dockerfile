FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ============================================================================
#  Vinzenz Fedora — sysadmin at Waystar Royco.
#  Has SSH reach to every host in the fleet (apache, john_ws, luke_ws).
#  Models the top-of-the-pyramid pivot: an attacker who lands here owns the
#  whole network. Vinzenz's private key in ~/.ssh/id_ed25519 is the central
#  loot artefact (T1552.004 — unsecured private key).
#
#  LAB ONLY — intentionally weak credentials.
# ============================================================================

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        openssh-client \
        sudo \
        bash \
        nano \
        less \
        rsync \
        procps \
        iproute2 \
        iputils-ping \
        ca-certificates \
        curl \
        rsyslog \
        inotify-tools \
        postgresql-client \
        nmap \
        tcpdump \
        net-tools \
        dnsutils \
        tmux \
        vim \
        htop \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    # Reclaim UID 1000 if the base image ships an `ubuntu` user.
    && if id -u ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
    # vinzenz.fedora — primary user (UID 1000, sudoer, weak password).
    && useradd -m -s /bin/bash -G sudo vinzenz.fedora \
    && echo 'vinzenz.fedora:VinzenzAdmin!2026' | chpasswd \
    && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Seed Vinzenz's home directory.
COPY vinzenz_ws/vinzenz_home/ /home/vinzenz.fedora/

# Vinzenz's private key — the cross-fleet master credential.
COPY shared-lab-keys/vincent_admin_key     /home/vinzenz.fedora/.ssh/id_ed25519
COPY shared-lab-keys/vincent_admin_key.pub /home/vinzenz.fedora/.ssh/id_ed25519.pub
# His pubkey is also in his own authorized_keys so he can ssh into himself
# (mostly for symmetry / "ssh vinzenz_ws@vinzenz_ws" loopback tests).
COPY shared-lab-keys/vincent_admin_key.pub /home/vinzenz.fedora/.ssh/authorized_keys

RUN chown -R vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora \
    && chmod 700 /home/vinzenz.fedora/.ssh \
    && chmod 600 /home/vinzenz.fedora/.ssh/id_ed25519 \
    && chmod 600 /home/vinzenz.fedora/.ssh/authorized_keys \
    && chmod 644 /home/vinzenz.fedora/.ssh/id_ed25519.pub \
                 /home/vinzenz.fedora/.ssh/config \
                 /home/vinzenz.fedora/.ssh/known_hosts \
    && chmod 600 /home/vinzenz.fedora/.pgpass

# -----------------------------------------------------------------------------
# Sloppy-operator pattern: Vinzenz caches his sudo password in a hidden
# config file so simulate_admin.sh and the apt-get cron don't have to
# prompt. 0600 + owned by vinzenz.fedora so only he (and root) can read.
# This intentionally replaces the earlier ``echo PASSWORD | sudo -S ...``
# pattern, which exposed the credential in ``ps aux`` argv. Now the
# password lives on disk only, and the maintenance scripts redirect it
# into ``sudo -S`` via stdin. Side benefit: an attacker who lands code
# exec as vinzenz.fedora can ``cat`` the token instead of waiting for
# the T1546.004 sudo-phish to fire -- realistic looting opportunity.
# -----------------------------------------------------------------------------
RUN install -d -m 700 -o vinzenz.fedora -g vinzenz.fedora /home/vinzenz.fedora/.config \
    && echo 'VinzenzAdmin!2026' > /home/vinzenz.fedora/.config/.maint_token \
    && chown vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora/.config/.maint_token \
    && chmod 600 /home/vinzenz.fedora/.config/.maint_token

# Lab File Integrity Monitor + rsyslog mirror — same pattern as john_ws.
COPY vinzenz_ws/lab-fim.sh         /usr/local/bin/lab-fim.sh
COPY vinzenz_ws/simulate_admin.sh  /usr/local/bin/simulate_admin.sh
COPY vinzenz_ws/40-lab-persist.conf /etc/rsyslog.d/40-lab-persist.conf
RUN chmod +x /usr/local/bin/lab-fim.sh /usr/local/bin/simulate_admin.sh

# Build-time activity baseline. The hydrator renders date-relative tokens at
# first boot (before rsyslog + lab-fim start), writing 14-60 days of
# believable past activity into /var/log/{auth.log,dpkg.log,apt/history.log,
# syslog}. Idempotent across container restarts via /var/lib/baseline-hydrated.
# See Infrastructure/shared-baseline/README.md.
COPY shared-baseline/hydrate-baseline.sh        /usr/local/bin/hydrate-baseline.sh
COPY shared-baseline/templates/sysadmin/        /usr/local/share/baseline/sysadmin/
RUN chmod +x /usr/local/bin/hydrate-baseline.sh

# Trust the lab internal CA so curl/wget against fake_internet domains
# (github.com, archive.ubuntu.com, etc.) works WITHOUT -k.
COPY shared-lab-keys/lab-ca.crt /usr/local/share/ca-certificates/waystar-lab-ca.crt
RUN update-ca-certificates >/dev/null 2>&1

# Workstation activity simulator — runs as vinzenz.fedora from the entrypoint
# when ACTIVITY_ENABLED=1. CRUCIAL persona: Vinzenz SSHes out to apache,
# john_ws, luke_ws during normal maintenance, generating the baseline of
# "Accepted publickey for vinzenz.fedora" entries on those hosts that the
# attacker's stolen-key activity (advanced chain) needs to hide in.
COPY lab-activity-sim/activity_sim.py /usr/local/bin/activity_sim.py
RUN chmod +x /usr/local/bin/activity_sim.py

COPY vinzenz_ws/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
