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

# Lab File Integrity Monitor + rsyslog mirror — same pattern as john_ws.
COPY vinzenz_ws/lab-fim.sh         /usr/local/bin/lab-fim.sh
COPY vinzenz_ws/40-lab-persist.conf /etc/rsyslog.d/40-lab-persist.conf
RUN chmod +x /usr/local/bin/lab-fim.sh

COPY vinzenz_ws/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
