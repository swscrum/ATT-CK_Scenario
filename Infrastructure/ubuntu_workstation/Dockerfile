FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ============================================================================
#  John Stravidis — frontend freelancer building Waystar Connect.
#  This is his dev/staging workstation, provisioned for the project.
#  See Documentation/scenario_story.md for the full backstory.
#
#  LAB ONLY — intentionally weak credentials for the attack-chain demo.
#  Do NOT use outside an isolated lab environment.
# ============================================================================

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        bash \
        git \
        nano \
        less \
        rsync \
        procps \
        iproute2 \
        iputils-ping \
        ca-certificates \
        nodejs \
        npm \
        xfce4 \
        xfce4-terminal \
        dbus \
        dbus-x11 \
        gnupg \
        tumbler \
        python3-dbus \
        python3-gi \
        tigervnc-standalone-server \
        rsyslog \
        inotify-tools \
        sqlite3 \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    # pm-utils is not packaged for Ubuntu 24.04; provide a stub so xfce4-session
    # doesn't log "No such file or directory" when probing power-management support.
    && printf '#!/bin/sh\nexit 1\n' > /usr/bin/pm-is-supported \
    && chmod +x /usr/bin/pm-is-supported \
    # Remove the `ubuntu` user if present — official ubuntu:24.04 images do
    # not typically include it, so guard the deletion to keep builds
    # reproducible across environments. Doing it before useradd john also
    # frees UID 1000 for john so he gets the conventional first-user UID when
    # that account exists.
    && if id -u ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
    # Create john.stravidis as the primary non-root user. He is a frontend
    # freelancer, NOT an administrator, so he is intentionally NOT in the sudo
    # group — least privilege. The sysadmin account vinzenz.fedora (below) is
    # the one with sudo. This keeps the attack chain sound: after the lateral
    # move onto this box the attacker holds an unprivileged identity, so the
    # defense-evasion step's attempts to wipe /var/log fail with permission
    # denied instead of trivially succeeding via sudo.
    # Weak interim password "waystar2026!" was set by the transition team and
    # was meant to be reset before go-live — never was. Same negligence vector
    # the story already documents.
    && useradd -m -s /bin/bash john.stravidis \
    && echo 'john.stravidis:waystar2026!' | chpasswd \
    # Allow password authentication and disable empty passwords in sshd.
    && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# Seed John's home directory + shared deploy keypair.
COPY ubuntu_workstation/john_home/ /home/john.stravidis/
COPY shared-lab-keys/john_deploy_key     /home/john.stravidis/.ssh/id_ed25519
COPY shared-lab-keys/john_deploy_key.pub /home/john.stravidis/.ssh/id_ed25519.pub
COPY shared-lab-keys/john_deploy_key.pub /home/john.stravidis/.ssh/authorized_keys
RUN chown -R john.stravidis:john.stravidis /home/john.stravidis \
    && chmod 700 /home/john.stravidis/.ssh \
    && chmod 600 /home/john.stravidis/.ssh/id_ed25519 \
    && chmod 600 /home/john.stravidis/.ssh/authorized_keys \
    && chmod 600 /home/john.stravidis/projects/waystar-connect/.pgpass \
    && chmod 644 /home/john.stravidis/.ssh/id_ed25519.pub \
                    /home/john.stravidis/.ssh/config \
                    /home/john.stravidis/.ssh/known_hosts \
    && chmod +x /home/john.stravidis/.vnc/xstartup \
    # Pre-create the gnupg directory so gpg-agent doesn't print "directory
    # created" messages on every first boot. gpg-agent is started by
    # xfce4-session to provide SSH key-agent integration.
    && mkdir -p /home/john.stravidis/.gnupg/private-keys-v1.d \
    && chown -R john.stravidis:john.stravidis /home/john.stravidis/.gnupg \
    && chmod 700 /home/john.stravidis/.gnupg \
                 /home/john.stravidis/.gnupg/private-keys-v1.d \
    # Build john's local dev SQLite (frontend fixture, NOT real patient data).
    # See seed_dev_db.sql next to the resulting dev.db for the schema.
    && sqlite3 /home/john.stravidis/projects/waystar-connect/dev.db \
         < /home/john.stravidis/projects/waystar-connect/seed_dev_db.sql \
    && chown john.stravidis:john.stravidis \
         /home/john.stravidis/projects/waystar-connect/dev.db \
    && cd /home/john.stravidis/projects/waystar-connect \
    && npm install \
    && chown -R john.stravidis:john.stravidis node_modules

# ============================================================================
#  vinzenz.fedora — sysadmin's named account on this host.
#  Vinzenz SSHes from his own workstation (10.30.0.8) using the shared
#  vincent_admin_key. He has sudo. Models the realistic enterprise pattern
#  where a sysadmin has a dedicated account on every managed box.
# ============================================================================
RUN useradd -m -s /bin/bash -G sudo vinzenz.fedora \
    && echo 'vinzenz.fedora:VinzenzAdmin!2026' | chpasswd \
    && mkdir -p /home/vinzenz.fedora/.ssh
COPY shared-lab-keys/vincent_admin_key.pub /home/vinzenz.fedora/.ssh/authorized_keys
RUN chown -R vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora \
    && chmod 700 /home/vinzenz.fedora/.ssh \
    && chmod 600 /home/vinzenz.fedora/.ssh/authorized_keys

COPY ubuntu_workstation/logind-stub.py /usr/local/bin/logind-stub.py
# D-Bus policy that allows root to own org.freedesktop.login1 (the logind stub).
COPY ubuntu_workstation/dbus-logind-stub.conf /etc/dbus-1/system.d/logind-stub.conf
COPY ubuntu_workstation/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    # tumbler's session service files include "SystemdService=" which tells D-Bus
    # to activate via systemd --user. Without a running systemd user instance the
    # directive is silently ignored and D-Bus falls back to the Exec= line — but
    # only if the key is absent. Strip it so the Exec= path is always used and
    # xfdesktop's GetFlavors call succeeds on first contact.
    && sed -i '/^SystemdService=/d' \
         /usr/share/dbus-1/services/org.xfce.Tumbler.Cache1.service \
         /usr/share/dbus-1/services/org.xfce.Tumbler.Manager1.service \
         /usr/share/dbus-1/services/org.xfce.Tumbler.Thumbnailer1.service

EXPOSE 22 5901

CMD ["/entrypoint.sh"]
