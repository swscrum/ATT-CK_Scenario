FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ============================================================================
#  John Stravidis — frontend freelancer building Waystar Connect.
#  This workstation is his (he was set up here while the box's previous
#  owner — Reiner Hermann — was on six months of medical leave).
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
        dbus-x11 \
        tigervnc-standalone-server \
    && rm -rf /var/lib/apt/lists/* \
    # Remove the `ubuntu` user if present — official ubuntu:24.04 images do
    # not typically include it, so guard the deletion to keep builds
    # reproducible across environments. Doing it before useradd john also
    # frees UID 1000 for john so he gets the conventional first-user UID when
    # that account exists.
    && if id -u ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
    # Create john.stravidis as the primary (and only non-root) user.
    # Weak interim password "waystar2026!" was set by the transition team and
    # was meant to be reset before go-live — never was. Same negligence vector
    # the story already documents.
    && useradd -m -s /bin/bash -G sudo john.stravidis \
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
RUN chown -R john.stravidis:john.stravidis /home/john.stravidis \
    && chmod 700 /home/john.stravidis/.ssh \
    && chmod 600 /home/john.stravidis/.ssh/id_ed25519 \
    && chmod 644 /home/john.stravidis/.ssh/id_ed25519.pub /home/john.stravidis/.ssh/config /home/john.stravidis/.ssh/known_hosts \
    && chmod +x /home/john.stravidis/.vnc/xstartup

COPY ubuntu_workstation/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 5901

CMD ["/entrypoint.sh"]
