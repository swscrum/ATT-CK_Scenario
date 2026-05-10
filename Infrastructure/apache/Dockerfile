# Base image ships the vulnerable Apache version (CVE-2021-41773).
FROM httpd:2.4.50

# Debian Buster is end of life — `apt update` doesn't work against the live
# mirrors any more, so we point at the archive mirror to install cron / dnsutils
# / openssh-server. (openssh-server is added so john.stravidis can deploy in.)
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /buster-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends cron iproute2 dnsutils openssh-server openssh-client coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Building Apache 2.4.49 ourselves would also work, but using the upstream
# httpd:2.4.50 image is faster and equally vulnerable to CVE-2021-41773.

# ============================================================================
#  MISCONFIGURATION — MITRE ATT&CK T1053.003 (Cron)
# ----------------------------------------------------------------------------
#  /opt/cleanup.sh is run by root cron every minute AND is world-writable
#  (chmod 777). Any user inside the container — including www-data, which is
#  the result of the CVE-2021-41773 exploit — can overwrite the script and
#  have arbitrary code executed as root within ~60 seconds.
# ============================================================================

# Maintenance script written by the "admin" — does real work (log rotation,
# tempfile cleanup, disk-usage snapshot). The TODO comment in the file
# explains in-fiction why the permissions are 777 ("only for debugging,
# revert before go-live") and were never reverted.
COPY apache/cleanup.sh /opt/cleanup.sh
RUN chmod 777 /opt/cleanup.sh
# rwxrwxrwx — anyone can overwrite, www-data can drop root-executable code.

RUN printf '* * * * * root /opt/cleanup.sh\n' > /etc/cron.d/cleanup \
    && chmod 644 /etc/cron.d/cleanup
# cron itself is configured correctly — it's the script's permissions that aren't.

# ============================================================================
#  john.stravidis — frontend freelancer who built Waystar Connect.
#  His SSH key is authorized so he can deploy from his workstation.
#  See Documentation/scenario_story.md for the in-fiction backstory.
# ============================================================================
RUN useradd -m -s /bin/bash john.stravidis
COPY apache/john_home/ /home/john.stravidis/
COPY html/ /opt/waystar-connect/dist/
COPY shared-lab-keys/john_deploy_key.pub /home/john.stravidis/.ssh/authorized_keys
RUN chown -R john.stravidis:john.stravidis /home/john.stravidis \
    && mkdir -p /opt/waystar-connect/dist.prev \
    && chown -R john.stravidis:john.stravidis /opt/waystar-connect \
    && chmod 700 /home/john.stravidis/.ssh \
    && chmod 600 /home/john.stravidis/.ssh/authorized_keys \
    && chmod 644 /home/john.stravidis/.ssh/config /home/john.stravidis/.ssh/known_hosts

# Start script: launch cron and sshd, then Apache in the foreground (so the
# container doesn't exit immediately after start).
RUN printf '#!/bin/sh\nservice cron start\nservice ssh start\nexec httpd-foreground\n' > /usr/local/bin/start.sh \
    && chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]

# ============================================================================
#  Reverse-routing setup
# ============================================================================
COPY apache/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# We override the entrypoint so the routing script runs BEFORE the CMD; the
# script then dutifully execs /usr/local/bin/start.sh.
ENTRYPOINT ["/entrypoint.sh"]


# Build with: docker compose up -d --build apache router
# Test with: docker compose exec apache cat /etc/cron.d/cleanup
#       or: sleep 63 && docker compose exec apache cat /var/log/cleanup.log  (expect new timestamps)
