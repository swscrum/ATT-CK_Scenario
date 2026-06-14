# Base image ships the vulnerable Apache version (CVE-2021-41773).
FROM httpd:2.4.50

# Debian Buster is end of life — `apt update` doesn't work against the live
# mirrors any more, so we point at the archive mirror to install cron / dnsutils
# / openssh-server. (openssh-server is added so john.stravidis can deploy in.)
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /buster-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        cron iproute2 dnsutils openssh-server openssh-client coreutils \
        rsync \
        python3 python3-psycopg2 \
        nmap sshpass \
        gawk \
        libcap2-bin \
        inotify-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && (test -x /usr/bin/base64 \
        || { b=$(command -v base64 2>/dev/null) && [ -n "$b" ] && ln -sf "$b" /usr/bin/base64; } \
        || true)

# ============================================================================
#  MISCONFIGURATION — MITRE ATT&CK T1548.001 (Abuse Elevation Control:
#                                              Setuid and Setgid — file capability)
# ----------------------------------------------------------------------------
#  Vinzenz set cap_setuid on python3 so the booking CGI (running as www-data
#  via mod_cgi) could chown user-uploaded session-note attachments to the
#  app's UID. He thought the capability applied only to the CGI script; in
#  reality file capabilities are per-binary, so EVERY invocation of
#  /usr/bin/python3 (by any user) silently gets cap_setuid+ep. A www-data
#  shell from CVE-2021-41773 can call os.setuid(0) and become root without
#  touching cron, sudo, or any SUID bit — and without writing to any path
#  the lab FIM is currently watching.
#
#  Drives the advanced-mode privesc step (advanced_webserver_privesc.py).
#  Basic mode still uses the /opt/cleanup.sh cron misconfig below (T1053.003);
#  both misconfigs coexist so both modes work from the same image.
# ============================================================================
RUN setcap cap_setuid,cap_setgid+ep "$(readlink -f /usr/bin/python3)" \
    && getcap "$(readlink -f /usr/bin/python3)"

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

# Maintenance script written by the sysadmin (Vinzenz Fedora) — does real work
# (log rotation, tempfile cleanup, disk-usage snapshot). John Stravidis chmod
# 777'd it while debugging a deploy permission issue and never reverted it; the
# TODO comment in the file explains that in-fiction ("revert to 700 before
# go-live"). See Documentation/scenario_story.md.
COPY apache/cleanup.sh /opt/cleanup.sh
RUN chmod 777 /opt/cleanup.sh
# rwxrwxrwx — anyone can overwrite, www-data can drop root-executable code.

RUN printf '* * * * * root /opt/cleanup.sh\n' > /etc/cron.d/cleanup \
    && chmod 644 /etc/cron.d/cleanup
# cron itself is configured correctly — it's the script's permissions that aren't.

# ============================================================================
#  john.stravidis — frontend freelancer who built Waystar Connect.
#  Only his PUBLIC key is authorized here, so he can deploy IN from his
#  workstation. The PRIVATE key deliberately does NOT live on apache: deploys
#  flow workstation -> apache, never the reverse (see john_home/.ssh/config and
#  shared-lab-keys/README.md), and the attack chain reads the private key from
#  the workstation, not from here. See issue #132 and
#  Documentation/scenario_story.md.
# ============================================================================
RUN useradd -m -s /bin/bash john.stravidis
COPY apache/john_home/ /home/john.stravidis/
COPY apache/dist/ /opt/waystar-connect/dist/
COPY shared-lab-keys/john_deploy_key.pub /home/john.stravidis/.ssh/authorized_keys
COPY apache/john_home/projects/waystar-connect/deploy.log /opt/waystar-connect/deploy.log
RUN chown -R john.stravidis:john.stravidis /home/john.stravidis \
    && mkdir -p /opt/waystar-connect/dist.prev \
    && chown -R john.stravidis:john.stravidis /opt/waystar-connect \
    && chmod 700 /home/john.stravidis/.ssh \
    && chmod 600 /home/john.stravidis/.ssh/authorized_keys \
    && chmod 644 /home/john.stravidis/.ssh/config /home/john.stravidis/.ssh/known_hosts \
    && chmod 600 /home/john.stravidis/.env

# ============================================================================
#  Waystar Connect DB credentials for the booking-form CGI.
# ----------------------------------------------------------------------------
#  /etc/waystar/db.env holds the `waystar-app` Postgres credentials used by
#  cgi-bin/book.py to insert into the appointments table on db-internal.
#  File is mode 0640 (root:www-data) — readable by the Apache worker, not
#  world-readable. NOTE: an attacker who lands a www-data shell via
#  CVE-2021-41773 can still read it, which is the intended scenario surface.
# ============================================================================
RUN mkdir -p /etc/waystar \
    && printf 'PGHOST=db-internal\nPGPORT=5432\nPGDATABASE=waystar\nPGUSER=waystar-app\nPGPASSWORD=AppBooking!2026\n' \
         > /etc/waystar/db.env \
    && chown root:www-data /etc/waystar/db.env \
    && chmod 640 /etc/waystar/db.env

# ============================================================================
#  vinzenz.fedora — sysadmin's named account on this host.
#  Vinzenz SSHes in from his workstation (10.30.0.8) using the shared
#  vincent_admin_key keypair. He has sudo. This is the sysadmin reach the
#  attack chain pivots to once the attacker compromises Vinzenz's box.
# ============================================================================
RUN apt-get update \
    && apt-get install -y --no-install-recommends sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash -G sudo vinzenz.fedora \
    && echo 'vinzenz.fedora:VinzenzAdmin!2026' | chpasswd \
    && mkdir -p /home/vinzenz.fedora/.ssh
# Seed Vinzenz's apache-side home with his lived-in dotfiles + bash_history.
COPY apache/vinzenz_home/ /home/vinzenz.fedora/
COPY shared-lab-keys/vincent_admin_key.pub /home/vinzenz.fedora/.ssh/authorized_keys
RUN chown -R vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora \
    && chmod 700 /home/vinzenz.fedora/.ssh \
    && chmod 600 /home/vinzenz.fedora/.ssh/authorized_keys

# ============================================================================
#  luke.smith — psychiatrist's named account on this host.
#  Luke SSHes in from his workstation (10.30.0.7) to push periodic backups
#  of his ~/Documents/notes/ tree (see ~luke.smith/.bash_history). NO sudo
#  — Luke is a clinical end-user, not an admin. Password auth (his sshd
#  on apache already allows it; mirrors his own workstation's posture).
# ============================================================================
RUN useradd -m -s /bin/bash luke.smith \
    && echo 'luke.smith:WaystarLuke!2026' | chpasswd \
    && mkdir -p /home/luke.smith/backup/notes
# Seed Luke's apache-side home (his backup-target account).
COPY apache/luke_home/ /home/luke.smith/
RUN chown -R luke.smith:luke.smith /home/luke.smith

# NOTE: cgi-bin is bind-mounted from ./apache/cgi-bin in docker-compose, so the
# +x bit on book.py is preserved from the host filesystem; no chmod here.

# Start script + lab-FIM + activity baseline.
#  - start.sh: cron + ssh, writes capability baseline (T1548.001 detection
#    anchor — PR #141), hydrates the activity baseline (this PR), kicks off
#    lab-fim, exec's httpd. Lives in the source tree so it can be edited
#    without rebaking inline shell into the Dockerfile.
#  - lab-fim.sh: inotify watcher for the basic-mode privesc tripwire +
#    cgi-bin webshell drop + sudoers tamper (PR #141).
#  - hydrate-baseline.sh + templates/apache: persona-keyed log baseline
#    (this PR) — renders 14-60 days of past auth/dpkg/apt/cleanup activity
#    so the host doesn't boot with a clean log slate.
COPY apache/start.sh                            /usr/local/bin/start.sh
COPY apache/lab-fim.sh                          /usr/local/bin/lab-fim.sh
COPY shared-baseline/hydrate-baseline.sh        /usr/local/bin/hydrate-baseline.sh
COPY shared-baseline/templates/apache/          /usr/local/share/baseline/apache/
RUN chmod +x /usr/local/bin/start.sh \
             /usr/local/bin/lab-fim.sh \
             /usr/local/bin/hydrate-baseline.sh

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
