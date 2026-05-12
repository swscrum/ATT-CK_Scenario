FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        bash \
        nano \
        less \
        procps \
        iproute2 \
        iputils-ping \
        ca-certificates \
        xfce4 \
        xfce4-terminal \
        dbus-x11 \
        tigervnc-standalone-server \
        rsyslog \
        inotify-tools \
    && rm -rf /var/lib/apt/lists/* \
    # LAB ONLY – intentional weak credentials for the attack-chain demo.
    # Do NOT use outside an isolated lab environment.
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:labpass' | chpasswd \
    && adduser labuser sudo \
    # Allow password authentication, disable empty passwords, enable VERBOSE
    # log level so sshd records public-key fingerprints (needed for SOC/SIEM
    # detection of T1021.004 — SSH lateral movement).
    && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && mkdir -p /root/.vnc \
    && printf '#!/bin/sh\nunset SESSION_MANAGER\nunset DBUS_SESSION_BUS_ADDRESS\nexec startxfce4\n' \
        > /root/.vnc/xstartup \
    && chmod +x /root/.vnc/xstartup

# rsyslog drop-in: mirrors syslog + auth.log to /var/log/persist so the
# host-persisted bind-mount captures them without chowning /var/log itself.
COPY 40-lab-persist.conf /etc/rsyslog.d/40-lab-persist.conf

# File integrity monitor — inotify watcher launched from entrypoint.
# Replaces auditd, which fails to register with the kernel audit subsystem
# inside Docker on this host (audit_enabled appears locked at boot).
COPY lab-fim.sh /usr/local/bin/lab-fim.sh
RUN chmod +x /usr/local/bin/lab-fim.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 5901

CMD ["/entrypoint.sh"]
