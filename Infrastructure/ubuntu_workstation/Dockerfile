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
    && rm -rf /var/lib/apt/lists/* \
    # LAB ONLY – intentional weak credentials for the attack-chain demo.
    # Do NOT use outside an isolated lab environment.
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:labpass' | chpasswd \
    && adduser labuser sudo \
    # Allow password authentication and disable empty passwords in sshd.
    && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    && mkdir -p /root/.vnc \
    && printf '#!/bin/sh\nunset SESSION_MANAGER\nunset DBUS_SESSION_BUS_ADDRESS\nexec startxfce4\n' \
        > /root/.vnc/xstartup \
    && chmod +x /root/.vnc/xstartup

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 5901

CMD ["/entrypoint.sh"]
