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
    && mkdir /run/sshd \
    && mkdir -p /root/.vnc \
    && printf '#!/bin/sh\nunset SESSION_MANAGER\nunset DBUS_SESSION_BUS_ADDRESS\nexec startxfce4\n' \
        > /root/.vnc/xstartup \
    && chmod +x /root/.vnc/xstartup

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 5901

CMD ["/entrypoint.sh"]
