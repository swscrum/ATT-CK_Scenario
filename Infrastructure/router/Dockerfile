FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables iproute2 iputils-ping dnsutils \
        ulogd2 \
    && rm -rf /var/lib/apt/lists/*

# ulogd2 configuration captures iptables NFLOG events into a file under
# /var/log so the SOC can ingest them via the bind-mount in compose.
COPY ulogd.conf /etc/ulogd.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
