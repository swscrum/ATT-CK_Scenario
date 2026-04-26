FROM ubuntu:latest

RUN apt-get update && apt-get install -y iptables iproute2 iputils-ping dnsutils

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
