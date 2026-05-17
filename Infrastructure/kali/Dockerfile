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
    python3 \
    python3-requests \
    python3-rich \
    sliver \
    && ln -s /usr/share/dirb/wordlists /usr/share/wordlists/dirb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /Attack-chain

CMD ["sleep", "infinity"]
