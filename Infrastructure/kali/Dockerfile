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
        python3 \
    && ln -s /usr/share/dirb/wordlists /usr/share/wordlists/dirb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /recon

CMD ["sleep", "infinity"]
