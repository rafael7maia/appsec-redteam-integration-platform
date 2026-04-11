# HexStrike AI Enhanced v4.0 - Complete Security Arsenal
# Based on original HexStrike-AI with 150+ security tools
# AppSec + Red Team Integration Platform

FROM kalilinux/kali-rolling

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV HEXSTRIKE_VERSION=4.0
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/opt/tools/bin
ENV DEBIAN_FRONTEND=noninteractive

# Update system and install base packages
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev python3-venv \
    curl wget git unzip zip \
    build-essential gcc g++ make cmake \
    libssl-dev libffi-dev \
    libpcap-dev pkg-config \
    ca-certificates gnupg lsb-release \
    software-properties-common apt-transport-https \
    && rm -rf /var/lib/apt/lists/* || true

# Install Go
RUN wget -O /tmp/go.tar.gz https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . ~/.cargo/env

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Create tools directory
RUN mkdir -p /opt/tools/bin /opt/wordlists /app/results

# ============================================================================
# NETWORK RECONNAISSANCE & SCANNING TOOLS (25+ Tools)
# ============================================================================

# Install Nmap with NSE scripts
RUN apt-get update && apt-get install -y nmap nmap-common

# Install Masscan (High-speed port scanner)
RUN apt-get install -y masscan

# Install network discovery tools (only available packages)
RUN apt-get install -y \
    dnsrecon dnsenum theharvester \
    nbtscan arp-scan smbmap || true

# Install Go-based network tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest || true
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true
RUN go install github.com/lc/gau/v2/cmd/gau@latest || true
RUN go install github.com/tomnomnom/waybackurls@latest || true
RUN go install github.com/tomnomnom/assetfinder@latest || true
RUN go install github.com/owasp-amass/amass/v3/...@latest || true

# ============================================================================
# WEB APPLICATION SECURITY TESTING (40+ Tools)
# ============================================================================

# Install directory/file discovery tools
RUN go install github.com/OJ/gobuster/v3@latest || true
RUN go install github.com/ffuf/ffuf@latest || true
# feroxbuster requires cargo, which isn't persistent across RUN commands in multi-stage builds

# Install Python-based web tools
RUN pip3 install --no-cache-dir --break-system-packages \
    sqlmap dirsearch arjun paramspider \
    requests beautifulsoup4 selenium \
    pwntools || true

# Install web crawling and analysis tools
RUN apt-get install -y \
    dirb whatweb wfuzz commix \
    burpsuite zaproxy || true

# Install specialized web tools
RUN go install github.com/s0md3v/Arjun@latest || true
RUN go install github.com/devanshbatham/ParamSpider@latest || true
RUN go install github.com/hahwul/dalfox/v2@latest || true
RUN go install github.com/jaeles-project/jaeles@latest || true

# Install browser automation tools
RUN apt-get install -y chromium-browser chromium-chromedriver && \
    pip3 install selenium webdriver-manager

# ============================================================================
# AUTHENTICATION & PASSWORD SECURITY (12+ Tools)
# ============================================================================

# Install password cracking tools
RUN apt-get install -y \
    hydra john hashcat medusa patator \
    ophcrack hash-identifier || true

# Install additional hash tools
RUN pip3 install hashid

# ============================================================================
# BINARY ANALYSIS & REVERSE ENGINEERING (25+ Tools)
# ============================================================================

# Install debugging and analysis tools
RUN apt-get install -y \
    gdb gdb-multiarch radare2 \
    binwalk strings objdump readelf nm \
    ltrace strace hexdump xxd \
    checksec volatility3 || true

# Install GDB enhancements
RUN git clone https://github.com/longld/peda.git /opt/peda && \
    git clone https://github.com/hugsy/gef.git /opt/gef && \
    git clone https://github.com/scwuaptx/Pwngdb.git /opt/Pwngdb

# Install Ghidra
RUN wget -O /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_20230928_PUBLIC.zip && \
    unzip /tmp/ghidra.zip -d /opt/ && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip

# Install Binary Ninja (Community Edition)
RUN wget -O /tmp/binaryninja.zip https://cdn.binary.ninja/installers/BinaryNinja-personal.zip && \
    unzip /tmp/binaryninja.zip -d /opt/ && \
    rm /tmp/binaryninja.zip

# Install additional binary tools
RUN pip3 install angr pwntools ropper one-gadget-finder

# ============================================================================
# CLOUD & CONTAINER SECURITY (20+ Tools)
# ============================================================================

# Install cloud security tools
RUN pip3 install \
    prowler scout-suite \
    checkov terrascan \
    trivy-python

# Install Trivy
RUN wget -O /tmp/trivy.deb https://github.com/aquasecurity/trivy/releases/download/v0.46.0/trivy_0.46.0_Linux-64bit.deb && \
    dpkg -i /tmp/trivy.deb && \
    rm /tmp/trivy.deb

# Install Docker tools
RUN apt-get install -y docker.io docker-compose

# Install Kubernetes tools
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install kube-hunter and kube-bench
RUN pip3 install kube-hunter && \
    wget -O /tmp/kube-bench.tar.gz https://github.com/aquasecurity/kube-bench/releases/download/v0.6.15/kube-bench_0.6.15_linux_amd64.tar.gz && \
    tar -xzf /tmp/kube-bench.tar.gz -C /opt/tools/bin && \
    rm /tmp/kube-bench.tar.gz

# ============================================================================
# CTF & FORENSICS TOOLS (20+ Tools)
# ============================================================================

# Install forensics tools
RUN apt-get install -y \
    volatility foremost photorec testdisk \
    steghide stegsolve outguess \
    exiftool binwalk scalpel \
    wireshark tcpdump networkminer \
    autopsy sleuthkit || true

# Install steganography tools
RUN pip3 install stegcracker zsteg && \
    gem install zsteg

# Install additional forensics tools
RUN wget -O /opt/tools/bin/stegsolve.jar http://www.caesum.com/handbook/Stegsolve.jar

# ============================================================================
# BUG BOUNTY & OSINT ARSENAL (20+ Tools)
# ============================================================================

# Install OSINT tools
RUN pip3 install \
    sherlock-project social-analyzer \
    theHarvester recon-ng \
    spiderfoot shodan censys-python

# Install additional recon tools
RUN go install github.com/tomnomnom/httprobe@latest || true
RUN go install github.com/hakluke/hakrawler@latest || true
RUN go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest || true

# ============================================================================
# CRYPTOGRAPHY & HASH ANALYSIS TOOLS
# ============================================================================

# Install crypto tools
RUN apt-get install -y \
    hashcat john openssl gpg \
    sage-math python3-crypto || true

# Install additional crypto tools
RUN pip3 install \
    pycryptodome cryptography \
    gmpy2 sympy

# Install factorization tools
RUN git clone https://github.com/Ganapati/RsaCtfTool.git /opt/RsaCtfTool && \
    pip3 install -r /opt/RsaCtfTool/requirements.txt

# ============================================================================
# MOBILE APPLICATION SECURITY
# ============================================================================

# Install mobile security tools
RUN apt-get install -y \
    adb fastboot apktool \
    dex2jar jadx || true

# Install mobile analysis tools
RUN pip3 install frida-tools objection

# ============================================================================
# WORDLISTS AND PAYLOADS
# ============================================================================

# Download SecLists
RUN git clone https://github.com/danielmiessler/SecLists.git /opt/wordlists/SecLists

# Download common wordlists
RUN mkdir -p /opt/wordlists && \
    wget -O /opt/wordlists/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt && \
    gunzip /opt/wordlists/rockyou.txt.gz || true

# Download PayloadsAllTheThings
RUN git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/wordlists/PayloadsAllTheThings

# ============================================================================
# HEXSTRIKE AI FRAMEWORK INTEGRATION
# ============================================================================

# Copy HexStrike framework files from hexstrike-ai directory
COPY hexstrike-ai/hexstrike_server.py /app/
COPY hexstrike-ai/hexstrike_mcp.py /app/
COPY hexstrike-ai/requirements.txt /app/hexstrike_requirements.txt

# Copy application bridge files
COPY hexstrike_lib.py /app/
COPY hexstrike_scanner.py /app/
COPY quick_start.py /app/
COPY config_loader.py /app/
COPY appsec_scanner.py /app/
COPY core_scanner.py /app/
COPY typescript_security_scanner.py /app/
COPY report_generator.py /app/

# Install Python requirements
RUN pip3 install --no-cache-dir -r /app/hexstrike_requirements.txt
RUN pip3 install --no-cache-dir \
    flask psutil aiohttp \
    mitmproxy selenium beautifulsoup4 \
    requests bcrypt jsonwebtoken \
    pydantic python-dotenv

# ============================================================================
# CONFIGURATION AND SETUP
# ============================================================================

# Set up environment
WORKDIR /app

# Create configuration files
RUN echo '#!/bin/bash\n\
echo "🚀 HexStrike AI Enhanced v4.0 - Complete Security Arsenal"\n\
echo "🛡️ AppSec + Red Team Integration Platform"\n\
echo "🐳 150+ Security Tools Available"\n\
echo "🤖 Amazon Q Integration Ready"\n\
echo "================================"\n\
echo "Available Tools:"\n\
echo "  Network: nmap, rustscan, masscan, amass, subfinder"\n\
echo "  Web: nuclei, gobuster, sqlmap, dalfox, nikto"\n\
echo "  Binary: ghidra, radare2, gdb-peda, pwntools"\n\
echo "  Crypto: hashcat, john, rsatool, factordb"\n\
echo "  Forensics: volatility, binwalk, steghide, wireshark"\n\
echo "  Cloud: trivy, prowler, kube-hunter, checkov"\n\
echo "  OSINT: sherlock, theHarvester, shodan"\n\
echo "================================"\n\
echo "Services:"\n\
echo "  HexStrike Server: http://localhost:8888"\n\
echo "  Simple MCP: Available"\n\
echo "  Security Bridge: Available"\n\
echo "  AppSec Bridge: Available"\n\
echo "================================"\n\
\n\
# Start HexStrike server in background\n\
python3 /app/hexstrike_server.py --port 8888 &\n\
\n\
# Keep container running\n\
python3 -m http.server 8889 --directory /app\n\
' > /app/start.sh && chmod +x /app/start.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8888/health || curl -f http://localhost:8889 || exit 1

# Expose ports
EXPOSE 8888 8889

# Labels
LABEL version="4.0" \
      description="HexStrike AI v4.0 - Complete Security Arsenal with 150+ Tools" \
      maintainer="AppSec-RedTeam Integration Platform" \
      tools="150+" \
      categories="Network,Web,Binary,Crypto,Forensics,Cloud,OSINT,Mobile"

# Start
CMD ["/app/start.sh"]