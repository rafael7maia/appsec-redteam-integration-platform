# 💰 Bug Bounty via Terminal - HexStrike AI

## 🎯 **Comandos Diretos para Bug Bounty**

### **FASE 1: RECONNAISSANCE** 🔍

#### **Subdomain Enumeration:**
```bash
# Descobrir subdomínios
docker exec hexstrike-ai subfinder -d target.com -silent > subdomains.txt

# Verificar subdomínios vivos
docker exec hexstrike-ai httpx -l subdomains.txt -title -tech-detect -o live_hosts.txt

# Análise de tecnologias
docker exec hexstrike-ai httpx -l live_hosts.txt -title -tech-detect -status-code
```

#### **Port Discovery:**
```bash
# Scan rápido de portas
docker exec hexstrike-ai masscan target.com -p1-10000 --rate=1000

# Scan detalhado com nmap
docker exec hexstrike-ai nmap -sV -p80,443,8080,8443 target.com

# Scan completo em alvos específicos
docker exec hexstrike-ai nmap -sV -A target.com
```

### **FASE 2: VULNERABILITY SCANNING** 🛡️

#### **Automated Vulnerability Discovery:**
```bash
# Scan crítico e alto
docker exec hexstrike-ai nuclei -u https://target.com -severity critical,high

# Scan de CVEs
docker exec hexstrike-ai nuclei -u https://target.com -t /root/nuclei-templates/cves/

# Scan de misconfigurations
docker exec hexstrike-ai nuclei -u https://target.com -t /root/nuclei-templates/misconfiguration/

# Scan de exposures
docker exec hexstrike-ai nuclei -u https://target.com -t /root/nuclei-templates/exposures/
```

#### **Web Application Testing:**
```bash
# Directory enumeration
docker exec hexstrike-ai gobuster dir -u https://target.com -w /app/wordlists/common.txt -x php,asp,aspx,jsp,html

# Parameter discovery
docker exec hexstrike-ai arjun -u https://target.com

# Additional directory search
docker exec hexstrike-ai dirsearch -u https://target.com -e php,asp,aspx,jsp

# WAF detection
docker exec hexstrike-ai wafw00f https://target.com
```

### **FASE 3: DEEP TESTING** 🔬

#### **SQL Injection Testing:**
```bash
# Basic SQLi test
docker exec hexstrike-ai sqlmap -u "https://target.com/page?id=1" --batch --risk=1 --level=1

# POST parameter testing
docker exec hexstrike-ai sqlmap -u "https://target.com/login" --data="username=admin&password=admin" --batch

# Cookie testing
docker exec hexstrike-ai sqlmap -u "https://target.com/" --cookie="sessionid=abc123" --batch
```

#### **Advanced Testing:**
```bash
# Technology fingerprinting
docker exec hexstrike-ai httpx -u https://target.com -title -tech-detect -server -status-code

# SSL/TLS testing
docker exec hexstrike-ai nuclei -u https://target.com -t /root/nuclei-templates/ssl/

# DNS testing
docker exec hexstrike-ai nuclei -u target.com -t /root/nuclei-templates/dns/
```

## 🚀 **WORKFLOWS COMPLETOS**

### **Workflow 1: E-commerce Target**
```bash
#!/bin/bash
TARGET="shop.example.com"

echo "=== RECONNAISSANCE ==="
docker exec hexstrike-ai subfinder -d $TARGET -silent > subs.txt
docker exec hexstrike-ai httpx -l subs.txt -title -tech-detect > live.txt

echo "=== VULNERABILITY SCANNING ==="
docker exec hexstrike-ai nuclei -l live.txt -severity critical,high,medium
docker exec hexstrike-ai gobuster dir -u https://$TARGET -w /app/wordlists/common.txt -x php,html,asp

echo "=== SQL INJECTION TESTING ==="
docker exec hexstrike-ai sqlmap -u "https://$TARGET/product?id=1" --batch --risk=1
```

### **Workflow 2: SaaS Platform**
```bash
#!/bin/bash
TARGET="app.example.com"

echo "=== API DISCOVERY ==="
docker exec hexstrike-ai gobuster dir -u https://$TARGET -w /app/wordlists/common.txt -x json,xml
docker exec hexstrike-ai arjun -u https://$TARGET/api/

echo "=== AUTHENTICATION TESTING ==="
docker exec hexstrike-ai nuclei -u https://$TARGET -t /root/nuclei-templates/misconfiguration/
docker exec hexstrike-ai nuclei -u https://$TARGET -t /root/nuclei-templates/exposures/

echo "=== BUSINESS LOGIC ==="
# Manual testing required here
```

### **Workflow 3: Financial Target**
```bash
#!/bin/bash
TARGET="bank.example.com"

echo "=== HIGH SECURITY SCAN ==="
docker exec hexstrike-ai nuclei -u https://$TARGET -severity critical -t /root/nuclei-templates/cves/
docker exec hexstrike-ai nuclei -u https://$TARGET -t /root/nuclei-templates/ssl/

echo "=== CAREFUL ENUMERATION ==="
docker exec hexstrike-ai gobuster dir -u https://$TARGET -w /app/wordlists/common.txt -q -t 10
docker exec hexstrike-ai wafw00f https://$TARGET
```

## 💡 **DICAS DE PRODUTIVIDADE**

### **Aliases Úteis:**
```bash
# Adicione ao seu .bashrc ou .zshrc
alias hsai="docker exec hexstrike-ai"
alias nuclei-critical="docker exec hexstrike-ai nuclei -severity critical,high"
alias subfinder-silent="docker exec hexstrike-ai subfinder -silent"
alias gobuster-common="docker exec hexstrike-ai gobuster dir -w /app/wordlists/common.txt"
```

### **Scripts de Automação:**
```bash
# Criar script quick-recon.sh
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
echo "Quick recon on $DOMAIN"

docker exec hexstrike-ai subfinder -d $DOMAIN -silent | \
docker exec -i hexstrike-ai httpx -title -tech-detect | \
tee results_$DOMAIN.txt

docker exec hexstrike-ai nuclei -l results_$DOMAIN.txt -severity critical,high
```

## 📊 **RESULTADOS E DOCUMENTAÇÃO**

### **Salvar Resultados:**
```bash
# Criar diretório para target
mkdir -p results/target.com/$(date +%Y%m%d)
cd results/target.com/$(date +%Y%m%d)

# Salvar todos os outputs
docker exec hexstrike-ai subfinder -d target.com -silent > subdomains.txt
docker exec hexstrike-ai nuclei -u https://target.com -severity critical,high -o vulnerabilities.txt
docker exec hexstrike-ai gobuster dir -u https://target.com -w /app/wordlists/common.txt -o directories.txt
```

### **Gerar Relatório:**
```bash
# Script para relatório básico
echo "# Bug Bounty Report - $(date)" > report.md
echo "## Target: $TARGET" >> report.md
echo "## Subdomains Found:" >> report.md
cat subdomains.txt >> report.md
echo "## Vulnerabilities:" >> report.md
cat vulnerabilities.txt >> report.md
```

## 🎯 **TARGETS DE ALTO VALOR**

### **Priorizar por Recompensa:**
1. **Fintech/Banking**: $5,000-$50,000
2. **E-commerce**: $1,000-$10,000  
3. **SaaS Platforms**: $500-$5,000
4. **Government**: $2,000-$20,000

### **Vulnerabilidades Mais Rentáveis:**
1. **RCE**: $5,000-$50,000
2. **SQL Injection**: $1,000-$15,000
3. **Auth Bypass**: $2,000-$10,000
4. **IDOR**: $500-$5,000
5. **XSS**: $100-$2,000

**Use estes comandos diretos para maximizar seus ganhos em bug bounty! 💰🚀**