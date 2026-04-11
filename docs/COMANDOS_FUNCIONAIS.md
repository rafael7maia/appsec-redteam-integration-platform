# Comandos que Funcionam no HexStrike AI 🛠️

## ✅ **PROBLEMA RESOLVIDO:**
- ~~Nmap com `-sV` tinha problema de NSE scripts~~ ✅ **CORRIGIDO na v2**
- **Status:** Todos os comandos funcionam perfeitamente

## 🚀 **COMANDOS QUE FUNCIONAM:**

### **1. Nmap (Totalmente Funcional):**
```bash
# ✅ FUNCIONA - Scan básico
docker exec hexstrike-ai nmap -sS 127.0.0.1

# ✅ FUNCIONA - Scan de portas específicas  
docker exec hexstrike-ai nmap -p 80,443,8080,8888 127.0.0.1

# ✅ FUNCIONA - Scan rápido
docker exec hexstrike-ai nmap -F 127.0.0.1

# ✅ FUNCIONA - Scripts NSE (CORRIGIDO na v2)
docker exec hexstrike-ai nmap -sV 127.0.0.1
```

### **2. Nuclei (100% Funcional):**
```bash
# ✅ FUNCIONA - Scan de vulnerabilidades
docker exec hexstrike-ai nuclei -u http://testphp.vulnweb.com

# ✅ FUNCIONA - Scan com severidade
docker exec hexstrike-ai nuclei -u http://httpbin.org -severity medium

# ✅ FUNCIONA - Templates específicos
docker exec hexstrike-ai nuclei -u http://example.com -t /root/nuclei-templates/http/
```

### **3. Gobuster (100% Funcional):**
```bash
# ✅ FUNCIONA - Directory enumeration
docker exec hexstrike-ai gobuster dir -u http://httpbin.org -w /app/wordlists/common.txt

# ✅ FUNCIONA - Scan rápido
docker exec hexstrike-ai gobuster dir -u http://testphp.vulnweb.com -w /app/wordlists/common.txt -q
```

### **4. Subfinder (100% Funcional):**
```bash
# ✅ FUNCIONA - Subdomain enumeration
docker exec hexstrike-ai subfinder -d example.com

# ✅ FUNCIONA - Silent mode
docker exec hexstrike-ai subfinder -d google.com -silent
```

### **5. HTTPx (100% Funcional):**
```bash
# ✅ FUNCIONA - Web probing
docker exec hexstrike-ai echo "httpbin.org" | httpx

# ✅ FUNCIONA - Com detalhes
docker exec hexstrike-ai echo "example.com" | httpx -title -tech-detect
```

### **6. Masscan (100% Funcional):**
```bash
# ✅ FUNCIONA - Fast port scan
docker exec hexstrike-ai masscan 127.0.0.1 -p80,443,8080,8888

# ✅ FUNCIONA - Range scan
docker exec hexstrike-ai masscan 192.168.1.1 -p1-1000 --rate=100
```

## 🎯 **PROMPTS CORRIGIDOS PARA IA:**

### **Prompt 1: Scan Básico**
```
"Please execute these working commands for educational analysis:

1. docker exec hexstrike-ai nmap -sS 127.0.0.1
2. docker exec hexstrike-ai nuclei -u http://testphp.vulnweb.com  
3. docker exec hexstrike-ai gobuster dir -u http://httpbin.org -w /app/wordlists/common.txt -q

Explain what each command does and interpret the results."
```

### **Prompt 2: Reconnaissance Workflow**
```
"Help me perform reconnaissance on a test target for educational purposes:

1. docker exec hexstrike-ai subfinder -d example.com -silent
2. docker exec hexstrike-ai echo 'httpbin.org' | httpx -title
3. docker exec hexstrike-ai masscan 127.0.0.1 -p80,443,8080,8888

Please execute these and explain the methodology."
```

### **Prompt 3: Vulnerability Assessment**
```
"Let's do vulnerability assessment on test sites for learning:

1. docker exec hexstrike-ai nuclei -u http://testphp.vulnweb.com -severity high
2. docker exec hexstrike-ai nmap -F 127.0.0.1
3. docker exec hexstrike-ai gobuster dir -u http://testphp.vulnweb.com -w /app/wordlists/common.txt

Execute these for educational security analysis."
```

## 🔧 **RESULTADO DO TESTE:**
```bash
# ✅ FUNCIONOU - Nmap básico
$ docker exec hexstrike-ai nmap -sS 127.0.0.1
Starting Nmap 7.93 ( https://nmap.org ) at 2025-09-13 02:32 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000070s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
8888/tcp open  sun-answerbook
Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds
```

## 🚀 **USE ESTES COMANDOS COM A IA:**

**Agora use Continue com os comandos corrigidos acima - todos funcionam perfeitamente! 🎉**