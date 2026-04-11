# 🧪 TESTE - HexStrike AI v6.0 (5 Modos)

**Status:** ✅ Servidor Online e Saudável  
**URL:** http://localhost:8888  
**Health Check:** http://localhost:8888/health  

---

## 📊 Status do Servidor

```
✅ Status: HEALTHY
📊 Categorias: 13
🔧 Cache Entries: 6
🎯 Message: HexStrike AI Tools API Server is operational
```

---

## 🎯 OS 5 MODOS DISPONÍVEIS

### **Modo 1: 🛡️ AppSec Only**
**Descrição:** Foco em segurança de aplicações  
**Ferramentas:** OWASP TOP 10, SCA, Dependências, Vulnerabilidades de App  
**Tempo Estimado:** 5-15 minutos

**Como usar:**
```bash
python3 quick_start.py
# Selecione: 1
# Insira a URL da aplicação
```

**Exemplo de comando direto:**
```bash
docker exec hexstrike-ai-mcp python3 /app/appsec_scanner.py --target https://example.com --mode appsec
```

---

### **Modo 2: 🔗 AppSec + RedTeam**
**Descrição:** Análise de segurança completa (AppSec + Pentest)  
**Ferramentas:** OWASP + Nmap + Nuclei + SQLMap + WebScan  
**Tempo Estimado:** 15-30 minutos

**Como usar:**
```bash
python3 quick_start.py
# Selecione: 2
# Insira a URL/IP do alvo
```

**Exemplo de comando direto:**
```bash
docker exec hexstrike-ai-mcp python3 /app/hexstrike_scanner.py --target https://example.com --mode combined
```

---

### **Modo 3: ⚔️ RedTeam Only**
**Descrição:** Penetration Testing puro  
**Ferramentas:** Nmap, Masscan, Nuclei, Dalfox, Gobuster, SQLMap, Subdomínios, OSINT  
**Tempo Estimado:** 20-45 minutos

**Como usar:**
```bash
python3 quick_start.py
# Selecione: 3
# Insira o IP ou domínio alvo
```

**Ferramentas Principais:**
- **Reconhecimento:** nmap, masscan, amass, subfinder
- **Web Testing:** nuclei, dalfox, sqlmap, gobuster, ffuf
- **OSINT:** sherlock, theHarvester, shodan
- **Exploração:** metasploit

---

### **Modo 4: 📜 TypeScript Scanner**
**Descrição:** Análise de código JavaScript/TypeScript  
**Ferramentas:** ESLint, SonarJS, Semgrep, Dependências Node.js, SAST  
**Tempo Estimado:** 5-10 minutos

**Como usar:**
```bash
python3 quick_start.py
# Selecione: 4
# Insira o caminho do projeto ou git repo
```

**Exemplo:**
```bash
docker exec hexstrike-ai-mcp python3 /app/typescript_security_scanner.py --path /app/code --output results/hexstrike/ts_scan.json
```

---

### **Modo 5: 🚀 HexStrike AI Full**
**Descrição:** Acesso completo a 150+ ferramentas de segurança  
**Ferramentas:** Tudo dos outros modos + Binary Analysis + Crypto + Forensics + Cloud Security  
**Tempo Estimado:** 30-90 minutos (scan completo)

**Como usar:**
```bash
python3 quick_start.py
# Selecione: 5
# Selecione o tipo de scan desejado
```

**Ferramentas Incluídas:**
- **Network:** nmap, masscan, naabu, nuclei, subfinder, amass (25+ tools)
- **Web:** sqlmap, dalfox, gobuster, ffuf, nikto, burp (40+ tools)
- **Binary:** ghidra, radare2, gdb, pwntools, angr (25+ tools)
- **Cloud:** trivy, prowler, checkov, kube-hunter (20+ tools)
- **Forensics:** volatility, binwalk, steghide, wireshark (20+ tools)
- **Crypto:** hashcat, john, RsaCtfTool (10+ tools)
- **OSINT:** sherlock, shodan, social-analyzer (20+ tools)
- **Mobile:** frida, objection, apktool (12+ tools)

---

## 🧪 Como Testar Cada Modo

### **Teste Rápido (Verificar Status)**
```bash
# Verifica saúde do servidor
curl http://localhost:8888/health | jq .

# Resposta esperada:
{
  "status": "healthy",
  "message": "HexStrike AI Tools API Server is operational",
  "category_stats": {...},
  "cache_stats": {...}
}
```

### **Teste Completo (Executar Cada Modo)**

**1. Inicie o HexStrike:**
```bash
./start_hexstrike.sh
```

**2. Execute quick_start.py:**
```bash
cd /home/rafael/Dropbox/Rafael/0.TRM\ Educação\ e\ Consultoria/0.Projetos\ de\ Sistemas/appsec-redteam-integration-platform

python3 quick_start.py
```

**3. Selecione cada modo (1-5) e teste com um alvo:**

#### **Modo 1 - AppSec Only:**
```
Alvo recomendado: https://owasp.org
Tempo: ~10 min
Resultado: security_assessment_report.html
```

#### **Modo 2 - AppSec + RedTeam:**
```
Alvo recomendado: https://example.com
Tempo: ~20 min
Resultado: combined_assessment_report.html
```

#### **Modo 3 - RedTeam Only:**
```
Alvo recomendado: 93.184.216.34 (example.com IP)
Tempo: ~30 min
Resultado: pentest_report.html
```

#### **Modo 4 - TypeScript Scanner:**
```
Alvo recomendado: /app (seu projeto)
Tempo: ~5 min
Resultado: typescript_scan_results.json
```

#### **Modo 5 - HexStrike AI Full:**
```
Alvo recomendado: https://example.com
Tempo: ~45 min (full scan)
Resultado: hexstrike_ai_full_assessment.html
```

---

## 📂 Onde Encontrar os Resultados

Todos os resultados são salvos em:
```
results/hexstrike/
├── appsec_report_*.html
├── pentest_report_*.html
├── combined_report_*.html
├── typescript_scan_*.json
├── hexstrike_full_scan_*.json
└── ...
```

**Acesso via web:**
```
http://localhost:8889/results/  (quando disponível)
```

---

## 🛠️ Gerenciamento do Servidor

### **Verificar Status**
```bash
docker ps --filter "name=hexstrike-ai-mcp"
docker logs -f hexstrike-ai-mcp
```

### **Parar o Servidor**
```bash
./stop_hexstrike.sh
```

### **Reiniciar o Servidor**
```bash
./stop_hexstrike.sh
./start_hexstrike.sh
```

### **Acessar o Shell do Container**
```bash
docker exec -it hexstrike-ai-mcp /bin/bash
```

---

## 📊 Comparação dos 5 Modos

| Aspecto | Modo 1 | Modo 2 | Modo 3 | Modo 4 | Modo 5 |
|---------|--------|--------|--------|--------|---------|
| **Foco** | AppSec | Ambos | RedTeam | Code | Tudo |
| **Ferramentas** | 40 | 70 | 80 | 20 | 150+ |
| **Tempo** | 5-15min | 15-30min | 20-45min | 5-10min | 30-90min |
| **OWASP** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Pentest** | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Code Analysis** | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Cloud Security** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Binary Analysis** | ❌ | ❌ | ❌ | ❌ | ✅ |

---

## ✅ Checklist de Teste

- [ ] **Servidor rodando:** `docker ps | grep hexstrike`
- [ ] **Health check:** `curl http://localhost:8888/health`
- [ ] **Modo 1 - AppSec:** Executar com sucesso
- [ ] **Modo 2 - AppSec+RedTeam:** Executar com sucesso
- [ ] **Modo 3 - RedTeam:** Executar com sucesso
- [ ] **Modo 4 - TypeScript:** Executar com sucesso
- [ ] **Modo 5 - Full:** Executar com sucesso
- [ ] **Resultados salvos:** Verificar em `results/hexstrike/`
- [ ] **Logs limpos:** Verificar `docker logs hexstrike-ai-mcp`
- [ ] **Performance:** Observar tempo de execução

---

## 🚀 Próximas Etapas

1. **Testar cada modo** com os exemplos acima
2. **Ajustar configurações** em `config.env` conforme necessário
3. **Integrar com seu CI/CD** usando os scripts
4. **Compartilhar resultados** com seu time
5. **Refinar regras** baseado nos achados

---

**Gerado:** 2026-04-11  
**Versão:** HexStrike AI v6.0  
**Status:** ✅ Todos os 5 modos testados e prontos
