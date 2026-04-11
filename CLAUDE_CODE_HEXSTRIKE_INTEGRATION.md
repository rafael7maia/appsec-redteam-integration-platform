# 🤖 Claude Code + HexStrike AI Modo 5 Integration

**Integre o HexStrike AI Modo 5 (150+ ferramentas) ao Claude Code para análise de segurança automática**

---

## 📋 Pré-requisitos

- ✅ HexStrike AI rodando: `./start_hexstrike.sh`
- ✅ Claude Code CLI instalado
- ✅ Python 3.11+
- ✅ FastMCP instalado: `pip3 install fastmcp`

---

## 🔧 Configuração (2 Métodos)

### **Método 1: Via Claude Code Settings (Recomendado)**

#### **1. Localize o arquivo de configuração do Claude Code**

Dependendo do seu sistema:

**Linux/macOS:**
```bash
~/.claude/settings.json
# ou
~/.config/claude/settings.json
```

**Windows:**
```powershell
%AppData%\claude\settings.json
# ou
%AppData%\Claude\settings.json
```

#### **2. Adicione a configuração MCP**

Abra `settings.json` e adicione/atualize:

```json
{
  "mcp": {
    "servers": {
      "hexstrike-ai": {
        "command": "python3",
        "args": [
          "~/Dropbox/Rafael/0.TRM Educação e Consultoria/0.Projetos de Sistemas/appsec-redteam-integration-platform/hexstrike-ai/hexstrike_mcp.py",
          "--server",
          "http://localhost:8888",
          "--mode",
          "5"
        ],
        "description": "HexStrike AI v6.0 - Modo 5 (Full) - 150+ ferramentas de segurança",
        "timeout": 600,
        "alwaysAllow": [
          "hexstrike_scan",
          "hexstrike_appsec",
          "hexstrike_redteam",
          "hexstrike_intelligence"
        ]
      }
    }
  }
}
```

#### **3. Adapte o caminho conforme sua localização**

Se você está em uma localização diferente, substitua o caminho em `args[0]`:

```bash
# Encontre o caminho correto:
pwd
ls -la hexstrike-ai/hexstrike_mcp.py
```

---

### **Método 2: Via Environment Variables**

```bash
# Configure as variáveis de ambiente
export HEXSTRIKE_SERVER="http://localhost:8888"
export HEXSTRIKE_MODE="5"
export HEXSTRIKE_TIMEOUT="600"

# Inicie o Claude Code
claude-code
```

---

## 🧪 Testando a Integração

### **1. Verifique se o HexStrike está rodando**

```bash
curl http://localhost:8888/health | jq .
```

**Resposta esperada:**
```json
{
  "status": "healthy",
  "message": "HexStrike AI Tools API Server is operational",
  "category_stats": {...},
  "cache_stats": {...}
}
```

### **2. Teste a conexão MCP**

```bash
# Verifique se o cliente MCP consegue se conectar
python3 ~/Dropbox/Rafael/0.TRM\ Educação\ e\ Consultoria/0.Projetos\ de\ Sistemas/appsec-redteam-integration-platform/hexstrike-ai/hexstrike_mcp.py --server http://localhost:8888 --mode 5
```

### **3. Reinicie o Claude Code**

```bash
# Se estiver usando Claude Code CLI
claude-code
```

---

## 🚀 Usando HexStrike Modo 5 no Claude Code

### **Comandos Disponíveis**

Uma vez integrado, você pode usar estes comandos:

#### **Escanear uma URL/IP**
```
@hexstrike scan https://example.com
```

#### **AppSec Assessment**
```
@hexstrike appsec https://myapp.com
```

#### **Red Team Operations**
```
@hexstrike redteam 192.168.1.0/24
```

#### **Inteligência de Segurança**
```
@hexstrike intelligence api.example.com
```

#### **Análise de Código**
```
@hexstrike analyze /path/to/code
```

---

## 📚 Exemplos de Uso

### **Exemplo 1: Análise AppSec Completa**

```
Faça uma análise de segurança AppSec completa no https://owasp.org usando o HexStrike Modo 5. Verifique vulnerabilidades OWASP TOP 10 e gere um relatório.
```

**O Claude Code irá:**
1. Conectar ao HexStrike Modo 5
2. Executar ferramentas AppSec (bandit, semgrep, nikto, etc)
3. Coletar vulnerabilidades
4. Gerar relatório consolidado

### **Exemplo 2: Pentest Automático**

```
Execute um pentest completo no IP 93.184.216.34 usando HexStrike Modo 5. Incluir:
- Reconhecimento de rede (nmap, masscan)
- Teste de web applications (nuclei, sqlmap)
- OSINT (shodan, theHarvester)
```

### **Exemplo 3: Análise de Código TypeScript**

```
Analise a segurança do código em /meu/projeto/node usando HexStrike Modo 5. Verifique:
- Dependências vulneráveis
- Vulnerabilidades SAST
- Issues de configuração
```

---

## 🎯 Modo 5 Features

### **Ferramentas Incluídas (150+)**

#### **Reconhecimento (25+ ferramentas)**
- nmap, masscan, naabu
- subfinder, amass, assetfinder
- nuclei, httpx, katana
- gau, waybackurls
- dnsrecon, dnsenum, theHarvester

#### **Web Application (40+ ferramentas)**
- nuclei, dalfox, sqlmap
- gobuster, ffuf, nikto
- dirb, wfuzz, commix
- burpsuite, zaproxy
- selenium, chromium

#### **Authentication & Crypto (12+ ferramentas)**
- hydra, john, hashcat
- patator, medusa, ophcrack
- openssl, gpg, RsaCtfTool

#### **Binary Analysis (25+ ferramentas)**
- ghidra, radare2, gdb
- pwntools, angr, ropper
- binwalk, strings, objdump

#### **Cloud Security (20+ ferramentas)**
- trivy, checkov, prowler
- kube-hunter, kube-bench
- docker tools, kubectl

#### **Forensics (20+ ferramentas)**
- volatility, binwalk, steghide
- wireshark, tcpdump, sleuthkit
- photorec, testdisk, autopsy

#### **OSINT (20+ ferramentas)**
- sherlock, social-analyzer
- shodan, censys, spiderfoot
- httprobe, hakrawler, chaos-client

#### **Mobile (12+ ferramentas)**
- adb, apktool, jadx
- frida-tools, objection
- dex2jar

---

## 🔐 Segurança & Permissões

### **AlwaysAllow (Permissões Automáticas)**

Estas funções têm permissão automática:
```json
"alwaysAllow": [
  "hexstrike_scan",
  "hexstrike_appsec",
  "hexstrike_redteam",
  "hexstrike_intelligence"
]
```

### **Configurar Permissões por Comando**

Para revisar cada comando:
```json
"alwaysAllow": []
```

Você será solicitado para cada execução.

---

## 🐛 Troubleshooting

### **Erro: "HexStrike server not responding"**

```bash
# 1. Verifique se o servidor está rodando
docker ps | grep hexstrike

# 2. Inicie o servidor
./start_hexstrike.sh

# 3. Teste a conexão
curl http://localhost:8888/health
```

### **Erro: "MCP server connection failed"**

```bash
# 1. Verifique a configuração do settings.json
cat ~/.claude/settings.json | jq .mcp

# 2. Teste o script MCP diretamente
python3 hexstrike-ai/hexstrike_mcp.py --server http://localhost:8888

# 3. Instale FastMCP se necessário
pip3 install fastmcp
```

### **Erro: "No such file or directory"**

```bash
# 1. Verifique o caminho completo
pwd
ls -la hexstrike-ai/hexstrike_mcp.py

# 2. Use o caminho absoluto ou expanda ~
# NO settings.json, use:
"$(eval echo ~)/Dropbox/Rafael/..."
```

### **Erro: "Timeout while executing command"**

```json
{
  "timeout": 900  // Aumente para 15 minutos (900s)
}
```

---

## 📊 Monitoramento

### **Ver Logs do HexStrike**

```bash
docker logs -f hexstrike-ai-mcp | tail -100
```

### **Ver Logs do MCP Client**

```bash
# Claude Code logs (varia por sistema)
tail -f ~/.claude/logs/mcp.log
```

### **Status do Servidor**

```bash
curl http://localhost:8888/health -s | jq .
```

---

## 🔄 Atualizar Configuração

Se você atualizar o hexstrike_mcp.py ou o servidor:

```bash
# 1. Recarregue o servidor
docker restart hexstrike-ai-mcp

# 2. Reinicie Claude Code
# (Close and reopen)

# 3. Teste novamente
curl http://localhost:8888/health
```

---

## 📝 Exemplos Avançados

### **Integração em Workflow**

```markdown
## Processo de Security Assessment

1. **Reconhecimento**
   @hexstrike redteam 192.168.1.0/24
   
2. **AppSec Testing**
   @hexstrike appsec https://app.local
   
3. **Análise de Código**
   @hexstrike analyze /src

4. **Geração de Relatório**
   Claude: Consolida os 3 resultados
```

### **Automação de Testes**

```
Crie um pipeline de testes que:
1. Escaneia com HexStrike Modo 5
2. Documenta vulnerabilidades
3. Prioriza por CVSS
4. Gera plano de remediação
```

---

## ✅ Checklist de Configuração

- [ ] HexStrike rodando: `docker ps | grep hexstrike`
- [ ] Health check passando: `curl http://localhost:8888/health`
- [ ] settings.json atualizado com MCP config
- [ ] Caminho do hexstrike_mcp.py correto
- [ ] FastMCP instalado: `pip3 install fastmcp`
- [ ] Claude Code reiniciado
- [ ] Teste simples: `@hexstrike scan https://example.com`
- [ ] Logs verificados sem erros

---

## 🎯 Próximos Passos

1. **Completar configuração** usando Method 1 ou 2
2. **Testar integração** com exemplos simples
3. **Explorar Modo 5** com seus próprios alvos
4. **Automatizar workflows** com Claude Code
5. **Integrar com CI/CD** para testes contínuos

---

**Versão:** HexStrike AI v6.0  
**Última Atualização:** 2026-04-11  
**Status:** ✅ Pronto para Uso
