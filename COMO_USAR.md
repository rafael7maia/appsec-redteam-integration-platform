# Como Usar HexStrike AI v6.0 - Guia Prático

Bem-vindo! Este guia mostra como usar o HexStrike AI integrado à plataforma AppSec + Red Team.

## Índice

1. [Começar Rápido](#começar-rápido)
2. [Modo 5: HexStrike AI Full Platform](#modo-5-hexstrike-ai-full-platform)
3. [Usando Docker (Recomendado)](#usando-docker-recomendado)
4. [Usando Localmente (Python Puro)](#usando-localmente-python-puro)
5. [Usando via API Python](#usando-via-api-python)
6. [Entendendo os Resultados](#entendendo-os-resultados)
7. [Troubleshooting](#troubleshooting)

---

## Começar Rápido

### Opção Mais Simples (Docker)

```bash
# 1. Inicie o HexStrike
./start_hexstrike.ps1

# 2. Execute o menu principal
python quick_start.py

# 3. Selecione a opção 5 (HexStrike AI Full Platform)
# 4. Configure seu alvo e vetores de ataque
# 5. Aguarde os resultados
# 6. Pause para desligar
./stop_hexstrike.ps1
```

**Tempo total**: ~5-10 minutos para um teste rápido

---

## Modo 5: HexStrike AI Full Platform

### O que é Mode 5?

Um novo modo de operação que oferece:

- **150+ ferramentas de segurança** pré-configuradas
- **12+ agentes de IA** que trabalham automaticamente
- **Análise inteligente** do alvo
- **Correlação automática** de vulnerabilidades
- **Relatórios estruturados** de segurança

### Quando Usar Mode 5?

| Cenário | Mode 1 | Mode 2 | Mode 3 | Mode 4 | Mode 5 |
|---------|--------|--------|--------|--------|--------|
| Análise de código | ✓ | ✓ | - | - | ✓ |
| Pentest externo | - | ✓ | ✓ | - | ✓ |
| Bug bounty | - | - | ✓ | - | ✓ |
| Express + Prisma | - | - | - | ✓ | ✓ |
| Análise completa | - | - | - | - | ✓ |

**Use Mode 5 quando precisar de:** Uma análise abrangente com múltiplas ferramentas trabalhando juntas.

---

## Usando Docker (Recomendado)

### Passo 1: Iniciar o HexStrike

```bash
./start_hexstrike.ps1
```

**O que acontece:**
1. ✓ Verifica se Docker está instalado
2. ✓ Cria a rede do Docker (appsec-network)
3. ✓ Faz o build da imagem (primeira vez)
4. ✓ Inicia o container
5. ✓ Aguarda health check
6. ✓ Exibe status final

**Saída esperada:**
```
[OK] Docker is installed
[OK] appsec-network created
[OK] Container started
[OK] HexStrike AI is healthy!

Access Points:
  API Server: http://localhost:8888
  Health Check: http://localhost:8888/health
```

### Passo 2: Executar uma Análise

```bash
python quick_start.py
```

**Será exibido:**
```
======================================================================
        AppSec + Red Team Integration Platform - Main Menu
======================================================================

Selecione o modo de operacao:
1. AppSec Only - Analise de codigo fonte (SCA, Secrets, SAST, DAST)
2. AppSec + Red Team - Analise completa com validacao externa
3. Red Team Only - Bug bounty hunting e pentest externo
4. TypeScript/Node.js Scanner - Analise especializada para Express + Prisma
5. HexStrike AI Full Platform - 150+ ferramentas com automacao IA

Escolha (1-5): 5
```

### Passo 3: Configurar o Alvo

Quando você seleciona 5, será solicitado:

```
Nomes do projeto: meu_primeiro_scan

--- Configuracao HexStrike AI Full Platform ---
Target Domain (ex: example.com): example.com

Atack Vectors (selecione multiplos separados por virgula):
1. reconnaissance - Coleta de informacoes
2. vulnerability_scanning - Scan de vulnerabilidades
3. exploitation - Execucao de exploits
4. web_application - Teste de aplicacoes web
5. network - Teste de rede
6. api_security - Teste de APIs
7. cloud - Teste de infraestrutura cloud

Escolha (ex: 1,2,4): 1,2,4
```

**Explicação dos vetores:**

| Vetor | O que faz | Tempo |
|-------|-----------|-------|
| reconnaissance | Coleta de informações (DNS, WHOIS, etc) | 2-5 min |
| vulnerability_scanning | Procura por vulnerabilidades conhecidas | 5-15 min |
| exploitation | Tenta explorar vulnerabilidades | 10-30 min |
| web_application | Testes de segurança web (OWASP Top 10) | 5-15 min |
| network | Testes de segurança de rede | 5-10 min |
| api_security | Análise de APIs REST/GraphQL | 5-10 min |
| cloud | Auditoria de recursos cloud (AWS/Azure/GCP) | 10-20 min |

### Passo 4: Aguardar Resultados

O HexStrike mostrará progress:

```
======================================================================
HexStrike AI Full Platform - Mode 5 Execution
======================================================================

[Banner profissional do HexStrike]

[Initializing HexStrike Scanner]
Target: example.com
Attack Vectors: reconnaissance, vulnerability_scanning, web_application
Authorization: educational_lab
Mode: Local Server

[Starting Scan Execution]
...processando...

[Scan Completed Successfully]
Total Findings: 12
  - Critical: 1
  - High: 3
  - Medium: 6
  - Low: 2
Execution Time: 23.45 seconds

[Results Saved]
Results file: projetos/meu_primeiro_scan/hexstrike_results_v5.json
Findings count: 12
```

### Passo 5: Desligar

```bash
./stop_hexstrike.ps1
```

**Faz:**
- Para o container gracefully (30s timeout)
- Salva os logs em `logs/hexstrike_shutdown_*.log`
- Remove o container
- Preserva os volumes (dados salvos)

---

## Usando Localmente (Python Puro)

Se você **não quer usar Docker**:

```bash
python quick_start.py
# Selecione modo 5
# Configure o alvo
```

**⚠️ Limitações no Windows:**
- Sem 150+ ferramentas pré-instaladas
- Sem suporte a alguns recursos avançados
- Não recomendado para produção

**✓ Vantagens:**
- Sem necessidade de Docker
- Desenvolvimento mais rápido
- Integração com IDE mais simples

---

## Usando via API Python

Para integração em scripts:

### Exemplo 1: Análise Simples

```python
from hexstrike_scanner import HexStrikeScanner

# Criar scanner
scanner = HexStrikeScanner(
    target_domain='example.com',
    attack_vectors=['reconnaissance', 'vulnerability_scanning'],
    authorization='educational_lab',
    use_docker=True
)

# Executar scan completo
result = scanner.execute_full_scan()

# Verificar sucesso
if result['success']:
    print(f"Scan concluído!")
    print(f"Total findings: {result['report']['summary']['total_findings']}")
    print(f"Critical: {result['report']['summary']['critical']}")
    print(f"High: {result['report']['summary']['high']}")
else:
    print(f"Erro: {result['error']}")
```

### Exemplo 2: Controle Fino

```python
from hexstrike_scanner import HexStrikeScanner
import json

# Criar scanner com Docker
scanner = HexStrikeScanner(
    target_domain='api.example.com',
    attack_vectors=['api_security', 'reconnaissance'],
    authorization='penetration_test',
    use_docker=True
)

# Iniciar servidor
if not scanner.start_server():
    print("Falha ao iniciar servidor")
    exit(1)

print("Servidor iniciado com sucesso")

# Executar scan
print("Executando scan...")
results = scanner.run_smart_scan()

# Processar resultados
if 'findings' in results:
    for finding in results['findings']:
        print(f"- {finding.get('type')}: {finding.get('severity')}")
        print(f"  {finding.get('description')}")
else:
    print("Nenhum finding encontrado")

# Parar servidor
scanner.stop_server()
print("Servidor parado")
```

### Exemplo 3: Loop de Testes

```python
from hexstrike_scanner import HexStrikeScanner
import json

# Lista de domínios para testar
targets = [
    'site1.com',
    'site2.com',
    'api.site3.com'
]

results_all = []

for target in targets:
    print(f"\n[*] Testando {target}...")

    scanner = HexStrikeScanner(
        target_domain=target,
        attack_vectors=['reconnaissance', 'vulnerability_scanning'],
        authorization='bug_bounty_program',
        use_docker=True
    )

    result = scanner.execute_full_scan()

    if result['success']:
        findings = result['report']['summary']
        print(f"    Critical: {findings['critical']}, High: {findings['high']}")
        results_all.append({
            'target': target,
            'findings': findings
        })

# Salvar resumo
with open('scan_summary.json', 'w') as f:
    json.dump(results_all, f, indent=2)

print("\n[+] Resumo salvo em scan_summary.json")
```

---

## Entendendo os Resultados

### Arquivo de Resultados

Os resultados são salvos em:
```
projetos/{project_name}/hexstrike_results_v5.json
```

### Estrutura do Resultado

```json
{
  "success": true,
  "mode": "hexstrike",
  "project": "meu_primeiro_scan",
  "target_domain": "example.com",
  "attack_vectors": ["reconnaissance", "vulnerability_scanning"],
  "authorization": "educational_lab",
  "scan_info": {
    "timestamp": "2025-12-24 14:30:45",
    "scanner": "HexStrike AI v6.0",
    "mode": "hexstrike"
  },
  "summary": {
    "total_findings": 12,
    "critical": 1,
    "high": 3,
    "medium": 6,
    "low": 2
  },
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "description": "Endpoint /search vulnerable to SQL injection",
      "target": "example.com",
      "cvss_score": 9.8,
      "remediation": "Use parameterized queries"
    },
    // ... mais findings ...
  ],
  "execution_time": 23.45,
  "report": { /* relatório completo */ }
}
```

### Interpretando Severidades

| Severity | CVSS | O que significa | Ação |
|----------|------|-----------------|------|
| CRITICAL | 9.0-10.0 | Risco extremo, exploração trivial | Corrigir ASAP |
| HIGH | 7.0-8.9 | Risco alto, exploração provável | Corrigir esta semana |
| MEDIUM | 4.0-6.9 | Risco moderado, exploração possível | Corrigir este mês |
| LOW | 0.1-3.9 | Risco baixo, exploração improvável | Documentar e monitorar |
| INFO | N/A | Informação útil, sem risco | Revisar |

---

## Troubleshooting

### Problema 1: Docker não inicia

```
[ERROR] Docker daemon is not running
```

**Solução:**
1. Abra o Docker Desktop
2. Aguarde ele carregar completamente
3. Execute novamente: `./start_hexstrike.ps1`

### Problema 2: Porta 8888 já em uso

```
[ERROR] Docker compose failed: port 8888 already in use
```

**Solução:**

Opção A - Matar processo que está usando a porta:
```powershell
# Ver processo na porta 8888
netstat -ano | findstr :8888

# Matar o processo (substitua PID)
taskkill /PID <PID> /F
```

Opção B - Usar porta diferente:

Edite `docker-compose.hexstrike.yml`:
```yaml
ports:
  - "8889:8888"  # Use 8889 em vez de 8888
```

Depois inicie: `./start_hexstrike.ps1`

### Problema 3: HexStrike não responde

```
[ERROR] Server did not start in time
```

**Solução:**

1. Verifique logs:
```bash
docker logs hexstrike-ai-mcp --tail 50
```

2. Aumente o timeout em `hexstrike_scanner.py`:
```python
return self._wait_for_server(max_retries=120, delay=2)  # 240s ao invés de 60s
```

### Problema 4: "ModuleNotFoundError: hexstrike_scanner"

**Solução:**

Certifique-se de estar no diretório correto:
```bash
cd C:\Users\rafael\Dropbox\Rafael\0.TRM Educação e Consultoria\0.Projetos de Sistemas\appsec-redteam-integration-platform
python quick_start.py
```

### Problema 5: Resultados vazios

```
Total Findings: 0
```

**Causas possíveis:**

1. **Alvo não responde** - Verifique se `example.com` é válido
2. **Firewall bloqueando** - Tente um alvo diferente
3. **Timeout** - Aumentar tempo de espera

---

## Exemplos de Uso Prático

### Caso 1: Teste Rápido de um Site

```bash
# Inicie Docker
./start_hexstrike.ps1

# Execute
python quick_start.py
# Escolha: 5
# Projeto: teste_rapido
# Target: seu-site.com
# Vetores: 1,2 (reconnaissance + vulnerability_scanning)

# Aguarde ~10 minutos
# Confira resultados em: projetos/teste_rapido/hexstrike_results_v5.json

./stop_hexstrike.ps1
```

### Caso 2: Bug Bounty Completo

```bash
./start_hexstrike.ps1

python quick_start.py
# Escolha: 5
# Projeto: bug_bounty_target_xyz
# Target: target.bugbounty.example.com
# Vetores: 1,2,3,4,6 (todos exceto network e cloud)
# Tempo estimado: 40-60 minutos

# Revise os findings e prepare relatório

./stop_hexstrike.ps1
```

### Caso 3: Teste de API

```bash
./start_hexstrike.ps1

python quick_start.py
# Escolha: 5
# Projeto: api_security_audit
# Target: api.example.com
# Vetores: 2,6 (vulnerability_scanning + api_security)

./stop_hexstrike.ps1
```

---

## Dicas e Boas Práticas

### ✓ Faça

- **Use Docker** para tudo - é mais confiável e fácil
- **Comece simples** - use apenas 1-2 vetores primeiro
- **Revise resultados** - nem todos os findings são reais (false positives)
- **Documente tudo** - salve os resultados e relatórios
- **Teste regularmente** - agende scans periódicos

### ✗ Evite

- Testar sites que não são seus (sem permissão)
- Usar "exploitation" em produção
- Ignorar CRITICAL findings
- Deixar HexStrike rodando indefinidamente
- Criar muitos containers de uma vez

---

## Próximos Passos

### 1. Integrar com CI/CD

Adicione ao seu pipeline de CI/CD para testar a cada commit:

```yaml
# Exemplo para GitHub Actions
- name: Run HexStrike Scan
  run: |
    python quick_start.py << EOF
    5
    ci_cd_scan
    your-domain.com
    2,4,6
    EOF
```

### 2. Configurar Claude Desktop

Se quiser usar HexStrike via Claude Desktop:

1. Copie: `hexstrike-ai/hexstrike-ai-mcp.json`
2. Para: `~/.config/Claude/claude_desktop_config.json`
3. Reinicie Claude Desktop

### 3. Agendar Scans

```powershell
# Windows Task Scheduler
# Crie tarefa que executa:
# python quick_start.py (com inputs pré-configurados)
```

---

## Suporte e Documentação

- **Documentação técnica**: `HEXSTRIKE_INTEGRATION.md`
- **Sumário de integração**: `INTEGRATION_SUMMARY.txt`
- **Commits**: Veja histórico no Git para decisões arquiteturais
- **GitHub**: https://github.com/rafael7maia/appsec-redteam-integration-platform

---

**Bom uso! Qualquer dúvida, consulte a documentação técnica ou revise os exemplos acima.**
