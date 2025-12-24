# 🚀 Guia Completo - Do Básico ao Avançado

> **Tudo que você precisa saber para usar a plataforma AppSec + Red Team v6.0 com HexStrike AI**

---

## 📚 Índice

1. [Nível 0: O Que É Isto?](#nível-0-o-que-é-isto)
2. [Nível 1: Setup Inicial](#nível-1-setup-inicial)
3. [Nível 2: Primeiro Scan](#nível-2-primeiro-scan)
4. [Nível 3: 5 Modos de Operação](#nível-3-5-modos-de-operação)
5. [Nível 4: Docker e Produção](#nível-4-docker-e-produção)
6. [Nível 5: API Python Avançada](#nível-5-api-python-avançada)
7. [Nível 6: Integração CI/CD](#nível-6-integração-cicd)
8. [Nível 7: Customização Avançada](#nível-7-customização-avançada)

---

## Nível 0: O Que É Isto?

### 🎯 Resposta Simples

Uma **plataforma de testes de segurança** que:
- Analisa seu código em busca de vulnerabilidades (AppSec)
- Testa aplicações rodando contra ataques reais (Red Team)
- Usa 150+ ferramentas de segurança automaticamente
- Tem 12+ agentes de IA que trabalham juntos

### 🤔 Para Que Serve?

| Você quer... | Use Modo | Tempo |
|-------------|----------|-------|
| Verificar código antes de deploy | 1 (AppSec) | 5-10 min |
| Testar app completa | 2 (AppSec+RedTeam) | 20-30 min |
| Bug bounty hunting | 3 (RedTeam) | 10-20 min |
| Teste especializado em Node.js/Express | 4 (TypeScript) | 5-10 min |
| Análise completa com IA | 5 (HexStrike Full) | 20-40 min |

### 📊 O Que Você Vai Receber

```
{
  "vulnerabilidades_encontradas": 12,
  "severidades": {
    "CRITICAL": 1,
    "HIGH": 3,
    "MEDIUM": 6,
    "LOW": 2
  },
  "arquivo_resultado": "projetos/seu_projeto/resultado.json",
  "tempo_execução": "15 minutos"
}
```

---

## Nível 1: Setup Inicial

### Requisitos Mínimos

```bash
# Verificar Python (precisa ser 3.8+)
python --version

# Resultado esperado:
# Python 3.8.10
# OU
# Python 3.11.5
# OU qualquer 3.8+
```

### Passo 1: Clonar o Repositório

```bash
# Ir para um local legal
cd C:\Users\seu_usuario\Documents

# Clonar
git clone https://github.com/rafael7maia/appsec-redteam-integration-platform.git

# Entrar na pasta
cd appsec-redteam-integration-platform

# Resultado: você está agora dentro do projeto
```

### Passo 2: Instalar Dependências

```bash
# Windows, macOS, Linux - TUDO IGUAL
pip install -r requirements.txt

# Vai instalar:
# - requests (para chamadas HTTP)
# - flask (para web)
# - beautifulsoup4 (para parsing HTML)
# - E mais...

# Tempo: 2-5 minutos
```

### Passo 3: Verificar Instalação

```bash
# Testar se tudo está funcionando
python quick_start.py

# Você vai ver:
# ======================================================================
#       AppSec + Red Team Integration Platform - Main Menu
# ======================================================================
#
# Selecione o modo de operacao:
# 1. AppSec Only
# 2. AppSec + Red Team
# ...

# Digite Ctrl+C para sair (ou escolha uma opção)
```

✅ **Se chegou aqui, tudo está pronto!**

---

## Nível 2: Primeiro Scan

### Cenário: Você Quer Testar Seu Próprio Código

#### Opção A: Scan Rápido (Sem Docker) - 5 minutos

```bash
# 1. Abra o menu
python quick_start.py

# 2. Digite: 1 (AppSec Only)
# Resultado: Análise de código-fonte apenas

# 3. Digite o projeto:
# > meu_primeiro_teste

# 4. Copie seu código para:
# projetos/meu_primeiro_teste/app/

# 5. Pressione Enter e aguarde

# Resultado salvo em:
# projetos/meu_primeiro_teste/appsec_results.json
```

#### Opção B: Scan Completo (Com Docker) - 30 minutos

⚠️ **Requer Docker instalado!**

**Windows:**
1. Download: https://docker.com/products/docker-desktop
2. Instale e reinicie
3. Abra Docker Desktop (ícone na barra de tarefas)

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
# Faça logout e login para efetivar
```

**Depois de Docker instalado:**

```bash
# 1. Iniciar HexStrike
./start_hexstrike.ps1
# Espera aparecer:
# [OK] HexStrike AI is healthy!

# 2. Abrir menu
python quick_start.py

# 3. Escolher modo 5 (HexStrike AI Full Platform)

# 4. Configurar:
# > nome_projeto: teste_hexstrike
# > target: example.com
# > vetores: 1,2,4 (reconnaissance, vulnerability_scanning, web_application)

# 5. Aguardar (5-40 minutos dependendo do vetor)

# 6. Parar HexStrike
./stop_hexstrike.ps1

# Resultados em:
# projetos/teste_hexstrike/hexstrike_results_v5.json
```

### 📊 Como Ler os Resultados

```json
{
  "summary": {
    "total_findings": 12,
    "critical": 1,     // Corrigir AGORA
    "high": 3,         // Corrigir esta semana
    "medium": 6,       // Corrigir este mês
    "low": 2           // Documentar e monitorar
  },
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "description": "Endpoint /search vulnerável",
      "remediation": "Use prepared statements"
    },
    // ... mais findings ...
  ]
}
```

---

## Nível 3: 5 Modos de Operação

### 📋 Modo 1: AppSec Only

**Para:** Análise de código estática

**Como usar:**
```bash
python quick_start.py
# Escolha: 1
# Configure seu projeto
# Seu código será analisado por:
# - SCA (Software Composition Analysis)
# - Secrets detection
# - SAST (Static Analysis)
# - DAST (Dynamic Analysis)
```

**Saída:** `projetos/{seu_projeto}/appsec_results.json`

**Vulnerabilidades encontradas:**
- SQL Injection em queries
- XSS em templates
- Senhas hardcoded
- Dependências desatualizadas

---

### 🔄 Modo 2: AppSec + Red Team

**Para:** Análise completa com validação de exploração

**Quando usar:**
- Tem código-fonte ✅
- Tem aplicação deployada ✅
- Quer prova de exploração ✅

**Como usar:**
```bash
python quick_start.py
# Escolha: 2
# Configure:
# > projeto: meu_app
# > target: http://localhost:5000 (sua app)
# > target_profile: e-commerce (seu tipo de negócio)

# Vai fazer:
# 1. Análise de código (AppSec)
# 2. Testes contra a app rodando (Red Team)
# 3. Correlacionar resultados
# 4. Dar nota final
```

**Saída:** `projetos/{seu_projeto}/integrated_results_v5.json`

---

### 🎯 Modo 3: Red Team Only

**Para:** Teste externo sem acesso ao código

**Quando usar:**
- Não tem código-fonte
- Quer testar externamente
- Bug bounty hunting
- Pentest black-box

**Como usar:**
```bash
python quick_start.py
# Escolha: 3
# Configure:
# > projeto: target_teste
# > target: exemplo.com (sem https://)
# > target_profile: entertainment

# Vai fazer:
# 1. Reconnaissance (coleta de info)
# 2. Vulnerability scanning
# 3. Exploitation (tenta explorar)
# 4. Valida vulnerabilidades reais
```

**Saída:** `projetos/{seu_projeto}/redteam_results_v5.json`

---

### 💻 Modo 4: TypeScript/Node.js Scanner

**Para:** Análise especializada de Express + Prisma

**Quando usar:**
- Seu código é Node.js/Express
- Usa Prisma ORM
- Quer análise específica de JWT
- Quer testar autenticação

**Como usar:**
```bash
python quick_start.py
# Escolha: 4
# Configure:
# > projeto: meu_backend
# > backend_path: ./src (path do seu código)

# Vai analisar:
# - JWT vulnerabilidades
# - SQL injection em queries
# - CORS configuration
# - IDOR patterns
# - Autenticação missing
```

**Saída:** `typescript_scan_results_{timestamp}.json`

---

### ⭐ Modo 5: HexStrike AI Full Platform

**Para:** Análise completa com 150+ ferramentas

**Quando usar:**
- Quer o máximo de profundidade
- Tem tempo (20-40 min)
- Quer múltiplos vetores simultaneamente
- Quer inteligência artificial analisando

**Como usar:**
```bash
# Prerequisito: Docker instalado e rodando
./start_hexstrike.ps1

python quick_start.py
# Escolha: 5
# Configure:
# > projeto: analise_completa
# > target: seu_dominio.com
# > vetores: 1,2,4 (veja tabela abaixo)

# Aguarde 20-40 minutos

./stop_hexstrike.ps1
```

**Vetores disponíveis:**

| Número | Nome | O que faz | Tempo |
|--------|------|-----------|-------|
| 1 | reconnaissance | OSINT, DNS, WHOIS | 5 min |
| 2 | vulnerability_scanning | Procura CVEs conhecidos | 10 min |
| 3 | exploitation | Tenta explorar | 15 min |
| 4 | web_application | OWASP Top 10 | 10 min |
| 5 | network | Testes de rede | 10 min |
| 6 | api_security | REST/GraphQL | 10 min |
| 7 | cloud | AWS/Azure/GCP | 15 min |

**Exemplo de uso:**
```bash
# Reconnaissance + Vulnerability scanning + Web app testing
Vetores (ex: 1,2,4): 1,2,4
# Total esperado: ~25 minutos

# Tudo menos exploitation e cloud
Vetores (ex: 1,2,4): 1,2,4,5,6
# Total esperado: ~40 minutos
```

**Saída:** `projetos/{seu_projeto}/hexstrike_results_v5.json`

---

## Nível 4: Docker e Produção

### 🐳 Por Que Docker?

Modo 5 (HexStrike) precisa de 150+ ferramentas instaladas. Docker é mais fácil porque:
- ✅ Tudo pré-instalado
- ✅ Sem conflitos de versão
- ✅ Funciona em qualquer OS
- ✅ Isolado do seu sistema

### Setup Docker - 5 minutos

**Windows:**
```powershell
# 1. Download
# https://docker.com/products/docker-desktop

# 2. Instale (clique Next, Next, Finish)

# 3. Abra Docker Desktop (paciência, demora um pouco)

# 4. Verifique no PowerShell
docker --version
# Resultado: Docker version 24.0.0

# 5. Pronto! Use os scripts
./start_hexstrike.ps1
./stop_hexstrike.ps1
```

**Linux (Ubuntu):**
```bash
# 1. Instalar
sudo apt update
sudo apt install docker.io docker-compose

# 2. Dar permissão
sudo usermod -aG docker $USER

# 3. Logout e login

# 4. Verificar
docker --version

# 5. Pronto!
./start_hexstrike.ps1
```

### 🚀 Usar HexStrike com Docker

```bash
# 1. Verificar Docker está rodando
docker ps
# Resultado: CONTAINER ID IMAGE ... (vazio é ok)

# 2. Iniciar
./start_hexstrike.ps1
# Espera:
# [OK] Docker is installed
# [OK] appsec-network created
# [OK] Container started
# [OK] HexStrike AI is healthy!

# 3. Usar normalmente
python quick_start.py
# Escolha modo 5

# 4. Parar quando terminar
./stop_hexstrike.ps1
# Resultado: [OK] Server stopped
```

### ⚠️ Problemas Comuns Docker

**Erro: "Docker daemon is not running"**
```bash
# Solução: Abra Docker Desktop na barra de tarefas
# Aguarde 30 segundos e tente novamente
```

**Erro: "Port 8888 already in use"**
```bash
# Solução 1: Matar outro processo
netstat -ano | findstr :8888
taskkill /PID {numero} /F

# Solução 2: Usar porta diferente
# Edite docker-compose.hexstrike.yml:
# ports:
#   - "8889:8888"  # Use 8889 em vez de 8888
```

---

## Nível 5: API Python Avançada

### 📌 Quando Usar

**Scenario 1: Integração em Script**
```python
# Você tem um script Python
# Quer executar scans dentro dele
```

**Scenario 2: Loop de Múltiplos Alvos**
```python
# Quer testar 10 domínios
# Quer automatizar tudo
```

**Scenario 3: Customização Avançada**
```python
# Quer modificar parâmetros
# Quer processar resultados programaticamente
```

### Exemplo 1: Scan Simples

```python
from hexstrike_scanner import HexStrikeScanner

# Criar scanner
scanner = HexStrikeScanner(
    target_domain='example.com',
    attack_vectors=['reconnaissance', 'vulnerability_scanning'],
    authorization='educational_lab',
    use_docker=True  # Usar Docker
)

# Executar scan completo
result = scanner.execute_full_scan()

# Ver resultados
if result['success']:
    print(f"Vulnerabilidades encontradas: {result['report']['summary']['total_findings']}")
    for finding in result['report']['findings']:
        print(f"- {finding['type']}: {finding['severity']}")
else:
    print(f"Erro: {result['error']}")
```

**Output esperado:**
```
Vulnerabilidades encontradas: 12
- SQL Injection: CRITICAL
- Missing Auth: HIGH
- XSS: HIGH
...
```

### Exemplo 2: Controle Fino

```python
from hexstrike_scanner import HexStrikeScanner

scanner = HexStrikeScanner(
    target_domain='api.example.com',
    attack_vectors=['api_security', 'vulnerability_scanning'],
    authorization='penetration_test',
    use_docker=True,
    port=8888  # Porta customizada se necessário
)

# Iniciar servidor manualmente
print("[*] Iniciando servidor...")
if not scanner.start_server():
    print("[ERROR] Falha ao iniciar")
    exit(1)

print("[*] Servidor está rodando!")

# Executar scan
print("[*] Executando scan...")
results = scanner.run_smart_scan()

# Processar resultados
if 'findings' in results:
    findings_by_severity = {}
    for finding in results['findings']:
        severity = finding.get('severity', 'MEDIUM')
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(finding)

    # Agrupar e exibir
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in findings_by_severity:
            print(f"\n{severity} ({len(findings_by_severity[severity])}):")
            for f in findings_by_severity[severity]:
                print(f"  - {f['type']}: {f['description']}")

# Parar servidor
print("[*] Parando servidor...")
scanner.stop_server()
print("[+] Concluído!")
```

### Exemplo 3: Loop de Múltiplos Alvos

```python
from hexstrike_scanner import HexStrikeScanner
import json

# Lista de domínios para testar
targets = [
    'site1.com',
    'site2.com',
    'api.site3.com'
]

# Armazenar resultados
all_results = []

# Iniciar scanner uma vez
scanner = HexStrikeScanner(
    target_domain=targets[0],
    attack_vectors=['reconnaissance', 'vulnerability_scanning'],
    authorization='bug_bounty_program',
    use_docker=True
)

# Reusar para todos os alvos
for i, target in enumerate(targets):
    print(f"\n[{i+1}/{len(targets)}] Testando {target}...")

    # Atualizar target
    scanner.target = target

    # Executar scan
    result = scanner.execute_full_scan()

    if result['success']:
        findings = result['report']['summary']
        print(f"    Critical: {findings['critical']}, High: {findings['high']}")

        all_results.append({
            'target': target,
            'findings': findings,
            'timestamp': result['report']['scan_info']['timestamp']
        })

# Salvar sumário
with open('bug_bounty_summary.json', 'w') as f:
    json.dump(all_results, f, indent=2)

print(f"\n[+] Sumário salvo em bug_bounty_summary.json")
print(f"[+] Total de alvos testados: {len(all_results)}")
```

**Saída esperada:**
```
[1/3] Testando site1.com...
    Critical: 1, High: 3
[2/3] Testando site2.com...
    Critical: 0, High: 2
[3/3] Testando api.site3.com...
    Critical: 2, High: 5

[+] Sumário salvo em bug_bounty_summary.json
[+] Total de alvos testados: 3
```

---

## Nível 6: Integração CI/CD

### 🔄 GitHub Actions

Executar scans automaticamente a cada push:

**Arquivo: `.github/workflows/security-scan.yml`**

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.8'

    - name: Install dependencies
      run: pip install -r requirements.txt

    - name: Run AppSec Scan
      run: |
        python quick_start.py << EOF
        1
        github_action_${{ github.run_id }}
        EOF

    - name: Upload results
      uses: actions/upload-artifact@v3
      with:
        name: security-results
        path: projetos/github_action_*/appsec_results.json

    - name: Check for CRITICAL findings
      run: |
        python -c "
        import json
        with open('projetos/github_action_*/appsec_results.json') as f:
            data = json.load(f)
            if data['summary']['critical'] > 0:
                print('[ERROR] CRITICAL vulnerabilities found!')
                exit(1)
        "
```

### 🏗️ GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.8
  script:
    - pip install -r requirements.txt
    - python quick_start.py << EOF
      1
      gitlab_$CI_PIPELINE_ID
      EOF
  artifacts:
    paths:
      - projetos/gitlab_*/appsec_results.json
    reports:
      sast: projetos/gitlab_*/appsec_results.json
```

### 🔨 Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Install') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    python quick_start.py << EOF
                    1
                    jenkins_${BUILD_ID}
                    EOF
                '''
            }
        }

        stage('Analyze') {
            steps {
                script {
                    def results = readJSON file: 'projetos/jenkins_*/appsec_results.json'
                    if (results.summary.critical > 0) {
                        error('CRITICAL vulnerabilities found!')
                    }
                }
            }
        }
    }
}
```

---

## Nível 7: Customização Avançada

### 🎨 Modificar Comportamento

**Alterar target_profiles.json:**

```json
{
  "meu_tipo_negocio": {
    "name": "Meu Negócio",
    "description": "Tipo específico",
    "sensitive_data_patterns": [
      "my_secret_pattern",
      "empresa_cpf_.*"
    ],
    "expected_public_emails": [
      "sac@",
      "support@",
      "info@"
    ],
    "risk_weight": 1.5
  }
}
```

**Usar no scan:**
```bash
python quick_start.py
# Escolha modo
# Configure:
# > target_profile: meu_tipo_negocio
```

### 🧩 Estender AppSec Scanner

```python
from appsec_scanner import AppSecScanner

class MeuScanner(AppSecScanner):
    def custom_analysis(self, code_path):
        """Análise customizada"""
        # Sua lógica aqui
        return findings

scanner = MeuScanner()
results = scanner.scan('/path/to/code')
```

### 🤖 Usar Componentes Individuais

```python
from hexstrike_lib import (
    ModernVisualEngine,
    IntelligentDecisionEngine,
    VulnerabilityCorrelator
)

# Visual
visual = ModernVisualEngine()
print(visual.create_banner("Meu Scan"))

# Decisão
engine = IntelligentDecisionEngine()
recommendations = engine.select_tools(target_profile)

# Correlação
correlator = VulnerabilityCorrelator()
correlated = correlator.correlate_findings({
    'tool1': results1,
    'tool2': results2
})
```

---

## 📚 Tabela de Referência Rápida

### Qual Modo Usar?

```
┌─────────────────────────┬──────────────┬──────────────┬─────────────┐
│ Seu Cenário             │ Modo | Tempo │ Requisito    │ Output      │
├─────────────────────────┼──────────────┼──────────────┼─────────────┤
│ Análise de código       │ 1    │ 5min  │ Código fonte │ JSON        │
│ Teste completo          │ 2    │ 20min │ Código+App   │ JSON        │
│ Bug bounty              │ 3    │ 15min │ Domínio      │ JSON        │
│ Express/Node.js         │ 4    │ 5min  │ Código TS    │ JSON        │
│ Análise máxima          │ 5    │ 30min │ Docker+Host  │ JSON        │
└─────────────────────────┴──────────────┴──────────────┴─────────────┘
```

### Arquivos de Saída

```
projetos/seu_projeto/
├── appsec_results.json              (Modo 1)
├── integrated_results_v5.json        (Modo 2)
├── redteam_results_v5.json           (Modo 3)
├── typescript_scan_results_*.json    (Modo 4)
└── hexstrike_results_v5.json         (Modo 5)
```

### Severidades

| Nível | CVSS | Tempo | Ação |
|-------|------|-------|------|
| CRITICAL | 9.0-10.0 | Agora | Corrigir imediatamente |
| HIGH | 7.0-8.9 | 1 semana | Corrigir com prioridade |
| MEDIUM | 4.0-6.9 | 1 mês | Corrigir planejado |
| LOW | 0.1-3.9 | 3 meses | Documentar |
| INFO | N/A | N/A | Revisar |

---

## 🆘 Troubleshooting

### Problema: "ModuleNotFoundError"
```bash
# Solução
pip install -r requirements.txt
```

### Problema: "Port 8888 already in use"
```bash
# Windows
netstat -ano | findstr :8888
taskkill /PID {PID} /F

# Linux/Mac
lsof -i :8888
kill -9 {PID}
```

### Problema: "Docker daemon is not running"
```bash
# Windows: Abra Docker Desktop
# Linux: sudo systemctl start docker
```

### Problema: Scan muito lento
```bash
# Use menos vetores
Vetores (ex: 1,2,4): 1,2
# Em vez de
Vetores (ex: 1,2,4): 1,2,3,4,5,6,7
```

---

## 📞 Próximos Passos

### Iniciante
1. Ler este guia (você está aqui!)
2. Fazer primeiro scan no Modo 1
3. Revisar resultados

### Intermediário
1. Tentar Modo 2 (AppSec+RedTeam)
2. Usar Docker com Modo 5
3. Explorar 5 modos diferentes

### Avançado
1. Usar API Python para automação
2. Integrar CI/CD
3. Customizar comportamento
4. Contribuir melhorias

---

**Fim do Guia Completo!**

Para mais detalhes:
- 📖 [COMO_USAR.md](COMO_USAR.md) - Guia prático português
- 🏗️ [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md) - Arquitetura técnica
- 💻 [README.md](README.md) - Visão geral
