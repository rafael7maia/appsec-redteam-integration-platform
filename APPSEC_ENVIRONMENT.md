# 🏗️ Complete AppSec Environment

## 🎯 **Ambiente Completo para Demonstração**

### **Arquitetura:**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Vulnerable     │    │   AppSec Tools  │    │   Red Team      │
│  Application    │◄──►│   (SCA/SAST/    │◄──►│   Validation    │
│  (Flask)        │    │    DAST)        │    │   (Our Bridge)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 **Quick Start**

### **1. Subir Ambiente Completo:**
```bash
cd cicd
docker-compose up -d
```

### **2. Acessar Serviços:**
- **Vulnerable App**: http://localhost:5000
- **DefectDojo**: http://localhost:8080 (admin/defectdojo)
- **Dependency Track**: http://localhost:8082
- **OWASP ZAP**: http://localhost:8090
- **Trivy**: http://localhost:8083
- **GitLeaks**: Run via `./run_gitleaks.sh`

## 📱 **Aplicação Vulnerável**

### **Vulnerabilidades Implementadas:**
- ✅ **SQL Injection** - `/login` endpoint
- ✅ **XSS** - `/search` endpoint  
- ✅ **Path Traversal** - `/file` endpoint
- ✅ **Command Injection** - `/cmd` endpoint
- ✅ **Insecure Deserialization** - `/deserialize` endpoint
- ✅ **Hardcoded Secrets** - Multiple files (.env, config.py, vulnerable-app.py)

### **Exemplos de Exploração:**
```bash
# SQL Injection
curl -X POST http://localhost:5000/login \
  -d "username=admin' OR '1'='1&password=anything"

# XSS
curl -X POST http://localhost:5000/search \
  -d "query=<script>alert('XSS')</script>"

# Path Traversal
curl "http://localhost:5000/file?file=../../../etc/passwd"
```

## 🔧 **Ferramentas AppSec**

### **Phase 1: SCA (Software Composition Analysis)**
```bash
# Trivy dependency scan
docker run --rm -v $(pwd)/codigo:/code aquasec/trivy:latest fs --format json /code
```

### **Phase 2: Secret Scanning**
```bash
# GitLeaks secret detection
docker run --rm -v $(pwd)/codigo:/code zricethezav/gitleaks:latest detect --source /code
```

### **Phase 3: SAST (Static Application Security Testing)**
```bash
# Bandit Python SAST
docker run --rm -v $(pwd)/codigo:/code cytopia/bandit bandit -r /code -f json
```

### **Phase 4: DAST (Dynamic Application Security Testing)**
```bash
# OWASP ZAP baseline scan
docker run --rm --network host zaproxy/zap-stable:latest zap-baseline.py -t http://localhost:5000
```

### **Phase 5: Red Team Validation**
```bash
# AppSec Bridge + Security Bridge
python appsec_bridge.py trivy results/trivy-sca.json
python security_bridge.py mitre_attack_chain localhost:5000
```

## 🔄 **Secure SDLC Pipeline**

### **Ordem Correta (Secure SDLC):**
```bash
# Execute pipeline completo
cd cicd
./secure_pipeline.sh
```

### **Fases do Pipeline:**
1. **SCA** - Trivy dependency scanning
2. **Secrets** - GitLeaks secret detection  
3. **SAST** - Bandit static analysis
4. **DAST** - OWASP ZAP dynamic testing
5. **Red Team** - Exploitation validation
6. **Report** - Consolidated findings

## 📊 **Exemplo de Resultados**

### **Input - Bandit SAST:**
```json
{
  "results": [
    {
      "filename": "vulnerable-app.py",
      "line_number": 45,
      "test_id": "B608",
      "test_name": "hardcoded_sql_expressions",
      "issue_severity": "MEDIUM",
      "issue_confidence": "MEDIUM"
    }
  ]
}
```

### **Output - AppSec Bridge:**
```json
{
  "summary": {
    "total_findings": 5,
    "exploitable": 5,
    "proven_exploitable": 4,
    "success_rate": "80.0%"
  }
}
```

## 🎯 **Demonstração de Valor**

### **Para Executivos:**
- **Antes**: "Encontramos 5 vulnerabilidades"
- **Depois**: "Provamos que 4 das 5 vulnerabilidades são exploráveis"

### **Para Desenvolvedores:**
- **Antes**: Ignoram warnings SAST
- **Depois**: Veem exploração real funcionando

### **Para AppSec Team:**
- **Antes**: Relatórios ignorados
- **Depois**: Valor demonstrado com provas

## 🔧 **Configuração Avançada**

### **Environment Variables:**
```bash
# DefectDojo
export DD_ADMIN_PASSWORD=your_password

# Dependency Track  
export DT_API_KEY=your_api_key

# ZAP
export ZAP_API_KEY=your_zap_key
```

### **Custom Scans:**
```bash
# Custom Nuclei templates
docker run -v $(pwd):/app projectdiscovery/nuclei \
  -u http://localhost:5000 -t /app/custom-templates/
```

## 📈 **Métricas de Sucesso**

### **KPIs AppSec:**
- **Vulnerability Detection Rate**: 100%
- **False Positive Rate**: <10%
- **Exploitation Proof Rate**: 80%
- **Remediation Time**: -50%

### **ROI Calculation:**
- **Tool Cost**: $X/year
- **Vulnerabilities Found**: Y
- **Exploitable Proven**: Z
- **Potential Breach Cost Avoided**: $W

## 🚀 **Próximos Passos**

### **v1.0 - Current:**
- ✅ Vulnerable app with 5 vulnerability types
- ✅ Complete AppSec toolchain
- ✅ Bridge to Red Team validation

### **v2.0 - Enhanced:**
- 🔄 CI/CD pipeline integration
- 🔄 Automated reporting
- 🔄 Slack/Teams notifications

### **v3.0 - Enterprise:**
- 🔄 Multi-application support
- 🔄 Custom vulnerability types
- 🔄 Executive dashboards

**🎯 Ambiente completo para demonstrar o valor real do AppSec através de exploração Red Team! 🚀**