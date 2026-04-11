# 🏗️ CICD - Complete AppSec Environment

## 🚀 **Quick Start**

### **1. Start Dependency Track (SCA)**
```bash
cd dependencytrack
docker-compose up -d
```
- **API**: http://192.168.0.72:8081
- **Frontend**: http://192.168.0.72:8082

### **2. Start DefectDojo (SAST/DAST Management)**
```bash
cd ../defectdojo
docker-compose up -d
```
- **DefectDojo**: http://localhost:8080 (admin/defectdojo)

### **3. Start Main Environment**
```bash
cd ..
docker-compose up -d
```
- **Vulnerable App**: http://localhost:5000
- **OWASP ZAP**: http://localhost:8090
- **Trivy**: http://localhost:8083

### **4. Run Secure SDLC Pipeline**
```bash
./secure_pipeline.sh
```

## 📁 **Structure**
```
cicd/
├── dependencytrack/        # SCA - Separate service
│   └── docker-compose.yaml # Uses IP 192.168.0.72
├── defectdojo/            # SAST/DAST management
│   └── docker-compose.yml
├── codigo/                # Vulnerable application
│   ├── vulnerable-app.py
│   ├── .env              # Secrets for GitLeaks
│   └── config.py         # More hardcoded secrets
├── docker-compose.yml    # Main environment
├── secure_pipeline.sh    # Complete SDLC pipeline
└── run_gitleaks.sh      # Standalone secret scan
```

## 🔄 **Services Structure**
- **dependencytrack/** - SCA (IP: 192.168.0.72:8081-8082)
- **defectdojo/** - SAST/DAST Management (localhost:8080)
- **docker-compose.yml** - Vulnerable app + scanning tools

## 🔄 **Secure SDLC Order**
1. **SCA** - Dependency Track + Trivy
2. **Secrets** - GitLeaks
3. **SAST** - Bandit + Semgrep
4. **DAST** - OWASP ZAP
5. **Red Team** - AppSec Bridge + Security Bridge

## 🌐 **Service URLs**
- **Dependency Track**: http://192.168.0.72:8081-8082
- **DefectDojo**: http://localhost:8080 (admin/defectdojo)
- **Vulnerable App**: http://localhost:5000
- **OWASP ZAP**: http://localhost:8090
- **Trivy**: http://localhost:8083

## 📊 **Results Location**
All scan results saved to: `results/`
- `trivy-sca.json`
- `gitleaks-report.json`
- `bandit-results.json`
- `consolidated_security_report.json`