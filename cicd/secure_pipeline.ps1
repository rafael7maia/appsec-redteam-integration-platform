Write-Host "🔒 Secure SDLC Pipeline - AI Bug Bounty Framework" -ForegroundColor Green
Write-Host "=================================================="

# Create results directory
New-Item -ItemType Directory -Force -Path "results" | Out-Null

Write-Host "🔍 Phase 0: Checking AppSec Services" -ForegroundColor Yellow
Write-Host "----------------------------------"

# Check if services are running
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5000" -TimeoutSec 5 -UseBasicParsing
    Write-Host "✅ Services are running. Proceeding with pipeline..." -ForegroundColor Green
    Write-Host "   - Vulnerable App: http://localhost:5000"
    Write-Host "   - DefectDojo: http://localhost:8080"
    Write-Host "   - Dependency Track: http://192.168.0.72:8081-8082"
    Write-Host ""
} catch {
    Write-Host "⚠️ Services not running. Please start them first:" -ForegroundColor Red
    Write-Host "   .\start_services.ps1"
    Write-Host "❌ Exiting pipeline..." -ForegroundColor Red
    exit 1
}

Write-Host "📋 Phase 1: SCA (Software Composition Analysis)" -ForegroundColor Yellow
Write-Host "-----------------------------------------------"
Write-Host "Running Trivy SCA scan..."
docker run --rm -v ${PWD}/codigo:/code aquasec/trivy:latest fs --format json --output /code/../results/trivy-sca.json /code

Write-Host "🔐 Phase 2: Secret Scanning" -ForegroundColor Yellow
Write-Host "---------------------------"
Write-Host "Running GitLeaks secret scan..."
docker run --rm -v ${PWD}/codigo:/code -v ${PWD}/results:/results zricethezav/gitleaks:latest detect --source /code --report-format json --report-path /results/gitleaks-report.json --verbose

Write-Host "🔍 Phase 3: SAST (Static Application Security Testing)" -ForegroundColor Yellow
Write-Host "------------------------------------------------------"
Write-Host "Running Bandit SAST scan..."
docker run --rm -v ${PWD}/codigo:/code cytopia/bandit bandit -r /code -f json -o /code/../results/bandit-results.json

Write-Host "🌐 Phase 4: DAST (Dynamic Application Security Testing)" -ForegroundColor Yellow
Write-Host "-------------------------------------------------------"
Write-Host "Running OWASP ZAP DAST scan..."
docker run --rm --network host -v ${PWD}/results:/zap/wrk/:rw zaproxy/zap-stable:latest zap-baseline.py -t http://localhost:5000 -J zap-report.json

Write-Host "🔄 Phase 5: AppSec Bridge Processing" -ForegroundColor Yellow
Write-Host "------------------------------------"
Set-Location ..

# Process each scan type with our bridge
Write-Host "Processing SCA results..."
if (Test-Path "cicd/results/trivy-sca.json") {
    python appsec_bridge.py trivy cicd/results/trivy-sca.json > cicd/results/bridge-sca.json
}

Write-Host "Processing Secret scan results..."
if (Test-Path "cicd/results/gitleaks-report.json") {
    python appsec_bridge.py gitleaks cicd/results/gitleaks-report.json > cicd/results/bridge-secrets.json
}

Write-Host "Processing SAST results..."
if (Test-Path "cicd/results/bandit-results.json") {
    python appsec_bridge.py bandit cicd/results/bandit-results.json > cicd/results/bridge-sast.json
}

Write-Host "⚔️ Phase 6: Red Team Validation" -ForegroundColor Yellow
Write-Host "-------------------------------"
Write-Host "Executing Red Team validation..."
python security_bridge.py mitre_attack_chain localhost:5000

Write-Host "📊 Phase 7: Consolidated Report" -ForegroundColor Yellow
Write-Host "------------------------------"
python generate_consolidated_report.py cicd/results/

Write-Host "🌐 Phase 8: HTML Report Generation" -ForegroundColor Yellow
Write-Host "----------------------------------"
python generate_html_report.py cicd/results/

Set-Location cicd

Write-Host "✅ Secure SDLC Pipeline Complete!" -ForegroundColor Green
Write-Host "📁 Results available in: cicd/results/"
Write-Host "🌐 Services running:"
Write-Host "   - Dependency Track: http://192.168.0.72:8081-8082"
Write-Host "   - DefectDojo: http://localhost:8080 (admin/defectdojo)"
Write-Host "   - Vulnerable App: http://localhost:5000"
Write-Host ""
Write-Host "📊 Reports generated:"
Write-Host "   - HTML Report: cicd/results/security_assessment_report.html"
Write-Host "   - JSON Report: cicd/results/consolidated_security_report.json"
Write-Host ""
Write-Host "💡 To stop services: .\stop_services.ps1"