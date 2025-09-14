#!/bin/bash

echo "🔒 Secure SDLC Pipeline - AI Bug Bounty Framework"
echo "=================================================="

# Create results directory
mkdir -p results

echo "🔍 Phase 0: Checking AppSec Services"
echo "----------------------------------"

# Check if services are running
if ! curl -s http://localhost:5000 > /dev/null; then
    echo "⚠️ Services not running. Please start them first:"
    echo "   ./start_services.sh"
    echo "❌ Exiting pipeline..."
    exit 1
fi

echo "✅ Services are running. Proceeding with pipeline..."
echo "   - Vulnerable App: http://localhost:5000"
echo "   - DefectDojo: http://localhost:8080"
echo "   - Dependency Track: http://192.168.0.72:8081-8082"
echo ""

echo "📋 Phase 1: SCA (Software Composition Analysis)"
echo "-----------------------------------------------"
# Generate SBOM for dependency analysis
echo "Generating SBOM..."
pip freeze > requirements.txt
cyclonedx-py -o results/sbom.json 2>/dev/null || echo "CycloneDX not available, using pip freeze"

# Trivy dependency scan
echo "Running Trivy SCA scan..."
docker run --rm -v $(pwd)/codigo:/code aquasec/trivy:latest fs --format json --output /code/../results/trivy-sca.json /code

echo "🔐 Phase 2: Secret Scanning"
echo "---------------------------"
# GitLeaks secret detection
echo "Running GitLeaks secret scan..."
docker run --rm -v $(pwd)/codigo:/code -v $(pwd)/results:/results zricethezav/gitleaks:latest detect --source /code --report-format json --report-path /results/gitleaks-report.json --verbose

echo "🔍 Phase 3: SAST (Static Application Security Testing)"
echo "------------------------------------------------------"
# Bandit for Python SAST
echo "Running Bandit SAST scan..."
docker run --rm -v $(pwd)/codigo:/code cytopia/bandit bandit -r /code -f json -o /code/../results/bandit-results.json

# Semgrep SAST (alternative)
echo "Running Semgrep SAST scan..."
docker run --rm -v $(pwd)/codigo:/code returntocorp/semgrep semgrep --config=auto --json --output=/code/../results/semgrep-results.json /code

echo "🌐 Phase 4: DAST (Dynamic Application Security Testing)"
echo "-------------------------------------------------------"
# Check if app is running
if ! curl -s http://localhost:5000 > /dev/null; then
    echo "⚠️  Application not running. Starting vulnerable app..."
    cd codigo && python vulnerable-app.py &
    APP_PID=$!
    sleep 5
    cd ..
fi

# OWASP ZAP DAST scan
echo "Running OWASP ZAP DAST scan..."
docker run --rm --network host -v $(pwd)/results:/zap/wrk/:rw zaproxy/zap-stable:latest zap-baseline.py -t http://localhost:5000 -J zap-report.json

# Kill app if we started it
if [ ! -z "$APP_PID" ]; then
    kill $APP_PID 2>/dev/null
fi

echo "🔄 Phase 5: AppSec Bridge Processing"
echo "------------------------------------"
cd ..

# Process each scan type with our bridge
echo "Processing SCA results..."
python appsec_bridge.py trivy cicd/results/trivy-sca.json > cicd/results/bridge-sca.json

echo "Processing Secret scan results..."
python appsec_bridge.py gitleaks cicd/results/gitleaks-report.json > cicd/results/bridge-secrets.json

echo "Processing SAST results..."
python appsec_bridge.py bandit cicd/results/bandit-results.json > cicd/results/bridge-sast.json

echo "⚔️ Phase 6: Red Team Validation"
echo "-------------------------------"
# Start app for exploitation
cd cicd/codigo && python vulnerable-app.py &
APP_PID=$!
sleep 3
cd ../..

# Execute exploitation based on findings
echo "Executing Red Team validation..."
python security_bridge.py mitre_attack_chain localhost:5000

# Cleanup
kill $APP_PID 2>/dev/null

echo "📊 Phase 7: Consolidated Report"
echo "------------------------------"
python generate_consolidated_report.py cicd/results/

echo "🛑 Phase 8: Cleanup (Optional)"
echo "------------------------------"
echo "Services are still running for analysis. To stop all services:"
echo "  docker-compose down"
echo "  cd defectdojo && docker-compose down && cd .."
echo "  cd dependencytrack && docker-compose down && cd .."

echo "✅ Secure SDLC Pipeline Complete!"
echo "📁 Results available in: cicd/results/"
echo "🌐 Services running:"
echo "   - Dependency Track: http://192.168.0.72:8081-8082"
echo "   - DefectDojo: http://localhost:8080 (admin/defectdojo)"
echo "   - Vulnerable App: http://localhost:5000"