#!/bin/bash

echo "🚀 Starting All AppSec Services"
echo "==============================="

# Start Dependency Track (SCA)
echo "📊 Starting Dependency Track (SCA)..."
cd dependencytrack
docker-compose up -d
echo "✅ Dependency Track started"
echo "   - API: http://192.168.0.72:8081"
echo "   - Frontend: http://192.168.0.72:8082"
cd ..

# Start DefectDojo (Vulnerability Management)
echo "🛡️ Starting DefectDojo (Vulnerability Management)..."
cd defectdojo
docker-compose up -d
echo "✅ DefectDojo started"
echo "   - Web UI: http://localhost:8080"
echo "   - Login: admin/defectdojo"
cd ..

# Start main environment (Vulnerable App + Tools)
echo "🔧 Starting main environment (App + Scanning Tools)..."
docker-compose up -d
echo "✅ Main environment started"
echo "   - Vulnerable App: http://localhost:5000"
echo "   - OWASP ZAP: http://localhost:8090"
echo "   - Trivy: http://localhost:8083"

# Wait for services to be ready
echo "⏳ Waiting for services to initialize (45 seconds)..."
sleep 45

echo "🔍 Checking service health..."
echo "================================"

# Check Vulnerable App
if curl -s http://localhost:5000 > /dev/null; then
    echo "✅ Vulnerable App: Ready"
else
    echo "⚠️ Vulnerable App: Not ready (may need more time)"
fi

# Check DefectDojo
if curl -s http://localhost:8080 > /dev/null; then
    echo "✅ DefectDojo: Ready"
else
    echo "⚠️ DefectDojo: Still initializing (may take 2-3 minutes)"
fi

# Check Dependency Track
if curl -s http://192.168.0.72:8081 > /dev/null; then
    echo "✅ Dependency Track: Ready"
else
    echo "⚠️ Dependency Track: Still initializing (may take 2-3 minutes)"
fi

# Check ZAP
if curl -s http://localhost:8090 > /dev/null; then
    echo "✅ OWASP ZAP: Ready"
else
    echo "⚠️ OWASP ZAP: Not ready"
fi

echo ""
echo "🎯 All services started! You can now:"
echo "   1. Run the complete pipeline: ./secure_pipeline.sh"
echo "   2. Access individual services via the URLs above"
echo "   3. Stop all services: ./stop_services.sh"