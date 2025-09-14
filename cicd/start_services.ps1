Write-Host "Starting All AppSec Services" -ForegroundColor Green
Write-Host "==============================="

# Start Dependency Track (SCA)
Write-Host "Starting Dependency Track (SCA)..." -ForegroundColor Yellow
Set-Location dependencytrack
docker-compose up -d
Write-Host "Dependency Track started" -ForegroundColor Green
Write-Host "   - API: http://192.168.0.72:8081"
Write-Host "   - Frontend: http://192.168.0.72:8082"
Set-Location ..

# Start DefectDojo (Vulnerability Management)
Write-Host "Starting DefectDojo (Vulnerability Management)..." -ForegroundColor Yellow
Set-Location defectdojo
docker-compose up -d
Write-Host "DefectDojo started" -ForegroundColor Green
Write-Host "   - Web UI: http://localhost:8080"
Write-Host "   - Login: admin/defectdojo"
Set-Location ..

# Start main environment (Vulnerable App + Tools)
Write-Host "Starting main environment (App + Scanning Tools)..." -ForegroundColor Yellow
docker-compose up -d
Write-Host "Main environment started" -ForegroundColor Green
Write-Host "   - Vulnerable App: http://localhost:5000"
Write-Host "   - OWASP ZAP: http://localhost:8090"
Write-Host "   - Trivy: http://localhost:8083"

# Wait for services to be ready
Write-Host "Waiting for services to initialize (45 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 45

Write-Host "Checking service health..." -ForegroundColor Yellow
Write-Host "================================"

# Check services
try {
    Invoke-WebRequest -Uri "http://localhost:5000" -TimeoutSec 5 -UseBasicParsing | Out-Null
    Write-Host "Vulnerable App: Ready" -ForegroundColor Green
} catch {
    Write-Host "Vulnerable App: Not ready" -ForegroundColor Red
}

try {
    Invoke-WebRequest -Uri "http://localhost:8080" -TimeoutSec 5 -UseBasicParsing | Out-Null
    Write-Host "DefectDojo: Ready" -ForegroundColor Green
} catch {
    Write-Host "DefectDojo: Still initializing" -ForegroundColor Red
}

try {
    Invoke-WebRequest -Uri "http://192.168.0.72:8081" -TimeoutSec 5 -UseBasicParsing | Out-Null
    Write-Host "Dependency Track: Ready" -ForegroundColor Green
} catch {
    Write-Host "Dependency Track: Still initializing" -ForegroundColor Red
}

Write-Host ""
Write-Host "All services started! You can now:" -ForegroundColor Green
Write-Host "   1. Run the complete pipeline: .\secure_pipeline.ps1"
Write-Host "   2. Access individual services via the URLs above"
Write-Host "   3. Stop all services: .\stop_services.ps1"