Write-Host "🛑 Stopping All AppSec Services" -ForegroundColor Red
Write-Host "==============================="

# Stop main environment
Write-Host "🔧 Stopping main environment..." -ForegroundColor Yellow
docker-compose down
Write-Host "✅ Main environment stopped" -ForegroundColor Green

# Stop DefectDojo
Write-Host "🛡️ Stopping DefectDojo..." -ForegroundColor Yellow
Set-Location defectdojo
docker-compose down
Write-Host "✅ DefectDojo stopped" -ForegroundColor Green
Set-Location ..

# Stop Dependency Track
Write-Host "📊 Stopping Dependency Track..." -ForegroundColor Yellow
Set-Location dependencytrack
docker-compose down
Write-Host "✅ Dependency Track stopped" -ForegroundColor Green
Set-Location ..

# Clean up any remaining containers
Write-Host "🧹 Cleaning up..." -ForegroundColor Yellow
docker system prune -f | Out-Null

Write-Host "✅ All services stopped successfully!" -ForegroundColor Green
Write-Host "💡 To start again: .\start_services.ps1"