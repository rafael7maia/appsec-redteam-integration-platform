# HexStrike AI MCP Server - Docker Shutdown Script
# Gracefully stops and removes the HexStrike AI container

param(
    [switch]$Force,
    [switch]$Verbose
)

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

# =============================================================================
# SCRIPT START
# =============================================================================

Write-Info "`n========================================="
Write-Info "HexStrike AI MCP Server - Docker Shutdown"
Write-Info "========================================="

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Info "`nWorking directory: $(Get-Location)"

# =============================================================================
# 1. CHECK IF CONTAINER IS RUNNING
# =============================================================================

Write-Info "`n[Step 1/4] Checking HexStrike container status..."

$containerRunning = docker ps -q -f name=hexstrike-ai-mcp 2>$null

if (-not $containerRunning) {
    Write-Warning "[!] HexStrike AI container is not currently running"
    Write-Info "Removing any stopped container..."
    docker-compose -f docker-compose.hexstrike.yml down 2>$null
    Write-Success "[OK] Cleanup completed"
    exit 0
}

Write-Info "[OK] Container is running (ID: $containerRunning)"

# =============================================================================
# 2. SAVE LOGS (optional)
# =============================================================================

Write-Info "`n[Step 2/4] Saving container logs..."

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "logs/hexstrike_shutdown_$timestamp.log"

if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" -Force > $null
}

try {
    docker logs hexstrike-ai-mcp > $logFile 2>&1
    Write-Success "[OK] Logs saved to: $logFile"
} catch {
    Write-Warning "[!] Could not save logs: $_"
}

# =============================================================================
# 3. STOP CONTAINER
# =============================================================================

Write-Info "`n[Step 3/4] Stopping HexStrike AI container..."

if ($Force) {
    Write-Warning "[*] Force stopping container (no graceful shutdown)..."
    try {
        docker-compose -f docker-compose.hexstrike.yml kill
        Write-Success "[OK] Container killed"
    } catch {
        Write-Error "[ERROR] Failed to kill container: $_"
        exit 1
    }
} else {
    Write-Warning "[*] Performing graceful shutdown (30 second timeout)..."
    try {
        docker-compose -f docker-compose.hexstrike.yml down --timeout 30
        Write-Success "[OK] Container stopped gracefully"
    } catch {
        Write-Error "[ERROR] Failed to stop container gracefully: $_"
        Write-Warning "[*] Attempting force stop..."
        docker-compose -f docker-compose.hexstrike.yml kill
    }
}

Start-Sleep -Seconds 2

# =============================================================================
# 4. VERIFY SHUTDOWN
# =============================================================================

Write-Info "`n[Step 4/4] Verifying shutdown..."

$stillRunning = docker ps -q -f name=hexstrike-ai-mcp 2>$null

if ($stillRunning) {
    Write-Error "[ERROR] Container is still running, forcing removal..."
    docker rm -f hexstrike-ai-mcp 2>$null
    Start-Sleep -Seconds 2
    $stillRunning = docker ps -q -f name=hexstrike-ai-mcp 2>$null
    if ($stillRunning) {
        Write-Error "[ERROR] Failed to remove container!"
        exit 1
    }
}

Write-Success "[OK] HexStrike AI container has been completely removed"

# =============================================================================
# SUMMARY
# =============================================================================

Write-Success "`n========================================="
Write-Success "HexStrike AI Server Stopped"
Write-Success "========================================="

Write-Info "`nStatus:"
Write-Info "  Logs saved to: $logFile"
Write-Info "  Container removed: Yes"
Write-Info "  Volumes preserved: Yes"

Write-Info "`nNext Steps:"
Write-Info "  Restart server: .\\start_hexstrike.ps1"
Write-Info "  View logs: cat $logFile"
Write-Info "  Cleanup volumes: docker volume prune"

Write-Success "`nShutdown completed successfully!"
Write-Info ""
