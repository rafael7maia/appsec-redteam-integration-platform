# HexStrike AI MCP Server - Docker Startup Script
# Initializes and starts the HexStrike AI container with health checks

param(
    [string]$Version = "v6.0",
    [switch]$BuildImage,
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
Write-Info "HexStrike AI MCP Server - Docker Startup"
Write-Info "========================================="

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Info "`nWorking directory: $(Get-Location)"

# =============================================================================
# 1. VERIFY DOCKER INSTALLATION
# =============================================================================

Write-Info "`n[Step 1/5] Verifying Docker installation..."

try {
    $dockerVersion = docker --version
    Write-Success "[OK] Docker is installed: $dockerVersion"
} catch {
    Write-Error "[ERROR] Docker is not installed or not in PATH"
    Write-Error "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    exit 1
}

try {
    $dockerComposeVersion = docker-compose --version
    Write-Success "[OK] Docker Compose is available: $dockerComposeVersion"
} catch {
    Write-Error "[ERROR] Docker Compose is not available"
    exit 1
}

# Verify Docker daemon is running
Write-Info "Checking if Docker daemon is running..."
try {
    docker ps > $null 2>&1
    Write-Success "[OK] Docker daemon is running"
} catch {
    Write-Error "[ERROR] Docker daemon is not running"
    Write-Error "Please start Docker Desktop and try again"
    exit 1
}

# =============================================================================
# 2. CREATE APPSEC NETWORK (if needed)
# =============================================================================

Write-Info "`n[Step 2/5] Verifying Docker network..."

$networkExists = docker network ls --filter name=appsec-network --format "{{.Name}}" 2>$null
if (-not $networkExists) {
    Write-Warning "[*] appsec-network does not exist, creating it..."
    try {
        docker network create --driver bridge appsec-network
        Write-Success "[OK] appsec-network created successfully"
    } catch {
        Write-Error "[ERROR] Failed to create appsec-network: $_"
        exit 1
    }
} else {
    Write-Success "[OK] appsec-network already exists"
}

# =============================================================================
# 3. BUILD IMAGE (optional)
# =============================================================================

if ($BuildImage) {
    Write-Info "`n[Step 3/5] Building Docker image..."

    if (-not (Test-Path "Dockerfile")) {
        Write-Error "[ERROR] Dockerfile not found in current directory"
        exit 1
    }

    Write-Warning "[*] Building appsec-redteam/hexstrike-ai:$Version (this may take a few minutes)..."
    try {
        docker build --tag "appsec-redteam/hexstrike-ai:$Version" --build-arg HEXSTRIKE_VERSION=6.0 .
        Write-Success "[OK] Docker image built successfully"
    } catch {
        Write-Error "[ERROR] Docker build failed: $_"
        exit 1
    }
} else {
    Write-Info "`n[Step 3/5] Skipping image build (use -BuildImage flag to rebuild)"
}

# =============================================================================
# 4. START CONTAINER
# =============================================================================

Write-Info "`n[Step 4/5] Starting HexStrike AI container..."

# Check if container already running
$containerRunning = docker ps --filter "name=hexstrike-ai-mcp" --format "{{.Names}}" 2>$null
if ($containerRunning) {
    Write-Warning "[*] hexstrike-ai-mcp container is already running"
    Write-Info "Stopping existing container..."
    docker-compose -f docker-compose.hexstrike.yml down 2>$null
    Start-Sleep -Seconds 2
}

# Check if results directory exists
if (-not (Test-Path "results/hexstrike")) {
    Write-Warning "[*] Creating results/hexstrike directory..."
    New-Item -ItemType Directory -Path "results/hexstrike" -Force > $null
}

# Start container with docker-compose
Write-Warning "[*] Starting HexStrike AI container..."
try {
    docker-compose -f docker-compose.hexstrike.yml up -d --remove-orphans
    Write-Success "[OK] Container started (PID: $(docker ps -q -f name=hexstrike-ai-mcp))"
} catch {
    Write-Error "[ERROR] Failed to start container: $_"
    exit 1
}

# =============================================================================
# 5. HEALTH CHECK
# =============================================================================

Write-Info "`n[Step 5/5] Waiting for HexStrike to be healthy..."

$maxWait = 120  # 2 minutes
$waited = 0
$pollInterval = 5

while ($waited -lt $maxWait) {
    # Check container status
    $healthStatus = docker inspect hexstrike-ai-mcp --format='{{.State.Health.Status}}' 2>$null
    $isRunning = docker ps -q -f name=hexstrike-ai-mcp 2>$null

    if (-not $isRunning) {
        Write-Error "[ERROR] Container failed to start or crashed"
        Write-Info "`nContainer logs:"
        docker logs hexstrike-ai-mcp --tail 20
        exit 1
    }

    if ($healthStatus -eq "healthy") {
        Write-Success "[OK] HexStrike AI is healthy!"
        break
    }

    $remaining = $maxWait - $waited
    Write-Info "[...] Waiting... ($remaining seconds remaining)"
    Start-Sleep -Seconds $pollInterval
    $waited += $pollInterval
}

if ($waited -ge $maxWait) {
    Write-Warning "[!] Health check timeout (server may still be starting)"
    Write-Info "Checking container status..."
    docker inspect hexstrike-ai-mcp
}

# =============================================================================
# 6. FINAL SUMMARY
# =============================================================================

Write-Success "`n========================================="
Write-Success "HexStrike AI Server Started Successfully"
Write-Success "========================================="

Write-Info "`nAccess Points:"
Write-Info "  API Server: http://localhost:8888"
Write-Info "  Health Check: http://localhost:8888/health"
Write-Info "  Smart Scan API: http://localhost:8888/api/intelligence/smart-scan"
Write-Info "`nManagement:"
Write-Info "  View logs: docker logs hexstrike-ai-mcp"
Write-Info "  Follow logs: docker logs -f hexstrike-ai-mcp"
Write-Info "  Stop server: .\\stop_hexstrike.ps1"
Write-Info "  Container shell: docker exec -it hexstrike-ai-mcp /bin/bash"

Write-Info "`nQuick Test:"
Write-Info "  curl http://localhost:8888/health"
Write-Info "  python quick_start.py  (then select Mode 5)"

Write-Success "`nServer is ready for HexStrike AI operations!"
Write-Info ""
