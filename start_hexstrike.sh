#!/bin/bash
# HexStrike AI MCP Server - Docker Startup Script for Linux/macOS
# Initializes and starts the HexStrike AI container with health checks

VERSION="${1:-v6.0}"
BUILD_IMAGE=false
VERBOSE=false

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Helper functions
success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

info() {
    echo -e "${CYAN}[i]${NC} $1"
}

# =============================================================================
# SCRIPT START
# =============================================================================

echo ""
info "========================================="
info "HexStrike AI MCP Server - Docker Startup"
info "========================================="

# Get script directory and change to it
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

info "Working directory: $(pwd)"

# =============================================================================
# 1. VERIFY DOCKER INSTALLATION
# =============================================================================

info ""
info "[Step 1/5] Verifying Docker installation..."

if ! command -v docker &> /dev/null; then
    error "Docker is not installed or not in PATH"
    echo "Please install Docker:"
    echo "  Ubuntu/Debian: sudo apt install docker.io docker-compose"
    echo "  Or from: https://www.docker.com/products/docker-desktop"
    exit 1
fi
success "Docker is installed: $(docker --version)"

if ! command -v docker-compose &> /dev/null; then
    error "Docker Compose is not available"
    echo "Please install Docker Compose:"
    echo "  Ubuntu/Debian: sudo apt install docker-compose"
    exit 1
fi
success "Docker Compose is available: $(docker-compose --version)"

# Verify Docker daemon is running
info "Checking if Docker daemon is running..."
if ! docker ps > /dev/null 2>&1; then
    error "Docker daemon is not running"
    echo "Please start Docker and try again:"
    echo "  sudo systemctl start docker"
    exit 1
fi
success "Docker daemon is running"

# =============================================================================
# 2. CREATE APPSEC NETWORK (if needed)
# =============================================================================

info ""
info "[Step 2/5] Verifying Docker network..."

if ! docker network ls --filter name=appsec-network --format "{{.Name}}" | grep -q appsec-network; then
    warning "appsec-network does not exist, creating it..."
    if docker network create --driver bridge appsec-network; then
        success "appsec-network created successfully"
    else
        error "Failed to create appsec-network"
        exit 1
    fi
else
    success "appsec-network already exists"
fi

# =============================================================================
# 3. BUILD IMAGE (optional)
# =============================================================================

info ""
if [ "$BUILD_IMAGE" = true ]; then
    info "[Step 3/5] Building Docker image..."

    if [ ! -f "Dockerfile" ]; then
        error "Dockerfile not found in current directory"
        exit 1
    fi

    warning "Building appsec-redteam/hexstrike-ai:$VERSION (this may take a few minutes)..."
    if docker build --tag "appsec-redteam/hexstrike-ai:$VERSION" --build-arg HEXSTRIKE_VERSION=6.0 .; then
        success "Docker image built successfully"
    else
        error "Docker build failed"
        exit 1
    fi
else
    info "[Step 3/5] Skipping image build (use: ./start_hexstrike.sh build to rebuild)"
fi

# =============================================================================
# 4. START CONTAINER
# =============================================================================

info ""
info "[Step 4/5] Starting HexStrike AI container..."

# Check if container already running
if docker ps --filter "name=hexstrike-ai-mcp" --format "{{.Names}}" | grep -q hexstrike-ai-mcp; then
    warning "hexstrike-ai-mcp container is already running"
    info "Stopping existing container..."
    docker-compose -f docker-compose.hexstrike.yml down 2>/dev/null
    sleep 2
fi

# Check if results directory exists
if [ ! -d "results/hexstrike" ]; then
    warning "Creating results/hexstrike directory..."
    mkdir -p results/hexstrike
fi

# Start container with docker-compose
warning "Starting HexStrike AI container..."
if docker-compose -f docker-compose.hexstrike.yml up -d --remove-orphans; then
    CONTAINER_ID=$(docker ps -q -f name=hexstrike-ai-mcp)
    success "Container started (ID: $CONTAINER_ID)"
else
    error "Failed to start container"
    exit 1
fi

# =============================================================================
# 5. HEALTH CHECK
# =============================================================================

info ""
info "[Step 5/5] Waiting for HexStrike to be healthy..."

MAX_WAIT=120  # 2 minutes
WAITED=0
POLL_INTERVAL=5

while [ $WAITED -lt $MAX_WAIT ]; do
    # Check container status
    HEALTH_STATUS=$(docker inspect hexstrike-ai-mcp --format='{{.State.Health.Status}}' 2>/dev/null)
    IS_RUNNING=$(docker ps -q -f name=hexstrike-ai-mcp 2>/dev/null)

    if [ -z "$IS_RUNNING" ]; then
        error "Container failed to start or crashed"
        echo ""
        info "Container logs (last 20 lines):"
        docker logs hexstrike-ai-mcp --tail 20
        exit 1
    fi

    if [ "$HEALTH_STATUS" = "healthy" ]; then
        success "HexStrike AI is healthy!"
        break
    fi

    REMAINING=$((MAX_WAIT - WAITED))
    info "Waiting... ($REMAINING seconds remaining)"
    sleep $POLL_INTERVAL
    WAITED=$((WAITED + POLL_INTERVAL))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    warning "Health check timeout (server may still be starting)"
    info "Checking container status..."
    docker inspect hexstrike-ai-mcp
fi

# =============================================================================
# 6. FINAL SUMMARY
# =============================================================================

echo ""
success "========================================="
success "HexStrike AI Server Started Successfully"
success "========================================="

echo ""
info "Access Points:"
info "  API Server: http://localhost:8888"
info "  Health Check: http://localhost:8888/health"
info "  Smart Scan API: http://localhost:8888/api/intelligence/smart-scan"
echo ""
info "Management:"
info "  View logs: docker logs hexstrike-ai-mcp"
info "  Follow logs: docker logs -f hexstrike-ai-mcp"
info "  Stop server: ./stop_hexstrike.sh"
info "  Container shell: docker exec -it hexstrike-ai-mcp /bin/bash"
echo ""
info "Quick Test:"
info "  curl http://localhost:8888/health"
info "  python quick_start.py  (then select Mode 5)"
echo ""
success "Server is ready for HexStrike AI operations!"
echo ""
