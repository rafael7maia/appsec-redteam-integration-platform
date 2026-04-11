#!/bin/bash
# HexStrike AI MCP Server - Docker Shutdown Script for Linux/macOS
# Gracefully stops and removes the HexStrike AI container

FORCE=false

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

# Parse arguments
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    FORCE=true
fi

# =============================================================================
# SCRIPT START
# =============================================================================

echo ""
info "========================================="
info "HexStrike AI MCP Server - Docker Shutdown"
info "========================================="

# Get script directory and change to it
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

info "Working directory: $(pwd)"

# =============================================================================
# 1. CHECK IF CONTAINER IS RUNNING
# =============================================================================

info ""
info "[Step 1/4] Checking HexStrike container status..."

CONTAINER_RUNNING=$(docker ps -q -f name=hexstrike-ai-mcp 2>/dev/null)

if [ -z "$CONTAINER_RUNNING" ]; then
    warning "HexStrike AI container is not currently running"
    info "Removing any stopped container..."
    docker-compose -f docker-compose.hexstrike.yml down 2>/dev/null
    success "Cleanup completed"
    exit 0
fi

info "Container is running (ID: $CONTAINER_RUNNING)"

# =============================================================================
# 2. SAVE LOGS (optional)
# =============================================================================

info ""
info "[Step 2/4] Saving container logs..."

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="logs/hexstrike_shutdown_$TIMESTAMP.log"

if [ ! -d "logs" ]; then
    mkdir -p logs
fi

if docker logs hexstrike-ai-mcp > "$LOG_FILE" 2>&1; then
    success "Logs saved to: $LOG_FILE"
else
    warning "Could not save logs"
fi

# =============================================================================
# 3. STOP CONTAINER
# =============================================================================

info ""
info "[Step 3/4] Stopping HexStrike AI container..."

if [ "$FORCE" = true ]; then
    warning "Force stopping container (no graceful shutdown)..."
    if docker-compose -f docker-compose.hexstrike.yml kill; then
        success "Container killed"
    else
        error "Failed to kill container"
        exit 1
    fi
else
    warning "Performing graceful shutdown (30 second timeout)..."
    if docker-compose -f docker-compose.hexstrike.yml down --timeout 30; then
        success "Container stopped gracefully"
    else
        error "Failed to stop container gracefully"
        warning "Attempting force stop..."
        docker-compose -f docker-compose.hexstrike.yml kill
    fi
fi

sleep 2

# =============================================================================
# 4. VERIFY SHUTDOWN
# =============================================================================

info ""
info "[Step 4/4] Verifying shutdown..."

STILL_RUNNING=$(docker ps -q -f name=hexstrike-ai-mcp 2>/dev/null)

if [ -n "$STILL_RUNNING" ]; then
    error "Container is still running, forcing removal..."
    docker rm -f hexstrike-ai-mcp 2>/dev/null
    sleep 2
    STILL_RUNNING=$(docker ps -q -f name=hexstrike-ai-mcp 2>/dev/null)
    if [ -n "$STILL_RUNNING" ]; then
        error "Failed to remove container!"
        exit 1
    fi
fi

success "HexStrike AI container has been completely removed"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
success "========================================="
success "HexStrike AI Server Stopped"
success "========================================="

echo ""
info "Status:"
info "  Logs saved to: $LOG_FILE"
info "  Container removed: Yes"
info "  Volumes preserved: Yes"
echo ""
info "Next Steps:"
info "  Restart server: ./start_hexstrike.sh"
info "  View logs: cat $LOG_FILE"
info "  Cleanup volumes: docker volume prune"
echo ""
success "Shutdown completed successfully!"
echo ""
