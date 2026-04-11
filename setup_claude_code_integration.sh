#!/bin/bash
# 🤖 Claude Code + HexStrike AI Modo 5 Integration Setup

set -e

# Colors
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
CYAN='\033[96m'
RESET='\033[0m'
BOLD='\033[1m'

# Functions
success() {
    echo -e "${GREEN}[✓]${RESET} $1"
}

error() {
    echo -e "${RED}[✗]${RESET} $1"
}

warning() {
    echo -e "${YELLOW}[!]${RESET} $1"
}

info() {
    echo -e "${CYAN}[i]${RESET} $1"
}

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}============================================${RESET}"
    echo -e "${CYAN}${BOLD}$1${RESET}"
    echo -e "${CYAN}${BOLD}============================================${RESET}"
    echo ""
}

# Main
print_header "🤖 Claude Code + HexStrike AI Modo 5 Setup"

# 1. Check prerequisites
info "Verificando pré-requisitos..."

# Check HexStrike server
if curl -s http://localhost:8888/health > /dev/null 2>&1; then
    success "HexStrike server está rodando"
else
    error "HexStrike server não está respondendo"
    error "Execute: ./start_hexstrike.sh"
    exit 1
fi

# Check Python
if command -v python3 &> /dev/null; then
    success "Python 3 instalado"
else
    error "Python 3 não encontrado"
    exit 1
fi

# Check FastMCP
if python3 -c "import mcp" 2>/dev/null; then
    success "FastMCP instalado"
else
    warning "FastMCP não instalado, tentando instalar..."
    pip3 install fastmcp --break-system-packages 2>/dev/null || pip3 install fastmcp
    success "FastMCP instalado"
fi

# 2. Get Claude Code settings path
print_header "📍 Localizando configuração do Claude Code"

# Detect OS and settings path
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    SETTINGS_PATH="$HOME/.claude/settings.json"
    if [ ! -f "$SETTINGS_PATH" ]; then
        SETTINGS_PATH="$HOME/.config/claude/settings.json"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    SETTINGS_PATH="$HOME/.claude/settings.json"
else
    error "Sistema operacional não reconhecido: $OSTYPE"
    exit 1
fi

# Check if settings file exists
if [ ! -f "$SETTINGS_PATH" ]; then
    warning "Claude Code settings não encontrado em: $SETTINGS_PATH"
    warning "Criando novo arquivo de configuração..."
    mkdir -p "$(dirname "$SETTINGS_PATH")"
    echo "{}" > "$SETTINGS_PATH"
fi

success "Configuração será atualizada em: $SETTINGS_PATH"

# 3. Get HexStrike path
print_header "📁 Configurando caminhos"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEXSTRIKE_MCP_PATH="$SCRIPT_DIR/hexstrike-ai/hexstrike_mcp.py"

if [ ! -f "$HEXSTRIKE_MCP_PATH" ]; then
    error "hexstrike_mcp.py não encontrado em: $HEXSTRIKE_MCP_PATH"
    exit 1
fi

success "HexStrike MCP: $HEXSTRIKE_MCP_PATH"

# 4. Create backup
print_header "💾 Criando backup"

BACKUP_PATH="${SETTINGS_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$SETTINGS_PATH" "$BACKUP_PATH"
success "Backup criado: $BACKUP_PATH"

# 5. Update settings.json
print_header "⚙️  Atualizando settings.json"

# Use Python to safely update JSON
python3 << EOF
import json
import os

settings_path = "$SETTINGS_PATH"
hexstrike_path = "$HEXSTRIKE_MCP_PATH"

# Read existing settings
with open(settings_path, 'r') as f:
    try:
        settings = json.load(f)
    except json.JSONDecodeError:
        settings = {}

# Ensure mcp key exists
if 'mcp' not in settings:
    settings['mcp'] = {}

if 'servers' not in settings['mcp']:
    settings['mcp']['servers'] = {}

# Add HexStrike configuration
settings['mcp']['servers']['hexstrike-ai'] = {
    "command": "python3",
    "args": [
        hexstrike_path,
        "--server",
        "http://localhost:8888",
        "--mode",
        "5"
    ],
    "description": "HexStrike AI v6.0 - Modo 5 (Full) - 150+ ferramentas de segurança",
    "timeout": 600,
    "alwaysAllow": [
        "hexstrike_scan",
        "hexstrike_appsec",
        "hexstrike_redteam",
        "hexstrike_intelligence"
    ]
}

# Write updated settings
with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)

print("✓ Configuração atualizada com sucesso!")
EOF

success "settings.json atualizado"

# 6. Verify configuration
print_header "✅ Verificando configuração"

python3 << EOF
import json

settings_path = "$SETTINGS_PATH"

with open(settings_path, 'r') as f:
    settings = json.load(f)

if 'mcp' in settings and 'servers' in settings['mcp'] and 'hexstrike-ai' in settings['mcp']['servers']:
    config = settings['mcp']['servers']['hexstrike-ai']
    print(f"✓ HexStrike MCP Server: {config['description']}")
    print(f"✓ Command: {config['command']}")
    print(f"✓ Timeout: {config['timeout']}s")
    print(f"✓ Modo: {config['args'][4]}")
else:
    print("✗ Configuração não foi salva corretamente!")
    exit(1)
EOF

# 7. Test MCP connection
print_header "🧪 Testando conexão MCP"

info "Testando conexão com HexStrike..."
if python3 "$HEXSTRIKE_MCP_PATH" --server http://localhost:8888 --mode 5 > /dev/null 2>&1; then
    success "Conexão MCP estabelecida com sucesso"
else
    warning "Conexão MCP pode precisar de configuração adicional"
fi

# 8. Final instructions
print_header "📚 Próximas Etapas"

echo -e "${BOLD}1. Reinicie Claude Code:${RESET}"
echo "   • Feche a janela do Claude Code"
echo "   • Reabra o Claude Code"
echo ""
echo -e "${BOLD}2. Use HexStrike Modo 5:${RESET}"
echo "   • @hexstrike scan https://example.com"
echo "   • @hexstrike appsec https://myapp.com"
echo "   • @hexstrike redteam 192.168.1.0/24"
echo ""
echo -e "${BOLD}3. Verificar Logs:${RESET}"
echo "   • Docker: docker logs -f hexstrike-ai-mcp"
echo "   • Health: curl http://localhost:8888/health"
echo ""
echo -e "${BOLD}4. Documentação:${RESET}"
echo "   • Leia: CLAUDE_CODE_HEXSTRIKE_INTEGRATION.md"
echo ""

print_header "✅ INTEGRAÇÃO COMPLETA!"

echo -e "${GREEN}${BOLD}HexStrike Modo 5 está pronto para uso no Claude Code!${RESET}"
echo ""
echo "Tipo: @hexstrike scan https://example.com"
echo ""
