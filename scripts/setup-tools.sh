#!/usr/bin/env bash
###############################################################################
#  PHANTOM AI v3 — Security Tool Setup (macOS / Homebrew)
#  Run once to install all tools the 7 agents need.
#
#  Usage:
#    chmod +x scripts/setup-tools.sh
#    ./scripts/setup-tools.sh
###############################################################################
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

header() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }
ok()     { echo -e "${GREEN}  ✓${NC} $1"; }
warn()   { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail()   { echo -e "${RED}  ✗${NC} $1"; }

echo -e "${RED}"
cat << 'BANNER'
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
  AI v3 — Tool Setup
BANNER
echo -e "${NC}"

# ── Prerequisites ──────────────────────────────────────────────────────────
header "Checking Prerequisites"

if ! command -v brew &>/dev/null; then
    warn "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
ok "Homebrew: $(brew --version | head -1)"

if ! command -v python3 &>/dev/null; then fail "Python 3 required — install from python.org"; exit 1; fi
ok "Python: $(python3 --version)"

if ! command -v node &>/dev/null; then
    warn "Node.js not found. Installing..."
    brew install node
fi
ok "Node: $(node --version)"

if ! command -v docker &>/dev/null; then
    warn "Docker not found. Install Docker Desktop from https://docker.com"
else
    ok "Docker: $(docker --version)"
fi

# ── Homebrew security tools ────────────────────────────────────────────────
header "Installing Security Tools (Homebrew)"

BREW_TOOLS=(
    # Recon
    subfinder amass whatweb
    # Web
    nuclei nikto gobuster ffuf feroxbuster
    # Network
    nmap masscan
    # Exploit
    hashcat john-jumbo exploitdb
    # Auth
    hydra
)

for tool in "${BREW_TOOLS[@]}"; do
    if brew list "$tool" &>/dev/null 2>&1; then
        ok "$tool (already installed)"
    else
        echo "  Installing $tool..."
        brew install "$tool" 2>/dev/null && ok "$tool" || warn "$tool — install failed (try manually)"
    fi
done

# ── pip tools ─────────────────────────────────────────────────────────────
header "Installing Python Security Tools (pip)"

PIP_TOOLS=(sqlmap theHarvester smbmap crackmapexec scoutsuite prowler kube-hunter pacu jwt_tool)
for tool in "${PIP_TOOLS[@]}"; do
    echo "  Installing $tool..."
    pip3 install "$tool" --break-system-packages --quiet 2>/dev/null \
        && ok "$tool" \
        || warn "$tool — install failed (try: pip3 install $tool)"
done

# ── Wordlists ──────────────────────────────────────────────────────────────
header "Installing Wordlists"

if brew list seclists &>/dev/null 2>&1; then
    ok "SecLists (already installed)"
else
    echo "  Installing SecLists (large download)..."
    brew install seclists && ok "SecLists" || warn "SecLists — failed"
fi

if brew list wordlist &>/dev/null 2>&1; then
    ok "RockYou.txt (already installed)"
else
    echo "  Installing wordlist (includes rockyou.txt)..."
    brew install wordlist && ok "RockYou.txt" || warn "wordlist — failed"
fi

# Check rockyou location
if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
    ok "rockyou.txt found: /usr/share/wordlists/rockyou.txt"
elif ls /opt/homebrew/share/wordlists/rockyou* &>/dev/null 2>&1; then
    RYPATH=$(ls /opt/homebrew/share/wordlists/rockyou* | head -1)
    ok "rockyou found: $RYPATH"
    # Create symlink for standard path
    sudo mkdir -p /usr/share/wordlists
    sudo ln -sf "$RYPATH" /usr/share/wordlists/rockyou.txt 2>/dev/null || warn "Could not create symlink (run manually)"
else
    warn "rockyou.txt not found — manually place at /usr/share/wordlists/rockyou.txt"
fi

# ── Ollama ────────────────────────────────────────────────────────────────
header "Installing Ollama (Local LLM)"

if command -v ollama &>/dev/null; then
    ok "Ollama: $(ollama --version 2>/dev/null || echo 'installed')"
else
    echo "  Installing Ollama..."
    brew install ollama && ok "Ollama" || {
        warn "Homebrew install failed — trying official installer"
        curl -fsSL https://ollama.ai/install.sh | sh
    }
fi

echo ""
echo "  Pulling recommended models (this may take a while)..."
for m in llama3.1 mistral; do
    echo "  → ollama pull $m"
    ollama pull "$m" 2>/dev/null && ok "$m" || warn "$m pull failed — run: ollama pull $m"
done

# ── Python backend dependencies ────────────────────────────────────────────
header "Installing Python Backend (backend/requirements.txt)"

if [ -f "backend/requirements.txt" ]; then
    pip3 install -r backend/requirements.txt --break-system-packages --quiet \
        && ok "Backend dependencies installed" \
        || warn "Some backend deps failed — check manually"
else
    warn "backend/requirements.txt not found — run from project root"
fi

# ── Docker services ────────────────────────────────────────────────────────
header "Starting Docker Data Services"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    if [ -f "docker/docker-compose.yml" ]; then
        echo "  Starting Redis, Neo4j, Chroma, PostgreSQL..."
        docker compose -f docker/docker-compose.yml up -d \
            && ok "All data services started" \
            || warn "Docker compose failed — check docker/docker-compose.yml"
    else
        warn "docker/docker-compose.yml not found — run from project root"
    fi
else
    warn "Docker not running — start Docker Desktop then run: docker compose -f docker/docker-compose.yml up -d"
fi

# ── Summary ────────────────────────────────────────────────────────────────
header "Setup Complete"
echo -e "${GREEN}PHANTOM AI v3 is ready.${NC}"
echo ""
echo "Next steps:"
echo "  1. Start Ollama:     ollama serve"
echo "  2. Start the app:    ./scripts/dev.sh     (development)"
echo "                       ./scripts/build-mac.sh  (build DMG)"
echo ""
echo "Data services (if Docker is running):"
echo "  Redis:      localhost:6379"
echo "  Neo4j:      localhost:7474  (neo4j / phantom123)"
echo "  Chroma:     localhost:8010"
echo "  PostgreSQL: localhost:5432  (phantom / phantom)"
echo ""
