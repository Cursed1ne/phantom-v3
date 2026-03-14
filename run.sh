#!/usr/bin/env bash
###############################################################################
#  PHANTOM AI v3 — One-command launcher
#  Usage:  ./run.sh
###############################################################################

set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC}  $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC}  $1"; }
fail() { echo -e "${RED}  ✗${NC}  $1"; exit 1; }
info() { echo -e "${CYAN}  →${NC}  $1"; }

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo -e "\n${BOLD}${CYAN}  ⬡  PHANTOM AI v3${NC}\n"

# ── 1. Ollama ─────────────────────────────────────────────────────────────────
info "Checking Ollama..."
if ! command -v ollama &>/dev/null; then
    fail "Ollama not found. Install from https://ollama.ai then re-run."
fi

if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
    info "Starting Ollama..."
    ollama serve &>/tmp/phantom_ollama.log &
    OLLAMA_PID=$!
    for i in {1..10}; do
        sleep 1
        curl -sf http://localhost:11434/api/tags &>/dev/null && break
        [ $i -eq 10 ] && fail "Ollama failed to start. Check /tmp/phantom_ollama.log"
    done
    ok "Ollama started"
else
    ok "Ollama already running"
    OLLAMA_PID=""
fi

# ── 2. Model check — pull preferred if nothing installed ──────────────────────
MODELS=$(curl -sf http://localhost:11434/api/tags | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(' '.join(m['name'] for m in d.get('models',[])))" 2>/dev/null || echo "")

PREFERRED=("qwen2.5-coder:7b" "llama3.1" "mistral" "llama3")
ACTIVE_MODEL=""
for m in "${PREFERRED[@]}"; do
    base="${m%%:*}"
    for installed in $MODELS; do
        if [[ "$installed" == "$m" || "$installed" == "$base" || "$installed" == "${base}:"* ]]; then
            ACTIVE_MODEL="$installed"
            break 2
        fi
    done
done

if [ -z "$ACTIVE_MODEL" ]; then
    warn "No model found. Pulling qwen2.5-coder:7b (~4.7 GB)..."
    ollama pull qwen2.5-coder:7b
    ACTIVE_MODEL="qwen2.5-coder:7b"
    ok "Model ready: $ACTIVE_MODEL"
else
    ok "Model: $ACTIVE_MODEL"
fi

# ── 3. Python deps ────────────────────────────────────────────────────────────
info "Checking Python dependencies..."
if ! python3 -c "import fastapi, uvicorn, httpx" &>/dev/null; then
    info "Installing Python packages..."
    pip3 install -r backend/requirements.txt --break-system-packages -q \
        || pip3 install fastapi uvicorn httpx websockets -q
fi
ok "Python deps ready"

# ── 3b. Playwright browser (Chromium) ─────────────────────────────────────────
info "Checking Playwright browser..."
if ! python3 -c "from playwright.sync_api import sync_playwright; sync_playwright().__enter__().chromium" &>/dev/null 2>&1; then
    info "Installing Playwright + Chromium (first time ~100MB)..."
    pip3 install playwright --break-system-packages -q 2>/dev/null || true
    python3 -m playwright install chromium 2>/dev/null && ok "Playwright Chromium installed" || warn "Playwright install failed — browser scan will use HTTP fallback"
else
    ok "Playwright ready"
fi

# ── 3c. Security tools — auto-install missing ones ────────────────────────────
info "Checking security tools..."

# Helper: try to install a Go-based tool
install_go_tool() {
    local name="$1" pkg="$2"
    if command -v go &>/dev/null; then
        info "Installing $name via go install..."
        go install "$pkg" 2>/dev/null && ok "$name installed" || warn "$name go install failed"
    else
        warn "$name not found. Install Go then: go install $pkg"
    fi
}

# nuclei
if ! command -v nuclei &>/dev/null; then
    warn "nuclei not found — trying to install..."
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
        brew install nuclei -q && ok "nuclei installed" || install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    else
        install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    fi
else
    ok "nuclei: $(command -v nuclei)"
fi

# sqlmap
if ! command -v sqlmap &>/dev/null; then
    warn "sqlmap not found — trying to install..."
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
        brew install sqlmap -q && ok "sqlmap installed" || warn "sqlmap install failed — try: brew install sqlmap"
    else
        pip3 install sqlmap --break-system-packages -q 2>/dev/null && ok "sqlmap installed via pip" || warn "sqlmap install failed"
    fi
else
    ok "sqlmap: $(command -v sqlmap)"
fi

# nikto
if ! command -v nikto &>/dev/null; then
    warn "nikto not found — trying to install..."
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
        brew install nikto -q && ok "nikto installed" || warn "nikto install failed — try: brew install nikto"
    else
        warn "nikto not found — install with: apt install nikto / brew install nikto"
    fi
else
    ok "nikto: $(command -v nikto)"
fi

# ffuf
if ! command -v ffuf &>/dev/null; then
    warn "ffuf not found — trying to install..."
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
        brew install ffuf -q && ok "ffuf installed" || install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"
    else
        install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"
    fi
else
    ok "ffuf: $(command -v ffuf)"
fi

# nmap (needed for most scans)
if ! command -v nmap &>/dev/null; then
    warn "nmap not found — trying to install..."
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
        brew install nmap -q && ok "nmap installed"
    else
        warn "nmap not found — install with: apt install nmap / brew install nmap"
    fi
else
    ok "nmap: $(command -v nmap)"
fi

# ── 4. Node deps ──────────────────────────────────────────────────────────────
if [ ! -d "node_modules" ]; then
    info "Installing Node dependencies (first time)..."
    npm install --legacy-peer-deps --silent
    ok "Node deps installed"
else
    ok "Node deps ready"
fi

# ── 5. Backend ────────────────────────────────────────────────────────────────
if curl -sf http://localhost:8000/health &>/dev/null; then
    ok "Backend already running on :8000"
    BACKEND_PID=""
else
    info "Starting backend on :8000..."
    (cd "$ROOT/backend" && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000) \
        &>/tmp/phantom_backend.log &
    BACKEND_PID=$!
    for i in {1..15}; do
        sleep 1
        curl -sf http://localhost:8000/health &>/dev/null && break
        [ $i -eq 15 ] && fail "Backend failed. Check /tmp/phantom_backend.log"
    done
    ok "Backend started (PID $BACKEND_PID)"
fi

# ── 6. Launch app ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  All systems go! Launching Phantom AI...${NC}"
echo -e "${CYAN}  Model: ${ACTIVE_MODEL}${NC}"
echo -e "${CYAN}  API:   http://localhost:8000${NC}"
echo -e "${CYAN}  Press Ctrl+C to stop everything\n${NC}"

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${CYAN}  Shutting down Phantom AI...${NC}"
    [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null && ok "Backend stopped"
    [ -n "${OLLAMA_PID:-}" ]  && kill "$OLLAMA_PID"  2>/dev/null && ok "Ollama stopped"
    echo -e "${CYAN}  Bye.\n${NC}"
}
trap cleanup EXIT INT TERM

npm start
