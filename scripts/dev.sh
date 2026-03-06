#!/usr/bin/env bash
###############################################################################
#  PHANTOM AI v3 — Development Mode
#  Starts React dev server + Electron simultaneously.
#  Hot-reload is active — edit any .jsx file and see it live instantly.
#
#  Usage:  ./scripts/dev.sh
###############################################################################
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${CYAN}  ⬡ PHANTOM AI v3 — Development Mode${NC}"
echo -e "${CYAN}  ─────────────────────────────────────${NC}"

# Must run from project root
cd "$(dirname "$0")/.."

# ── Preflight checks ──────────────────────────────────────────────────────
if ! command -v node &>/dev/null;   then echo -e "${RED}Error: Node.js not found${NC}"; exit 1; fi
if ! command -v python3 &>/dev/null; then echo -e "${RED}Error: Python 3 not found${NC}"; exit 1; fi

# ── Warn if Ollama is offline ─────────────────────────────────────────────
if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
    echo -e "${YELLOW}  ⚠ Ollama offline — agents will run in simulation mode${NC}"
    echo -e "${YELLOW}    Start with: ollama serve${NC}"
fi

# ── Install deps if node_modules is missing ───────────────────────────────
if [ ! -d "node_modules" ]; then
    echo -e "\n  Installing Node dependencies..."
    npm install --legacy-peer-deps --silent
    echo -e "${GREEN}  ✓ Dependencies installed${NC}"
fi

# ── Start backend (Python FastAPI) in background ──────────────────────────
echo -e "\n  Starting Python backend on :8000..."
python3 backend/main.py &
BACKEND_PID=$!

# ── Start React + Electron ─────────────────────────────────────────────────
echo -e "  Starting React dev server + Electron...\n"
npm start

# ── Cleanup on exit ───────────────────────────────────────────────────────
trap "kill $BACKEND_PID 2>/dev/null; echo -e '\n${CYAN}  PHANTOM stopped.${NC}'" EXIT
