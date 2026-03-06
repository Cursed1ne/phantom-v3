#!/usr/bin/env bash
###############################################################################
#  PHANTOM AI v3 — macOS Production Build
#  Produces a universal DMG (arm64 + x64) in the dist/ directory.
#  Works on Apple Silicon (M1/M2/M3/M4) and Intel Macs.
#
#  Usage:  ./scripts/build-mac.sh
###############################################################################
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail() { echo -e "${RED}  ✗${NC} $1"; exit 1; }

echo -e "\n${CYAN}  ⬡ PHANTOM AI v3 — macOS Build${NC}"
echo -e "${CYAN}  ────────────────────────────────${NC}\n"

# Must run from project root
cd "$(dirname "$0")/.."

# ── Preflight ─────────────────────────────────────────────────────────────
command -v node    &>/dev/null || fail "Node.js not found"
command -v python3 &>/dev/null || fail "Python 3 not found"
node -e "require('electron')" 2>/dev/null || warn "Electron not installed — will install via npm"

ok "Node $(node --version)"
ok "Python $(python3 --version)"

# ── Install npm deps ───────────────────────────────────────────────────────
echo "  Installing Node dependencies..."
npm install --legacy-peer-deps --silent
ok "Node modules ready"

# ── Install Python deps ────────────────────────────────────────────────────
echo "  Installing Python backend dependencies..."
pip3 install -r backend/requirements.txt --break-system-packages --quiet 2>/dev/null \
    && ok "Python dependencies ready" \
    || warn "Some Python deps failed — backend may run in limited mode"

# ── Build React (production bundle) ───────────────────────────────────────
echo "  Building React production bundle..."
GENERATE_SOURCEMAP=false npm run build
ok "React build complete → build/"

# ── Electron builder ───────────────────────────────────────────────────────
echo "  Building Electron app (arm64 + x64)..."
npx electron-builder --mac dmg --arm64 --x64

# ── Done ──────────────────────────────────────────────────────────────────
DMG=$(ls dist/*.dmg 2>/dev/null | head -1 || echo "")
if [ -n "$DMG" ]; then
    ok "DMG created: $DMG"
    SIZE=$(du -sh "$DMG" | cut -f1)
    echo ""
    echo -e "${GREEN}  Build successful!${NC}"
    echo "  File: $DMG ($SIZE)"
    echo "  Install: drag Phantom AI to /Applications"
else
    warn "DMG not found in dist/ — check electron-builder output above"
fi
