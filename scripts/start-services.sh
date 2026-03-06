#!/usr/bin/env bash
###############################################################################
#  PHANTOM AI v3 — Start & Health-Check All Services
#  Checks Ollama, Docker data layer, and backend.
#  Safe to run multiple times — idempotent.
#
#  Usage:  ./scripts/start-services.sh
###############################################################################
set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail() { echo -e "${RED}  ✗${NC} $1"; }

cd "$(dirname "$0")/.."

echo -e "${CYAN}\n  ⬡ PHANTOM AI v3 — Service Status\n${NC}"

# ── Ollama ────────────────────────────────────────────────────────────────
echo "  Ollama (LLM engine)..."
if curl -sf http://localhost:11434/api/tags &>/dev/null; then
    MODELS=$(curl -sf http://localhost:11434/api/tags | python3 -c "import sys,json; d=json.load(sys.stdin); print(', '.join(m['name'] for m in d.get('models',[])))" 2>/dev/null || echo "unknown")
    ok "Ollama running — models: $MODELS"
else
    warn "Ollama offline — starting..."
    nohup ollama serve >/tmp/ollama.log 2>&1 &
    sleep 3
    if curl -sf http://localhost:11434/api/tags &>/dev/null; then ok "Ollama started"; else fail "Ollama failed — run: ollama serve"; fi
fi

# ── Docker services ────────────────────────────────────────────────────────
echo ""
echo "  Docker data services..."
if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    warn "Docker not running — data layer unavailable (app runs with SQLite fallback)"
else
    if [ -f "docker/docker-compose.yml" ]; then
        docker compose -f docker/docker-compose.yml up -d --quiet-pull 2>/dev/null || warn "Some services failed"

        sleep 2

        # Redis
        if docker exec phantom_redis redis-cli ping &>/dev/null 2>&1; then ok "Redis      → :6379"; else warn "Redis not ready"; fi

        # Neo4j
        if curl -sf http://localhost:7474 &>/dev/null; then ok "Neo4j      → :7474 (browser), :7687 (bolt)"; else warn "Neo4j not ready (may take 30s first boot)"; fi

        # Chroma
        if curl -sf http://localhost:8010/api/v1/heartbeat &>/dev/null; then ok "Chroma     → :8010"; else warn "Chroma not ready"; fi

        # Postgres
        if docker exec phantom_postgres pg_isready -U phantom &>/dev/null 2>&1; then ok "PostgreSQL → :5432"; else warn "PostgreSQL not ready"; fi
    else
        warn "docker/docker-compose.yml not found — run from project root"
    fi
fi

# ── Python backend ────────────────────────────────────────────────────────
echo ""
echo "  Python backend..."
if curl -sf http://localhost:8000/health &>/dev/null; then
    ok "Backend API → :8000"
else
    warn "Backend offline — starting..."
    nohup python3 backend/main.py >/tmp/phantom_backend.log 2>&1 &
    sleep 2
    if curl -sf http://localhost:8000/health &>/dev/null; then ok "Backend started"; else warn "Backend failed — check /tmp/phantom_backend.log"; fi
fi

echo -e "${CYAN}\n  Ready. Run:  ./scripts/dev.sh  or  ./scripts/build-mac.sh\n${NC}"
