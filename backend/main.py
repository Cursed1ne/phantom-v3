"""
╔══════════════════════════════════════════════════════════════════════╗
║  PHANTOM AI v3 — Python Backend (FastAPI)                           ║
║                                                                      ║
║  Architecture:                                                       ║
║    • REST API  — scan sessions, findings, config                    ║
║    • WebSocket — real-time agent output streaming to UI             ║
║    • SQLite    — local persistence (findings, sessions, learned)    ║
║    • Ollama    — local LLM via HTTP streaming API                   ║
║    • Tool runner — subprocess wrapper for security tools            ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from autopilot import run_autopilot_scan, inspect_dependencies

# ── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
log = logging.getLogger("phantom")

# ── Config from environment (set by Electron main process) ──────────
DB_PATH    = os.environ.get("PHANTOM_DB",   "phantom.db")
PORT       = int(os.environ.get("PHANTOM_PORT", "8000"))
OLLAMA_URL = os.environ.get("OLLAMA_URL",   "http://localhost:11434")


# ════════════════════════════════════════════════════════════════════
#  DATABASE — SQLite, three tables
#  We use SQLite because it needs zero configuration and ships with
#  Python. For production scale, swap for Postgres (see memory layer).
# ════════════════════════════════════════════════════════════════════

def init_db() -> sqlite3.Connection:
    """
    Create tables if they don't exist yet and return an open connection.
    WAL mode gives us concurrent reads without blocking writes, which
    matters because FastAPI is async but sqlite3 is sync.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # lets us access cols by name
    conn.execute("PRAGMA journal_mode=WAL") # write-ahead logging
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript("""
    -- One row per scan session
    CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        target      TEXT NOT NULL,
        target_type TEXT DEFAULT 'web',
        started_at  TEXT NOT NULL,
        finished_at TEXT,
        status      TEXT DEFAULT 'running',   -- running | complete | stopped
        agents_used TEXT,                     -- JSON array of agent ids
        risk_score  REAL DEFAULT 0
    );

    -- One row per vulnerability finding
    CREATE TABLE IF NOT EXISTS findings (
        id          TEXT PRIMARY KEY,
        session_id  TEXT NOT NULL,
        severity    TEXT NOT NULL,            -- CRITICAL | HIGH | MEDIUM | LOW | INFO
        description TEXT NOT NULL,
        agent       TEXT,                     -- which agent found it
        tool        TEXT,                     -- which tool produced it
        iteration   INTEGER DEFAULT 0,
        cvss        REAL DEFAULT 0,
        raw_output  TEXT,                     -- truncated tool output that triggered it
        created_at  TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
    );

    -- Persistent learning memory: ONLY tool-confirmed patterns are stored.
    -- verified=1 means a real tool found this; seen_count tracks confirmations.
    -- Unverified patterns (verified=0) are pruned after 7 days with seen_count<2.
    CREATE TABLE IF NOT EXISTS learned (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern     TEXT UNIQUE NOT NULL,
        vuln_type   TEXT,
        tech_stack  TEXT,
        agent       TEXT,
        tool        TEXT,
        seen_count  INTEGER DEFAULT 1,
        verified    INTEGER DEFAULT 1,   -- 1=confirmed by tool output, 0=unverified
        confidence  REAL    DEFAULT 0.5, -- 0.0-1.0; increases with seen_count
        last_seen   TEXT NOT NULL,
        first_seen  TEXT NOT NULL
    );

    -- Tool execution stats for analytics
    CREATE TABLE IF NOT EXISTS tool_stats (
        tool        TEXT PRIMARY KEY,
        runs        INTEGER DEFAULT 0,
        findings    INTEGER DEFAULT 0,
        last_run    TEXT
    );

    -- Saved workflow profiles for authenticated browser automation.
    CREATE TABLE IF NOT EXISTS autopilot_profiles (
        id           TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        description  TEXT,
        target_match TEXT,
        config_json  TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    );

    -- History of Ollama training/adaptation runs.
    CREATE TABLE IF NOT EXISTS ollama_training_runs (
        id            TEXT PRIMARY KEY,
        model_name    TEXT NOT NULL,
        base_model    TEXT NOT NULL,
        status        TEXT NOT NULL,   -- success | failed
        message       TEXT,
        dataset_path  TEXT,
        modelfile_path TEXT,
        created_at    TEXT NOT NULL
    );
    """)
    conn.commit()

    # ── Schema migrations (safe to run every startup) ──────────────────
    # Add columns that may not exist in older DBs
    for migration in [
        "ALTER TABLE learned ADD COLUMN tool TEXT",
        "ALTER TABLE learned ADD COLUMN verified INTEGER DEFAULT 1",
        "ALTER TABLE learned ADD COLUMN confidence REAL DEFAULT 0.5",
        "ALTER TABLE learned ADD COLUMN first_seen TEXT",
        "ALTER TABLE findings ADD COLUMN confirmed INTEGER DEFAULT 1",
    ]:
        try:
            conn.execute(migration)
        except Exception:
            pass  # column already exists — ignore

    # Backfill first_seen for existing rows
    conn.execute("UPDATE learned SET first_seen=last_seen WHERE first_seen IS NULL")

    # Prune stale unverified patterns: seen once, older than 7 days
    conn.execute("""
        DELETE FROM learned
        WHERE verified=0 AND seen_count < 2
          AND last_seen < datetime('now','-7 days')
    """)

    conn.commit()
    return conn


# Shared connection — opened at startup, closed at shutdown
_db: Optional[sqlite3.Connection] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: connect DB on startup, close on shutdown."""
    global _db
    _db = init_db()
    log.info(f"SQLite database opened: {DB_PATH}")
    yield
    if _db:
        _db.close()
        log.info("Database closed")


# ════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="PHANTOM AI v3",
    description="Enterprise Autonomous Pentest Backend",
    version="3.0.0",
    lifespan=lifespan,
)

# Allow the React/Electron renderer to call us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ════════════════════════════════════════════════════════════════════
#  PYDANTIC MODELS
# ════════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target:      str
    target_type: str        = "web"
    agents:      List[str]  = ["recon", "web", "network", "exploit"]
    model:       str        = "llama3.1"
    depth:       str        = "standard"   # quick | standard | deep
    max_iter:    int        = 10

class FindingCreate(BaseModel):
    session_id:  str
    severity:    str
    description: str
    agent:       Optional[str] = None
    tool:        Optional[str] = None
    iteration:   int           = 0
    cvss:        float         = 0.0
    raw_output:  Optional[str] = None

class LearnRequest(BaseModel):
    pattern:    str
    vuln_type:  str
    tech_stack: Optional[str] = None
    agent:      Optional[str] = None
    tool:       Optional[str] = None
    verified:   bool           = True   # False = speculative, True = tool-confirmed


class ProxyReplayRequest(BaseModel):
    method:  str
    url:     str
    headers: Optional[Dict[str, str]] = None
    body:    Optional[str]            = None

class ToolRunRequest(BaseModel):
    tool:    str
    args:    List[str]      = []
    timeout: int            = 120


class AutopilotRequest(BaseModel):
    target:           str
    username:         Optional[str] = None
    password:         Optional[str] = None
    email:            Optional[str] = None
    max_pages:        int = 40
    headless:         bool = True
    use_proxy:        bool = True
    proxy_url:        str = "http://127.0.0.1:8888"
    timeout_per_tool: int = 180
    login_path:       Optional[str] = None
    register_path:    Optional[str] = None
    profile_id:       Optional[str] = None
    workflow_profile: Optional[Dict[str, Any]] = None
    captured_requests: Optional[List[Dict[str, Any]]] = None
    proxy_history_limit: int = 400
    js_audit:         bool = True
    tools:            List[str] = Field(
        default_factory=lambda: [
            "whatweb",
            "nmap",
            "nuclei",
            "nikto",
            "sqlmap",
            "ffuf",
            "gobuster",
            "feroxbuster",
            "searchsploit",
        ]
    )


class WorkflowProfileIn(BaseModel):
    id:           Optional[str] = None
    name:         str
    description:  Optional[str] = None
    target_match: Optional[str] = None
    config:       Dict[str, Any]


class OllamaTrainRequest(BaseModel):
    model_name:        str = "phantom-security:latest"
    base_model:        str = "llama3.1:latest"
    max_findings:      int = 250
    include_workflows: bool = True


# ════════════════════════════════════════════════════════════════════
#  WEBSOCKET MANAGER
#  Keeps track of all connected clients so we can fan out agent
#  output in real time. The UI subscribes once and receives everything.
# ════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        log.info(f"WS connected — total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active = [c for c in self.active if c is not ws]
        log.info(f"WS disconnected — total: {len(self.active)}")

    async def broadcast(self, data: Dict[str, Any]):
        """Send a JSON message to every connected client."""
        msg = json.dumps(data)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# ════════════════════════════════════════════════════════════════════
#  VULNERABILITY PATTERN EXTRACTION
#  The agents use Ollama to decide what actions to take, but once a
#  tool actually runs, we extract structured findings from the raw text
#  using simple regex. This is fast, deterministic, and works offline.
# ════════════════════════════════════════════════════════════════════

SEV_ORDER   = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
DEFAULT_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5, "INFO": 1.0}

def extract_findings(output: str, tool: str, agent: str, session_id: str, iteration: int) -> List[Dict]:
    """
    Scan raw tool output for tagged severity lines like:
        [CRITICAL] /.env exposed — secrets accessible
        [HIGH] MySQL 3306 externally accessible

    Returns a list of finding dicts ready to INSERT into the database.
    """
    found: List[Dict] = []
    seen = set()

    def push(sev_raw: str, desc_raw: str, cvss_override: Optional[float] = None):
        sev = str(sev_raw or "").strip().upper()
        if sev not in DEFAULT_CVSS:
            return
        desc = re.sub(r"\s+", " ", str(desc_raw or "")).strip()[:220]
        if len(desc) < 4:
            return
        key = f"{sev}|{desc}"
        if key in seen:
            return
        seen.add(key)
        found.append({
            "id":          str(uuid4()),
            "session_id":  session_id,
            "severity":    sev,
            "description": desc,
            "agent":       agent,
            "tool":        tool,
            "iteration":   iteration,
            "cvss":        cvss_override if cvss_override is not None else DEFAULT_CVSS.get(sev, 0),
            "raw_output":  output[:500],
            "created_at":  datetime.utcnow().isoformat(),
        })

    # Nuclei usually returns either plain-text lines with [severity] tags
    # or JSONL lines when run with -jsonl.
    if tool == "nuclei":
        for line in output.splitlines():
            t = line.strip()
            if not t:
                continue
            if t.startswith("{") and t.endswith("}"):
                try:
                    obj = json.loads(t)
                    sev = (obj.get("info", {}) or {}).get("severity") or obj.get("severity")
                    name = (obj.get("info", {}) or {}).get("name") or obj.get("template-id") or "Nuclei finding"
                    where = obj.get("matched-at") or obj.get("host") or obj.get("url") or ""
                    push(sev, f"{name} — {where}" if where else name)
                    continue
                except Exception:
                    pass
            plain = re.search(
                r"^(?P<where>\S+)\s+\[(?P<template>[^\]]+)\]\s+\[(?P<sev>critical|high|medium|low|info)\]",
                t,
                re.IGNORECASE,
            )
            if plain:
                push(plain.group("sev"), f"{plain.group('template')} — {plain.group('where')}")
                continue
            sev_m = re.search(r"\[(critical|high|medium|low|info)\]", t, re.IGNORECASE)
            if sev_m:
                cleaned = re.sub(r"\[[^\]]+\]", " ", t)
                push(sev_m.group(1), cleaned)

    # Parse open risky ports from nmap/masscan output.
    if tool in ("nmap", "masscan"):
        port_risk = {
            23: ("HIGH", "Telnet exposed"),
            3306: ("HIGH", "MySQL exposed"),
            5432: ("HIGH", "PostgreSQL exposed"),
            6379: ("CRITICAL", "Redis exposed"),
            9200: ("HIGH", "Elasticsearch exposed"),
            27017: ("HIGH", "MongoDB exposed"),
            11211: ("HIGH", "Memcached exposed"),
        }
        for line in output.splitlines():
            m = re.search(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)", line, re.IGNORECASE)
            if not m:
                m = re.search(r"Discovered open port (\d+)\/(tcp|udp)", line, re.IGNORECASE)
            if m:
                port = int(m.group(1))
                service = m.group(3) if len(m.groups()) > 2 and m.group(3) else "service"
                if port in port_risk:
                    sev, label = port_risk[port]
                    push(sev, f"{label} ({port}/{m.group(2)} {service})")
                else:
                    push("INFO", f"Open port detected ({port}/{m.group(2)} {service})")
            cve = re.search(r"(CVE-\d{4}-\d{4,7})", line, re.IGNORECASE)
            if cve:
                push("HIGH", f"Known vulnerability reference: {cve.group(1).upper()}")

    # Generic [SEVERITY] line extraction fallback.
    if tool != "nuclei":
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            pattern = re.compile(rf"\[{sev}\]\s*(.{{4,240}})", re.IGNORECASE)
            for match in pattern.finditer(output):
                push(sev, match.group(1), DEFAULT_CVSS.get(sev, 0))

    return found


# ════════════════════════════════════════════════════════════════════
#  TOOL RUNNER
#  Every security tool runs in an isolated subprocess with a hard
#  timeout. stdout and stderr are merged and returned as a single
#  string that the LLM can reason about.
# ════════════════════════════════════════════════════════════════════

async def run_tool(tool: str, args: List[str], timeout: int = 120) -> Dict[str, Any]:
    """
    Run an external CLI tool asynchronously. Returns:
        { output: str, code: int, tool: str, duration_s: float }
    """
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            tool, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {"output": f"[timeout after {timeout}s]", "code": -1, "tool": tool, "duration_s": timeout}

        output = (stdout or b"").decode("utf-8", errors="replace") + \
                 (stderr or b"").decode("utf-8", errors="replace")
        output = output.strip() or f"[{tool}] completed with no output (likely zero findings for current checks)."
        return {
            "output":     output[:12000],
            "code":       proc.returncode,
            "tool":       tool,
            "duration_s": round(time.time() - start, 2),
        }
    except FileNotFoundError:
        return {
            "output":     f"{tool}: command not found — install with: brew install {tool}",
            "code":       -1,
            "tool":       tool,
            "duration_s": 0,
        }
    except Exception as e:
        return {"output": str(e), "code": -1, "tool": tool, "duration_s": 0}


# ════════════════════════════════════════════════════════════════════
#  OLLAMA STREAMING HELPER
#  Streams LLM tokens from Ollama and yields them one chunk at a time.
#  The agent orchestrator calls this, then broadcasts each token over
#  the WebSocket so the UI shows the "thinking" text in real time.
# ════════════════════════════════════════════════════════════════════

async def stream_ollama(messages: List[Dict], model: str, system: str = ""):
    """
    Generator that yields text tokens from the Ollama /api/chat endpoint.
    Uses httpx async streaming so we never block the event loop.
    """
    payload = {
        "model":    model,
        "messages": messages,
        "stream":   True,
        "system":   system,
        "options":  {"temperature": 0.2, "num_predict": 1800},
    }
    try:
        async with httpx.AsyncClient(timeout=180) as client:
            async with client.stream("POST", f"{OLLAMA_URL}/api/chat", json=payload) as resp:
                if resp.status_code != 200:
                    yield f"\n[Ollama error {resp.status_code}]"
                    return
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if data.get("done"):
                            return
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        yield f"\n[Ollama connection error: {e}]"


# ════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """Simple liveness probe — Electron pings this to know we're up."""
    return {"status": "ok", "version": "3.0.0", "db": DB_PATH}


# ── Sessions ─────────────────────────────────────────────────────────

@app.post("/sessions")
async def create_session(req: ScanRequest):
    session_id = str(uuid4())
    _db.execute(
        "INSERT INTO sessions (id, target, target_type, started_at, agents_used) VALUES (?,?,?,?,?)",
        (session_id, req.target, req.target_type, datetime.utcnow().isoformat(), json.dumps(req.agents))
    )
    _db.commit()
    log.info(f"Session created: {session_id} → {req.target}")
    return {"session_id": session_id}


@app.get("/sessions")
async def list_sessions():
    rows = _db.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


@app.patch("/sessions/{session_id}/finish")
async def finish_session(session_id: str, risk_score: float = 0.0):
    _db.execute(
        "UPDATE sessions SET status='complete', finished_at=?, risk_score=? WHERE id=?",
        (datetime.utcnow().isoformat(), risk_score, session_id)
    )
    _db.commit()
    return {"ok": True}


# ── Findings ──────────────────────────────────────────────────────────

@app.post("/findings")
async def save_finding(req: FindingCreate):
    fid = str(uuid4())
    _db.execute(
        "INSERT INTO findings (id,session_id,severity,description,agent,tool,iteration,cvss,raw_output,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (fid, req.session_id, req.severity, req.description, req.agent, req.tool,
         req.iteration, req.cvss, req.raw_output, datetime.utcnow().isoformat())
    )
    _db.commit()
    return {"id": fid}


@app.get("/findings/{session_id}")
async def get_findings(session_id: str):
    rows = _db.execute(
        "SELECT * FROM findings WHERE session_id=? ORDER BY cvss DESC", (session_id,)
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/findings")
async def all_findings(limit: int = 200):
    rows = _db.execute(
        "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ── Learning memory ───────────────────────────────────────────────────

@app.post("/learn")
async def learn_pattern(req: LearnRequest):
    """
    Upsert a learned pattern. Only tool-verified findings should be stored
    here (verified=True). Confidence grows with seen_count, capped at 1.0.
    Unverified guesses are marked verified=0 and pruned after 7 days.
    """
    now = datetime.utcnow().isoformat()
    verified_int = 1 if req.verified else 0
    existing = _db.execute("SELECT id, seen_count FROM learned WHERE pattern=?", (req.pattern,)).fetchone()
    if existing:
        new_count = existing["seen_count"] + 1
        new_conf  = min(1.0, 0.3 + 0.14 * new_count)   # 0.44 @ 1x → 1.0 @ ~5x
        _db.execute(
            "UPDATE learned SET seen_count=?, confidence=?, last_seen=?, verified=MAX(verified,?) WHERE pattern=?",
            (new_count, new_conf, now, verified_int, req.pattern)
        )
    else:
        _db.execute(
            "INSERT INTO learned (pattern,vuln_type,tech_stack,agent,tool,seen_count,verified,confidence,last_seen,first_seen)"
            " VALUES (?,?,?,?,?,1,?,0.44,?,?)",
            (req.pattern, req.vuln_type, req.tech_stack, req.agent, req.tool, verified_int, now, now)
        )
    _db.commit()
    return {"ok": True}


@app.get("/learn")
async def get_learned(limit: int = 50):
    # Only return verified patterns (confidence > 0.3) to inject into prompts
    rows = _db.execute(
        "SELECT * FROM learned WHERE verified=1 ORDER BY confidence DESC, seen_count DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/learn")
async def clear_learned():
    _db.execute("DELETE FROM learned")
    _db.commit()
    return {"ok": True}


@app.delete("/learn/unverified")
async def prune_unverified():
    """Remove all unverified or low-confidence patterns."""
    _db.execute("DELETE FROM learned WHERE verified=0 OR confidence < 0.3")
    _db.commit()
    return {"ok": True}


# ── Proxy request replay ───────────────────────────────────────────────

@app.post("/proxy/replay")
async def proxy_replay(req: ProxyReplayRequest):
    """
    Replay an HTTP/HTTPS request from the backend with full response.
    Used by the Repeater tab in the UI.
    """
    try:
        method  = (req.method or "GET").upper()
        headers = req.headers or {}
        # Remove headers that cause issues with replayed requests
        for h in ["content-length", "transfer-encoding", "host"]:
            headers.pop(h, None)
            headers.pop(h.title(), None)

        timeout = httpx.Timeout(30.0)
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = await client.request(
                method  = method,
                url     = req.url,
                headers = headers,
                content = req.body.encode() if req.body else None,
            )
            return {
                "ok":      True,
                "status":  response.status_code,
                "headers": dict(response.headers),
                "body":    response.text[:8000],
                "elapsed_ms": int(response.elapsed.total_seconds() * 1000) if response.elapsed else 0,
            }
    except httpx.TimeoutException:
        return {"ok": False, "error": "Request timed out (30s)"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Tool execution ────────────────────────────────────────────────────

@app.post("/tool/run")
async def tool_run(req: ToolRunRequest):
    """
    Run a security tool and return its output.
    Also updates per-tool stats for the analytics panel.
    """
    result = await run_tool(req.tool, req.args, req.timeout)

    # Update stats
    _db.execute(
        "INSERT INTO tool_stats (tool, runs, last_run) VALUES (?,1,?) "
        "ON CONFLICT(tool) DO UPDATE SET runs=runs+1, last_run=excluded.last_run",
        (req.tool, datetime.utcnow().isoformat())
    )
    _db.commit()
    return result


@app.get("/tool/stats")
async def tool_stats():
    rows = _db.execute("SELECT * FROM tool_stats ORDER BY runs DESC").fetchall()
    return [dict(r) for r in rows]


# ── Ollama proxy ──────────────────────────────────────────────────────

@app.get("/ollama/models")
async def get_models():
    """Fetch available local models from Ollama."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            data = resp.json()
            return {"models": [m["name"] for m in data.get("models", [])]}
    except Exception as e:
        return {"models": [], "error": str(e)}


def _parse_json_or(text: str, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _profile_row_to_obj(row: sqlite3.Row) -> Dict[str, Any]:
    obj = dict(row)
    obj["config"] = _parse_json_or(obj.get("config_json", "{}"), {})
    obj.pop("config_json", None)
    return obj


def _find_profile_for_target(target: str) -> Optional[Dict[str, Any]]:
    host = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}").hostname or ""
    rows = _db.execute(
        "SELECT * FROM autopilot_profiles ORDER BY updated_at DESC"
    ).fetchall()
    for row in rows:
        obj = _profile_row_to_obj(row)
        matcher = (obj.get("target_match") or "").strip().lower()
        if not matcher:
            continue
        if matcher in host.lower() or matcher in (target or "").lower():
            return obj
    return None


@app.get("/autopilot/profiles")
async def autopilot_profiles():
    rows = _db.execute(
        "SELECT * FROM autopilot_profiles ORDER BY updated_at DESC"
    ).fetchall()
    return {"profiles": [_profile_row_to_obj(r) for r in rows]}


@app.post("/autopilot/profiles")
async def autopilot_profile_upsert(req: WorkflowProfileIn):
    now = datetime.utcnow().isoformat()
    profile_id = req.id or str(uuid4())
    existing = _db.execute("SELECT id FROM autopilot_profiles WHERE id=?", (profile_id,)).fetchone()
    if existing:
        _db.execute(
            "UPDATE autopilot_profiles SET name=?, description=?, target_match=?, config_json=?, updated_at=? WHERE id=?",
            (
                req.name.strip(),
                (req.description or "").strip() or None,
                (req.target_match or "").strip() or None,
                json.dumps(req.config or {}, ensure_ascii=False),
                now,
                profile_id,
            ),
        )
    else:
        _db.execute(
            "INSERT INTO autopilot_profiles (id, name, description, target_match, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                profile_id,
                req.name.strip(),
                (req.description or "").strip() or None,
                (req.target_match or "").strip() or None,
                json.dumps(req.config or {}, ensure_ascii=False),
                now,
                now,
            ),
        )
    _db.commit()
    row = _db.execute("SELECT * FROM autopilot_profiles WHERE id=?", (profile_id,)).fetchone()
    return {"ok": True, "profile": _profile_row_to_obj(row)}


@app.delete("/autopilot/profiles/{profile_id}")
async def autopilot_profile_delete(profile_id: str):
    _db.execute("DELETE FROM autopilot_profiles WHERE id=?", (profile_id,))
    _db.commit()
    return {"ok": True}


@app.get("/autopilot/deps")
async def autopilot_deps():
    """
    Return dependency readiness for browser automation and scan toolchain.
    UI uses this to show actionable setup guidance.
    """
    return inspect_dependencies()


@app.post("/autopilot/run")
async def autopilot_run(req: AutopilotRequest):
    """
    End-to-end autonomous scan:
      - Auth-aware crawl (Playwright preferred, HTTP fallback)
      - Multi-tool execution
      - JS analysis + CVE hinting
      - Findings persisted into regular findings table
    """
    session_id = str(uuid4())
    started_at = datetime.utcnow().isoformat()

    _db.execute(
        "INSERT INTO sessions (id, target, target_type, started_at, status, agents_used, risk_score) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session_id, req.target, "web", started_at, "running", json.dumps(["web", "network", "exploit"]), 0),
    )
    _db.commit()

    try:
        payload = req.model_dump()
        selected_profile = None
        if req.profile_id:
            row = _db.execute("SELECT * FROM autopilot_profiles WHERE id=?", (req.profile_id,)).fetchone()
            if row:
                selected_profile = _profile_row_to_obj(row)
        if not selected_profile:
            selected_profile = _find_profile_for_target(req.target)

        if selected_profile:
            profile_cfg = selected_profile.get("config") or {}
            merged_cfg = dict(profile_cfg)
            merged_cfg.update(payload.get("workflow_profile") or {})
            payload["workflow_profile"] = merged_cfg
            if not payload.get("login_path"):
                payload["login_path"] = profile_cfg.get("login_path")
            if not payload.get("register_path"):
                payload["register_path"] = profile_cfg.get("register_path")
            payload["workflow_profile_name"] = selected_profile.get("name")
            payload["workflow_profile_id"] = selected_profile.get("id")

        report = await run_autopilot_scan(payload)
        tool_runs = report.get("tool_runs", []) or []

        findings: List[Dict[str, Any]] = []
        seen = set()

        def push_finding(severity: str, description: str, tool: str = "autopilot", agent: str = "web", cvss: Optional[float] = None):
            sev = str(severity or "").strip().upper()
            if sev not in DEFAULT_CVSS:
                sev = "INFO"
            desc = re.sub(r"\s+", " ", str(description or "")).strip()[:220]
            if len(desc) < 4:
                return
            key = f"{sev}|{desc}"
            if key in seen:
                return
            seen.add(key)
            findings.append({
                "id": str(uuid4()),
                "session_id": session_id,
                "severity": sev,
                "description": desc,
                "agent": agent,
                "tool": tool,
                "iteration": 1,
                "cvss": cvss if cvss is not None else DEFAULT_CVSS.get(sev, 1.0),
                "raw_output": "",
                "created_at": datetime.utcnow().isoformat(),
            })

        # Parse each tool output with existing parser.
        for i, tr in enumerate(tool_runs, start=1):
            tool_name = str(tr.get("tool") or "tool")
            output = str(tr.get("output") or "")
            parsed = extract_findings(output, tool_name, "web", session_id, i)
            for f in parsed:
                key = f"{f.get('severity')}|{f.get('description')}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)

            _db.execute(
                "INSERT INTO tool_stats (tool, runs, last_run) VALUES (?,1,?) "
                "ON CONFLICT(tool) DO UPDATE SET runs=runs+1, last_run=excluded.last_run",
                (tool_name, datetime.utcnow().isoformat())
            )

        # Include JS/manual findings from autopilot pipeline.
        for jf in (report.get("js_audit", {}) or {}).get("findings", []) or []:
            push_finding(
                severity=jf.get("severity", "MEDIUM"),
                description=jf.get("description", "JavaScript security finding"),
                tool=jf.get("tool", "js-audit"),
                agent="web",
            )
        for mf in report.get("manual_findings", []) or []:
            push_finding(
                severity=mf.get("severity", "INFO"),
                description=mf.get("description", "Autopilot note"),
                tool=mf.get("tool", "autopilot"),
                agent="web",
            )

        for f in findings:
            _db.execute(
                "INSERT INTO findings (id, session_id, severity, description, agent, tool, iteration, cvss, raw_output, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f["id"], f["session_id"], f["severity"], f["description"], f.get("agent"),
                    f.get("tool"), f.get("iteration", 1), f.get("cvss", 0.0),
                    f.get("raw_output", ""), f["created_at"],
                )
            )

        sev_weight = {"CRITICAL": 2.2, "HIGH": 1.2, "MEDIUM": 0.5, "LOW": 0.2, "INFO": 0.05}
        risk_score = round(min(10.0, sum(sev_weight.get(f["severity"], 0.0) for f in findings)), 2)

        _db.execute(
            "UPDATE sessions SET finished_at=?, status=?, risk_score=? WHERE id=?",
            (datetime.utcnow().isoformat(), "complete", risk_score, session_id)
        )
        _db.commit()

        counts = {sev: 0 for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "ok": True,
            "session_id": session_id,
            "risk_score": risk_score,
            "profile": {
                "id": payload.get("workflow_profile_id"),
                "name": payload.get("workflow_profile_name"),
            } if payload.get("workflow_profile_id") or payload.get("workflow_profile_name") else None,
            "counts": counts,
            "findings": [
                {
                    "id": f["id"],
                    "severity": f["severity"],
                    "description": f["description"],
                    "tool": f.get("tool"),
                    "agent": f.get("agent"),
                    "cvss": f.get("cvss", 0),
                    "created_at": f.get("created_at"),
                }
                for f in findings
            ],
            "report": report,
        }
    except Exception as e:
        _db.execute(
            "UPDATE sessions SET finished_at=?, status=? WHERE id=?",
            (datetime.utcnow().isoformat(), "stopped", session_id)
        )
        _db.commit()
        raise HTTPException(status_code=500, detail=f"autopilot failed: {e}")


@app.post("/ollama/train")
async def ollama_train(req: OllamaTrainRequest):
    """
    Build an adapted Ollama model from local findings and workflow knowledge.
    This is not gradient training; it creates a derived local model with
    specialized system instructions + scenario examples.
    """
    run_id = str(uuid4())
    created_at = datetime.utcnow().isoformat()
    work_dir = os.path.join(os.path.dirname(__file__), "memory", "ollama_training")
    os.makedirs(work_dir, exist_ok=True)

    max_findings = max(20, min(req.max_findings, 1000))
    rows = _db.execute(
        "SELECT severity, description, tool, agent, created_at FROM findings "
        "ORDER BY created_at DESC LIMIT ?",
        (max_findings,),
    ).fetchall()
    findings = [dict(r) for r in rows]

    learned_rows = _db.execute(
        "SELECT pattern, vuln_type, tech_stack, agent, seen_count, last_seen "
        "FROM learned ORDER BY seen_count DESC, last_seen DESC LIMIT 200"
    ).fetchall()
    learned = [dict(r) for r in learned_rows]

    profiles = []
    if req.include_workflows:
        prow = _db.execute("SELECT name, target_match, config_json FROM autopilot_profiles ORDER BY updated_at DESC LIMIT 100").fetchall()
        for r in prow:
            cfg = _parse_json_or(r["config_json"], {})
            profiles.append({
                "name": r["name"],
                "target_match": r["target_match"],
                "login_path": cfg.get("login_path"),
                "register_path": cfg.get("register_path"),
                "auth_success_markers": cfg.get("auth_success_markers", []),
            })

    dataset_path = os.path.join(work_dir, f"{run_id}.jsonl")
    modelfile_path = os.path.join(work_dir, f"{run_id}.Modelfile")

    dataset_lines: List[str] = []
    for f in findings[:400]:
        sev = (f.get("severity") or "INFO").upper()
        desc = f.get("description") or ""
        tool = f.get("tool") or "tool"
        agent = f.get("agent") or "agent"
        prompt = (
            "Analyze this pentest signal and return triage guidance.\n"
            f"Severity: {sev}\nTool: {tool}\nAgent: {agent}\nFinding: {desc}\n"
            "Required format: RISK, LIKELY_CAUSE, VERIFICATION, REMEDIATION."
        )
        response = (
            f"RISK: {sev}\n"
            f"LIKELY_CAUSE: {desc}\n"
            "VERIFICATION: Reproduce with controlled requests and confirm impact.\n"
            "REMEDIATION: Apply least-privilege, strict validation, and secure defaults."
        )
        dataset_lines.append(json.dumps({
            "messages": [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": response},
            ]
        }, ensure_ascii=False))

    with open(dataset_path, "w", encoding="utf-8") as f:
        for line in dataset_lines:
            f.write(line + "\n")

    system_parts = [
        "You are PHANTOM Security Analyst, specialized in web/app/api pentesting.",
        "Prioritize exploitability, business impact, and reproducibility.",
        "Use concise but actionable remediation steps.",
        "Map results to OWASP Top 10 where possible.",
    ]
    if learned:
        top = learned[:40]
        system_parts.append("Local learned patterns:")
        for p in top:
            system_parts.append(f"- {p.get('pattern')} (seen {p.get('seen_count', 1)}x)")
    if profiles:
        system_parts.append("Known workflow profiles:")
        for p in profiles[:20]:
            system_parts.append(
                f"- {p.get('name')} match={p.get('target_match') or '*'} "
                f"login={p.get('login_path') or '-'} register={p.get('register_path') or '-'}"
            )
    system_text = "\n".join(system_parts)

    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(f"FROM {req.base_model}\n")
        f.write("PARAMETER temperature 0.15\n")
        f.write("PARAMETER top_p 0.9\n")
        f.write("PARAMETER num_ctx 8192\n")
        f.write("SYSTEM \"\"\"\n")
        f.write(system_text.replace("\"\"\"", "'''"))
        f.write("\n\"\"\"\n")
        for line in dataset_lines[:40]:
            obj = _parse_json_or(line, {})
            msgs = obj.get("messages") or []
            if len(msgs) >= 2:
                user = (msgs[0].get("content") or "").replace('"', '\\"')
                assistant = (msgs[1].get("content") or "").replace('"', '\\"')
                f.write(f"MESSAGE user \"{user}\"\n")
                f.write(f"MESSAGE assistant \"{assistant}\"\n")

    cmd = ["ollama", "create", req.model_name, "-f", modelfile_path]
    status = "success"
    message = ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        message = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode != 0:
            status = "failed"
            raise HTTPException(status_code=500, detail=f"ollama create failed: {message[:800]}")
    except subprocess.TimeoutExpired:
        status = "failed"
        message = "ollama create timed out"
        raise HTTPException(status_code=500, detail=message)
    except FileNotFoundError:
        status = "failed"
        message = "ollama command not found"
        raise HTTPException(status_code=500, detail=message)
    except HTTPException:
        raise
    except Exception as e:
        status = "failed"
        message = str(e)
        raise HTTPException(status_code=500, detail=f"ollama training failed: {message}")
    finally:
        _db.execute(
            "INSERT INTO ollama_training_runs (id, model_name, base_model, status, message, dataset_path, modelfile_path, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, req.model_name, req.base_model, status, message[:4000], dataset_path, modelfile_path, created_at),
        )
        _db.commit()

    return {
        "ok": True,
        "run_id": run_id,
        "model_name": req.model_name,
        "base_model": req.base_model,
        "examples": len(dataset_lines),
        "profiles_used": len(profiles),
        "dataset_path": dataset_path,
        "modelfile_path": modelfile_path,
        "output": message[:8000],
    }


# ════════════════════════════════════════════════════════════════════
#  WEBSOCKET — AGENT STREAMING
#  This is the heart of the real-time UI experience. The renderer
#  connects here once and we push every token/event as JSON frames.
#  Message types the UI understands:
#    agent_thought   — LLM reasoning text (streamed token-by-token)
#    agent_token     — single LLM token for live typing effect
#    agent_action    — tool about to be executed
#    agent_output    — raw tool output
#    agent_findings  — structured findings extracted from tool output
#    agent_done      — agent finished, includes summary
#    session_done    — all agents finished
# ════════════════════════════════════════════════════════════════════

@app.websocket("/ws/agent")
async def agent_ws(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Wait for the initial scan configuration from the UI
        raw = await ws.receive_text()
        config = json.loads(raw)
        log.info(f"WS agent stream started: {config.get('target')}")

        target      = config.get("target",   "localhost")
        target_type = config.get("type",     "web")
        model       = config.get("model",    "llama3.1")
        depth       = config.get("depth",    "standard")
        max_iter    = int(config.get("max_iter", 10))
        agents_req  = config.get("agents",   ["planner","recon","web","network","exploit"])
        session_id  = config.get("session_id", str(uuid4()))

        # Load ONLY verified, high-confidence learned patterns.
        # We inject a rich description so the agent knows what worked before,
        # but the CRITICAL RULES in the system prompt prevent hallucination.
        learned_rows = _db.execute(
            "SELECT pattern, vuln_type, tool, seen_count, confidence "
            "FROM learned WHERE verified=1 AND confidence >= 0.4 "
            "ORDER BY confidence DESC, seen_count DESC LIMIT 10"
        ).fetchall()
        learned_ctx = "\n".join(
            f"  • [{r['vuln_type']}] {r['pattern']} "
            f"(tool: {r['tool'] or '?'}, confirmed {r['seen_count']}×, confidence {r['confidence']:.0%})"
            for r in learned_rows
        )

        all_findings: List[Dict] = []

        # ── Run each agent sequentially (planner first, then parallel groups) ──
        for agent_id in agents_req:
            if agent_id == "planner" and agents_req.index(agent_id) == 0:
                # Planner always goes first
                pass
            await run_agent_loop(
                ws, session_id, agent_id, target, target_type,
                model, depth, max_iter, learned_ctx, all_findings
            )

        # Signal completion
        await manager.broadcast({
            "type":          "session_done",
            "session_id":    session_id,
            "total_findings": len(all_findings),
            "critical":       sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "high":           sum(1 for f in all_findings if f["severity"] == "HIGH"),
        })

        # Persist risk score
        risk = min(10.0, sum(f.get("cvss", 0) * 0.15 for f in all_findings))
        _db.execute(
            "UPDATE sessions SET status='complete', finished_at=?, risk_score=? WHERE id=?",
            (datetime.utcnow().isoformat(), round(risk, 1), session_id)
        )
        _db.commit()

    except WebSocketDisconnect:
        log.info("WS client disconnected")
    except Exception as e:
        log.error(f"WS error: {e}", exc_info=True)
    finally:
        manager.disconnect(ws)


# ── Per-agent loop ─────────────────────────────────────────────────────

async def run_agent_loop(
    ws: WebSocket,
    session_id: str,
    agent_id: str,
    target: str,
    target_type: str,
    model: str,
    depth: str,
    max_iter: int,
    learned_ctx: str,
    all_findings: List[Dict],
):
    """
    The core autonomous loop for a single agent. Each iteration:
      1. Sends the current context to the LLM (streamed token by token)
      2. Parses the LLM's ACTION decision
      3. Runs the chosen tool as a subprocess
      4. Extracts findings from the tool output
      5. Saves findings to DB + broadcasts to UI
      6. Appends the full exchange to message history
      7. Checks if the LLM said DONE: true — if so, exits early

    The key insight is that the LLM is the *analyst*, not the scanner.
    It reads tool output and decides what to run next, just like a
    human pentester would.
    """

    AGENT_PERSONAS = {
        "planner": (
            "You are the PHANTOM PLANNER — the master strategist. "
            "Analyse the target and produce a prioritised attack plan. "
            "Delegate specific tasks to: recon, web, identity, network, cloud, exploit agents. "
            "Format: THOUGHT: ... | STRATEGY: ... | DELEGATE: <agent> — <task> | DONE: true/false"
        ),
        "recon": (
            "You are the PHANTOM RECON agent — elite asset discovery. "
            "Tools available: subfinder, amass, theHarvester, whatweb, nmap, shodan. "
            "Discover: subdomains, IPs, emails, tech stack, org structure. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        ),
        "web": (
            "You are the PHANTOM WEB agent — web application security expert. "
            "Test OWASP Top 10: injection, broken auth, IDOR, SSRF, XXE, XSS, deserialization. "
            "Tools: nuclei, nikto, sqlmap, gobuster, ffuf, whatweb, zaproxy. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        ),
        "identity": (
            "You are the PHANTOM IDENTITY agent — authentication & SSO specialist. "
            "Test: JWT (alg:none, HMAC crack), OAuth redirect_uri, SAML, MFA bypass, session fixation. "
            "Tools: jwt_tool, hydra, curl. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | FINDING: ..."
        ),
        "network": (
            "You are the PHANTOM NETWORK agent — infrastructure specialist. "
            "Tools: nmap, masscan, smbmap, enum4linux, crackmapexec. "
            "Find: open ports, service versions, SMB null sessions, default creds. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        ),
        "cloud": (
            "You are the PHANTOM CLOUD agent — cloud security specialist. "
            "Tools: scoutsuite, prowler, kube-hunter, pacu. "
            "Check: S3 buckets, IAM misconfigs, SGs, CloudTrail, metadata service. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        ),
        "exploit": (
            "You are the PHANTOM EXPLOIT analyst — risk validation specialist. "
            "Tools: searchsploit, msfconsole, hashcat, john. "
            "Validate: CVEs present, exploitability, blast radius, pivot paths. "
            "Format: THOUGHT: ... | CVE: ... | CVSS: ... | EXPLOITABLE: true/false | ACTION: <tool_name>"
        ),
    }

    # Build other agents' findings as context
    other_findings_ctx = "\n".join(
        f"  [{f['severity']}] {f['description'][:80]} (by {f['agent']})"
        for f in all_findings[:8]
    )

    system_prompt = f"""{AGENT_PERSONAS.get(agent_id, 'You are a security analyst.')}

TARGET: {target}  |  TYPE: {target_type}  |  DEPTH: {depth}  |  MAX_ITER: {max_iter}

CONFIRMED PATTERNS FROM PREVIOUS SCANS (tool-verified):
{learned_ctx or '  (none yet — first scan)'}

FINDINGS FROM OTHER AGENTS SO FAR:
{other_findings_ctx or '  (none yet)'}

CRITICAL ANTI-HALLUCINATION RULES:
1. NEVER write [SEVERITY] lines in THOUGHT or HYPOTHESIS sections.
2. ONLY write [SEVERITY] lines when a tool's actual stdout/stderr explicitly confirms the issue.
3. If the tool output is empty or says "no findings", output DONE: true — do NOT invent results.
4. LEARNED PATTERNS are hints only — verify each with a tool before reporting.
5. Do not repeat the same finding across iterations.

RESPONSE FORMAT:
THOUGHT: <your reasoning>
HYPOTHESIS: <expected finding>
ACTION: <tool_name>
[after tool output] DONE: true | SUMMARY: <brief summary with tool names as evidence>

Be concise. Every ACTION must name a real CLI tool from your available list.
"""

    history = [
        {"role": "user", "content": f"Begin {agent_id} assessment of {target}. Max {max_iter} iterations."}
    ]

    agent_findings_count = 0

    await manager.broadcast({
        "type":     "agent_start",
        "agent":    agent_id,
        "target":   target,
        "max_iter": max_iter,
    })

    for iteration in range(1, max_iter + 1):
        # ── LLM reasoning step ────────────────────────────────────
        await manager.broadcast({"type": "agent_thinking", "agent": agent_id, "iter": iteration})

        full_response = ""
        async for token in stream_ollama(history, model, system_prompt):
            full_response += token
            await manager.broadcast({"type": "agent_token", "agent": agent_id, "token": token, "iter": iteration})

        # Broadcast the complete thought
        await manager.broadcast({
            "type":     "agent_thought",
            "agent":    agent_id,
            "text":     full_response,
            "iter":     iteration,
        })

        # ── Parse the LLM's decision ──────────────────────────────
        thought    = re.search(r"THOUGHT:\s*(.*?)(?=HYPOTHESIS:|ACTION:|DONE:|STRATEGY:|$)", full_response, re.I | re.S)
        hypothesis = re.search(r"HYPOTHESIS:\s*(.*?)(?=ACTION:|REASON:|DONE:|$)",            full_response, re.I | re.S)
        action_m   = re.search(r"ACTION:\s*(\S+)",                                           full_response, re.I)
        done_m     = re.search(r"DONE:\s*true",                                              full_response, re.I)
        summary_m  = re.search(r"SUMMARY:\s*([\s\S]*?)$",                                    full_response, re.I)

        # ── Check for done signal ─────────────────────────────────
        if done_m:
            await manager.broadcast({
                "type":     "agent_done",
                "agent":    agent_id,
                "iter":     iteration,
                "findings": agent_findings_count,
                "summary":  summary_m.group(1).strip() if summary_m else "",
            })
            break

        # ── Tool execution ────────────────────────────────────────
        agent_tool_cycle = {
            "planner":  [],
            "recon":    ["subfinder", "amass", "whatweb", "theHarvester"],
            "web":      ["nuclei", "nikto", "sqlmap", "gobuster", "ffuf"],
            "identity": ["jwt_tool", "hydra"],
            "network":  ["nmap", "masscan", "smbmap", "enum4linux", "crackmapexec"],
            "cloud":    ["scout", "prowler", "kube-hunter"],
            "exploit":  ["searchsploit", "hashcat", "john"],
        }
        if action_m:
            tool_name = action_m.group(1).strip().lower()
        else:
            cycle = agent_tool_cycle.get(agent_id, [])
            if not cycle:
                await manager.broadcast({
                    "type":     "agent_done",
                    "agent":    agent_id,
                    "iter":     iteration,
                    "findings": agent_findings_count,
                    "summary":  "No executable tool required for this agent.",
                })
                break
            tool_name = cycle[(iteration - 1) % len(cycle)]

        # Map common tool aliases / shorthand the LLM might use
        tool_alias = {
            "gobuster": "gobuster", "ffuf": "ffuf", "nuclei": "nuclei",
            "nmap": "nmap", "nikto": "nikto", "sqlmap": "sqlmap",
            "subfinder": "subfinder", "amass": "amass", "masscan": "masscan",
            "smbmap": "smbmap", "enum4linux": "enum4linux",
            "scoutsuite": "scout", "scout": "scout", "prowler": "prowler",
            "kube-hunter": "kube-hunter", "kubehunter": "kube-hunter",
            "searchsploit": "searchsploit", "hydra": "hydra",
            "hashcat": "hashcat", "john": "john", "whatweb": "whatweb",
            "jwt_tool": "jwt_tool", "jwt-tool": "jwt_tool",
            "theharvester": "theHarvester", "hydra_ssh": "hydra",
        }
        resolved_tool = tool_alias.get(tool_name, tool_name)

        await manager.broadcast({
            "type":     "agent_action",
            "agent":    agent_id,
            "tool":     resolved_tool,
            "iter":     iteration,
            "thought":  thought.group(1).strip() if thought else "",
            "hypothesis": hypothesis.group(1).strip() if hypothesis else "",
        })

        # Build minimal safe args for the tool
        tool_args = build_tool_args(resolved_tool, target, depth)
        result    = await run_tool(resolved_tool, tool_args, timeout=120 if depth != "deep" else 240)

        await manager.broadcast({
            "type":   "agent_output",
            "agent":  agent_id,
            "tool":   resolved_tool,
            "output": result["output"][:3000],
            "code":   result.get("code", 0),
            "iter":   iteration,
        })

        # ── Extract and save findings ─────────────────────────────
        new_findings = extract_findings(result["output"], resolved_tool, agent_id, session_id, iteration)
        if new_findings:
            for f in new_findings:
                _db.execute(
                    "INSERT OR IGNORE INTO findings (id,session_id,severity,description,agent,tool,iteration,cvss,raw_output,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (f["id"], f["session_id"], f["severity"], f["description"],
                     f["agent"], f["tool"], f["iteration"], f["cvss"],
                     f["raw_output"], f["created_at"])
                )
                # Learn the pattern — store a specific, evidence-based signature.
                # Pattern = "tool: first 60 chars of description" so the LLM gets
                # real context, not a useless generic "tool+type→severity" string.
                now_iso = datetime.utcnow().isoformat()
                desc_short = f["description"][:60].rstrip()
                learn_pat  = f"{resolved_tool}: {desc_short}"
                new_conf_val = min(1.0, 0.3 + 0.14 * 1)
                _db.execute(
                    "INSERT INTO learned "
                    "(pattern,vuln_type,tech_stack,agent,tool,seen_count,verified,confidence,last_seen,first_seen) "
                    "VALUES (?,?,?,?,?,1,1,?,?,?) "
                    "ON CONFLICT(pattern) DO UPDATE SET "
                    "  seen_count=seen_count+1, "
                    "  confidence=MIN(1.0, 0.3 + 0.14*(seen_count+1)), "
                    "  verified=1, "
                    "  last_seen=excluded.last_seen",
                    (learn_pat, f["severity"], target_type, agent_id,
                     resolved_tool, new_conf_val, now_iso, now_iso)
                )
            _db.commit()
            all_findings.extend(new_findings)
            agent_findings_count += len(new_findings)

            await manager.broadcast({
                "type":     "agent_findings",
                "agent":    agent_id,
                "findings": new_findings,
                "iter":     iteration,
            })

        # ── Append to LLM conversation history ───────────────────
        history.append({"role": "assistant", "content": full_response})
        history.append({
            "role": "user",
            "content": (
                f"TOOL [{resolved_tool}] output (truncated):\n{result['output'][:2000]}\n\n"
                f"Findings so far: {agent_findings_count}. Continue analysis."
            )
        })

        # Keep history bounded to avoid context overflow
        if len(history) > 28:
            history = history[:2] + history[-24:]

    # Final status broadcast even if we hit max_iter without DONE
    await manager.broadcast({
        "type":     "agent_done",
        "agent":    agent_id,
        "findings": agent_findings_count,
        "summary":  f"Completed {max_iter} iterations. {agent_findings_count} findings.",
    })


# ── Tool argument builder ─────────────────────────────────────────────

WL_MEDIUM  = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
WL_SMALL   = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
WL_ROCKYOU = "/usr/share/wordlists/rockyou.txt"

def build_tool_args(tool: str, target: str, depth: str = "standard") -> List[str]:
    """
    Returns safe, opinionated argument lists for each tool.
    The 'depth' parameter controls how aggressive the scan is:
      quick    = fast checks, low noise
      standard = balanced (default)
      deep     = thorough, slower, more coverage
    """
    wl = WL_MEDIUM if depth != "quick" else WL_SMALL
    t4 = "-T4" if depth != "quick" else "-T3"
    threads = "50" if depth == "deep" else "30"
    raw = (target or "").strip()
    parsed = urlparse(raw) if raw.startswith("http://") or raw.startswith("https://") else None
    host = (parsed.hostname if parsed and parsed.hostname else raw.replace("http://", "").replace("https://", "")).split("/")[0].split(":")[0]
    web_base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/") if parsed and parsed.netloc else f"https://{host}"

    args_map = {
        "subfinder":     ["-d", host, "-silent", "-all"],
        "amass":         ["enum", "-d", host, "-passive", "-silent"],
        "whatweb":       [web_base, "-v", "--log-verbose=/dev/stdout"],
        "nmap":          ["-Pn", "--unprivileged", "-sV", "-sC", "--open", t4, "--top-ports", "1000", host],
        "masscan":       [host, "-p", "80,443,22,21,8080,8443,3306,5432", "--rate", "5000"],
        "smbmap":        ["-H", host],
        "enum4linux":    ["-a", host],
        "crackmapexec":  ["smb", host],
        "nuclei":        ["-u", web_base, "-as",
                          "-severity", "critical,high,medium,low,info", "-silent", "-jsonl", "-duc", "-no-color"],
        "nikto":         ["-h", web_base, "-nointeractive"],
        "sqlmap":        ["-u", f"{web_base}/", "-crawl=2", "--batch",
                          "--level=2", "--risk=1", "--random-agent", "--quiet"],
        "gobuster":      ["dir", "-u", web_base, "-w", wl, "-q",
                          "--no-error", "-t", threads, "-x", "php,html,js,txt,bak,sql,env"],
        "ffuf":          ["-u", f"{web_base}/FUZZ", "-w", wl,
                          "-mc", "200,204,301,302,403", "-t", threads, "-silent"],
        "feroxbuster":   ["--url", web_base, "--wordlist", wl, "--quiet", "--no-recursion"],
        "hydra":         ["-l", "admin", "-P", WL_ROCKYOU, host,
                          "http-post-form", "/login:user=^USER^&pass=^PASS^:Invalid", "-t", "4", "-f"],
        "jwt_tool":      ["-t", web_base, "--all"],
        "scout":         ["aws", "--report-name", "scout-out", "--no-browser"],
        "prowler":       ["aws", "--output-formats", "json", "-q"],
        "kube-hunter":   ["--remote", host, "--report", "json"],
        "searchsploit":  ["--json", host],
        "hashcat":       ["-a", "0", "-m", "0", "hashes.txt", WL_ROCKYOU, "--quiet", "--show"],
        "john":          [f"--wordlist={WL_ROCKYOU}", "--format=auto", "hashes.txt"],
        "curl":          ["-sI", web_base, "--max-time", "10"],
    }
    return args_map.get(tool, [host])


# ════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    log.info(f"Starting Phantom backend on port {PORT}")
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=PORT,
        reload=False,
        log_level="info",
    )
