"""
PHANTOM AI v3 — PostgreSQL Store
──────────────────────────────────
PostgreSQL is the primary relational store for anything that needs to
survive restarts, be queried with complex joins, or be exported for
compliance reports.

Schema design philosophy:
  • findings and sessions are write-once (append-only) so we never
    lose historical data — we only add to it.
  • The compliance_mappings table links each finding to one or more
    compliance frameworks (OWASP, PCI-DSS, NIST, ISO 27001) so we
    can generate audit-ready reports automatically.
  • The attack_chains table records multi-step exploitation paths
    that the exploit agent identifies.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

log = logging.getLogger(__name__)

try:
    import asyncpg
    PG_AVAILABLE = True
except ImportError:
    PG_AVAILABLE = False
    log.warning("asyncpg not installed — PostgreSQL store disabled")

# ── DDL: table definitions ────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pg_sessions (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    target_type  TEXT DEFAULT 'web',
    started_at   TIMESTAMPTZ DEFAULT NOW(),
    finished_at  TIMESTAMPTZ,
    status       TEXT DEFAULT 'running',
    agents_used  JSONB DEFAULT '[]',
    risk_score   FLOAT DEFAULT 0,
    metadata     JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS pg_findings (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES pg_sessions(id),
    severity     TEXT NOT NULL,
    description  TEXT NOT NULL,
    agent        TEXT,
    tool         TEXT,
    iteration    INT DEFAULT 0,
    cvss         FLOAT DEFAULT 0,
    raw_output   TEXT,
    evidence     TEXT,
    remediation  TEXT,
    cve          TEXT,
    cwe          TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pg_attack_chains (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    session_id   TEXT NOT NULL,
    chain_steps  JSONB NOT NULL,   -- ordered list of finding IDs
    description  TEXT,
    risk_score   FLOAT DEFAULT 0,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pg_compliance (
    finding_id   TEXT NOT NULL,
    framework    TEXT NOT NULL,   -- OWASP_TOP10 | PCI_DSS | NIST | ISO27001
    control_id   TEXT NOT NULL,   -- e.g. A01:2021 | 6.5.1 | SI-3
    control_name TEXT,
    PRIMARY KEY (finding_id, framework, control_id)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_findings_session   ON pg_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON pg_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_created   ON pg_findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_target    ON pg_sessions(target);
"""

# Compliance framework mappings for common vulnerability types
OWASP_MAPPINGS = {
    "SQL Injection":     ("OWASP_TOP10", "A03:2021", "Injection"),
    "XSS":               ("OWASP_TOP10", "A03:2021", "Injection"),
    "IDOR":              ("OWASP_TOP10", "A01:2021", "Broken Access Control"),
    "JWT":               ("OWASP_TOP10", "A07:2021", "Identification and Auth Failures"),
    "SSRF":              ("OWASP_TOP10", "A10:2021", "Server-Side Request Forgery"),
    "XXE":               ("OWASP_TOP10", "A05:2021", "Security Misconfiguration"),
    "Path Traversal":    ("OWASP_TOP10", "A01:2021", "Broken Access Control"),
    "AWS Key":           ("OWASP_TOP10", "A02:2021", "Cryptographic Failures"),
    "Credential":        ("OWASP_TOP10", "A02:2021", "Cryptographic Failures"),
    "RCE":               ("OWASP_TOP10", "A03:2021", "Injection"),
}


class PostgresStore:
    """Async PostgreSQL store using asyncpg connection pool."""

    def __init__(self, dsn: str = "postgresql://phantom:phantom123@localhost:5432/phantom"):
        self.dsn  = dsn
        self._pool = None

    async def connect(self) -> bool:
        if not PG_AVAILABLE:
            return False
        try:
            self._pool = await asyncpg.create_pool(
                self.dsn, min_size=2, max_size=10, command_timeout=30
            )
            async with self._pool.acquire() as conn:
                await conn.execute(SCHEMA_SQL)
            log.info(f"PostgreSQL connected: {self.dsn.split('@')[-1]}")
            return True
        except Exception as e:
            log.warning(f"PostgreSQL connection failed: {e}")
            self._pool = None
            return False

    async def disconnect(self):
        if self._pool:
            await self._pool.close()

    # ── Sessions ─────────────────────────────────────────────────────

    async def create_session(self, target: str, target_type: str,
                              agents: List[str]) -> str:
        if not self._pool:
            return str(uuid4())
        sid = str(uuid4())
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO pg_sessions (id, target, target_type, agents_used) VALUES ($1,$2,$3,$4)",
                sid, target, target_type, json.dumps(agents),
            )
        return sid

    async def finish_session(self, session_id: str, risk_score: float):
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE pg_sessions SET status='complete', finished_at=NOW(), risk_score=$1 WHERE id=$2",
                risk_score, session_id,
            )

    async def list_sessions(self, limit: int = 20) -> List[Dict]:
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM pg_sessions ORDER BY started_at DESC LIMIT $1", limit
            )
        return [dict(r) for r in rows]

    # ── Findings ──────────────────────────────────────────────────────

    async def save_finding(self, finding: Dict):
        """
        Persist a finding to PostgreSQL and automatically map it to
        compliance frameworks based on keyword matching.
        """
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO pg_findings
                    (id, session_id, severity, description, agent, tool,
                     iteration, cvss, raw_output, created_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
                ON CONFLICT (id) DO NOTHING
                """,
                finding.get("id"),
                finding.get("session_id"),
                finding.get("severity"),
                finding.get("description"),
                finding.get("agent"),
                finding.get("tool"),
                finding.get("iteration", 0),
                finding.get("cvss", 0),
                finding.get("raw_output", "")[:2000],
            )
            # Auto-map to compliance frameworks
            desc = finding.get("description", "").upper()
            for keyword, (framework, control_id, control_name) in OWASP_MAPPINGS.items():
                if keyword.upper() in desc:
                    await conn.execute(
                        """
                        INSERT INTO pg_compliance (finding_id, framework, control_id, control_name)
                        VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING
                        """,
                        finding.get("id"), framework, control_id, control_name,
                    )

    async def get_findings(self, session_id: str) -> List[Dict]:
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM pg_findings WHERE session_id=$1 ORDER BY cvss DESC",
                session_id,
            )
        return [dict(r) for r in rows]

    async def get_findings_with_compliance(self, session_id: str) -> List[Dict]:
        """Return findings enriched with compliance framework mappings."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT f.*, c.framework, c.control_id, c.control_name
                FROM pg_findings f
                LEFT JOIN pg_compliance c ON c.finding_id = f.id
                WHERE f.session_id = $1
                ORDER BY f.cvss DESC
                """,
                session_id,
            )
        return [dict(r) for r in rows]

    # ── Attack chains ─────────────────────────────────────────────────

    async def save_attack_chain(self, session_id: str, steps: List[str],
                                 description: str, risk_score: float):
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO pg_attack_chains (session_id, chain_steps, description, risk_score) VALUES ($1,$2,$3,$4)",
                session_id, json.dumps(steps), description, risk_score,
            )

    # ── Analytics ────────────────────────────────────────────────────

    async def get_stats(self) -> Dict[str, Any]:
        """Dashboard stats: total findings by severity, top tools, risk trend."""
        if not self._pool:
            return {}
        async with self._pool.acquire() as conn:
            sev = await conn.fetch(
                "SELECT severity, count(*) as cnt FROM pg_findings GROUP BY severity"
            )
            top_tools = await conn.fetch(
                "SELECT tool, count(*) as cnt FROM pg_findings GROUP BY tool ORDER BY cnt DESC LIMIT 10"
            )
            total_sessions = await conn.fetchval("SELECT count(*) FROM pg_sessions")
        return {
            "by_severity":    {r["severity"]: r["cnt"] for r in sev},
            "top_tools":      [dict(r) for r in top_tools],
            "total_sessions": total_sessions,
        }
