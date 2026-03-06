-- PHANTOM AI v3 — PostgreSQL Schema
-- Auto-runs when the container is first created

CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target      TEXT NOT NULL,
    target_type TEXT DEFAULT 'web',
    started_at  TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status      TEXT DEFAULT 'running',
    agents_used TEXT[],
    tools_used  TEXT[],
    risk_score  FLOAT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    severity   TEXT NOT NULL,
    description TEXT NOT NULL,
    agent      TEXT,
    tool       TEXT,
    iteration  INTEGER,
    cvss       FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS learned_patterns (
    id         SERIAL PRIMARY KEY,
    pattern    TEXT UNIQUE NOT NULL,
    vuln_type  TEXT,
    tech_type  TEXT,
    agent      TEXT,
    seen_count INTEGER DEFAULT 1,
    last_seen  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tool_stats (
    tool        TEXT PRIMARY KEY,
    run_count   INTEGER DEFAULT 0,
    avg_runtime FLOAT DEFAULT 0,
    success_rate FLOAT DEFAULT 1.0,
    last_used   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_session  ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_agent    ON findings(agent);
