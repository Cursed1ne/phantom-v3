# ⬡ PHANTOM AI v3
## Enterprise Autonomous Penetration Testing Platform

> Self-driving red team assessment — 7 agents, 30+ tools, 4-layer memory, local LLM.

---

## What it is

PHANTOM AI v3 is a fully autonomous penetration testing platform that runs security assessments without human intervention. It combines 7 specialised AI agents (each powered by a local Ollama LLM), over 30 integrated security tools, a 4-layer data/memory system, and an Electron desktop app with a real-time dark-cyberpunk UI.

**Target audience:** Security engineers, red teamers, pentest labs, and anyone who wants automated, AI-driven vulnerability discovery on authorised targets.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Electron Desktop App (arm64 + x64 DMG)                     │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  React UI (12 views · Recharts · SVG attack graph)     │ │
│  └───────────────────┬─────────────────────────────────────┘ │
│                      │ IPC / WebSocket                        │
│  ┌───────────────────▼─────────────────────────────────────┐ │
│  │  Electron Main (HTTPS MITM Proxy :8888 · WS :8001)     │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       │ REST
┌──────────────────────▼──────────────────────────────────────┐
│  FastAPI Backend :8000                                       │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │ Planner  │  Recon   │   Web    │ Identity │ Network  │  │
│  │  Agent   │  Agent   │  Agent   │  Agent   │  Agent   │  │
│  ├──────────┴──────────┴──────────┴──────────┤  Cloud   │  │
│  │              Exploit Agent                │  Agent   │  │
│  └───────────────────────────────────────────┴──────────┘  │
│                                                              │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────────────────┐ │
│  │ Redis  │ │ Neo4j  │ │Chroma  │ │    PostgreSQL         │ │
│  │:6379   │ │:7474   │ │:8010   │ │    :5432             │ │
│  │State   │ │Graph   │ │Vectors │ │    Findings          │ │
│  └────────┘ └────────┘ └────────┘ └──────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Ollama :11434  (llama3.1 / mistral / any local model)      │
└─────────────────────────────────────────────────────────────┘
```

---

## The 7 Agents

| Agent | Role | Key Tools |
|-------|------|-----------|
| 🧩 **Planner** | Master strategist — builds attack plan, delegates to specialists | nmap, whatweb, curl |
| 🔭 **Recon** | Asset discovery, OSINT, subdomain enumeration | subfinder, amass, theHarvester |
| 🌐 **Web** | OWASP Top 10, injection, directory brute-force | nuclei, nikto, sqlmap, gobuster, ffuf |
| 🔐 **Identity** | Auth/SSO/JWT/OAuth/SAML testing | jwt_tool, hydra, curl |
| 🗺 **Network** | Port scanning, SMB, service enumeration | nmap, masscan, smbmap, enum4linux |
| ☁ **Cloud** | AWS/GCP/Azure posture, Kubernetes | ScoutSuite, prowler, kube-hunter, pacu |
| 💥 **Exploit** | CVE research, hash cracking, blast radius | searchsploit, hashcat, john |

**Execution order:**
1. Planner runs first (sets strategy)
2. Specialist agents run in parallel batches of 3
3. Exploit analyst runs last to validate everything

---

## Prerequisites

- **macOS** (M1/M2/M3/M4 or Intel) — Windows build also supported
- **Node.js** 18+ — `brew install node`
- **Python 3.10+** — `brew install python`
- **Docker Desktop** — [docker.com](https://docker.com) (for Neo4j/Redis/Chroma/Postgres)
- **Ollama** — `brew install ollama` then `ollama pull llama3.1`

---

## Quick Start

### 1 — Clone / place files
```bash
mkdir phantom-v3 && cd phantom-v3
# copy all project files here (matching the directory structure)
```

### 2 — One-time setup (installs all tools + wordlists + data services)
```bash
chmod +x scripts/setup-tools.sh
./scripts/setup-tools.sh
```

### 3 — Start Ollama (local LLM)
```bash
ollama serve
# In another tab:
ollama pull llama3.1   # recommended — fast and capable
```

### 4 — Run in development mode (hot reload)
```bash
./scripts/dev.sh
```

### 5 — Build production DMG
```bash
./scripts/build-mac.sh
# Output: dist/Phantom AI-3.0.0.dmg
```

---

## Data Services

Start all 4 data services via Docker:
```bash
docker-compose -f docker/docker-compose.yml up -d
```

| Service | URL | Credentials |
|---------|-----|-------------|
| Redis | localhost:6379 | none |
| Neo4j Browser | localhost:7474 | neo4j / phantom123 |
| Chroma | localhost:8010 | none |
| PostgreSQL | localhost:5432 | phantom / phantom |

> If Docker is unavailable, the backend automatically falls back to SQLite — no data services needed for basic operation.

---

## HTTPS Proxy Setup

Phantom intercepts HTTPS traffic on **localhost:8888** using a per-host MITM CA.

**macOS setup:**
1. Open System Settings → Network → your connection → Proxies
2. Enable HTTP Proxy: `127.0.0.1` port `8888`
3. In the Phantom app → Settings → click **Install CA Certificate**

The proxy auto-detects: SQL injection, XSS, SSTI, RCE, path traversal, LFI/SSRF, exposed JWT/Bearer tokens, and AWS keys in every request.

---

## UI Views

| View | What it shows |
|------|---------------|
| **Dashboard** | Live risk score, finding counts, agent grid, Recharts |
| **Targets** | Add hosts/IPs/CIDRs, credential vault, scope notes |
| **Agents** | Launch/stop/pause agents, live LLM stream, step-by-step log |
| **Proxy** | Intercepted requests, flagged traffic, request/response inspector |
| **Network** | Manual nmap/masscan/smbmap with live output |
| **Identity** | JWT decoder, OAuth/OIDC checklist, encoder/decoder |
| **Cloud** | AWS/GCP/Azure posture scan, CIS checklist |
| **Graph** | SVG attack graph — nodes for target, tools, findings |
| **Intel** | Learning engine, memory system status, Docker reference |
| **Findings** | All findings, sortable table, CVSS scores |
| **Report** | Export: Executive HTML, Technical HTML, SARIF JSON, raw JSON |
| **Settings** | Ollama config, CA cert management, system info |

---

## Report Formats

From the Findings or Report view, export:
- **Executive Report** — HTML: risk overview, business impact, critical findings
- **Technical Report** — HTML: full finding table, tool attribution, CVSS
- **SARIF JSON** — machine-readable, compatible with GitHub Code Scanning, VS Code
- **Raw JSON** — complete findings array with all metadata

---

## Wordlists

The agents use these wordlists automatically when present:

| Path | Size | Use |
|------|------|-----|
| `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | 220k lines | Directory brute-force |
| `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` | 87k lines | Quick scans |
| `/usr/share/wordlists/rockyou.txt` | 14.3M passwords | JWT HMAC cracking, SSH brute-force |
| `/usr/share/seclists/Discovery/Web-Content/common.txt` | 4.7k lines | Fast recon |

Install via: `brew install wordlist seclists`

---

## Resuming After a Crash

This project was built in phases. If the build ever needs to restart:
```
Tell Claude: "resume Phase N"
```
Where N is the phase number from `PHASE_TRACKER.md`.

---

## Safety & Ethics

**For authorised testing only.** By using PHANTOM AI you confirm that you have explicit written permission to test all target systems. The platform includes scope enforcement — never test systems outside your defined scope.

Key guardrails built in:
- Proof-based validation only (no destructive exploits)
- Rate limiting on all automated tools
- Audit logging of all agent actions
- Kill switch (Stop All) available at any time
- SAFE MODE on the Exploit agent — CVE research and hash cracking only

---

## File Structure

```
phantom-v3/
├── electron/
│   ├── main.js          # Electron main: HTTPS proxy, IPC, backend launcher
│   └── preload.js       # Context bridge: exposes phantom API to renderer
├── src/
│   ├── App.jsx          # Full React UI (2,473 lines, 12 views)
│   ├── index.js         # React entry point
│   └── index.css        # Dark cyberpunk design system
├── public/
│   └── index.html       # HTML shell (Google Fonts: Orbitron + JetBrains Mono)
├── backend/
│   ├── main.py          # FastAPI server (866 lines)
│   ├── requirements.txt # Python dependencies
│   ├── agents/          # 7 agent modules (base + 6 specialists)
│   └── memory/          # 4 data stores (Redis, Chroma, Neo4j, Postgres)
├── docker/
│   ├── docker-compose.yml  # All 4 data services
│   └── init.sql            # PostgreSQL schema
├── scripts/
│   ├── setup-tools.sh   # One-time tool installer
│   ├── dev.sh           # Hot-reload dev mode
│   ├── build-mac.sh     # Production DMG builder
│   └── start-services.sh # Health-check and start all services
├── package.json         # Electron + React + all deps (pinned versions)
└── PHASE_TRACKER.md     # Build phase tracker for resuming
```

---

*PHANTOM AI v3 · Enterprise Autonomous Pentest Platform · For authorised use only*
