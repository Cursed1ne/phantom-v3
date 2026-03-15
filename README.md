# ⬡ Phantom AI v3

> **Autonomous AI-Powered Penetration Testing Platform**

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/AI-Autonomous%20Pentest-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-Proprietary-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/AI%20LLM%20Scanner-AIE--10%20Taxonomy-purple?style=for-the-badge" />
</p>

---

## Patent & Intellectual Property Notice

**PATENT PENDING**

This software and the novel methodologies embedded within it — including but not limited to the **SPECTRA**, **RIFT**, **MIMIC**, **NEXUS**, **GHOST**, and **ORACLE** autonomous security testing frameworks — are the subject of a patent application filed by:

**Doshan**
Inventor & Architect — Phantom AI v3

> *All rights reserved. Unauthorized reproduction, distribution, or reverse engineering of the core AI agent architecture is strictly prohibited.*

---

## What is Phantom AI?

Phantom AI v3 is a **fully autonomous penetration testing platform** that combines AI-driven crawling, active exploitation, and three patented novel security analysis modules into a single desktop application powered by a local LLM (Ollama — 100% private, no data leaves your machine).

---

## Three Patented Innovations

| Module | What It Solves | Why It's Novel |
|--------|---------------|----------------|
| **SPECTRA** — Semantic Policy Extractor & Constraint Tester | Finds business logic vulnerabilities that no scanner can find | First tool to use an LLM to *read* an app's rules and *test* their enforcement |
| **RIFT** — Race Condition & Temporal Vulnerability Finder | Automatically detects race conditions and timing side-channels | First autonomous race condition finder using semantic endpoint classification + concurrent burst testing |
| **MIMIC** — Multi-Identity Cross-User Authorization Tester | Automatically finds IDOR and broken object-level authorization | First tool to autonomously register a second identity and systematically test cross-user access |

---

## AI LLM Security Engine — Autonomous AI/LLM Vulnerability Scanner

Phantom AI v3 includes a dedicated **AI exploitation engine** that tests AI-powered applications and LLM APIs against the **AI Exploitation Top 10 (AIE-10)** — a unified taxonomy derived from OWASP LLM Top 10 (2025) + MITRE ATLAS + current academic research.

> Full taxonomy: [`docs/AI_EXPLOITATION_TOP10.md`](docs/AI_EXPLOITATION_TOP10.md)

### What the AI Scanner Tests

| # | AIE Category | Severity | OWASP LLM | MITRE ATLAS |
|---|-------------|----------|-----------|-------------|
| AIE-01 | Direct Prompt Injection | CRITICAL | LLM01:2025 | AML.T0013 |
| AIE-02 | Indirect Prompt Injection (RAG/tool hijack) | CRITICAL | LLM01:2025 | AML.T0013 |
| AIE-03 | System Prompt Extraction | HIGH | LLM07:2025 | AML.T0040 |
| AIE-04 | Model Architecture Fingerprinting | HIGH | LLM01:2025 | AML.T0016 |
| AIE-05 | Training Data Extraction (memorization) | HIGH | LLM02:2025 | AML.T0018 |
| AIE-06 | Membership Inference Attack | MEDIUM | LLM06:2025 | AML.T0017 |
| AIE-07 | Adversarial Input / Evasion | HIGH | LLM05:2025 | AML.T0043 |
| AIE-08 | RAG / Vector Store Poisoning | CRITICAL | LLM08:2025 | AML.T0023 |
| AIE-09 | Excessive Agency / Tool Abuse | CRITICAL | LLM06:2025 | AML.T0047 |
| AIE-10 | Unbounded Consumption / DoS | MEDIUM | LLM10:2025 | AML.T0027 |

### Three Novel Patent-Pending AI Modules

| Module | Full Name | What It Does |
|--------|-----------|--------------|
| **NEXUS** | Neural Extraction via Unified Sampling | Binary-search safety boundary mapping across 4 semantic axes; fingerprints architecture, temperature, and RLHF training characteristics |
| **GHOST** | Gradient-free Holistic Optimization of Subversive Tokens | Evolves universal adversarial prefixes using homoglyphs, zero-width characters, and context wrappers to bypass safety filters |
| **ORACLE** | Output Reasoning & Confidence Level Exploitation | Behavioral membership inference without logprobs; hallucination surface mapping; timing side-channel attacks |

### AI Scanner API

```bash
# REST — launch a full AI pentest
curl -X POST http://localhost:8000/ai/scan \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://api.example.com","model_name":"gpt-4","api_key":"sk-..."}'

# WebSocket — stream live findings in real time
wscat -c ws://localhost:8000/ws/ai-scan

# View the full AIE-10 taxonomy as JSON
curl http://localhost:8000/ai/taxonomy
```

The AI scanner runs as an **8-phase autonomous pipeline**: endpoint discovery → prompt injection → model extraction → RAG poisoning → tool abuse → NEXUS → GHOST → ORACLE → report.

---

## Unique Capabilities vs. Competitors

| Feature | Phantom AI v3 | Burp Suite Pro | Metasploit | OWASP ZAP |
|---------|:-------------:|:--------------:|:----------:|:---------:|
| Fully autonomous (zero human input after start) | ✅ | ❌ | ❌ | ❌ |
| Business logic constraint testing | ✅ | ❌ | ❌ | ❌ |
| Autonomous race condition detection | ✅ | ⚠️ manual | ❌ | ❌ |
| Cross-user IDOR auto-testing | ✅ | ❌ | ❌ | ❌ |
| On-device continuous learning | ✅ | ❌ | ❌ | ❌ |
| Natural language control | ✅ | ❌ | ❌ | ❌ |
| Kill-chain graph visualization | ✅ | ❌ | ⚠️ partial | ❌ |
| Login/signup automation | ✅ | ⚠️ partial | ❌ | ❌ |
| Post-exploitation chaining | ✅ | ❌ | ✅ | ❌ |
| AI/LLM vulnerability scanning (AIE-10) | ✅ | ❌ | ❌ | ❌ |
| Autonomous AI safety boundary mapping | ✅ | ❌ | ❌ | ❌ |
| 100% local / air-gapped | ✅ | ❌ | ❌ | ❌ |

---

## Quick Start

### macOS / Linux — One Command

```bash
git clone https://github.com/Cursed1ne/phantom-v3.git
cd phantom-v3
chmod +x run.sh
./run.sh
```

`run.sh` automatically installs all missing dependencies (nmap, nuclei, sqlmap, nikto, ffuf) and launches the full platform.

### Windows — One Command

```batch
git clone https://github.com/Cursed1ne/phantom-v3.git
cd phantom-v3
run.bat
```

For a full first-time setup with automatic dependency installation:

```powershell
# Run as Administrator
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1
```

---

## Prerequisites

| Dependency | Notes |
|------------|-------|
| [Ollama](https://ollama.ai) | Local LLM — download and run before starting |
| Python 3.10+ | `brew install python` / `winget install Python.Python.3` |
| Node.js 18+ | `brew install node` / `winget install OpenJS.NodeJS` |
| nmap | Auto-installed by run scripts |
| nuclei | Auto-installed by run scripts |
| sqlmap | Auto-installed by run scripts |

---

## Architecture

```
User (natural language or URL)
         │
         ▼
  ┌──────────────────┐
  │   Autopilot      │  ← Master AI orchestrator
  └──────┬───────────┘
         │
    ┌────▼────┐
    │ Crawler │  ← Playwright browser automation
    │         │    Login / signup / session capture
    └────┬────┘
         │
    ┌────▼────────┐
    │  Attacker   │  ← SQLi · XSS · LFI · SSTI · CMDi · SSRF
    │             │    Post-exploitation chaining
    └────┬────────┘
         │
    ┌────▼────┐  ┌──────┐  ┌───────┐
    │ SPECTRA │  │ RIFT │  │ MIMIC │   ← Three novel patented modules
    └────┬────┘  └──┬───┘  └───┬───┘
         └──────────┴──────────┘
                    │
    ┌───────────────▼────────────────────────┐
    │   AI Exploitation Engine (AIE-10)      │  ← LLM/AI API target scanner
    │   NEXUS · GHOST · ORACLE               │    Patent Pending — Doshan
    └───────────────┬────────────────────────┘
                    │
    ┌───────────────▼────────────┐
    │  Kill-Chain Graph Builder  │  ← Visual attack path
    └───────────────┬────────────┘
                    │
    ┌───────────────▼────────────┐
    │  Report Generator          │  ← CVSS-scored findings
    └────────────────────────────┘
```

---

## File Structure

```
phantom-v3/
├── backend/
│   ├── main.py              ← FastAPI REST + WebSocket API
│   ├── autopilot.py         ← Master orchestrator
│   ├── attacker.py          ← Active exploitation engine
│   ├── spectra.py           ← [PATENT PENDING] Business constraint tester
│   ├── rift.py              ← [PATENT PENDING] Race condition finder
│   ├── mimic.py             ← [PATENT PENDING] Cross-user IDOR tester
│   ├── persistent_chat.py   ← LLM chat with memory + tool routing
│   ├── graph_builder.py     ← Kill-chain graph construction
│   ├── trainer.py           ← Continuous learning engine
│   ├── agents/              ← Modular agent plugins
│   └── ai_exploiter/        ← AI/LLM exploitation engine (AIE-10)
│       ├── ai_autopilot.py  ←   8-phase autonomous AI pentest orchestrator
│       ├── prompt_injector.py ← AIE-01/02: Direct + indirect injection (26 payloads)
│       ├── model_extractor.py ← AIE-04/05: Architecture + training data extraction
│       ├── rag_attacker.py  ←   AIE-08: RAG/vector store poisoning
│       ├── tool_abuser.py   ←   AIE-09: Excessive agency exploitation
│       ├── nexus.py         ←   [PATENT PENDING] Safety boundary mapper
│       ├── ghost.py         ←   [PATENT PENDING] Adversarial token optimizer
│       └── oracle.py        ←   [PATENT PENDING] Behavioral inference engine
├── src/
│   └── App.jsx              ← React UI
├── electron/
│   └── main.js              ← Electron main process
├── run.sh                   ← macOS/Linux one-command launcher
├── run.bat                  ← Windows one-command launcher
└── setup.ps1                ← Windows full setup script
```

---

## The 7 Agents

| Agent | Role | Key Tools |
|-------|------|-----------|
| Planner | Master strategist — builds attack plan, delegates | nmap, whatweb |
| Recon | Asset discovery, OSINT, subdomain enumeration | subfinder, amass |
| Web | OWASP Top 10, injection, directory brute-force | nuclei, nikto, sqlmap, ffuf |
| Identity | Auth/SSO/JWT/OAuth testing | jwt_tool, hydra |
| Network | Port scanning, SMB, service enumeration | nmap, masscan |
| Cloud | AWS/GCP/Azure posture, Kubernetes | ScoutSuite, prowler |
| Exploit | CVE research, post-exploitation, chaining | searchsploit, custom chains |

---

## Safety & Ethics

**For authorized testing only.** By using Phantom AI you confirm that you have explicit written permission to test all target systems.

- All findings are proof-based (no destructive exploits by default)
- Rate limiting on all automated tools
- Audit logging of all agent actions
- Kill switch available at any time
- 100% local — no data is sent to any external server

---

## Report Formats

Export results as:
- **Executive Report** (HTML) — risk overview, business impact, critical findings
- **Technical Report** (HTML) — full finding table, tool attribution, CVSS scores
- **SARIF JSON** — compatible with GitHub Code Scanning
- **Raw JSON** — complete findings with all metadata

---

## Author

**Doshan**
Creator, Inventor & Lead Architect — Phantom AI v3

> *"Security through understanding, not obscurity."*

---

<p align="center">
  <b>⬡ Phantom AI v3 — Patent Pending &copy; Doshan. All Rights Reserved.</b>
</p>
