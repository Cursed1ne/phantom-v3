# Phantom AI v3 — Session Resume Notes
Last updated: 2026-03-07

## What This Project Is
Electron + React + FastAPI autonomous pentest platform.
Path: `/Volumes/OneTouch/doshan_disck/phantom-v3/`
GitHub: https://github.com/Cursed1ne/phantom-v3

## Current Session Goal
User requested 3 major fixes + features:
1. CA cert broken → fixed with osascript admin dialog
2. Local LLM giving wrong results → fixed model auto-detect + strict prompts
3. Single command that does everything → built `python3 backend/cli.py scan <target>`

---

## ✅ COMPLETED STEPS

### Step 1 — CA Cert Fix (`electron/main.js` lines 439–484)
- **What**: Replaced silent `security add-trusted-cert` with `osascript` elevation (shows macOS admin password dialog)
- **Key change**: `execWithTimeout(osascript..., 60000)` — 60s timeout for user to type password
- **Order**: pre-check → osascript elevation → login keychain fallback → clipboard copy + manual instructions
- **Status**: ✅ DONE

### Step 2 — LLM Fixes (`backend/agents/base.py`)
- **What**: Added `detect_best_model()` function that queries Ollama API and prefers `qwen3-coder`
- **What**: Changed `BaseAgent.__init__` default model from `"llama3.1"` → `""` + auto-detect
- **What**: Rewrote `_build_system(phase)` with 2-phase strict prompts:
  - plan phase (iter 1): `PLAN_1/2/3 + ACTION:` only, max 1200 tokens
  - act phase (iter 2+): `THOUGHT/ACTION/ARGS/DONE` only, max 600 tokens
- **What**: Added forced tool call guard — if LLM produces no `ACTION:` for 2 consecutive iters, injects nudge
- **What**: `_stream_llm(system, max_tokens)` now has 3-retry backoff (2s, 4s)
- **Status**: ✅ DONE

### Step 3 — Training Data Generator (`backend/trainer.py`) — NEW FILE
- **What**: Generates Ollama-compatible JSONL training data from verified DB findings
- **What**: Maps finding types → correct `ACTION: tool / ARGS: exact-cli-args` templates
- **What**: `build_training_examples(findings)` → list of JSON strings
- **What**: `generate_dataset(db_path, out_path)` → writes .jsonl file from SQLite
- **CLI**: `python3 backend/trainer.py --db phantom.db --out /tmp/train.jsonl --modelfile`
- **Status**: ✅ DONE

### Step 4 — Kill-Chain Graph Builder (`backend/graph_builder.py`) — NEW FILE
- **What**: Maps findings to kill-chain phases: initial→foothold→escalation→impact
- **What**: `build_exploitation_graph(findings, target)` → `{nodes, edges, attack_paths, risk_score, summary}`
- **What**: Color coding: initial=blue, foothold=orange, escalation=red, impact=black
- **Status**: ✅ DONE

### Step 5 — Backend Upgrades (`backend/main.py`)
- **What**: Added `detect_best_model` import + `app.state.active_model` set in lifespan
- **What**: `ScanRequest.model` default changed from `"llama3.1"` → `""`
- **What**: WebSocket loop uses detected model: `model = config.get("model","") or getattr(app.state,'active_model','llama3.1')`
- **What**: `/ollama/train` now uses `trainer.build_training_examples()` (ACTION-format JSONL)
- **What**: `/ollama/train` now only uses confirmed findings (`WHERE confirmed=1 OR confirmed IS NULL`)
- **What**: Added auto-train trigger in `autopilot_run` (if >= 3 confirmed findings, fires background task)
- **NEW endpoints**:
  - `GET /ollama/active-model` → `{"model": "qwen3-coder:latest"}`
  - `GET /ollama/training-history` → last 10 training runs
  - `POST /graph/build` → runs `graph_builder.build_exploitation_graph()`
  - `POST /proxy/analyze` → scans proxy history for vuln patterns, returns findings
- **Status**: ✅ DONE

### Step 6 — CLI Orchestrator (`backend/cli.py`) — NEW FILE
- **What**: `python3 backend/cli.py scan <target>` runs full pipeline:
  1. Check/start Ollama
  2. Start uvicorn backend if not running
  3. POST /sessions → session_id
  4. POST /autopilot/run (background browser scan)
  5. WebSocket /ws/agent → stream all agents to terminal
  6. Wait for session_done
  7. GET /findings/{session_id}
  8. POST /graph/build → exploitation graph
  9. Generate HTML report → `reports/phantom_<host>_<date>.html`
  10. Print terminal summary table
- **Flags**: `--agents all`, `--out ./reports/`, `--report html|json|all`, `--no-browser`, `--depth`, `--max-iter`
- **Also**: `train` and `status` subcommands
- **npm scripts needed**: `"scan": "python3 backend/cli.py scan"` in package.json
- **Status**: ✅ DONE (but needs `import re` fix at top of file)

---

## ⏳ REMAINING STEPS

### Step 7 — Fix `backend/cli.py` imports
- `import re` needs to be at top of module (not inside functions)
- `websockets` package needed: add to `backend/requirements.txt`
- Fix: remove `import re as _re` inside `_do_scan()` and `import re` inside `main()`

### Step 8 — Update `src/App.jsx`
Three changes needed:

**8a. GraphView — kill-chain phase colors + "Build Graph" button**
- Find `GraphView` component (around line 1800-2000)
- Add `PHASE_COLORS` constant: `{initial:'#3b82f6', foothold:'#f97316', escalation:'#ef4444', impact:'#111827', unknown:'#6b7280'}`
- Add "Build Exploitation Graph" button that calls `fetch('/proxy/analyze...` wait no: `POST http://localhost:8000/graph/build`
- Use phase colors on SVG nodes instead of single color

**8b. ProxyView — "Analyze Traffic" button**
- Find `ProxyView` component (around line 2400)
- Add a button in the toolbar: calls `POST http://localhost:8000/proxy/analyze` with current `reqs` state
- Show results as a findings list below the proxy table

**8c. IntelView — Active model + training status**
- Find `IntelView` component
- On mount: fetch `GET http://localhost:8000/ollama/active-model` → show "Active model: qwen3-coder"
- Fetch `GET http://localhost:8000/ollama/training-history` → show last training timestamp
- Add "Auto-training: ON" badge

### Step 9 — `package.json` scripts
Add to `"scripts"` section:
```json
"scan":    "python3 backend/cli.py scan",
"train":   "python3 backend/cli.py train",
"phantom": "python3 backend/cli.py"
```

### Step 10 — Git commit + push
```bash
cd /Volumes/OneTouch/doshan_disck/phantom-v3
git add -A
git commit -m "feat: single-command CLI + kill-chain graph + LLM fix + CA cert fix + auto-train"
git push origin main
```

---

## HOW TO RESUME

Tell Claude:
> "resume phantom-v3 from RESUME.md — we need to complete steps 7-10"

Or more specifically:
> "fix the cli.py import, update App.jsx with graph colors + Analyze Traffic + IntelView model status, add npm scripts, then git push"

Key files:
- `/Volumes/OneTouch/doshan_disck/phantom-v3/backend/cli.py` — fix `import re`
- `/Volumes/OneTouch/doshan_disck/phantom-v3/backend/requirements.txt` — add `websockets`
- `/Volumes/OneTouch/doshan_disck/phantom-v3/src/App.jsx` — 3 UI changes (graph, proxy, intel)
- `/Volumes/OneTouch/doshan_disck/phantom-v3/package.json` — add scan/train/phantom scripts

---

## QUICK TEST COMMANDS (after everything is done)
```bash
# Test CLI
python3 backend/cli.py status
python3 backend/cli.py scan http://testphp.vulnweb.com

# Test backend endpoints
curl http://localhost:8000/ollama/active-model
curl http://localhost:8000/ollama/training-history
curl -X POST http://localhost:8000/graph/build -H 'Content-Type: application/json' -d '{}'

# Test cert (Phantom app must be running)
# Settings → Install CA → should see macOS admin password dialog
```

## ARCHITECTURE SUMMARY
```
electron/main.js      ← HTTPS proxy + IPC + cert install (FIXED: osascript elevation)
backend/
  main.py             ← FastAPI :8000, WebSocket :8001 (FIXED: model auto-detect, new endpoints)
  cli.py              ← NEW: single command scan orchestrator
  autopilot.py        ← Playwright browser crawl + tool chain
  trainer.py          ← NEW: LLM training data generator
  graph_builder.py    ← NEW: kill-chain exploitation graph
  agents/
    base.py           ← FIXED: model detect, strict prompts, retry, forced tool call
    planner/recon/web/identity/network/cloud/exploit.py
src/App.jsx           ← React UI (PENDING: graph colors, Analyze Traffic, Intel model)
package.json          ← PENDING: scan/train/phantom scripts
```
