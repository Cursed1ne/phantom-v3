# PHANTOM AI v3 — Session Resume Notes
## Last updated: 2026-03-07 (Session 4)

---

## SESSION 4 — COMPLETED

### Feature 1: OpenAPI / Swagger / GraphQL Discovery (`backend/autopilot.py`)
Added `_probe_api_specs(base_url)` function called automatically after the crawler phase in `run_autopilot_scan()`.

- Probes 12 common OpenAPI/Swagger paths: `/openapi.json`, `/swagger.json`, `/api-docs`, etc.
- Probes 4 GraphQL endpoints: `/graphql`, `/api/graphql`, `/gql`, `/query`
- If spec found: extracts endpoint list, adds them to `discovered_urls` for deeper fuzzing
- Generates findings: "Swagger spec exposed" (LOW/MEDIUM) or "GraphQL introspection enabled" (MEDIUM)
- Results in `api_specs` key of autopilot return dict + `summary.api_specs_found` count

### Feature 2: OAuth/SSO Detection + Testing (`backend/autopilot.py`)
Added `_test_oauth_endpoints(base_url)` function called after API spec probing.

- Probes 11 OAuth/OIDC paths: `/.well-known/openid-configuration`, `/oauth/authorize`, `/connect/token`, etc.
- Tests discovered `authorize` endpoints for 3 vulnerabilities:
  1. **Open Redirect** (HIGH, CVSS 7.4): redirect_uri=http://evil.com accepted
  2. **Missing State Parameter** (MEDIUM, CVSS 5.4): no state= in redirect → CSRF risk
  3. **Implicit Flow Allowed** (LOW, CVSS 4.3): response_type=token accepted
- Results in `oauth` key + findings added to `manual_findings`

### Feature 3: Mobile/APK Scanner (`backend/main.py`)
New endpoint: `POST /scan/apk?apk_path=/path/to/app.apk&session_id=<optional>`

- Decompiles with `apktool d` (resources/manifest) + `jadx -d` (Java source)
- Greps for 9 secret patterns:
  - Google API Key, Firebase Server Key, Google OAuth Client ID
  - Hardcoded secrets (password=, api_key=, etc.)
  - Hardcoded API endpoints, Insecure HTTP, Debug mode, Backup allowed, Exported components
- Persists HIGH/MEDIUM/LOW findings to DB if session_id provided
- Gracefully handles missing tools: "install with: brew install apktool jadx"

### Feature 4: scan_apk Chat Tool (`backend/persistent_chat.py`)
New AI tool registered in `_TOOL_HANDLERS`:
- System prompt: `TOOL: scan_apk {"apk_path": "/path/to/app.apk"}`
- Calls `/scan/apk` endpoint, streams finding events back to chat
- LLM can now say "Let me scan that APK for secrets" and actually do it

### Feature 5: Dedicated Report View (`src/App.jsx`)
New `ReportView` component replacing the missing dedicated report tab.

- **Risk score banner**: Computed score (0-100) with CRITICAL/HIGH/MEDIUM/LOW label
- **Severity heatmap**: 5 colored blocks (CRITICAL/HIGH/MEDIUM/LOW/INFO) — click to expand group
- **Expandable findings by severity**: Click severity block → shows all findings in that group
- **Export HTML**: Opens printable/saveable HTML report in new browser tab (or `API.dialog.save`)
- **Export JSON**: Saves structured findings JSON
- NAV entry: `{ id: 'report', icon: '📄', label: 'Report' }` — routes to `<ReportView findings={findings} targetHost={targetHost} />`

---

## SESSION 3 — COMPLETED (kept for reference)

### Fix 1: WebSocket port bug (8001 → 8000)
- `backend/cli.py` line 39: `ws://localhost:8001` → `ws://localhost:8000`
- `src/App.jsx` line 14: WS_URL default → 8000

### Fix 2: Session loss on tab switch → Persistent chat
- `chat_sessions` + `chat_messages` SQLite tables added
- `backend/persistent_chat.py` created — saves every turn to DB
- `/ws/chat` rewritten with session ID handshake + replay protocol
- `ChatView` uses localStorage `phantom_chat_session_id` + replay events

### Fix 3: Regex AI → Real LLM tool-calling
- `persistent_chat.py` uses LLM-native TOOL: pattern
- 9 tools: scan, run_tool, query_findings, build_graph, generate_report, train_model, analyze_proxy, target_info, scan_apk

### Fix 4: Duplicate Report tab removed
- Old duplicate `{id: 'report', icon: '📄'}` that pointed to `FindingsView` removed
- Now replaced with proper `ReportView`

---

## ALL FILES CHANGED ACROSS SESSIONS

| File | Last Changed | Change Summary |
|------|-------------|----------------|
| `backend/cli.py` | Session 3 | Port 8001→8000 |
| `backend/main.py` | Session 4 | chat tables; /ws/chat rewrite; POST /scan/apk |
| `backend/persistent_chat.py` | Session 4 | LLM agent + scan_apk tool |
| `backend/autopilot.py` | Session 4 | OpenAPI probe + OAuth tester |
| `src/App.jsx` | Session 4 | ReportView + Report NAV; persistent ChatView |
| `electron/main.js` | Session 2 | CA cert fix |
| `backend/agents/base.py` | Session 2 | LLM fixes |
| `backend/trainer.py` | Session 2 | NEW — training data |
| `backend/graph_builder.py` | Session 2 | NEW — kill-chain graph |
| `backend/chat_agent.py` | Session 3 | OLD regex agent (superseded) |

---

## HOW TO TEST

```bash
# Start backend
cd /Volumes/OneTouch/doshan_disck/phantom-v3/backend
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Start app (separate terminal)
cd /Volumes/OneTouch/doshan_disck/phantom-v3
npm start

# ── Test persistent chat ──────────────────────────────────────
# 1. Open AI Chat tab
# 2. Type: "scan https://petstore.swagger.io"
# 3. Switch tabs → come back → history should be there

# ── Test OpenAPI discovery ────────────────────────────────────
# Scan a Swagger target — check autopilot result for "api_specs" key
curl -s -X POST http://localhost:8000/autopilot/run \
  -H "Content-Type: application/json" \
  -d '{"session_id":"test","target":"https://petstore.swagger.io"}' | python3 -m json.tool | grep -A5 api_specs

# ── Test APK scan ─────────────────────────────────────────────
curl -s -X POST "http://localhost:8000/scan/apk?apk_path=/path/to/app.apk"

# ── Test Report view ──────────────────────────────────────────
# Run agents → click 📄 Report tab
# → Severity heatmap + risk score shown
# → Click any severity block → findings expand
# → Click "Export HTML" → printable report opens

# ── Check GitHub is PRIVATE ───────────────────────────────────
gh repo view Cursed1ne/phantom-v3 --json visibility
# → {"visibility":"PRIVATE"}
```

---

## GITHUB STATUS
- Repo: https://github.com/Cursed1ne/phantom-v3
- Visibility: PRIVATE (created with --private flag)
- Changes in Sessions 3+4: **NOT pushed** (user request)
- Last pushed: commit 9149955

When ready to push:
```bash
cd /Volumes/OneTouch/doshan_disck/phantom-v3
git add backend/cli.py backend/main.py backend/persistent_chat.py backend/autopilot.py src/App.jsx RESUME.md
git commit -m "feat: OpenAPI/OAuth/APK scanning + ReportView + persistent LLM chat"
git push origin main
```

---

## CLAUDE CODE LIMITS — HOW TO EXTEND

| Method | How |
|--------|-----|
| `/compact` | Compresses current context to ~20% size. Run before hitting the limit. |
| `/resume` | On restart, restores previous session context |
| Claude Max | $100–200/mo — much higher rate limits |
| Own API key | `ANTHROPIC_API_KEY=sk-ant-... claude` — pay per token, no hard cap |
| Split sessions | Independent features in separate sessions avoids context bloat |

---

## NEXT STEPS (future sessions)

1. **Verify end-to-end**: Start backend + app, scan a real target, check OpenAPI/OAuth probes fire
2. **Parallel agents**: Run recon + web agents simultaneously (asyncio.gather in run_autopilot_scan)
3. **Live scan output in chat**: Connect /ws/agent stream → relay findings to chat in real time
4. **GraphQL security testing**: If introspection enabled → query for mutations, test for injection
5. **Better APK testing**: Add MobSF integration for deeper analysis
6. **CORS testing**: Check Access-Control-Allow-Origin: * + credentialed requests
7. **GitHub push** when user is ready
