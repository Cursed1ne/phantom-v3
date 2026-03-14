"""
╔══════════════════════════════════════════════════════════════════════╗
║  PHANTOM AI — Persistent Conversational Agent                       ║
║                                                                      ║
║  A true LLM-native agent (like Claude/ChatGPT) that:               ║
║  • Persists conversation to DB — survives tab switches              ║
║  • Replays full history on reconnect — no session loss              ║
║  • Uses LLM tool-calling — LLM decides what to do, not regex       ║
║  • Runs real security tools and reports only tool-confirmed results ║
║  • Evolves from every scan (injects learned patterns into prompt)   ║
║                                                                      ║
║  Tool-calling pattern:                                              ║
║    LLM outputs: TOOL: <name> <json_args>                           ║
║    Agent parses → executes → appends result → LLM continues        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import re
import sqlite3
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import httpx

log = logging.getLogger("phantom.chat")

OLLAMA_URL = "http://localhost:11434"

# ── Tool call regex ──────────────────────────────────────────────────────────
# Matches:  TOOL: scan {"target": "https://example.com"}
# Works after stripping <think>...</think> tags (qwen3-coder model)
_TOOL_RE = re.compile(
    r"^TOOL:\s*(\w+)\s*(\{.*?\})?",
    re.MULTILINE | re.DOTALL,
)

# Strip qwen3-coder <think>...</think> reasoning blocks before processing
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

# ── System prompt ────────────────────────────────────────────────────────────
_SYSTEM_TEMPLATE = """You are **Phantom AI** — an elite autonomous penetration testing assistant.
You think like an expert red-teamer and communicate clearly like a consultant.

You have access to real security tools. Use them to find actual vulnerabilities.
NEVER invent or guess findings — only report what tools confirm.

═══════════════════════════════════════════
 AVAILABLE TOOLS — call exactly like this:
═══════════════════════════════════════════
TOOL: scan {{"target": "https://example.com"}}
  → Full autonomous pentest: crawler + nmap + nuclei + nikto + sqlmap + ffuf + AI agents

TOOL: run_tool {{"tool": "nmap", "args": "-sV -sC --open -T4 target.com"}}
  → Run a single CLI security tool with custom arguments
  → Available tools: nmap, nuclei, nikto, sqlmap, ffuf, gobuster, subfinder, whatweb,
    feroxbuster, searchsploit, hydra, jwt_tool, masscan, curl

TOOL: query_findings {{}}
  → Show all findings from the current scan session

TOOL: build_graph {{}}
  → Build kill-chain exploitation path graph from findings

TOOL: generate_report {{}}
  → Generate HTML pentest report with all findings

TOOL: train_model {{}}
  → Retrain the local LLM on verified scan findings to improve future scans

TOOL: analyze_proxy {{}}
  → Analyze captured HTTPS proxy traffic for vulnerability patterns

TOOL: target_info {{}}
  → Show current target, active session, and scan status

TOOL: scan_apk {{"apk_path": "/path/to/app.apk"}}
  → Decompile and scan an Android APK for secrets, insecure configs, hardcoded endpoints
  → Requires apktool and/or jadx to be installed

═══════════════════════════════════════════
 RULES:
═══════════════════════════════════════════
1. Call tools when you need real data. Don't make up scan results.
2. After tool output, analyze it and explain findings to the user.
3. For complex targets: scan → query_findings → build_graph → generate_report
4. Be conversational. Explain what you're doing and why.
5. If the user asks a security question without a target, answer from knowledge.
6. One TOOL call per response. Wait for the result before calling another.

{context_section}"""

_CONTEXT_SECTION_TMPL = """═══════════════════════════════════════════
 CURRENT CONTEXT:
═══════════════════════════════════════════
Target:     {target}
Session ID: {session_id}
Findings:   {finding_count} found so far
Model:      {model}
"""


class PersistentChatAgent:
    """
    DB-backed conversational AI agent.

    One instance per chat session. Survives WebSocket disconnects and tab switches
    because all conversation history is stored in the chat_messages table.
    On reconnect, `get_replay_events()` returns the full history for UI restoration.

    Architecture:
        User message → LLM (full history + system prompt) → parse TOOL: calls →
        execute tool → append result to history → LLM continues → stream to frontend
    """

    def __init__(
        self,
        chat_session_id: str,
        model: str,
        db: sqlite3.Connection,
    ) -> None:
        self.chat_session_id = chat_session_id
        self.model           = model or "llama3.1"
        self._db             = db
        self._history: List[Dict] = []   # OpenAI-format message list
        self._ctx: Dict[str, Any] = {}   # current_target, session_id, etc.
        self._load_from_db()

    # ────────────────────────────────────────────────────────────────────────
    #  DB persistence
    # ────────────────────────────────────────────────────────────────────────

    def _load_from_db(self) -> None:
        """Restore conversation history and context from DB."""
        try:
            rows = self._db.execute(
                "SELECT role, content, event_type, metadata_json "
                "FROM chat_messages WHERE chat_session_id=? ORDER BY id ASC",
                (self.chat_session_id,),
            ).fetchall()
            # Rebuild LLM history (user/assistant turns only)
            for r in rows:
                if r["role"] in ("user", "assistant"):
                    self._history.append({"role": r["role"], "content": r["content"]})
                elif r["role"] == "tool":
                    # Tool results as system messages for LLM context
                    self._history.append({"role": "system", "content": r["content"]})

            ctx_row = self._db.execute(
                "SELECT context_json FROM chat_sessions WHERE id=?",
                (self.chat_session_id,),
            ).fetchone()
            if ctx_row and ctx_row["context_json"]:
                self._ctx = json.loads(ctx_row["context_json"] or "{}")
        except Exception as e:
            log.warning(f"[chat] Failed to load from DB: {e}")

    def _save_message(
        self,
        role: str,
        content: str,
        event_type: str = "text",
        metadata: Optional[Dict] = None,
    ) -> None:
        """Persist a single message to chat_messages."""
        try:
            self._db.execute(
                "INSERT INTO chat_messages "
                "(chat_session_id, role, content, event_type, metadata_json, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    self.chat_session_id,
                    role,
                    content,
                    event_type,
                    json.dumps(metadata or {}),
                    datetime.utcnow().isoformat(),
                ),
            )
            self._db.execute(
                "UPDATE chat_sessions SET updated_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), self.chat_session_id),
            )
            self._db.commit()
        except Exception as e:
            log.warning(f"[chat] Failed to save message: {e}")

    def _save_ctx(self) -> None:
        """Persist current context (target, session_id, etc.) to DB."""
        try:
            self._db.execute(
                "UPDATE chat_sessions SET context_json=?, updated_at=? WHERE id=?",
                (json.dumps(self._ctx), datetime.utcnow().isoformat(), self.chat_session_id),
            )
            self._db.commit()
        except Exception as e:
            log.warning(f"[chat] Failed to save context: {e}")

    # ────────────────────────────────────────────────────────────────────────
    #  Replay (restore UI after reconnect)
    # ────────────────────────────────────────────────────────────────────────

    async def get_replay_events(self) -> List[Dict]:
        """
        Return all stored messages as frontend events.
        Called on reconnect to restore the conversation UI without re-running anything.
        """
        try:
            rows = self._db.execute(
                "SELECT role, content, event_type, metadata_json, created_at "
                "FROM chat_messages WHERE chat_session_id=? ORDER BY id ASC",
                (self.chat_session_id,),
            ).fetchall()
        except Exception:
            return []

        events: List[Dict] = []
        for r in rows:
            meta = {}
            try:
                meta = json.loads(r["metadata_json"] or "{}")
            except Exception:
                pass

            etype = r["event_type"]
            role  = r["role"]

            if etype == "finding":
                events.append({"type": "finding", **meta})
            elif etype == "scan_start":
                events.append({"type": "scan_start", **meta})
            elif etype == "tool_result":
                events.append({
                    "type":    "tool_result",
                    "tool":    meta.get("tool", "?"),
                    "content": r["content"][:500],   # truncate for replay
                })
            else:
                # Regular user/assistant text
                events.append({
                    "type":    "message",
                    "role":    role,
                    "content": r["content"],
                    "ts":      (r["created_at"] or "")[:16].replace("T", " "),
                })

        return events

    # ────────────────────────────────────────────────────────────────────────
    #  Public entry point
    # ────────────────────────────────────────────────────────────────────────

    async def process(
        self,
        user_msg: str,
        backend_url: str = "http://localhost:8000",
    ) -> AsyncGenerator[Dict, None]:
        """
        Process one user message. Yields frontend events:
          token       — streaming LLM character
          text        — complete text block
          finding     — inline vulnerability card
          scan_start  — scan kicked off
          tool_result — tool output
          done        — end of response
        """
        # Save user message to DB + history
        self._history.append({"role": "user", "content": user_msg})
        self._save_message("user", user_msg, event_type="text")

        # ── Fast-path: "scan https://..." → skip LLM, fire scan tool directly ──
        _url_match = re.search(r'https?://\S+', user_msg)
        if _url_match and len(user_msg.split()) <= 6:
            _target = _url_match.group(0).rstrip('.,)')
            async for ev in self._execute_tool("scan", {"target": _target}, backend_url):
                yield ev
            yield {"type": "done"}
            return

        # Build LLM message list
        messages = self._build_messages()

        # Stream LLM response — buffer tokens, strip <think> before sending to UI
        full_response = ""
        think_buffer  = ""          # accumulates <think>...</think> silently
        in_think      = False

        async for ev in self._stream_llm(messages):
            if ev["type"] != "token":
                yield ev
                continue

            token = ev["text"]
            full_response += token

            # Handle qwen3-coder <think> blocks — collect silently, don't stream
            if "<think>" in token:
                in_think = True
            if in_think:
                think_buffer += token
                if "</think>" in token:
                    in_think = False
                    think_buffer = ""
                continue  # don't yield thinking tokens to UI

            # Also skip bare TOOL: lines from being streamed (will be shown as tool card)
            if token.strip().startswith("TOOL:"):
                continue

            yield ev

        # Strip <think> blocks from full response before parsing
        clean_for_tools = _THINK_RE.sub("", full_response).strip()

        # Parse and strip TOOL: calls from response
        tool_calls = self._parse_tool_calls(clean_for_tools)
        clean_response = self._strip_tool_calls(clean_for_tools).strip()

        # Save clean assistant response
        if clean_response:
            self._history.append({"role": "assistant", "content": clean_response})
            self._save_message("assistant", clean_response, event_type="text")

        # Execute tool calls one by one
        for tool_name, tool_args in tool_calls:
            yield {"type": "text", "text": f"\n\n🔧 **Running:** `{tool_name}`...\n"}
            tool_result_text = ""
            async for ev in self._execute_tool(tool_name, tool_args, backend_url):
                yield ev
                if ev["type"] == "text":
                    tool_result_text += ev.get("text", "")
                elif ev["type"] == "token":
                    tool_result_text += ev.get("text", "")

            # Append tool result to history for next LLM turn
            tool_ctx = f"[TOOL RESULT: {tool_name}]\n{tool_result_text[:3000]}"
            self._history.append({"role": "system", "content": tool_ctx})
            self._save_message("tool", tool_ctx, event_type="tool_result",
                               metadata={"tool": tool_name})

            # After tool execution: LLM interprets the result
            messages_after = self._build_messages()
            analysis_text = ""
            async for ev in self._stream_llm(messages_after, max_tokens=600):
                yield ev
                if ev["type"] == "token":
                    analysis_text += ev["text"]

            analysis_calls = self._parse_tool_calls(analysis_text)
            clean_analysis = self._strip_tool_calls(analysis_text).strip()
            if clean_analysis:
                self._history.append({"role": "assistant", "content": clean_analysis})
                self._save_message("assistant", clean_analysis, event_type="text")

            # Handle follow-up tool calls (max 1 level deep to avoid infinite loops)
            for next_tool, next_args in analysis_calls[:1]:
                yield {"type": "text", "text": f"\n\n🔧 **Running:** `{next_tool}`...\n"}
                async for ev in self._execute_tool(next_tool, next_args, backend_url):
                    yield ev

    # ────────────────────────────────────────────────────────────────────────
    #  LLM streaming
    # ────────────────────────────────────────────────────────────────────────

    def _build_messages(self) -> List[Dict]:
        """Build the full message list for the LLM API call."""
        # Inject current context into system prompt
        finding_count = 0
        if self._ctx.get("session_id"):
            try:
                row = self._db.execute(
                    "SELECT COUNT(*) as n FROM findings WHERE session_id=?",
                    (self._ctx["session_id"],),
                ).fetchone()
                finding_count = row["n"] if row else 0
            except Exception:
                pass

        learned_rows = []
        try:
            learned_rows = self._db.execute(
                "SELECT pattern, vuln_type, tool, confidence "
                "FROM learned WHERE verified=1 AND confidence >= 0.5 "
                "ORDER BY confidence DESC LIMIT 5"
            ).fetchall()
        except Exception:
            pass

        learned_section = ""
        if learned_rows:
            learned_section = "\n═══════════════════════════════════════════\n LEARNED FROM PREVIOUS SCANS:\n═══════════════════════════════════════════\n"
            for r in learned_rows:
                learned_section += f"  • [{r['vuln_type']}] {r['pattern']} (tool: {r['tool']}, confidence: {r['confidence']:.0%})\n"

        if self._ctx.get("current_target"):
            ctx_section = _CONTEXT_SECTION_TMPL.format(
                target=self._ctx.get("current_target", "None"),
                session_id=(self._ctx.get("session_id") or "None")[:8] + "…",
                finding_count=finding_count,
                model=self.model,
            ) + learned_section
        else:
            ctx_section = "No active scan target. Ask the user for a target to scan." + learned_section

        system = _SYSTEM_TEMPLATE.format(context_section=ctx_section)

        msgs: List[Dict] = [{"role": "system", "content": system}]

        # Add rolling history (last 20 turns to avoid context overflow)
        for h in self._history[-20:]:
            msgs.append(h)

        return msgs

    async def _stream_llm(
        self,
        messages: List[Dict],
        max_tokens: int = 1200,
    ) -> AsyncGenerator[Dict, None]:
        """Stream tokens from Ollama."""
        payload = {
            "model":    self.model,
            "messages": messages,
            "stream":   True,
            "options":  {
                "temperature": 0.2,
                "num_predict": max_tokens,
                # NOTE: do NOT add stop tokens for TOOL: — that would prevent tool calls
            },
        }

        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=180) as client:
                    async with client.stream(
                        "POST", f"{OLLAMA_URL}/api/chat", json=payload
                    ) as resp:
                        if resp.status_code != 200:
                            yield {"type": "text", "text": f"[Ollama error {resp.status_code}]"}
                            return
                        async for line in resp.aiter_lines():
                            if not line.strip():
                                continue
                            try:
                                d = json.loads(line)
                                token = d.get("message", {}).get("content", "")
                                if token:
                                    yield {"type": "token", "text": token}
                            except Exception:
                                pass
                return  # success
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(2 * (attempt + 1))
                else:
                    yield {"type": "text", "text": f"\n[LLM connection error after 3 retries: {e}]\n"}

    # ────────────────────────────────────────────────────────────────────────
    #  Tool call parsing
    # ────────────────────────────────────────────────────────────────────────

    def _parse_tool_calls(self, text: str) -> List[Tuple[str, Dict]]:
        """Extract all TOOL: <name> <json> lines from LLM response."""
        calls = []
        for match in _TOOL_RE.finditer(text):
            name    = match.group(1).strip()
            raw_arg = (match.group(2) or "{}").strip()
            try:
                args = json.loads(raw_arg)
            except Exception:
                args = {}
            if name in _TOOL_HANDLERS:
                calls.append((name, args))
        return calls

    def _strip_tool_calls(self, text: str) -> str:
        """Remove TOOL: lines from text for clean display."""
        return _TOOL_RE.sub("", text).strip()

    # ────────────────────────────────────────────────────────────────────────
    #  Tool execution dispatch
    # ────────────────────────────────────────────────────────────────────────

    async def _execute_tool(
        self,
        tool_name: str,
        args: Dict,
        backend_url: str,
    ) -> AsyncGenerator[Dict, None]:
        """Route tool_name to the correct handler."""
        handler = _TOOL_HANDLERS.get(tool_name)
        if not handler:
            yield {"type": "text",
                   "text": f"⚠ Unknown tool: `{tool_name}`. Available: {', '.join(_TOOL_HANDLERS)}"}
            return
        async for ev in handler(self, args, backend_url):
            yield ev

    # ────────────────────────────────────────────────────────────────────────
    #  Tool handlers
    # ────────────────────────────────────────────────────────────────────────

    async def _tool_scan(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        target = args.get("target") or self._ctx.get("current_target")
        if not target:
            yield {"type": "text",
                   "text": "⚠ No target specified. Example: `TOOL: scan {\"target\": \"https://example.com\"}`"}
            return

        # Normalise
        if not target.startswith("http"):
            target = "https://" + target
        self._ctx["current_target"] = target
        self._save_ctx()

        yield {"type": "text", "text": f"**Starting full scan on** `{target}`\n\n"}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Create session
                r = await client.post(
                    f"{backend_url}/sessions",
                    json={"target": target, "agents": ["recon", "web", "network", "exploit"]},
                )
                r.raise_for_status()
                session_id = r.json().get("id", "")
                self._ctx["session_id"] = session_id
                self._save_ctx()

            yield {"type": "scan_start", "session_id": session_id, "target": target}
            self._save_message(
                "tool",
                f"Scan started: session_id={session_id}",
                event_type="scan_start",
                metadata={"session_id": session_id, "target": target},
            )
            yield {"type": "text",
                "text": (
                    f"Session ID: `{session_id}`\n\n"
                    "Launching autonomous agents (recon → web → network → exploit).\n"
                    "This runs in the background — switch to the **Agents** tab to watch live output.\n\n"
                    "I'll summarize findings when the scan completes. "
                    "You can also ask me `show findings` at any time."
                )}

            # Fire autopilot in background (short timeout — just kick it off)
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    await client.post(
                        f"{backend_url}/autopilot/run",
                        json={"target": target, "headless": True},
                    )
            except Exception:
                pass  # Long-running — timeout expected

        except Exception as e:
            yield {"type": "text", "text": f"**Scan error:** `{e}`"}

    async def _tool_run_tool(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        tool = args.get("tool", "")
        tool_args = args.get("args", "")
        if not tool:
            yield {"type": "text", "text": "⚠ Specify `tool` and `args` in TOOL: run_tool call."}
            return

        args_list = tool_args.split() if isinstance(tool_args, str) else tool_args

        yield {"type": "text", "text": f"Running: `{tool} {' '.join(str(a) for a in args_list)}`\n"}
        try:
            async with httpx.AsyncClient(timeout=180) as client:
                r = await client.post(
                    f"{backend_url}/tool/run",
                    json={"tool": tool, "args": args_list, "timeout": 120},
                )
                data = r.json()
                output = data.get("output", data.get("error", "No output"))
                yield {"type": "text",
                    "text": f"```\n{output[:3000]}\n```"}
        except Exception as e:
            yield {"type": "text", "text": f"**Tool error:** `{e}`"}

    async def _tool_query_findings(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        session_id = args.get("session_id") or self._ctx.get("session_id")
        if session_id:
            rows = self._db.execute(
                "SELECT severity, description, agent, tool, cvss "
                "FROM findings WHERE session_id=? ORDER BY cvss DESC LIMIT 30",
                (session_id,),
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT severity, description, agent, tool, cvss "
                "FROM findings ORDER BY cvss DESC LIMIT 30"
            ).fetchall()

        if not rows:
            yield {"type": "text",
                "text": "No findings yet. Start a scan first: `scan https://target.com`"}
            return

        counts: Dict[str, int] = {}
        for r in rows:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1

        summary_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                summary_parts.append(f"**{sev}**: {counts[sev]}")

        yield {"type": "text",
            "text": f"**{len(rows)} findings** — {' · '.join(summary_parts)}\n\n"}

        for r in rows[:15]:
            f_ev = {
                "type":        "finding",
                "severity":    r["severity"],
                "description": r["description"],
                "tool":        r["tool"] or r["agent"] or "?",
                "cvss":        r["cvss"],
            }
            yield f_ev
            self._save_message(
                "tool",
                f"[{r['severity']}] {r['description']}",
                event_type="finding",
                metadata=f_ev,
            )

        if len(rows) > 15:
            yield {"type": "text",
                "text": f"\n*…and {len(rows) - 15} more in the **Findings** tab.*"}

        # Return text summary for LLM context
        yield {"type": "text",
            "text": f"\n\n**Summary:** {len(rows)} total findings, "
                    f"risk score ~{min(10, counts.get('CRITICAL',0)*2.5 + counts.get('HIGH',0)*1.2):.1f}/10"}

    async def _tool_build_graph(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        session_id = self._ctx.get("session_id")
        target     = self._ctx.get("current_target", "")
        yield {"type": "text", "text": "Building exploitation kill-chain graph...\n"}
        try:
            findings = []
            if session_id:
                rows = self._db.execute(
                    "SELECT severity, description, agent, tool FROM findings WHERE session_id=?",
                    (session_id,),
                ).fetchall()
                findings = [dict(r) for r in rows]

            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{backend_url}/graph/build",
                    json={"findings": findings, "target": target},
                )
                data = r.json()

            nodes = data.get("nodes", [])
            paths = data.get("attack_paths", [])
            risk  = data.get("risk_score", 0)
            yield {"type": "text",
                "text": (
                    f"Graph built: **{len(nodes)} nodes**, **{len(paths)} attack paths**, "
                    f"risk `{risk}/10`.\n\n"
                    f"{data.get('summary', '')}\n\n"
                    "Open the **Graph** tab → **Build Exploit Graph** to visualize."
                )}
        except Exception as e:
            yield {"type": "text", "text": f"**Graph error:** `{e}`"}

    async def _tool_generate_report(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        session_id = self._ctx.get("session_id")
        target     = self._ctx.get("current_target", "?")
        if not session_id:
            yield {"type": "text",
                "text": "No active session. Run a scan first."}
            return

        rows = self._db.execute(
            "SELECT severity, description, agent, tool, cvss FROM findings WHERE session_id=?",
            (session_id,),
        ).fetchall()

        fCrit = sum(1 for r in rows if r["severity"] == "CRITICAL")
        fHigh = sum(1 for r in rows if r["severity"] == "HIGH")
        fMed  = sum(1 for r in rows if r["severity"] == "MEDIUM")
        risk  = min(10, fCrit * 2.5 + fHigh * 1.2 + fMed * 0.4)

        yield {"type": "text",
            "text": (
                f"**Pentest Report — {target}**\n\n"
                f"- Risk Score: **{risk:.1f}/10**\n"
                f"- Critical: **{fCrit}**  ·  High: **{fHigh}**  ·  Medium: **{fMed}**\n"
                f"- Total findings: **{len(rows)}**\n"
                f"- Session: `{session_id}`\n\n"
                "**Top findings:**\n"
            )}

        for r in list(rows)[:5]:
            yield {
                "type":        "finding",
                "severity":    r["severity"],
                "description": r["description"],
                "tool":        r["tool"] or "?",
                "cvss":        r["cvss"],
            }

        yield {"type": "text",
            "text": (
                f"\n\nFor full HTML report run:\n"
                f"`python3 backend/cli.py scan {target} --report html`\n"
                "Or open the **Findings** tab → export buttons."
            )}

    async def _tool_train_model(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        yield {"type": "text", "text": "Triggering LLM training on verified findings...\n"}
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                r = await client.post(
                    f"{backend_url}/ollama/train",
                    json={
                        "model_name": "phantom-security:latest",
                        "base_model": self.model,
                        "max_findings": 500,
                    },
                )
                data = r.json()
            examples = data.get("examples", data.get("training_examples", 0))
            status   = data.get("status", "?")
            yield {"type": "text",
                "text": f"Training **{status}** — `{examples}` examples generated.\n\n"
                        "The model will improve on future scans of similar targets. "
                        "Check the **Intel** tab for training history."}
        except Exception as e:
            yield {"type": "text", "text": f"**Training error:** `{e}`"}

    async def _tool_analyze_proxy(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        yield {"type": "text", "text": "Analyzing captured proxy traffic...\n"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(f"{backend_url}/proxy/analyze", json={})
                data = r.json()

            findings = data.get("findings", [])
            if not findings:
                yield {"type": "text",
                    "text": "No vulnerability patterns found in proxy traffic.\n"
                            "Capture traffic via the **Proxy** tab first."}
                return

            yield {"type": "text",
                "text": f"Found **{len(findings)}** patterns in proxy traffic:\n"}
            for f in findings[:8]:
                yield {
                    "type":        "finding",
                    "severity":    f.get("severity", "INFO"),
                    "description": f.get("description", ""),
                    "tool":        "proxy",
                    "cvss":        f.get("cvss", 0),
                }
        except Exception as e:
            yield {"type": "text", "text": f"**Proxy analyze error:** `{e}`"}

    async def _tool_target_info(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        target     = self._ctx.get("current_target", "None set")
        session_id = self._ctx.get("session_id")

        finding_count = 0
        status        = "No scan"
        if session_id:
            try:
                row = self._db.execute(
                    "SELECT status FROM sessions WHERE id=?", (session_id,)
                ).fetchone()
                status = row["status"] if row else "?"
                fc_row = self._db.execute(
                    "SELECT COUNT(*) as n FROM findings WHERE session_id=?", (session_id,)
                ).fetchone()
                finding_count = fc_row["n"] if fc_row else 0
            except Exception:
                pass

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{backend_url}/ollama/active-model")
                model = r.json().get("model", self.model)
        except Exception:
            model = self.model

        yield {"type": "text",
            "text": (
                f"**Current context:**\n\n"
                f"- Target: `{target}`\n"
                f"- Session: `{session_id or 'None'}`\n"
                f"- Scan status: `{status}`\n"
                f"- Findings so far: `{finding_count}`\n"
                f"- Active model: `{model}`\n"
            )}


    async def _tool_scan_apk(
        self, args: Dict, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        """Decompile + scan an Android APK for secrets, insecure configs, endpoints."""
        apk_path = (args.get("apk_path") or "").strip()
        if not apk_path:
            yield {"type": "text", "text": "⚠ Please specify the APK path. Example:\n`TOOL: scan_apk {\"apk_path\": \"/path/to/app.apk\"}`"}
            return

        yield {"type": "text", "text": f"📱 Scanning APK: `{apk_path}`\nDecompiling with apktool + jadx…"}

        try:
            async with httpx.AsyncClient(timeout=200) as client:
                r = await client.post(
                    f"{backend_url}/scan/apk",
                    params={
                        "apk_path": apk_path,
                        "session_id": self._ctx.get("session_id", ""),
                    },
                )
                result = r.json()
        except Exception as e:
            yield {"type": "text", "text": f"⚠ APK scan request failed: {e}"}
            return

        if not result.get("ok"):
            yield {"type": "text", "text": f"⚠ APK scan error: {result.get('error', 'Unknown error')}"}
            return

        findings = result.get("findings", [])
        tools_used = result.get("tools_used", [])

        yield {"type": "text", "text": f"✅ APK scan complete — used: {', '.join(tools_used) or 'none'}"}

        if not findings:
            yield {"type": "text", "text": "No secrets or security issues found in this APK."}
            return

        yield {"type": "text", "text": f"Found **{len(findings)} issue(s)**:"}
        for f in findings:
            yield {
                "type": "finding",
                "severity": f.get("severity", "MEDIUM"),
                "description": f.get("description", ""),
                "tool": f.get("tool", "apk_scanner"),
                "cvss": f.get("cvss", ""),
            }

        # Save scan result to history
        self._save_message(
            role="tool",
            content=f"APK scan of {apk_path}: {len(findings)} finding(s)",
            event_type="tool_result",
            metadata={"tool": "scan_apk", "apk_path": apk_path, "finding_count": len(findings)},
        )


# ── Tool dispatch table ──────────────────────────────────────────────────────
# Must be defined after all methods are defined on the class.
_TOOL_HANDLERS: Dict[str, Any] = {
    "scan":            PersistentChatAgent._tool_scan,
    "run_tool":        PersistentChatAgent._tool_run_tool,
    "query_findings":  PersistentChatAgent._tool_query_findings,
    "build_graph":     PersistentChatAgent._tool_build_graph,
    "generate_report": PersistentChatAgent._tool_generate_report,
    "train_model":     PersistentChatAgent._tool_train_model,
    "analyze_proxy":   PersistentChatAgent._tool_analyze_proxy,
    "target_info":     PersistentChatAgent._tool_target_info,
    "scan_apk":        PersistentChatAgent._tool_scan_apk,
}
