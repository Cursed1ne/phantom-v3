"""
╔══════════════════════════════════════════════════════════════════════╗
║  PHANTOM AI — Conversational Chat Agent                             ║
║                                                                      ║
║  Natural-language interface: type prompts, AI orchestrates          ║
║  the entire platform (scan, analyze, report, train, graph).         ║
║                                                                      ║
║  Event types streamed over WebSocket:                               ║
║    token       — streaming LLM char (typing effect)                 ║
║    text        — full markdown-lite block                           ║
║    finding     — inline severity card                               ║
║    scan_start  — scan session kicked off                            ║
║    graph       — exploitation graph summary                         ║
║    done        — end of response (re-enable input)                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import logging
import re
import sqlite3
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx

log = logging.getLogger("phantom.chat")

OLLAMA_URL = "http://localhost:11434"

# ── Intent patterns ─────────────────────────────────────────────────────────
# Evaluated in order; first match wins.
_INTENTS: List[tuple] = [
    ("scan",    re.compile(
        r"\b(scan|pentest|pen\s*test|attack|audit|check|probe|test)\b.{0,60}(https?://\S+|\w[\w\-]*\.\w+)",
        re.I)),
    ("report",  re.compile(r"\b(report|summary|generate.*report|export|pdf|html)\b", re.I)),
    ("train",   re.compile(r"\b(train|fine.?tune|retrain|improve.*model|update.*model)\b", re.I)),
    ("graph",   re.compile(r"\b(graph|exploit.*(chain|path)|kill.?chain|attack.*(path|vector))\b", re.I)),
    ("vuln",    re.compile(r"\b(vuln|finding|issue|weakness|bug|cve|risk|what.*found|show.*find|list.*find|discover)\b", re.I)),
    ("proxy",   re.compile(r"\b(proxy|traffic|intercept|analyze.*traffic|analyze.*proxy)\b", re.I)),
    ("status",  re.compile(r"\b(status|model|health|active\s*model|running|version|what.*model|which.*model)\b", re.I)),
    ("help",    re.compile(r"\b(help|what can you|what do you|commands|options|how to|usage)\b", re.I)),
]

# ── System prompt for general chat ──────────────────────────────────────────
_SYSTEM = """You are Phantom AI — an elite automated penetration testing assistant.
You speak with the precision of an expert red-teamer and the clarity of a security consultant.
You have access to a full pentest platform: autonomous agents (recon, web, network, exploit),
HTTPS MITM proxy, kill-chain graph builder, HTML report generator, and Ollama LLM training.

When asked to perform actions, confirm what you will do then describe the result.
Keep answers concise, technical, and actionable. No fluff.
Format: use **bold** for emphasis, `code` for commands/paths, - bullet lists for steps."""


class PhantomChatAgent:
    """
    Conversational AI for Phantom v3.
    One instance per WebSocket connection — preserves context across turns.
    """

    def __init__(self, model: str, db: sqlite3.Connection) -> None:
        self.model   = model or "llama3.1"
        self._db     = db
        self.history: List[Dict] = []     # rolling chat history (last 6 turns)
        self.ctx: Dict[str, Any] = {}     # current_target, session_id, last_findings

    # ────────────────────────────────────────────────────────────────────────
    #  Public entry point
    # ────────────────────────────────────────────────────────────────────────

    async def process(
        self,
        user_msg: str,
        backend_url: str = "http://localhost:8000",
    ) -> AsyncGenerator[Dict, None]:
        """Detect intent → dispatch → yield streamed events."""
        self.history.append({"role": "user", "content": user_msg})

        intent = self._intent(user_msg)
        log.info(f"[chat] intent={intent!r}  msg={user_msg[:60]!r}")

        if intent == "scan":
            url = self._extract_url(user_msg)
            if url:
                async for ev in self._do_scan(url, backend_url):
                    yield ev
            else:
                yield {"type": "text", "text":
                    "Please include a target URL. Example: `scan https://example.com`"}

        elif intent == "report":
            async for ev in self._do_report(backend_url):
                yield ev

        elif intent == "train":
            async for ev in self._do_train(backend_url):
                yield ev

        elif intent == "graph":
            async for ev in self._do_graph(backend_url):
                yield ev

        elif intent == "vuln":
            async for ev in self._do_query_findings():
                yield ev

        elif intent == "proxy":
            async for ev in self._do_proxy_analyze(backend_url):
                yield ev

        elif intent == "status":
            async for ev in self._do_status(backend_url):
                yield ev

        elif intent == "help":
            async for ev in self._do_help():
                yield ev

        else:
            # General LLM chat with security persona
            async for ev in self._do_llm_chat(user_msg):
                yield ev

    # ────────────────────────────────────────────────────────────────────────
    #  Intent detection
    # ────────────────────────────────────────────────────────────────────────

    def _intent(self, msg: str) -> str:
        for name, pattern in _INTENTS:
            if pattern.search(msg):
                return name
        return "chat"

    def _extract_url(self, msg: str) -> Optional[str]:
        """Pull out http(s) URL or bare host from message."""
        m = re.search(r"https?://[^\s,;\"']+", msg)
        if m:
            return m.group(0).rstrip(".,;)")
        # bare domain / host
        m = re.search(
            r"\b(?:scan|test|pentest|audit|probe|check)\s+([\w][\w\-]*\.[\w\-\.]+(?::\d+)?(?:/\S*)?)",
            msg, re.I,
        )
        if m:
            url = m.group(1)
            if not url.startswith("http"):
                url = "https://" + url
            return url
        return None

    # ────────────────────────────────────────────────────────────────────────
    #  Handlers
    # ────────────────────────────────────────────────────────────────────────

    async def _do_scan(
        self, url: str, backend_url: str
    ) -> AsyncGenerator[Dict, None]:
        """Create session → trigger autopilot → stream updates."""
        self.ctx["current_target"] = url
        yield {"type": "text", "text": f"**Initiating scan on** `{url}`...\n"}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # 1. Create session
                r = await client.post(
                    f"{backend_url}/sessions",
                    json={"target": url, "agents": ["recon", "web", "network", "exploit"]},
                )
                r.raise_for_status()
                session_id = r.json().get("id", "")
                self.ctx["session_id"] = session_id
                yield {"type": "scan_start", "session_id": session_id, "target": url}
                yield {"type": "text",
                    "text": f"Session ID: `{session_id}`\n\nThe **Agents** tab will show live reasoning. "
                            "When done, say `show vulnerabilities` to see findings here.\n\n"
                            "Launching autonomous agents now..."}

                # 2. Fire autopilot in background (don't wait for completion)
                try:
                    await client.post(
                        f"{backend_url}/autopilot/run",
                        json={"target": url, "headless": True},
                        timeout=5,   # short — we just want to kick it off
                    )
                except Exception:
                    pass  # autopilot timeout is expected since it's long-running

        except Exception as e:
            yield {"type": "text", "text": f"**Error starting scan:** `{e}`"}

    async def _do_query_findings(self) -> AsyncGenerator[Dict, None]:
        """Show findings from the current session."""
        session_id = self.ctx.get("session_id")

        if session_id:
            rows = self._db.execute(
                "SELECT severity, description, agent, tool, cvss "
                "FROM findings WHERE session_id=? "
                "ORDER BY cvss DESC LIMIT 20",
                (session_id,),
            ).fetchall()
        else:
            # No active session — show latest across all sessions
            rows = self._db.execute(
                "SELECT severity, description, agent, tool, cvss "
                "FROM findings ORDER BY cvss DESC LIMIT 20"
            ).fetchall()

        if not rows:
            target = self.ctx.get("current_target", "")
            yield {"type": "text",
                "text": f"No findings yet.{' Run `scan ' + target + '` first.' if not target else ' Start a scan first.'}"}
            return

        counts: Dict[str, int] = {}
        for r in rows:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1

        summary = "  ·  ".join(
            f"**{sev}**: {n}"
            for sev, n in sorted(counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0]) if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99)
        )
        yield {"type": "text", "text": f"**{len(rows)} findings**   {summary}\n"}

        for r in rows[:10]:
            yield {
                "type":        "finding",
                "severity":    r["severity"],
                "description": r["description"],
                "tool":        r["tool"] or r["agent"] or "?",
                "cvss":        r["cvss"],
            }

        if len(rows) > 10:
            yield {"type": "text", "text": f"\n*...and {len(rows) - 10} more. Open the **Findings** tab to see all.*"}

    async def _do_report(self, backend_url: str) -> AsyncGenerator[Dict, None]:
        """Generate a quick inline summary + direct user to Report tab."""
        session_id = self.ctx.get("session_id")
        target     = self.ctx.get("current_target", "")

        rows = []
        if session_id:
            rows = self._db.execute(
                "SELECT severity, description, agent, cvss FROM findings WHERE session_id=? ORDER BY cvss DESC",
                (session_id,),
            ).fetchall()

        if not rows:
            yield {"type": "text",
                "text": "No findings to report yet. Run a scan first.\n\n"
                        "Tip: `scan https://target.com`"}
            return

        fCrit = sum(1 for r in rows if r["severity"] == "CRITICAL")
        fHigh = sum(1 for r in rows if r["severity"] == "HIGH")
        risk  = min(10, fCrit * 2.5 + fHigh * 1.2)

        yield {"type": "text",
            "text": f"**Scan Report — {target or 'Unknown target'}**\n\n"
                    f"- **Risk Score:** `{risk:.1f}/10`\n"
                    f"- **Findings:** `{len(rows)}` total "
                    f"({fCrit} critical, {fHigh} high)\n"
                    f"- **Session:** `{session_id}`\n\n"
                    "For a full HTML report, run:\n"
                    f"`python3 backend/cli.py scan {target} --report html`\n\n"
                    "Or open the **Report** tab in the UI to export PDF/JSON/SARIF."}

    async def _do_train(self, backend_url: str) -> AsyncGenerator[Dict, None]:
        """Trigger LLM training on verified findings."""
        yield {"type": "text", "text": "**Triggering LLM training** on verified findings...\n"}
        try:
            async with httpx.AsyncClient(timeout=60) as client:
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
                    "text": f"✅ Training **{status}** — `{examples}` examples generated.\n\n"
                            "The model adapts from confirmed tool findings. "
                            "Check the **Intel** tab for training history."}
        except Exception as e:
            yield {"type": "text", "text": f"**Training error:** `{e}`"}

    async def _do_graph(self, backend_url: str) -> AsyncGenerator[Dict, None]:
        """Build exploitation kill-chain graph."""
        session_id = self.ctx.get("session_id")
        target     = self.ctx.get("current_target", "")
        yield {"type": "text", "text": "**Building exploitation kill-chain graph...**\n"}

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

            summary = data.get("summary", "")
            risk    = data.get("risk_score", 0)
            paths   = data.get("attack_paths", [])
            nodes   = data.get("nodes", [])

            yield {"type": "graph", "data": data}
            yield {"type": "text",
                "text": f"Graph built with **{len(nodes)} nodes** — {summary}\n\n"
                        f"- **Risk score:** `{risk}/10`\n"
                        f"- **Attack paths:** `{len(paths)}`\n\n"
                        "Open the **Graph** tab and click **Build Exploit Graph** to visualize."}
        except Exception as e:
            yield {"type": "text", "text": f"**Graph error:** `{e}`"}

    async def _do_proxy_analyze(self, backend_url: str) -> AsyncGenerator[Dict, None]:
        """Analyze proxy traffic for vulnerabilities."""
        yield {"type": "text", "text": "**Analyzing proxy traffic...**\n"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(f"{backend_url}/proxy/analyze", json={})
                data = r.json()

            findings = data.get("findings", [])
            if not findings:
                yield {"type": "text",
                    "text": "No vulnerability patterns found in proxy traffic.\n"
                            "Make sure you have captured traffic via the **Proxy** tab."}
                return

            yield {"type": "text", "text": f"Found **{len(findings)} patterns** in proxy traffic:\n"}
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

    async def _do_status(self, backend_url: str) -> AsyncGenerator[Dict, None]:
        """Show platform status: model, sessions, findings."""
        yield {"type": "text", "text": f"**Active Model:** `{self.model}`\n\n"}

        # Ollama models
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get("http://localhost:11434/api/tags")
                models = [m["name"] for m in r.json().get("models", [])]
            yield {"type": "text",
                "text": f"**Available models:** `{'`, `'.join(models[:6])}`\n"}
        except Exception:
            yield {"type": "text", "text": "⚠ Ollama not reachable at `localhost:11434`\n"}

        # DB stats
        try:
            sessions  = self._db.execute("SELECT COUNT(*) as n FROM sessions").fetchone()["n"]
            findings  = self._db.execute("SELECT COUNT(*) as n FROM findings").fetchone()["n"]
            critical  = self._db.execute("SELECT COUNT(*) as n FROM findings WHERE severity='CRITICAL'").fetchone()["n"]
            yield {"type": "text",
                "text": f"\n**Platform stats:**\n"
                        f"- Scan sessions: `{sessions}`\n"
                        f"- Total findings: `{findings}` ({critical} critical)\n"
                        f"- Backend: `{backend_url}`"}
        except Exception:
            pass

    async def _do_help(self) -> AsyncGenerator[Dict, None]:
        """Show available commands."""
        yield {"type": "text", "text":
            "**Phantom AI — Commands**\n\n"
            "- `scan https://target.com` — full autonomous pentest scan\n"
            "- `show vulnerabilities` — list findings from active scan\n"
            "- `build exploit graph` — kill-chain exploitation path\n"
            "- `generate report` — summary + HTML report instructions\n"
            "- `analyze proxy traffic` — scan captured HTTP traffic\n"
            "- `train the model` — retrain LLM on verified findings\n"
            "- `model status` — active model + platform health\n"
            "- *Any security question* — expert LLM answer\n\n"
            "The **Agents** tab shows live AI reasoning. "
            "The **Graph** tab visualizes kill-chains."}

    async def _do_llm_chat(self, user_msg: str) -> AsyncGenerator[Dict, None]:
        """Stream general security LLM response."""
        messages = [{"role": "system", "content": _SYSTEM}]
        # Inject current scan context if available
        if self.ctx.get("current_target"):
            messages.append({
                "role": "system",
                "content": f"Current scan target: {self.ctx['current_target']}. "
                           f"Session: {self.ctx.get('session_id', 'none')}.",
            })
        # Last 6 history turns (3 pairs)
        for h in self.history[-6:]:
            messages.append(h)

        payload = {
            "model":   self.model,
            "messages": messages,
            "stream":  True,
            "options": {"temperature": 0.3, "num_predict": 800},
        }

        full = ""
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                async with client.stream(
                    "POST", f"{OLLAMA_URL}/api/chat", json=payload
                ) as resp:
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            d = json.loads(line)
                            token = d.get("message", {}).get("content", "")
                            if token:
                                full += token
                                yield {"type": "token", "text": token}
                        except Exception:
                            pass
        except Exception as e:
            yield {"type": "text", "text": f"[LLM error: {e}]"}

        if full:
            self.history.append({"role": "assistant", "content": full})
            # Keep history bounded
            if len(self.history) > 20:
                self.history = self.history[-20:]
