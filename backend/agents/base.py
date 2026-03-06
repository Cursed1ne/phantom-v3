"""
PHANTOM AI v3 — BaseAgent
──────────────────────────
Every specialist agent inherits from this class. The design follows the
"ReAct" (Reasoning + Acting) pattern: the agent reasons about its next
step in natural language, decides on an action (tool to run), observes
the result, and loops until it's either done or hit the iteration limit.

Key responsibilities this base class handles:
  • Ollama streaming — token-by-token LLM output
  • Tool execution  — subprocess with hard timeout + error capture
  • Finding extraction — regex mining of severity-tagged lines
  • History management — bounded conversation window to avoid overflow
  • Learning persistence — successful patterns written to the DB
"""

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional
from uuid import uuid4

import httpx

log = logging.getLogger(__name__)

# ── Severity constants ────────────────────────────────────────────────
SEVERITIES   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DEFAULT_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5, "INFO": 1.0}

# ── Model auto-detection ──────────────────────────────────────────────
# Preference order: security/coder models first, then general models
_MODEL_PREFERENCE = [
    "qwen3-coder", "qwen2.5-coder", "qwen2.5-coder:7b", "qwen2.5-coder:latest",
    "codellama", "codellama:latest", "codellama:7b",
    "llama3.1", "llama3.1:latest", "llama3", "llama3:latest",
    "mistral", "mistral:latest",
]
_DETECTED_MODEL: Optional[str] = None


def detect_best_model() -> str:
    """
    Query Ollama for installed models and pick the best one based on
    _MODEL_PREFERENCE. Result is cached in _DETECTED_MODEL.
    Falls back to 'llama3.1' if Ollama is unavailable.
    """
    global _DETECTED_MODEL
    if _DETECTED_MODEL:
        return _DETECTED_MODEL
    try:
        resp = httpx.get("http://localhost:11434/api/tags", timeout=3)
        if resp.status_code == 200:
            names = [m["name"] for m in resp.json().get("models", [])]
            for pref in _MODEL_PREFERENCE:
                base = pref.split(":")[0]
                for name in names:
                    if name == pref or name.startswith(base + ":") or name == base:
                        _DETECTED_MODEL = name
                        log.info(f"[model-detect] Selected model: {_DETECTED_MODEL}")
                        return _DETECTED_MODEL
    except Exception as e:
        log.debug(f"[model-detect] Ollama query failed: {e}")
    _DETECTED_MODEL = "llama3.1"
    log.info(f"[model-detect] Fallback model: {_DETECTED_MODEL}")
    return _DETECTED_MODEL

# ── Wordlist paths (Kali / Homebrew installs) ────────────────────────
WL_SMALL   = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
WL_MEDIUM  = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
WL_BIG     = "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"
WL_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
WL_COMMON  = "/usr/share/seclists/Discovery/Web-Content/common.txt"
WL_API     = "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"


class BaseAgent(ABC):
    """
    Abstract base for all PHANTOM agents.

    Subclasses must implement:
      • agent_id  : str property  — e.g. "recon"
      • tools     : list property — tool names this agent can call
      • persona   : str property  — system-prompt personality text
      • build_args: method        — maps (tool, target, depth) → argv list

    Optional overrides:
      • pre_run()  — setup before the loop starts
      • post_run() — teardown / final summary after the loop
    """

    OLLAMA_URL = "http://localhost:11434"

    def __init__(
        self,
        target:       str,
        target_type:  str                       = "web",
        model:        str                       = "",   # empty = auto-detect from Ollama
        depth:        str                       = "standard",
        max_iter:     int                       = 10,
        session_id:   str                       = "",
        learned_ctx:  str                       = "",
        broadcast_fn: Optional[Callable]        = None,
        other_findings: Optional[List[Dict]]    = None,
    ):
        self.target          = target
        self.target_type     = target_type
        self.model           = model or detect_best_model()   # auto-detect if empty
        self.depth           = depth
        self.max_iter        = max_iter
        self.session_id      = session_id or str(uuid4())
        self.learned_ctx     = learned_ctx
        self.broadcast       = broadcast_fn or (lambda _: None)
        self.other_findings  = other_findings or []

        # Conversation history for this agent's LLM session
        self._history: List[Dict] = []
        # All findings this agent has produced
        self.findings: List[Dict] = []
        # Accumulated tool outputs for summarisation
        self.observations: List[str] = []

    # ── Abstract interface ────────────────────────────────────────────

    @property
    @abstractmethod
    def agent_id(self) -> str:
        """Unique lower-case identifier, e.g. 'recon'."""
        ...

    @property
    @abstractmethod
    def tools(self) -> List[str]:
        """CLI tool names this agent is allowed to call."""
        ...

    @property
    @abstractmethod
    def persona(self) -> str:
        """The system-prompt text that gives this agent its specialist role."""
        ...

    @abstractmethod
    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        """Return the argv list to pass when running `tool` against `target`."""
        ...

    # ── Optional lifecycle hooks ──────────────────────────────────────

    async def pre_run(self):  pass
    async def post_run(self): pass

    # ── System prompt assembly ────────────────────────────────────────

    def _build_system(self, phase: str = "act") -> str:
        """
        Build the system prompt.
        phase='plan' — iteration 1: produce a 3-step plan + first ACTION only.
        phase='act'  — iterations 2+: strict THOUGHT/ACTION/ARGS/DONE format.
        """
        # Inject only top 5 highest-confidence learned patterns (not all of them)
        learned_lines = []
        if self.learned_ctx:
            for line in self.learned_ctx.strip().splitlines()[:5]:
                learned_lines.append(f"  {line.strip()}")
        learned_block = "\n".join(learned_lines) if learned_lines else "  (none)"

        header = (
            f"{self.persona}\n\n"
            f"TARGET: {self.target}  |  TYPE: {self.target_type}  |  DEPTH: {self.depth}\n"
            f"TOOLS: {', '.join(self.tools)}\n\n"
            f"VERIFIED PATTERNS (tool-confirmed, top 5):\n{learned_block}\n\n"
        )

        if phase == "plan":
            return (
                header +
                "PLAN PHASE — write exactly these 4 lines and nothing else:\n"
                "PLAN_1: <first tool to run and why in ≤15 words>\n"
                "PLAN_2: <second tool and why>\n"
                "PLAN_3: <third tool and why>\n"
                "ACTION: <name of FIRST tool from your TOOLS list>\n\n"
                "RULES: No [SEVERITY] lines. No invented findings. "
                "Tool names must be exact CLI names from the TOOLS list above."
            )
        else:
            return (
                header +
                "ACT PHASE — respond in this EXACT format only (max 4 sentences total):\n"
                "THOUGHT: <one sentence — what you know from last tool output>\n"
                "ACTION: <tool_name>  ← must be ONE exact name from TOOLS list\n"
                "ARGS: <exact CLI arguments to pass to the tool>\n"
                "DONE: false\n\n"
                "OR if all planned tools have run and nothing critical remains:\n"
                "DONE: true\n"
                "SUMMARY: <one paragraph citing tool names and real evidence>\n\n"
                "STRICT RULES (violation = wrong result):\n"
                "1. NEVER write [SEVERITY] tags — only tool stdout may contain those.\n"
                "2. NEVER invent findings. If tool found nothing → DONE: true.\n"
                "3. ACTION must be exactly ONE tool name from your TOOLS list.\n"
                "4. ARGS must be real CLI args, not pseudocode or placeholders.\n"
                "5. Maximum 4 sentences in your entire response."
            )

    # ── Main run loop ─────────────────────────────────────────────────

    async def run(self) -> List[Dict]:
        """
        Execute the ReAct loop and return all findings produced.
        Broadcasts rich status events so the UI stays in sync.

        Phase 1 (iteration 1): plan phase — LLM outputs PLAN_1/2/3 + first ACTION.
        Phase 2 (iterations 2+): act phase — strict THOUGHT/ACTION/ARGS/DONE format.
        Forced tool call injected if LLM fails to produce ACTION: for 2 iterations.
        """
        await self.pre_run()

        self._history = [
            {"role": "user",
             "content": f"Begin {self.agent_id} assessment of {self.target}. "
                        f"Max {self.max_iter} iterations. Use your TOOLS list."}
        ]

        await self._emit("agent_start", {
            "agent": self.agent_id, "target": self.target,
            "max_iter": self.max_iter, "model": self.model,
        })

        _no_action_streak = 0  # track consecutive iterations with no ACTION:

        for iteration in range(1, self.max_iter + 1):
            phase = "plan" if iteration == 1 else "act"
            system = self._build_system(phase=phase)
            max_tokens = 1200 if iteration == 1 else 600

            await self._emit("agent_thinking", {"agent": self.agent_id, "iter": iteration, "phase": phase})

            # ── LLM reasoning ─────────────────────────────────────
            full_text = ""
            async for token in self._stream_llm(system, max_tokens=max_tokens):
                full_text += token
                await self._emit("agent_token", {"agent": self.agent_id, "token": token, "iter": iteration})

            await self._emit("agent_thought", {"agent": self.agent_id, "text": full_text, "iter": iteration})

            # ── Parse structured fields ───────────────────────────
            thought    = self._extract(r"THOUGHT:\s*(.*?)(?=ACTION:|DONE:|$)", full_text)
            action_raw = self._extract(r"ACTION:\s*(\S+)",                     full_text)
            is_done    = bool(re.search(r"DONE:\s*true", full_text, re.I))
            summary    = self._extract(r"SUMMARY:\s*([\s\S]*?)$",              full_text)

            if is_done:
                await self._emit("agent_done", {
                    "agent":    self.agent_id,
                    "iter":     iteration,
                    "findings": len(self.findings),
                    "summary":  summary,
                })
                break

            # ── Forced tool call guard ─────────────────────────────
            if not action_raw:
                _no_action_streak += 1
            else:
                _no_action_streak = 0

            if _no_action_streak >= 2:
                # LLM is stuck — inject a nudge to force it to pick a tool
                self._history.append({
                    "role": "user",
                    "content": (
                        f"You have not called a tool in {_no_action_streak} iterations. "
                        f"You MUST now pick exactly one tool from: {', '.join(self.tools)}.\n"
                        "Respond with only:\nACTION: <tool_name>\nDONE: false"
                    )
                })
                _no_action_streak = 0
                await self._emit("agent_nudge", {
                    "agent": self.agent_id, "iter": iteration,
                    "message": "Forcing tool call — LLM was not producing ACTION lines",
                })
                continue  # re-run LLM with nudge in history

            # ── Tool execution ─────────────────────────────────────
            tool = self._resolve_tool(action_raw)
            args = self.build_args(tool, self.target, self.depth)

            await self._emit("agent_action", {
                "agent": self.agent_id, "tool": tool,
                "iter":  iteration,     "thought": thought,
            })

            result = await self._run_tool(tool, args)
            output = result.get("output", "")
            self.observations.append(output)

            await self._emit("agent_output", {
                "agent":  self.agent_id, "tool": tool,
                "output": output[:2500], "code": result.get("code"), "iter": iteration,
            })

            # ── Extract findings ───────────────────────────────────
            new_f = self._extract_findings(output, tool, iteration)
            if new_f:
                self.findings.extend(new_f)
                await self._emit("agent_findings", {"agent": self.agent_id, "findings": new_f, "iter": iteration})

            # ── Update conversation history ────────────────────────
            self._history.append({"role": "assistant", "content": full_text})
            self._history.append({
                "role": "user",
                "content": (
                    f"TOOL [{tool}] output (truncated to 1500 chars):\n{output[:1500]}\n\n"
                    f"Findings confirmed so far: {len(self.findings)}. "
                    "Proceed to next tool or DONE: true if finished."
                )
            })
            # Bounded window — keep first 2 (user init + first response) + last 20
            if len(self._history) > 24:
                self._history = self._history[:2] + self._history[-20:]

        # Ensure done is always broadcast even on max_iter hit
        await self._emit("agent_done", {
            "agent":    self.agent_id,
            "findings": len(self.findings),
            "summary":  f"Completed {self.max_iter} iterations. {len(self.findings)} findings confirmed.",
        })

        await self.post_run()
        return self.findings

    # ── LLM streaming ─────────────────────────────────────────────────

    async def _stream_llm(self, system: str, max_tokens: int = 600) -> AsyncGenerator[str, None]:
        """
        Stream tokens from Ollama. Retries up to 3 times on connection errors.
        max_tokens=1200 for plan phase (iter 1), 600 for act phase (iter 2+).
        """
        payload = {
            "model":    self.model,
            "messages": self._history,
            "stream":   True,
            "system":   system,
            "options":  {"temperature": 0.15, "num_predict": max_tokens},
        }
        last_err: Optional[Exception] = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=180) as client:
                    async with client.stream("POST", f"{self.OLLAMA_URL}/api/chat", json=payload) as resp:
                        if resp.status_code != 200:
                            yield f"\n[LLM error {resp.status_code}]"
                            return
                        async for line in resp.aiter_lines():
                            if not line.strip():
                                continue
                            try:
                                data  = json.loads(line)
                                token = data.get("message", {}).get("content", "")
                                if token:
                                    yield token
                                if data.get("done"):
                                    return
                            except json.JSONDecodeError:
                                continue
                return  # success — exit retry loop
            except Exception as e:
                last_err = e
                if attempt < 2:
                    log.warning(f"[{self.agent_id}] Ollama error (attempt {attempt+1}/3): {e}")
                    await asyncio.sleep(2 * (attempt + 1))  # 2s, 4s backoff
                else:
                    yield f"\n[Ollama connection error after 3 retries: {last_err}]\n"

    # ── Tool runner ────────────────────────────────────────────────────

    async def _run_tool(self, tool: str, args: List[str], timeout: int = 120) -> Dict:
        timeout = 240 if self.depth == "deep" else timeout
        start   = time.time()
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
                return {"output": f"[timeout after {timeout}s]", "code": -1, "tool": tool}

            out = (stdout or b"").decode("utf-8", errors="replace") + \
                  (stderr or b"").decode("utf-8", errors="replace")
            return {"output": out[:12000], "code": proc.returncode, "tool": tool,
                    "duration_s": round(time.time() - start, 2)}
        except FileNotFoundError:
            return {"output": f"{tool}: not found — install: brew install {tool}", "code": -1, "tool": tool}
        except Exception as e:
            return {"output": str(e), "code": -1, "tool": tool}

    # ── Finding extractor ──────────────────────────────────────────────
    # Evidence-based: only extract findings when the tool actually ran
    # and produced meaningful output (not just LLM reasoning text).

    # Patterns that indicate the LLM is writing its own findings, not the tool.
    _LLM_HALLUCINATION_MARKERS = re.compile(
        r"(THOUGHT:|HYPOTHESIS:|ACTION:|I will|I should|I'll|Let me|Based on|"
        r"Assuming|It appears|It seems|This suggests|Potentially|Might be|"
        r"Could be|Likely|Probably|In my|As a|Next,|First,|Then,|Finally,)",
        re.IGNORECASE,
    )

    # Tools that produce their own severity tags in real output.
    _STRUCTURED_TOOLS = {"nuclei", "nikto", "nmap", "masscan", "sqlmap",
                         "gobuster", "ffuf", "feroxbuster", "searchsploit",
                         "amass", "subfinder", "whatweb", "hydra",
                         "smbmap", "enum4linux", "crackmapexec"}

    def _extract_findings(self, output: str, tool: str, iteration: int) -> List[Dict]:
        found: List[Dict] = []
        seen: set = set()

        # Guard 1: Tool must have actually run and returned real output.
        # If the output looks like an LLM thought monologue, skip it.
        if len(output.strip()) < 30:
            return found
        if tool.endswith(": not found") or "[timeout" in output[:50]:
            return found

        # Guard 2: If output is dominated by LLM-style reasoning text,
        # it means the LLM hallucinated the output — reject it.
        first_200 = output[:200]
        if self._LLM_HALLUCINATION_MARKERS.search(first_200):
            log.debug(f"[{self.agent_id}] Skipping hallucinated output for {tool}")
            return found

        def push(sev: str, desc: str) -> None:
            sev = sev.upper()
            if sev not in DEFAULT_CVSS:
                return
            desc = re.sub(r"\s+", " ", desc).strip()[:220]
            if len(desc) < 5:
                return
            key = f"{sev}|{desc[:80]}"
            if key in seen:
                return
            seen.add(key)
            found.append({
                "id":          str(uuid4()),
                "session_id":  self.session_id,
                "severity":    sev,
                "description": desc,
                "agent":       self.agent_id,
                "tool":        tool,
                "iteration":   iteration,
                "cvss":        DEFAULT_CVSS[sev],
                "raw_output":  output[:600],
                "confirmed":   True,   # always True here — only from tool output
                "created_at":  datetime.utcnow().isoformat(),
            })

        # Nuclei-specific: JSONL or plain tagged lines
        if tool == "nuclei":
            for line in output.splitlines():
                t = line.strip()
                if not t:
                    continue
                if t.startswith("{"):
                    try:
                        obj = json.loads(t)
                        sev  = (obj.get("info",{}) or {}).get("severity") or obj.get("severity","")
                        name = (obj.get("info",{}) or {}).get("name") or obj.get("template-id","Nuclei finding")
                        where = obj.get("matched-at") or obj.get("host") or ""
                        push(sev, f"{name} — {where}" if where else name)
                        continue
                    except Exception:
                        pass
                m = re.search(r"^\S+\s+\[([^\]]+)\]\s+\[(critical|high|medium|low|info)\]", t, re.I)
                if m:
                    push(m.group(2), f"{m.group(1)} — {t[:120]}")

        # nmap / masscan port-risk
        if tool in ("nmap", "masscan"):
            port_risk = {
                22: ("MEDIUM", "SSH exposed"),
                23: ("HIGH",     "Telnet exposed (unencrypted)"),
                3306: ("HIGH",   "MySQL exposed"),
                5432: ("HIGH",   "PostgreSQL exposed"),
                6379: ("CRITICAL","Redis exposed (no auth)"),
                9200: ("HIGH",   "Elasticsearch exposed"),
                27017: ("HIGH",  "MongoDB exposed"),
                11211: ("HIGH",  "Memcached exposed"),
                2181: ("HIGH",   "ZooKeeper exposed"),
                4848: ("HIGH",   "GlassFish admin exposed"),
            }
            for line in output.splitlines():
                m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line, re.I)
                if m:
                    port = int(m.group(1))
                    svc  = m.group(3)
                    if port in port_risk:
                        sev, label = port_risk[port]
                        push(sev, f"{label} ({port}/{m.group(2)} {svc})")
                    else:
                        push("INFO", f"Open port {port}/{m.group(2)} {svc}")
                cve = re.search(r"(CVE-\d{4}-\d{4,7})", line, re.I)
                if cve:
                    push("HIGH", f"CVE reference found: {cve.group(1).upper()}")

        # Generic [SEVERITY] tag extraction for all other structured tools
        if tool in self._STRUCTURED_TOOLS and tool not in ("nuclei", "nmap", "masscan"):
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                for m in re.finditer(rf"\[{sev}\]\s*(.{{5,240}})", output, re.I):
                    push(sev, m.group(1))

        return found

    # ── Helpers ────────────────────────────────────────────────────────

    def _extract(self, pattern: str, text: str) -> str:
        m = re.search(pattern, text, re.I | re.S)
        return m.group(1).strip()[:300] if m else ""

    def _resolve_tool(self, raw: str) -> str:
        """Map LLM output (which may be imprecise) to a known tool name."""
        raw = (raw or "").lower().strip()
        aliases = {
            "nmap": "nmap", "masscan": "masscan", "gobuster": "gobuster",
            "ffuf": "ffuf", "nuclei": "nuclei", "nikto": "nikto",
            "sqlmap": "sqlmap", "subfinder": "subfinder", "amass": "amass",
            "smbmap": "smbmap", "enum4linux": "enum4linux",
            "crackmapexec": "crackmapexec", "cme": "crackmapexec",
            "hydra": "hydra", "hashcat": "hashcat", "john": "john",
            "searchsploit": "searchsploit", "jwt_tool": "jwt_tool",
            "scoutsuite": "scout", "scout": "scout",
            "prowler": "prowler", "kube-hunter": "kube-hunter",
            "whatweb": "whatweb", "curl": "curl",
        }
        if raw in aliases:
            return aliases[raw]
        for alias, real in aliases.items():
            if alias in raw:
                return real
        # Fallback to first tool in this agent's list
        return self.tools[0] if self.tools else "curl"

    async def _emit(self, event_type: str, data: Dict):
        """Broadcast a structured event to all WebSocket clients."""
        try:
            await self.broadcast({"type": event_type, **data})
        except Exception:
            pass  # Don't crash the agent loop on broadcast failure
