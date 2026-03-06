"""PHANTOM AI v3 — Planner Agent
Master strategist that coordinates all other agents.
"""
from typing import List
from .base import BaseAgent, WL_MEDIUM


class PlannerAgent(BaseAgent):

    @property
    def agent_id(self): return "planner"

    @property
    def tools(self): return ["nmap", "whatweb", "curl", "subfinder"]

    @property
    def persona(self):
        return (
            "You are the PHANTOM PLANNER — the master strategist and orchestrator. "
            "Your job is to analyse the target, produce a prioritised attack plan, "
            "and delegate specific tasks to specialist agents. "
            "Think like an experienced red team lead: identify the highest-value attack surface, "
            "consider the tech stack, and sequence tests for maximum impact. "
            "Format strictly: THOUGHT: ... | STRATEGY: ... | "
            "DELEGATE: <agent> — <task> | DONE: true/false"
        )

    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        return {
            "nmap":      ["-sV", "--open", "-T4", "--top-ports", "100", target],
            "whatweb":   [f"https://{target}", "--log-verbose=/dev/stdout"],
            "curl":      ["-sI", f"https://{target}", "--max-time", "8"],
            "subfinder": ["-d", target, "-silent"],
        }.get(tool, [target])
