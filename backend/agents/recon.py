"""PHANTOM AI v3 — Recon Agent: OSINT, subdomain enum, fingerprinting."""
from typing import List
from .base import BaseAgent, WL_MEDIUM


class ReconAgent(BaseAgent):

    @property
    def agent_id(self): return "recon"

    @property
    def tools(self):
        return ["subfinder", "amass", "whatweb", "curl", "nmap", "theHarvester"]

    @property
    def persona(self):
        return (
            "You are the PHANTOM RECON agent — elite asset discovery and OSINT specialist. "
            "Your mission: map the complete attack surface before any exploitation begins. "
            "Discover: subdomains, IP ranges, email addresses, technologies, cloud providers, "
            "certificate transparency entries, open ports, and organisational structure. "
            "A thorough recon phase directly enables every other agent to be more effective. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        )

    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        passive = depth == "quick"
        return {
            "subfinder":     ["-d", target, "-silent", "-all"],
            "amass":         ["enum", "-d", target, "-passive" if passive else "-active", "-silent"],
            "theHarvester":  ["-d", target, "-b", "all", "-l", "100"],
            "whatweb":       [f"https://{target}", "-v", "--log-verbose=/dev/stdout"],
            "nmap":          ["-sV", "--open", "-T4", "--top-ports", "500", target],
            "curl":          ["-sI", f"https://{target}", "--max-time", "8"],
        }.get(tool, [target])
