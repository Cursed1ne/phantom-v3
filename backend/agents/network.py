"""PHANTOM AI v3 — Network Agent: ports, services, SMB, lateral movement paths."""
from typing import List
from .base import BaseAgent


class NetworkAgent(BaseAgent):

    @property
    def agent_id(self): return "network"

    @property
    def tools(self):
        return ["nmap", "masscan", "smbmap", "enum4linux", "crackmapexec"]

    @property
    def persona(self):
        return (
            "You are the PHANTOM NETWORK agent — an infrastructure and network security specialist. "
            "Think like an internal attacker who already has a foothold and is looking to pivot. "
            "Your priorities: "
            "1) Port scan — find every open service with version detection. "
            "2) Service exploitation paths — old OpenSSH, default creds on management interfaces. "
            "3) SMB/NetBIOS — null sessions, user enumeration, password policy weaknesses. "
            "4) Database exposure — MySQL/Postgres/Redis/MongoDB accessible externally. "
            "5) Firewall gaps — unexpected ports, dual-homed hosts, VPN endpoints. "
            "Correlate your findings with what the web and recon agents found. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        )

    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        timing = "-T4" if depth != "quick" else "-T3"
        return {
            "nmap":         ["-sV", "-sC", "--open", timing, "--top-ports",
                             "1000" if depth == "deep" else "500", target],
            "masscan":      [target, "-p", "0-65535" if depth == "deep" else "1-10000",
                             "--rate", "10000"],
            "smbmap":       ["-H", target],
            "enum4linux":   ["-a", target],
            "crackmapexec": ["smb", target, "--shares", "--users"],
        }.get(tool, [target])
