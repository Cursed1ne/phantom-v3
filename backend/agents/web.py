"""PHANTOM AI v3 — Web Agent: OWASP Top 10, injection, directory brute-force."""
from typing import List
from .base import BaseAgent, WL_MEDIUM, WL_SMALL, WL_ROCKYOU


class WebAgent(BaseAgent):

    @property
    def agent_id(self): return "web"

    @property
    def tools(self):
        return ["nuclei", "nikto", "sqlmap", "gobuster", "ffuf", "whatweb", "zaproxy", "feroxbuster"]

    @property
    def persona(self):
        return (
            "You are the PHANTOM WEB agent — a world-class web application security specialist. "
            "You test every aspect of the OWASP Top 10: injection (SQL, NoSQL, LDAP, OS command), "
            "broken authentication, sensitive data exposure, XML external entities (XXE), "
            "broken access control (IDOR), security misconfiguration, XSS, insecure deserialization, "
            "known vulnerabilities (CVEs), and insufficient logging. "
            "Prioritise tests based on tech stack fingerprinting. Always run directory brute-force "
            "alongside vulnerability scanning — hidden endpoints are gold. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        )

    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        wl     = WL_MEDIUM if depth != "quick" else WL_SMALL
        threads = "60" if depth == "deep" else "40"
        ext    = "php,html,js,txt,bak,sql,env,zip,tar.gz" if depth == "deep" else "php,html,js,txt,bak"
        return {
            "nuclei":      ["-u", f"https://{target}", "-t", "cves,misconfiguration,exposures,technologies",
                            "-severity", "critical,high,medium", "-silent", "-no-color", "-timeout", "10"],
            "nikto":       ["-h", f"https://{target}", "-nointeractive", "-Format", "txt"],
            "sqlmap":      ["-u", f"https://{target}/", "-crawl=3", "--batch", "--level=3",
                            "--risk=2", "--random-agent", "--quiet"],
            "gobuster":    ["dir", "-u", f"https://{target}", "-w", wl, "-q",
                            "--no-error", "-t", threads, "-x", ext],
            "ffuf":        ["-u", f"https://{target}/FUZZ", "-w", wl,
                            "-mc", "200,204,301,302,403,500", "-t", threads, "-silent"],
            "feroxbuster": ["--url", f"https://{target}", "--wordlist", wl,
                            "--quiet", "--no-recursion", "--threads", threads],
            "whatweb":     [f"https://{target}", "-v", "--log-verbose=/dev/stdout"],
            "zaproxy":     ["-cmd", "-quickurl", f"https://{target}", "-quickout", "/dev/stdout"],
        }.get(tool, [f"https://{target}"])
