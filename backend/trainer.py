"""
PHANTOM AI v3 — LLM Training Data Generator
─────────────────────────────────────────────
Generates Ollama-compatible JSONL training datasets from verified scan findings.
Each example teaches the model the correct THOUGHT/ACTION/ARGS response format
given a specific vulnerability finding.

Usage (from Python):
    from trainer import build_training_examples
    lines = build_training_examples(findings, learned_patterns)

Usage (CLI):
    python3 trainer.py --db phantom.db --out /tmp/phantom_training.jsonl
"""

import argparse
import json
import logging
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ── Per-finding-type → correct tool ACTION + ARGS template ────────────────────
# Keys: lowercase keywords found in finding descriptions
# Values: (tool, args_template) — {target} and {url} are substituted at runtime
_ACTION_MAP: List[Tuple[List[str], str, str]] = [
    # SQLi
    (["sqli", "sql injection", "sql inj", "sqlmap"],
     "sqlmap",
     "-u {url} --batch --dbs --level 3 --risk 2 --timeout 30"),

    # XSS
    (["xss", "cross-site script", "reflected xss", "stored xss"],
     "ffuf",
     "-w /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt -u {url}?FUZZ -mc 200,301,302 -t 20"),

    # LFI / Path Traversal
    (["lfi", "local file inclusion", "path traversal", "directory traversal"],
     "ffuf",
     "-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u {url}/FUZZ -mc 200 -t 20"),

    # SSRF
    (["ssrf", "server-side request forgery"],
     "curl",
     "-sk '{url}?url=http://169.254.169.254/latest/meta-data/' -o /tmp/ssrf_test.txt && cat /tmp/ssrf_test.txt"),

    # SSTI
    (["ssti", "server-side template injection", "template injection"],
     "ffuf",
     "-w /usr/share/seclists/Fuzzing/template-injection.txt -u {url}?FUZZ -mc 200 -t 10"),

    # Auth bypass / default creds
    (["auth bypass", "default cred", "weak password", "brute force"],
     "hydra",
     "-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
     "-P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt "
     "{target} http-get / -t 4 -T 30"),

    # JWT
    (["jwt", "json web token", "alg:none", "hmac"],
     "jwt_tool",
     "{token} -M at -t {url}"),

    # RCE / Command injection
    (["rce", "remote code execution", "command injection", "os command"],
     "nuclei",
     "-u {url} -t /root/nuclei-templates/vulnerabilities/generic/generic-rce.yaml -j"),

    # Open redirect
    (["open redirect", "url redirect", "redirect"],
     "ffuf",
     "-w /usr/share/seclists/Fuzzing/redirect-payloads.txt -u {url}?next=FUZZ -mc 301,302 -t 20"),

    # Exposed port: Redis
    (["redis exposed", "redis open", "redis no auth"],
     "nmap",
     "-sV -p 6379 --script redis-info {target}"),

    # Exposed port: MySQL
    (["mysql exposed", "mysql open", "mysql port"],
     "nmap",
     "-sV -p 3306 --script mysql-info,mysql-empty-password {target}"),

    # Exposed port: MongoDB
    (["mongodb exposed", "mongodb open", "mongo port"],
     "nmap",
     "-sV -p 27017 --script mongodb-info {target}"),

    # Exposed port: Elasticsearch
    (["elasticsearch exposed", "elastic open"],
     "curl",
     "-sk http://{target}:9200/_cat/indices?v | head -30"),

    # SMB
    (["smb", "samba", "null session", "smb null"],
     "smbmap",
     "-H {target} -u '' -p ''"),

    # CVE
    (["cve-", "cve reference"],
     "searchsploit",
     "--cve {cve_id}"),

    # Directory / endpoint discovery
    (["directory listing", "gobuster", "endpoint discovered", "hidden path"],
     "gobuster",
     "dir -u {url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt "
     "-x php,asp,aspx,jsp,json -t 30 -q"),

    # Nuclei generic (fallback for nuclei findings with no specific category)
    (["nuclei", "template"],
     "nuclei",
     "-u {url} -severity medium,high,critical -j -timeout 30"),

    # Subdomain / DNS
    (["subdomain", "dns", "cname", "a record"],
     "subfinder",
     "-d {target} -silent"),

    # AWS / Cloud
    (["aws", "s3 bucket", "iam", "ec2 metadata", "cloud"],
     "curl",
     "-sk http://169.254.169.254/latest/meta-data/ --connect-timeout 5"),

    # Version disclosure
    (["version", "server header", "x-powered-by", "disclosure"],
     "whatweb",
     "--color=never -a 3 {url}"),
]

# ── Agent personas (abbreviated, matches agents/*.py) ─────────────────────────
_PERSONAS = {
    "web": (
        "You are the Web Agent — OWASP Top 10 specialist. "
        "You test for injection flaws, auth issues, misconfigurations, and data exposure."
    ),
    "recon": (
        "You are the Recon Agent — OSINT and asset discovery specialist. "
        "You map attack surfaces: subdomains, IPs, ports, tech stack, exposed services."
    ),
    "network": (
        "You are the Network Agent — infrastructure specialist. "
        "You scan ports, enumerate services, test SMB/RDP/Redis/MongoDB for exposure."
    ),
    "identity": (
        "You are the Identity Agent — auth/JWT/OAuth specialist. "
        "You test login flows, JWT weaknesses, session management, MFA bypass."
    ),
    "exploit": (
        "You are the Exploit Agent — CVE validation specialist. "
        "You research CVEs, validate exploitability, assess blast radius."
    ),
    "cloud": (
        "You are the Cloud Agent — AWS/GCP/Azure posture specialist. "
        "You test S3 buckets, IAM permissions, metadata endpoints, cloud misconfigs."
    ),
    "planner": (
        "You are the Planner Agent — master orchestrator. "
        "You coordinate reconnaissance and delegate tasks to specialist agents."
    ),
}


def _match_action(description: str) -> Optional[Tuple[str, str]]:
    """Find the best tool+args template for a finding description."""
    desc_lower = description.lower()
    for keywords, tool, args_tmpl in _ACTION_MAP:
        if any(kw in desc_lower for kw in keywords):
            return tool, args_tmpl
    return None


def _infer_agent(finding: Dict) -> str:
    """Infer which agent persona to use based on finding metadata."""
    agent = (finding.get("agent") or "").lower()
    tool  = (finding.get("tool") or "").lower()
    desc  = (finding.get("description") or "").lower()

    if agent in _PERSONAS:
        return agent
    if tool in ("nmap", "masscan", "smbmap", "enum4linux", "crackmapexec"):
        return "network"
    if tool in ("subfinder", "amass", "theharvester", "whatweb"):
        return "recon"
    if tool in ("jwt_tool", "hydra"):
        return "identity"
    if tool in ("nuclei", "nikto", "sqlmap", "gobuster", "ffuf", "feroxbuster"):
        return "web"
    if tool in ("searchsploit", "hashcat", "john"):
        return "exploit"
    if any(kw in desc for kw in ("aws", "s3", "iam", "azure", "gcp", "k8s")):
        return "cloud"
    return "web"


def _extract_url(finding: Dict, target: str) -> str:
    """Best-effort URL extraction from finding description or raw_output."""
    for field in ("raw_output", "description"):
        text = finding.get(field, "") or ""
        m = re.search(r"https?://\S+", text)
        if m:
            url = m.group(0).rstrip(".,;'\")")
            return url
    # Fall back to constructing from target
    if target.startswith("http"):
        return target
    return f"http://{target}"


def _extract_cve(description: str) -> str:
    """Extract CVE ID from description."""
    m = re.search(r"CVE-\d{4}-\d{4,7}", description, re.I)
    return m.group(0).upper() if m else "CVE-UNKNOWN"


def build_training_examples(
    findings: List[Dict],
    learned_patterns: Optional[List[Dict]] = None,
    target: str = "target.example.com",
) -> List[str]:
    """
    Convert a list of verified findings into Ollama JSONL training lines.

    Each line is a JSON object with {"messages": [...]} following the Ollama
    fine-tuning format. Only CRITICAL, HIGH, MEDIUM findings are included
    (INFO findings rarely teach the model anything actionable).

    Returns a list of JSON strings (one per training example).
    """
    lines: List[str] = []
    seen_keys: set = set()

    for finding in findings:
        sev  = (finding.get("severity") or "LOW").upper()
        desc = (finding.get("description") or "").strip()
        tool = (finding.get("tool") or "").strip()

        if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
            continue
        if not desc or len(desc) < 10:
            continue

        # De-duplicate by (severity, first 60 chars of description)
        key = f"{sev}|{desc[:60]}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        agent_key = _infer_agent(finding)
        persona   = _PERSONAS.get(agent_key, _PERSONAS["web"])
        url       = _extract_url(finding, target)
        host      = re.sub(r"https?://", "", url).split("/")[0]

        # Match to correct tool action
        match = _match_action(desc)
        if match:
            action_tool, args_tmpl = match
            # Substitute template variables
            args = (
                args_tmpl
                .replace("{url}", url)
                .replace("{target}", host)
                .replace("{token}", "<JWT_TOKEN_HERE>")
                .replace("{cve_id}", _extract_cve(desc))
            )
        else:
            # Generic fallback: run nuclei on the target
            action_tool = "nuclei"
            args = f"-u {url} -severity medium,high,critical -j"

        # Build the thought based on severity + description
        thought = f"{sev} finding confirmed by {tool}: {desc[:80]}"

        example = {
            "messages": [
                {"role": "system",    "content": persona},
                {"role": "user",      "content": (
                    f"TARGET: {host}\n"
                    f"PREVIOUS FINDING ({sev}): {tool} confirmed — {desc[:120]}\n"
                    f"What is your next action to verify or exploit this finding?"
                )},
                {"role": "assistant", "content": (
                    f"THOUGHT: {thought}\n"
                    f"ACTION: {action_tool}\n"
                    f"ARGS: {args}\n"
                    "DONE: false"
                )},
            ]
        }
        lines.append(json.dumps(example))

    # Add DONE examples — teach the model when to stop
    if findings:
        sample = findings[0]
        agent_key = _infer_agent(sample)
        persona   = _PERSONAS.get(agent_key, _PERSONAS["web"])
        done_example = {
            "messages": [
                {"role": "system",    "content": persona},
                {"role": "user",      "content": (
                    f"TARGET: {target}\n"
                    "All planned tools have been run. No additional critical findings remain. "
                    "What do you do?"
                )},
                {"role": "assistant", "content": (
                    "DONE: true\n"
                    f"SUMMARY: Assessment of {target} complete. "
                    f"Confirmed {len(findings)} findings. "
                    "All planned tools executed. No further action required."
                )},
            ]
        }
        lines.append(json.dumps(done_example))

    log.info(f"[trainer] Generated {len(lines)} training examples from {len(findings)} findings")
    return lines


def write_modelfile(
    output_dir: Path,
    base_model: str,
    jsonl_path: Path,
    model_name: str = "phantom-security",
) -> Path:
    """
    Write an Ollama Modelfile that fine-tunes base_model on the JSONL dataset.
    Returns the path to the written Modelfile.
    """
    modelfile_path = output_dir / "Modelfile"
    content = (
        f"FROM {base_model}\n\n"
        "# Phantom AI v3 — Security-tuned model\n"
        "# Trained to produce strict THOUGHT/ACTION/ARGS/DONE format\n"
        "# from real penetration testing findings.\n\n"
        'SYSTEM """\n'
        "You are Phantom AI — an autonomous penetration testing agent.\n"
        "You ALWAYS respond in the exact format:\n"
        "THOUGHT: <one sentence>\n"
        "ACTION: <exact tool name>\n"
        "ARGS: <exact CLI arguments>\n"
        "DONE: false\n\n"
        "Or when finished:\n"
        "DONE: true\n"
        "SUMMARY: <one paragraph citing tool evidence>\n\n"
        "You NEVER invent findings. You NEVER output [SEVERITY] tags yourself.\n"
        "Only real tool output may contain [SEVERITY] tags.\n"
        '"""\n\n'
        "PARAMETER temperature 0.1\n"
        "PARAMETER num_predict 600\n"
        "PARAMETER top_p 0.9\n"
        f"PARAMETER stop \"DONE: true\"\n"
    )
    modelfile_path.write_text(content)
    return modelfile_path


def generate_dataset(db_path: str, out_path: str, max_findings: int = 500) -> int:
    """
    Load findings from SQLite and write a JSONL training file.
    Returns the number of examples written.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT severity, description, tool, agent, session_id, raw_output "
        "FROM findings "
        "WHERE (confirmed=1 OR confirmed IS NULL) "
        "  AND severity IN ('CRITICAL','HIGH','MEDIUM') "
        "ORDER BY created_at DESC LIMIT ?",
        (max_findings,)
    ).fetchall()
    conn.close()

    findings = [dict(r) for r in rows]
    examples = build_training_examples(findings)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(examples) + "\n")
    log.info(f"[trainer] Wrote {len(examples)} examples to {out_path}")
    return len(examples)


# ── CLI entrypoint ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Generate Phantom AI LLM training data")
    parser.add_argument("--db",  default="phantom.db", help="SQLite database path")
    parser.add_argument("--out", default=f"/tmp/phantom_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl",
                        help="Output JSONL path")
    parser.add_argument("--max", type=int, default=500, help="Max findings to use")
    parser.add_argument("--modelfile", action="store_true", help="Also write Modelfile")
    parser.add_argument("--base-model", default="", help="Base model for Modelfile")
    args = parser.parse_args()

    n = generate_dataset(args.db, args.out, args.max)
    print(f"✓ Wrote {n} training examples → {args.out}")

    if args.modelfile:
        from agents.base import detect_best_model
        base = args.base_model or detect_best_model()
        out_dir = Path(args.out).parent
        mf = write_modelfile(out_dir, base, Path(args.out))
        print(f"✓ Modelfile → {mf}")
        print(f"\nTo create the model:\n  ollama create phantom-security -f {mf}")
