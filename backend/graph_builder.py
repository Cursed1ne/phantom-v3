"""
PHANTOM AI v3 — Kill-Chain Exploitation Graph Builder
──────────────────────────────────────────────────────
Converts a list of scan findings into a structured attack graph following
the cyber kill chain: Initial Access → Foothold → Privilege Escalation → Impact.

Each finding is mapped to a phase by keyword matching. Nodes and directed edges
are returned in a format the React GraphView component can render directly.

Usage:
    from graph_builder import build_exploitation_graph
    graph = build_exploitation_graph(findings_list)
    # graph = {"nodes": [...], "edges": [...], "attack_paths": [...], "risk_score": float}
"""

import re
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

# ── Kill-chain phase taxonomy ──────────────────────────────────────────────────
# Maps phase name → keywords (checked against finding description, lowercase)
KILL_CHAIN: Dict[str, List[str]] = {
    "initial": [
        "port", "open service", "banner", "version disclosure", "info disclosure",
        "server header", "x-powered-by", "default cred", "open redirect",
        "directory listing", "robots.txt", "sitemap", "subdomain", "dns",
        "cors", "security header", "cookie", "fingerprint", "whatweb",
        "nikto", "enumeration", "exposed endpoint",
    ],
    "foothold": [
        "sqli", "sql injection", "xss", "cross-site script", "rce",
        "remote code execution", "lfi", "local file inclusion", "path traversal",
        "ssrf", "server-side request forgery", "ssti", "template injection",
        "auth bypass", "authentication bypass", "idor", "insecure direct",
        "xxe", "xml external", "file upload", "command injection",
        "deserialization", "jwt", "broken auth", "session fixation",
        "csrf", "cross-site request", "oauth", "saml",
    ],
    "escalation": [
        "privilege escalation", "privesc", "sudo", "suid", "writable",
        "session hijack", "token theft", "api key", "aws key", "credential",
        "password", "hash", "ntlm", "kerberos", "lateral movement",
        "smb", "pass the hash", "golden ticket", "rbac", "iam",
        "admin panel", "dashboard exposed", "internal network",
    ],
    "impact": [
        "data exfil", "database dump", "data breach", "remote shell",
        "reverse shell", "admin access", "root access", "full control",
        "rce confirmed", "arbitrary file read", "arbitrary file write",
        "s3 bucket", "cloud storage", "backup exposed", "source code",
        "pii", "personal data", "payment", "credit card",
        "aws credentials", "service account", "full compromise",
    ],
}

# Phase display metadata
PHASE_META: Dict[str, Dict] = {
    "initial":    {"label": "Initial Access",         "color": "#3b82f6", "order": 0},
    "foothold":   {"label": "Foothold",               "color": "#f97316", "order": 1},
    "escalation": {"label": "Privilege Escalation",   "color": "#ef4444", "order": 2},
    "impact":     {"label": "Impact",                 "color": "#111827", "order": 3},
    "unknown":    {"label": "Unknown",                "color": "#6b7280", "order": 4},
}

# Severity → CVSS weight for risk score
SEVERITY_WEIGHT = {"CRITICAL": 2.2, "HIGH": 1.2, "MEDIUM": 0.5, "LOW": 0.2, "INFO": 0.05}


def _classify_phase(description: str) -> str:
    """Classify a finding into a kill-chain phase by keyword matching."""
    desc = description.lower()
    # Check in reverse order (impact > escalation > foothold > initial)
    # so that the most severe phase wins for ambiguous findings
    for phase in ["impact", "escalation", "foothold", "initial"]:
        if any(kw in desc for kw in KILL_CHAIN[phase]):
            return phase
    return "unknown"


def _severity_order(sev: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(sev.upper(), 5)


def build_exploitation_graph(findings: List[Dict], target: Optional[str] = None) -> Dict:
    """
    Build a kill-chain exploitation graph from a list of findings.

    Returns:
        {
          "nodes": [{"id", "label", "severity", "phase", "phase_label",
                     "color", "tool", "description", "cvss"}],
          "edges": [{"id", "from", "to", "label", "phase"}],
          "attack_paths": [[node_id, ...], ...],  # ordered chains from root to impact
          "phase_counts": {"initial": N, "foothold": N, ...},
          "risk_score": float,
          "summary": str,
        }
    """
    nodes: List[Dict] = []
    edges: List[Dict] = []
    seen_descs: set = set()

    # ── Root node ──────────────────────────────────────────────────────
    # Infer target from findings if not provided
    if not target:
        for f in findings:
            raw = f.get("raw_output", "") or ""
            m = re.search(r"https?://(\S+?)(?:/|\s|$)", raw)
            if m:
                target = m.group(1)
                break
        target = target or "target"

    root_id = "root"
    nodes.append({
        "id":          root_id,
        "label":       target,
        "severity":    "INFO",
        "phase":       "root",
        "phase_label": "Target",
        "color":       "#1e3a5f",
        "tool":        "",
        "description": f"Scan target: {target}",
        "cvss":        0.0,
        "is_root":     True,
    })

    # ── Group findings by phase ────────────────────────────────────────
    phase_buckets: Dict[str, List[Dict]] = {
        p: [] for p in ["initial", "foothold", "escalation", "impact", "unknown"]
    }

    for finding in findings:
        sev  = (finding.get("severity") or "INFO").upper()
        desc = (finding.get("description") or "").strip()

        if not desc or len(desc) < 5:
            continue

        # De-duplicate
        key = f"{sev}|{desc[:60]}"
        if key in seen_descs:
            continue
        seen_descs.add(key)

        phase = _classify_phase(desc)
        phase_buckets[phase].append(finding)

    # ── Create nodes for each finding ─────────────────────────────────
    phase_node_ids: Dict[str, List[str]] = {p: [] for p in phase_buckets}

    for phase, bucket in phase_buckets.items():
        # Sort by severity (critical first)
        bucket.sort(key=lambda f: _severity_order(f.get("severity", "INFO")))
        meta = PHASE_META.get(phase, PHASE_META["unknown"])

        for finding in bucket:
            node_id = str(uuid4())
            sev  = (finding.get("severity") or "INFO").upper()
            desc = (finding.get("description") or "").strip()
            tool = (finding.get("tool") or "unknown").strip()
            cvss = finding.get("cvss") or SEVERITY_WEIGHT.get(sev, 0.2)

            # Shorten label for display
            label = desc[:60] + ("…" if len(desc) > 60 else "")

            nodes.append({
                "id":          node_id,
                "label":       label,
                "severity":    sev,
                "phase":       phase,
                "phase_label": meta["label"],
                "color":       meta["color"],
                "tool":        tool,
                "description": desc,
                "cvss":        cvss,
                "is_root":     False,
            })
            phase_node_ids[phase].append(node_id)

    # ── Create edges ───────────────────────────────────────────────────
    # 1. root → all initial access nodes
    for node_id in phase_node_ids["initial"]:
        edges.append({
            "id":    str(uuid4()),
            "from":  root_id,
            "to":    node_id,
            "label": "exposes",
            "phase": "initial",
        })

    # 2. initial → foothold (each initial → each foothold = attacker uses initial to gain foothold)
    for init_id in phase_node_ids["initial"][:3]:  # top 3 to avoid graph explosion
        for foot_id in phase_node_ids["foothold"][:3]:
            edges.append({
                "id":    str(uuid4()),
                "from":  init_id,
                "to":    foot_id,
                "label": "enables",
                "phase": "foothold",
            })

    # 3. foothold → escalation
    for foot_id in phase_node_ids["foothold"][:3]:
        for esc_id in phase_node_ids["escalation"][:3]:
            edges.append({
                "id":    str(uuid4()),
                "from":  foot_id,
                "to":    esc_id,
                "label": "leads to",
                "phase": "escalation",
            })

    # 4. escalation → impact
    for esc_id in phase_node_ids["escalation"][:3]:
        for imp_id in phase_node_ids["impact"][:3]:
            edges.append({
                "id":    str(uuid4()),
                "from":  esc_id,
                "to":    imp_id,
                "label": "achieves",
                "phase": "impact",
            })

    # 5. Direct connections when phases are skipped (e.g., RCE directly to impact)
    if not phase_node_ids["escalation"] and phase_node_ids["foothold"] and phase_node_ids["impact"]:
        for foot_id in phase_node_ids["foothold"][:2]:
            for imp_id in phase_node_ids["impact"][:2]:
                edges.append({
                    "id":    str(uuid4()),
                    "from":  foot_id,
                    "to":    imp_id,
                    "label": "direct impact",
                    "phase": "impact",
                })

    # 6. Unknown phase nodes connect to root
    for node_id in phase_node_ids["unknown"]:
        edges.append({
            "id":    str(uuid4()),
            "from":  root_id,
            "to":    node_id,
            "label": "found",
            "phase": "unknown",
        })

    # ── Compute attack paths ───────────────────────────────────────────
    # Build a simple adjacency map and trace paths root → impact
    adj: Dict[str, List[str]] = {}
    for edge in edges:
        adj.setdefault(edge["from"], []).append(edge["to"])

    attack_paths: List[List[str]] = []

    def _dfs(node_id: str, path: List[str], visited: set):
        if len(path) > 8:  # max depth guard
            return
        path = path + [node_id]
        # If this node is an impact node, record the path
        node = next((n for n in nodes if n["id"] == node_id), None)
        if node and node.get("phase") == "impact":
            attack_paths.append(path)
            return
        for neighbor in adj.get(node_id, []):
            if neighbor not in visited:
                _dfs(neighbor, path, visited | {node_id})

    _dfs(root_id, [], {root_id})

    # Sort paths: longest first (most complete chain)
    attack_paths.sort(key=lambda p: -len(p))

    # ── Risk score ────────────────────────────────────────────────────
    total_weight = sum(
        SEVERITY_WEIGHT.get(n["severity"], 0.05)
        for n in nodes
        if not n.get("is_root")
    )
    risk_score = min(10.0, round(total_weight, 2))

    # ── Phase counts ─────────────────────────────────────────────────
    phase_counts = {p: len(ids) for p, ids in phase_node_ids.items()}

    # ── Summary ──────────────────────────────────────────────────────
    total = sum(phase_counts.values())
    chain_phases = [p for p in ["initial", "foothold", "escalation", "impact"] if phase_counts[p] > 0]
    chain_str = " → ".join(p.capitalize() for p in chain_phases) if chain_phases else "No chain found"
    summary = (
        f"{total} findings mapped across {len(chain_phases)} kill-chain phases. "
        f"Chain: {chain_str}. "
        f"Risk score: {risk_score}/10. "
        f"{len(attack_paths)} exploitation path(s) identified."
    )

    return {
        "nodes":        nodes,
        "edges":        edges,
        "attack_paths": attack_paths[:10],   # top 10 paths
        "phase_counts": phase_counts,
        "risk_score":   risk_score,
        "summary":      summary,
        "target":       target,
    }
