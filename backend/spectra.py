"""
SPECTRA — Semantic Policy Extractor & Constraint Tester
Patent Pending — Doshan / Phantom AI v3

Gap it fills: No existing automated tool extracts application-level
business rules and verifies they are actually enforced server-side.

Technique:
  1. Sends crawled page content + JS source to the local LLM
  2. LLM extracts human-readable security constraints:
       "users can only view their own orders"
       "admin role required to access /admin/*"
  3. Each constraint → generates a concrete HTTP test that SHOULD be denied
  4. Executes test → any 2xx with data = broken access control finding

Based on OWASP Top 10 A01 (Broken Access Control) + OWASP A04 (Insecure Design).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

# ── Constants ─────────────────────────────────────────────────────────────────

OLLAMA_URL = "http://localhost:11434"
_CVSS: Dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.5,
    "LOW": 3.5,
    "INFO": 1.0,
}

_CONSTRAINT_EXTRACTION_PROMPT = """\
You are a security analyst. Analyse the following web application content and \
extract explicit security constraints — rules the application promises to enforce.

Content:
{content}

For each constraint you find, output a JSON object on its own line:
{{"rule": "<the rule in plain English>", "resource": "<path or pattern>", \
"method": "GET|POST|ANY", "denied_role": "unauthenticated|other_user|non_admin", \
"test_type": "unauth|other_user|role_escalation|mass_assign"}}

Output ONLY the JSON lines. No explanation. Maximum 8 constraints."""

# Regex fallback patterns when LLM is unavailable
_AUTH_HINTS = [
    (r"(?i)(must be logged in|requires auth|login required|sign in to)", "unauth"),
    (r"(?i)(admin only|administrators only|requires admin|admin access)", "non_admin"),
    (r"(?i)(your (own|personal) (data|profile|orders|account))", "other_user"),
    (r"(?i)(only (view|access|modify) your)", "other_user"),
]

_MASS_ASSIGN_PARAMS = ["role", "is_admin", "admin", "is_superuser", "privilege", "group"]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SecurityConstraint:
    rule: str
    resource: str
    method: str = "GET"
    denied_role: str = "unauthenticated"   # unauthenticated | other_user | non_admin
    test_type: str = "unauth"              # unauth | other_user | role_escalation | mass_assign
    source: str = "llm"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    severity: str,
    description: str,
    url: str = "",
    evidence: str = "",
    rule: str = "",
) -> Dict[str, Any]:
    sev = severity.upper()
    return {
        "id":          str(uuid.uuid4()),
        "severity":    sev,
        "description": description[:500],
        "tool":        "SPECTRA",
        "agent":       "spectra",
        "module":      "Semantic Policy Extractor & Constraint Tester",
        "patent":      "Patent Pending — Doshan",
        "iteration":   1,
        "cvss":        _CVSS.get(sev, 1.0),
        "raw_output":  f"rule={rule!r}\nevidence={evidence[:600]}",
        "url":         url,
        "created_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "owasp":       "A01:2021 – Broken Access Control",
        "cwe":         "CWE-284",
    }


def _build_context_bundle(crawler_result: Dict[str, Any]) -> str:
    """Collect crawled text, JS snippets and page titles into one LLM-ready blob."""
    parts: List[str] = []

    # Page summaries
    for page in (crawler_result.get("pages") or [])[:15]:
        title = page.get("title", "")
        url   = page.get("url", "")
        body  = page.get("body_text") or page.get("content") or ""
        if body or title:
            parts.append(f"[PAGE] {url} — {title}\n{body[:600]}")

    # JS source hints
    for js in (crawler_result.get("js_content") or [])[:5]:
        parts.append(f"[JS] {js[:400]}")

    # Visited URLs — these often contain resource patterns like /orders/42
    visited = (crawler_result.get("visited_urls") or [])[:40]
    if visited:
        parts.append("[URLS]\n" + "\n".join(visited))

    # Form actions
    for form in (crawler_result.get("form_endpoints") or [])[:20]:
        parts.append(f"[FORM] {form.get('method','GET')} {form.get('url','')}")

    return "\n\n".join(parts)[:3000]


# ── Constraint extraction ──────────────────────────────────────────────────────

async def _extract_via_llm(
    context: str,
    llm_url: str,
    model: str,
    timeout: float = 25.0,
) -> List[SecurityConstraint]:
    prompt = _CONSTRAINT_EXTRACTION_PROMPT.format(content=context)
    constraints: List[SecurityConstraint] = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{llm_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False,
                      "options": {"temperature": 0.1, "num_predict": 600}},
            )
            if resp.status_code != 200:
                return constraints
            raw = resp.json().get("response", "")
            for line in raw.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    constraints.append(SecurityConstraint(
                        rule=str(obj.get("rule", ""))[:200],
                        resource=str(obj.get("resource", "/"))[:200],
                        method=str(obj.get("method", "GET")).upper(),
                        denied_role=str(obj.get("denied_role", "unauthenticated")),
                        test_type=str(obj.get("test_type", "unauth")),
                        source="llm",
                    ))
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception:
        pass
    return constraints[:8]


def _extract_via_regex(
    context: str,
    visited_urls: List[str],
) -> List[SecurityConstraint]:
    """Regex-based fallback when LLM call fails or returns nothing."""
    constraints: List[SecurityConstraint] = []

    for pattern, test_type in _AUTH_HINTS:
        if re.search(pattern, context):
            # Guess a resource from visited_urls
            resource = "/"
            if visited_urls:
                resource = visited_urls[0]
            constraints.append(SecurityConstraint(
                rule=f"Inferred from content hint: {pattern}",
                resource=resource,
                method="GET",
                denied_role="unauthenticated" if test_type == "unauth" else "non_admin",
                test_type=test_type,
                source="regex",
            ))

    # Always add mass-assignment probe against first form endpoint if any
    # (we'll discover at test-time whether it's actually accepted)
    constraints.append(SecurityConstraint(
        rule="Mass-assignment: unauthorized parameter injection",
        resource="/",
        method="POST",
        denied_role="unauthenticated",
        test_type="mass_assign",
        source="heuristic",
    ))
    return constraints[:8]


async def extract_constraints(
    crawler_result: Dict[str, Any],
    llm_url: str,
    model: str,
) -> List[SecurityConstraint]:
    context = _build_context_bundle(crawler_result)
    if not context.strip():
        return []

    constraints = await _extract_via_llm(context, llm_url, model)
    if not constraints:
        visited = crawler_result.get("visited_urls") or []
        constraints = _extract_via_regex(context, visited)
    return constraints


# ── Constraint testing ─────────────────────────────────────────────────────────

async def _resolve_resource_url(base_url: str, resource: str, visited_urls: List[str]) -> str:
    """Best-effort URL resolution for a resource pattern extracted by the LLM."""
    # If it already looks like a full URL
    if resource.startswith("http"):
        return resource

    # Strip glob/wildcard parts
    resource = resource.split("{")[0].rstrip("*").rstrip("/") or "/"

    # If we have a visiting URL that matches the pattern, prefer that
    for u in visited_urls:
        if resource in u:
            return u

    # Fall back to base_url + resource
    base = base_url.rstrip("/")
    if not resource.startswith("/"):
        resource = "/" + resource
    return base + resource


async def test_constraint(
    session: httpx.AsyncClient,
    constraint: SecurityConstraint,
    base_url: str,
    session_cookies: Dict[str, str],
    secondary_cookies: Optional[Dict[str, str]],
    visited_urls: List[str],
    form_endpoints: List[Dict],
) -> Optional[Dict[str, Any]]:
    url = await _resolve_resource_url(base_url, constraint.resource, visited_urls)
    method = constraint.method if constraint.method in ("GET", "POST", "PUT", "PATCH", "DELETE") else "GET"

    try:
        if constraint.test_type == "unauth":
            # Fire request with NO cookies
            if method == "GET":
                resp = await session.get(url, cookies={}, timeout=10)
            else:
                resp = await session.post(url, cookies={}, timeout=10)

            # 2xx with non-trivial body = likely unauthorised access
            if resp.status_code in range(200, 300) and len(resp.content) > 100:
                body = resp.text[:300]
                # Exclude redirect-to-login patterns
                if not any(kw in body.lower() for kw in ("login", "sign in", "unauthorized", "forbidden")):
                    return _make_finding(
                        "HIGH",
                        f"Broken Access Control (unauthenticated): {url} returns data without auth. "
                        f"Rule: \"{constraint.rule}\"",
                        url=url,
                        evidence=body,
                        rule=constraint.rule,
                    )

        elif constraint.test_type == "other_user" and secondary_cookies:
            # Fire request as User B
            if method == "GET":
                resp = await session.get(url, cookies=secondary_cookies, timeout=10)
            else:
                resp = await session.post(url, cookies=secondary_cookies, timeout=10)

            if resp.status_code in range(200, 300) and len(resp.content) > 100:
                body = resp.text[:300]
                # Check User A identifying data appears in User B's response
                a_ids = [v for v in session_cookies.values() if len(v) > 4]
                if any(a_id in body for a_id in a_ids):
                    return _make_finding(
                        "CRITICAL",
                        f"IDOR / Cross-User Data Leak: {url} returns User A data to User B. "
                        f"Rule: \"{constraint.rule}\"",
                        url=url,
                        evidence=body,
                        rule=constraint.rule,
                    )
                # Softer check: any 200 accessing another user's supposed resource
                return _make_finding(
                    "HIGH",
                    f"Potential IDOR: {url} returned 200 to secondary user. "
                    f"Rule: \"{constraint.rule}\"",
                    url=url,
                    evidence=body[:200],
                    rule=constraint.rule,
                )

        elif constraint.test_type in ("non_admin", "role_escalation"):
            # Test if authenticated non-admin can reach admin endpoints
            admin_paths = ["/admin", "/admin/users", "/admin/settings",
                           "/dashboard/admin", "/management", "/superuser"]
            for apath in admin_paths:
                aurl = base_url.rstrip("/") + apath
                resp = await session.get(aurl, cookies=session_cookies, timeout=8)
                if resp.status_code in range(200, 300) and len(resp.content) > 200:
                    body = resp.text[:300]
                    if not any(kw in body.lower() for kw in ("forbidden", "not authorized")):
                        return _make_finding(
                            "HIGH",
                            f"Privilege Escalation: {aurl} accessible to non-admin user. "
                            f"Rule: \"{constraint.rule}\"",
                            url=aurl,
                            evidence=body,
                            rule=constraint.rule,
                        )

        elif constraint.test_type == "mass_assign":
            # Try adding admin/role params to form POSTs
            for form in form_endpoints[:5]:
                form_url = str(form.get("url") or "")
                if not form_url:
                    continue
                for param in _MASS_ASSIGN_PARAMS:
                    payload = {param: "admin", "username": "spectra_test",
                               "email": "spectra@test.local", "password": "Phantom!Test123"}
                    try:
                        resp = await session.post(form_url, data=payload,
                                                  cookies=session_cookies, timeout=10)
                        if resp.status_code in range(200, 302):
                            # Check if the privileged param was reflected / accepted
                            if param in resp.text or "admin" in resp.text.lower():
                                return _make_finding(
                                    "HIGH",
                                    f"Mass Assignment: parameter '{param}=admin' accepted at {form_url}. "
                                    f"Rule: \"{constraint.rule}\"",
                                    url=form_url,
                                    evidence=resp.text[:300],
                                    rule=constraint.rule,
                                )
                    except Exception:
                        continue

    except (httpx.RequestError, asyncio.TimeoutError):
        pass
    return None


# ── Main entry point ───────────────────────────────────────────────────────────

async def run_spectra(
    crawler_result: Dict[str, Any],
    base_url: str,
    session_cookies: Dict[str, str],
    broadcast_fn: Optional[Callable],
    llm_url: str = OLLAMA_URL,
    model: str = "llama3.1",
    secondary_cookies: Optional[Dict[str, str]] = None,
    timeout: float = 90.0,
) -> List[Dict[str, Any]]:
    """
    SPECTRA: extract semantic security constraints from crawled content
    and test whether the application actually enforces them.

    Returns a list of findings in Phantom AI standard format.
    """

    async def push(msg: str):
        if broadcast_fn:
            try:
                await broadcast_fn({"type": "spectra_log", "message": msg, "target": base_url})
            except Exception:
                pass

    await push("🧩 SPECTRA: extracting semantic security constraints from crawled content…")

    findings: List[Dict[str, Any]] = []
    visited_urls = list(crawler_result.get("visited_urls") or [])
    form_endpoints = list(crawler_result.get("form_endpoints") or [])

    # ── Step 1: Extract constraints ───────────────────────────────────────────
    try:
        constraints = await asyncio.wait_for(
            extract_constraints(crawler_result, llm_url, model),
            timeout=30.0,
        )
    except asyncio.TimeoutError:
        await push("🧩 SPECTRA: LLM extraction timed out — using regex fallback")
        context = _build_context_bundle(crawler_result)
        constraints = _extract_via_regex(context, visited_urls)

    if not constraints:
        await push("🧩 SPECTRA: no security constraints found in crawled content")
        return findings

    await push(f"🧩 SPECTRA: found {len(constraints)} security constraint(s) to test")
    for c in constraints:
        await push(f"🧩   constraint [{c.test_type}]: \"{c.rule}\" → {c.resource}")

    # ── Step 2: Test each constraint ──────────────────────────────────────────
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    async with httpx.AsyncClient(
        follow_redirects=True,
        verify=False,
        limits=limits,
    ) as session:
        tasks = [
            test_constraint(
                session, c, base_url, session_cookies,
                secondary_cookies, visited_urls, form_endpoints,
            )
            for c in constraints
        ]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        except asyncio.TimeoutError:
            results = []

    for r in results:
        if r:
            findings.append(r)
            await push(f"🔥 SPECTRA FINDING [{r['severity']}]: {r['description'][:120]}")

    await push(f"🧩 SPECTRA done — {len(findings)} finding(s)")
    return findings
