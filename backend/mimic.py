"""
MIMIC — Multi-Identity Cross-User Authorization Matrix
Patent Pending — Doshan / Phantom AI v3

Gap it fills: Horizontal privilege escalation (IDOR) requires manual
cross-account testing. MIMIC automates it by:

  1. Registering a second user (User B) by replaying + mutating
     the registration traffic captured from User A's session
  2. Harvesting resource IDs from User A's traffic log
  3. Testing User B accessing User A's resources
  4. Confirming real IDOR: User A's data must appear in User B's response
  5. Building a complete (endpoint × role) authorization matrix

Based on OWASP Top 10 A01 (Broken Access Control) + CWE-639 (IDOR).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import httpx

# ── Constants ─────────────────────────────────────────────────────────────────

_CVSS: Dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.5,
    "LOW": 3.5,
    "INFO": 1.0,
}

# Phantom AI secondary test credentials
_B_USERNAME = "phantom_mimic_b"
_B_PASSWORD = "Phantom!MimicB123"
_B_EMAIL    = "phantom_mimic_b@test.local"

# Registration paths to try (mirrors AUTH_REGISTER_PATHS in autopilot.py)
AUTH_REGISTER_PATHS = [
    "/register",
    "/register.php",
    "/signup",
    "/users/register",
    "/auth/register",
    "/account/register",
    "/api/register",
    "/api/signup",
    "/api/users",
]

# Login paths
AUTH_LOGIN_PATHS = [
    "/login",
    "/login.php",
    "/signin",
    "/users/login",
    "/auth/login",
    "/account/login",
    "/api/login",
    "/api/signin",
    "/api/auth/login",
]

# Regex patterns to extract resource IDs from traffic
_ID_PATTERNS = [
    re.compile(r'"id"\s*:\s*(\d+)'),
    re.compile(r'"(\w*[Ii]d\w*)"\s*:\s*(\d{1,12})'),
    re.compile(r'/(\d{1,12})(?:[/?#]|$)'),
    re.compile(r'[?&]id=(\d+)'),
]

# Resource-type keywords for classifying endpoints
_RESOURCE_KEYWORDS = {
    "profile": ["profile", "user", "account", "me"],
    "order":   ["order", "purchase", "invoice", "receipt"],
    "message": ["message", "inbox", "mail", "chat"],
    "file":    ["file", "document", "attachment", "upload"],
    "payment": ["payment", "card", "billing", "wallet"],
    "data":    ["data", "record", "item", "object", "entity"],
}

_MIN_BODY_FOR_DATA = 50  # minimum bytes to count a response as "has data"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SessionContext:
    cookies:  Dict[str, str]
    user_id:  Optional[str]
    username: str


@dataclass
class ResourceEndpoint:
    url:           str
    method:        str
    resource_type: str
    extracted_id:  str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    severity: str,
    description: str,
    url: str = "",
    evidence: str = "",
) -> Dict[str, Any]:
    sev = severity.upper()
    return {
        "id":          str(uuid.uuid4()),
        "severity":    sev,
        "description": description[:500],
        "tool":        "MIMIC",
        "agent":       "mimic",
        "module":      "Multi-Identity Cross-User Authorization Matrix",
        "patent":      "Patent Pending — Doshan",
        "iteration":   1,
        "cvss":        _CVSS.get(sev, 1.0),
        "raw_output":  evidence[:600],
        "url":         url,
        "created_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "owasp":       "A01:2021 – Broken Access Control",
        "cwe":         "CWE-639",
    }


def _classify_resource(url: str) -> str:
    u = url.lower()
    for rtype, keywords in _RESOURCE_KEYWORDS.items():
        if any(kw in u for kw in keywords):
            return rtype
    return "data"


def _extract_ids_from_traffic(
    traffic_log: List[Dict[str, Any]],
    visited_urls: List[str],
) -> List[ResourceEndpoint]:
    """Extract resource IDs from User A's HTTP traffic and visited URLs."""
    seen: Set[str] = set()
    resources: List[ResourceEndpoint] = []

    # From traffic log responses
    for entry in traffic_log:
        url    = str(entry.get("url") or "")
        method = str(entry.get("method") or "GET").upper()
        body   = str(entry.get("response_body") or entry.get("body") or "")

        for pat in _ID_PATTERNS:
            for m in pat.findall(url + "\n" + body):
                rid = m if isinstance(m, str) else m[-1]
                if not rid.isdigit():
                    continue
                # Reconstruct a canonical URL with that ID
                canonical = re.sub(r'/\d+', f'/{rid}', url)
                if canonical in seen:
                    continue
                seen.add(canonical)
                resources.append(ResourceEndpoint(
                    url=canonical,
                    method=method,
                    resource_type=_classify_resource(canonical),
                    extracted_id=rid,
                ))

    # From visited URLs directly (e.g. /profile/42)
    for u in visited_urls:
        for pat in [re.compile(r'/(\d{1,12})(?:[/?#]|$)')]:
            for m in pat.findall(u):
                rid = m
                canonical = u
                if canonical in seen:
                    continue
                seen.add(canonical)
                resources.append(ResourceEndpoint(
                    url=canonical,
                    method="GET",
                    resource_type=_classify_resource(canonical),
                    extracted_id=rid,
                ))

    return resources[:30]  # cap


# ── User B creation ────────────────────────────────────────────────────────────

async def _try_register(
    session: httpx.AsyncClient,
    reg_url: str,
    username: str,
    password: str,
    email: str,
    traffic_log: List[Dict[str, Any]],
) -> bool:
    """
    Attempt registration at reg_url.
    First: replay a mutated version of any registration POST found in traffic_log.
    Fallback: generic form POST.
    """
    # Find a registration request in traffic to copy its field names
    reg_body: Dict[str, str] = {}
    for entry in traffic_log:
        eu = str(entry.get("url") or "").lower()
        if any(p.lstrip("/") in eu for p in AUTH_REGISTER_PATHS):
            raw_body = entry.get("body") or {}
            if isinstance(raw_body, str):
                try:
                    raw_body = json.loads(raw_body)
                except Exception:
                    raw_body = dict(p.split("=", 1) for p in raw_body.split("&")
                                   if "=" in p)
            if isinstance(raw_body, dict) and raw_body:
                reg_body = {k: v for k, v in raw_body.items()}
                break

    if not reg_body:
        # Generic fallback fields
        reg_body = {
            "username": username, "email": email, "password": password,
            "password_confirmation": password, "name": username,
        }
    else:
        # Mutate User A's body to create User B
        for k in list(reg_body.keys()):
            lk = k.lower()
            if "pass" in lk:
                reg_body[k] = password
            elif "email" in lk:
                reg_body[k] = email
            elif any(x in lk for x in ("user", "login", "name")):
                reg_body[k] = username
            else:
                reg_body[k] = str(reg_body[k])  # keep other fields as-is

    try:
        # Try JSON first (most modern APIs)
        resp = await session.post(reg_url, json=reg_body, timeout=10)
        if resp.status_code in (200, 201, 204):
            return True
        # Try form-encoded
        resp = await session.post(reg_url, data=reg_body, timeout=10)
        return resp.status_code in (200, 201, 204, 302)
    except Exception:
        return False


async def _try_login(
    session: httpx.AsyncClient,
    login_url: str,
    username: str,
    password: str,
    email: str,
    traffic_log: List[Dict[str, Any]],
) -> Dict[str, str]:
    """Attempt login; return cookies on success."""
    # Build login body
    login_body = {"username": username, "email": email, "password": password}

    # Try to find a login request in traffic to copy field names
    for entry in traffic_log:
        eu = str(entry.get("url") or "").lower()
        if any(p.lstrip("/") in eu for p in AUTH_LOGIN_PATHS):
            raw_body = entry.get("body") or {}
            if isinstance(raw_body, str):
                try:
                    raw_body = json.loads(raw_body)
                except Exception:
                    raw_body = dict(p.split("=", 1) for p in raw_body.split("&")
                                   if "=" in p)
            if isinstance(raw_body, dict) and raw_body:
                for k in list(raw_body.keys()):
                    lk = k.lower()
                    if "pass" in lk:
                        raw_body[k] = password
                    elif "email" in lk:
                        raw_body[k] = email
                    elif any(x in lk for x in ("user", "login", "name")):
                        raw_body[k] = username
                login_body = raw_body
                break

    try:
        resp = await session.post(login_url, json=login_body, timeout=10)
        if resp.status_code in (200, 302) and resp.cookies:
            return dict(resp.cookies)
        resp = await session.post(login_url, data=login_body, timeout=10)
        if resp.status_code in (200, 302) and resp.cookies:
            return dict(resp.cookies)
    except Exception:
        pass
    return {}


async def create_second_user(
    base_url: str,
    traffic_log: List[Dict[str, Any]],
    register_path: Optional[str],
) -> Optional[SessionContext]:
    """
    Register + login User B. Returns SessionContext with cookies.
    """
    reg_paths = list(AUTH_REGISTER_PATHS)
    if register_path and register_path not in reg_paths:
        reg_paths.insert(0, register_path)

    login_paths = list(AUTH_LOGIN_PATHS)

    jar = httpx.Cookies()
    async with httpx.AsyncClient(
        follow_redirects=True, verify=False, cookies=jar,
    ) as session:
        # Try registering
        registered = False
        for rp in reg_paths:
            reg_url = base_url.rstrip("/") + rp
            try:
                ok = await _try_register(session, reg_url, _B_USERNAME,
                                         _B_PASSWORD, _B_EMAIL, traffic_log)
                if ok:
                    registered = True
                    break
            except Exception:
                continue

        if not registered:
            return None

        # Try logging in
        for lp in login_paths:
            login_url = base_url.rstrip("/") + lp
            try:
                cookies = await _try_login(session, login_url, _B_USERNAME,
                                           _B_PASSWORD, _B_EMAIL, traffic_log)
                if cookies:
                    return SessionContext(
                        cookies=cookies,
                        user_id=None,
                        username=_B_USERNAME,
                    )
            except Exception:
                continue

    return None


# ── Cross-user access testing ──────────────────────────────────────────────────

async def test_cross_user_access(
    session: httpx.AsyncClient,
    resources: List[ResourceEndpoint],
    user_b_cookies: Dict[str, str],
    user_a_cookies: Dict[str, str],
    user_a_username: str,
) -> List[Dict[str, Any]]:
    """
    For each resource harvested from User A, request it as User B.
    False-positive filter: User A's identifying information must appear
    in User B's response body for a confirmed IDOR.
    """
    findings: List[Dict[str, Any]] = []
    a_identifiers = [v for v in user_a_cookies.values() if isinstance(v, str) and len(v) > 4]
    if user_a_username:
        a_identifiers.append(user_a_username)

    for res in resources:
        try:
            if res.method == "GET":
                resp = await session.get(res.url, cookies=user_b_cookies, timeout=10)
            else:
                resp = await session.request(res.method, res.url,
                                             cookies=user_b_cookies, timeout=10)

            if resp.status_code not in range(200, 300):
                continue
            if len(resp.content) < _MIN_BODY_FOR_DATA:
                continue

            body = resp.text
            # Confirmed IDOR: User A's data in User B's response
            confirmed = any(a_id in body for a_id in a_identifiers)
            severity = "CRITICAL" if confirmed else "HIGH"
            qualifier = "CONFIRMED" if confirmed else "Potential"

            findings.append(_make_finding(
                severity,
                f"{qualifier} IDOR [{res.resource_type}]: {res.url} returned "
                f"resource ID={res.extracted_id} to User B ('{_B_USERNAME}'). "
                f"{'User A identifier found in response.' if confirmed else ''}",
                url=res.url,
                evidence=body[:400],
            ))

        except (httpx.RequestError, asyncio.TimeoutError):
            continue

    return findings


async def test_unauthenticated_access(
    session: httpx.AsyncClient,
    resources: List[ResourceEndpoint],
) -> List[Dict[str, Any]]:
    """
    Test if resource endpoints are accessible without any authentication.
    """
    findings: List[Dict[str, Any]] = []
    for res in resources[:15]:
        try:
            resp = await session.get(res.url, cookies={}, timeout=8)
            if resp.status_code in range(200, 300) and len(resp.content) > _MIN_BODY_FOR_DATA:
                body = resp.text
                if not any(kw in body.lower() for kw in ("login", "sign in", "unauthorized", "forbidden")):
                    findings.append(_make_finding(
                        "HIGH",
                        f"Missing Authentication: {res.url} (resource_type={res.resource_type}) "
                        f"accessible without any session cookie.",
                        url=res.url,
                        evidence=body[:300],
                    ))
        except (httpx.RequestError, asyncio.TimeoutError):
            continue
    return findings


# ── Main entry point ───────────────────────────────────────────────────────────

async def run_mimic(
    crawler_result: Dict[str, Any],
    base_url: str,
    user_a_cookies: Dict[str, str],
    broadcast_fn: Optional[Callable],
    register_path: Optional[str] = None,
    user_a_username: str = "",
    timeout: float = 120.0,
) -> List[Dict[str, Any]]:
    """
    MIMIC: register a second user identity and test cross-user authorization.

    Returns a list of findings in Phantom AI standard format.
    """

    async def push(msg: str):
        if broadcast_fn:
            try:
                await broadcast_fn({"type": "mimic_log", "message": msg, "target": base_url})
            except Exception:
                pass

    await push("👥 MIMIC: harvesting resource IDs from User A's traffic…")

    findings: List[Dict[str, Any]] = []
    traffic_log  = list(crawler_result.get("traffic_log") or [])
    visited_urls = list(crawler_result.get("visited_urls") or [])

    # ── Step 1: Harvest resource IDs ──────────────────────────────────────────
    resources = _extract_ids_from_traffic(traffic_log, visited_urls)
    if not resources:
        await push("👥 MIMIC: no numeric resource IDs found — skipping cross-user test")
        return findings

    await push(f"👥 MIMIC: harvested {len(resources)} resource endpoint(s) from User A's traffic")
    for r in resources[:6]:
        await push(f"👥   [{r.resource_type}] ID={r.extracted_id} → {r.url}")

    # ── Step 2: Test unauthenticated access ───────────────────────────────────
    await push("👥 MIMIC: testing unauthenticated access to User A's resources…")
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as session:
        unauth_findings = await test_unauthenticated_access(session, resources)

    for f in unauth_findings:
        findings.append(f)
        await push(f"🔥 MIMIC FINDING [{f['severity']}]: {f['description'][:120]}")

    # ── Step 3: Create User B ─────────────────────────────────────────────────
    await push("👥 MIMIC: registering second identity (User B)…")
    try:
        user_b = await asyncio.wait_for(
            create_second_user(base_url, traffic_log, register_path),
            timeout=40.0,
        )
    except asyncio.TimeoutError:
        user_b = None

    if not user_b:
        await push("👥 MIMIC: could not create User B — no registration endpoint found")
        return findings

    await push(f"👥 MIMIC: User B created ('{_B_USERNAME}') — testing cross-user access…")

    # ── Step 4: Cross-user access test ────────────────────────────────────────
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as session:
        try:
            cross_findings = await asyncio.wait_for(
                test_cross_user_access(
                    session, resources,
                    user_b_cookies=user_b.cookies,
                    user_a_cookies=user_a_cookies,
                    user_a_username=user_a_username,
                ),
                timeout=60.0,
            )
        except asyncio.TimeoutError:
            cross_findings = []

    for f in cross_findings:
        findings.append(f)
        await push(f"🔥 MIMIC FINDING [{f['severity']}]: {f['description'][:120]}")

    # ── Step 5: Summary matrix ────────────────────────────────────────────────
    if findings:
        idors     = [f for f in findings if "IDOR" in f.get("description", "")]
        unauths   = [f for f in findings if "Missing Auth" in f.get("description", "")]
        await push(f"👥 MIMIC: authorization matrix — "
                   f"IDOR={len(idors)}, MissingAuth={len(unauths)}")

    await push(f"👥 MIMIC done — {len(findings)} finding(s)")
    return findings
