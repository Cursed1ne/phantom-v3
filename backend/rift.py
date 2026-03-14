"""
RIFT — Race Condition & Timing Side-Channel Finder
Patent Pending — Doshan / Phantom AI v3

Gap it fills: TOCTOU / double-spend / concurrent state mutation is
unsolved by any automated tool. RIFT is the first engine that:

  1. Semantically identifies state-modifying endpoints by keyword analysis
  2. Fires N=20 truly concurrent requests using asyncio.gather
  3. Detects idempotency violations (race condition)
  4. Measures response-time oracle for valid vs. invalid parameters
     to reveal user-enumeration / timing side-channels

Based on OWASP Top 10 A04 (Insecure Design) + CWE-362 (TOCTOU).
"""

from __future__ import annotations

import asyncio
import statistics
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

# ── Constants ─────────────────────────────────────────────────────────────────

_CVSS: Dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.5,
    "LOW": 3.5,
    "INFO": 1.0,
}

# Keywords that suggest a one-shot or state-mutating operation
RACY_KEYWORDS = {
    "transfer", "buy", "purchase", "redeem", "apply", "book",
    "vote", "use", "submit", "checkout", "pay", "withdraw",
    "claim", "consume", "spend", "activate", "gift", "coupon",
    "order", "reserve", "charge", "debit", "refund", "discount",
}

_TIMING_CANDIDATE_PARAMS = [
    "username", "email", "user", "login", "account",
    "token", "id", "code", "key",
]

# How many concurrent requests to fire
_BURST_COUNT = 20

# Minimum body length to consider a response non-trivial
_MIN_BODY = 20

# Timing side-channel threshold in seconds
_TIMING_THRESHOLD_S = 0.10


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class RacyEndpoint:
    url: str
    method: str
    body: Dict[str, str]
    reason: str


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
        "tool":        "RIFT",
        "agent":       "rift",
        "module":      "Race Condition & Timing Side-Channel Finder",
        "patent":      "Patent Pending — Doshan",
        "iteration":   1,
        "cvss":        _CVSS.get(sev, 1.0),
        "raw_output":  evidence[:600],
        "url":         url,
        "created_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "owasp":       "A04:2021 – Insecure Design",
        "cwe":         "CWE-362",
    }


def _url_is_racy(url: str, method: str) -> Optional[str]:
    """Return a reason string if the URL+method looks like a state-mutating endpoint."""
    u = url.lower()
    for kw in RACY_KEYWORDS:
        if kw in u:
            return f"URL contains racy keyword '{kw}'"
    # POST/PUT/PATCH to any endpoint is potentially state-mutating
    if method.upper() in ("POST", "PUT", "PATCH"):
        return f"{method.upper()} request to {url}"
    return None


def _extract_numeric_fields(body_text: str) -> List[str]:
    """Try to find numeric fields in a JSON response for divergence analysis."""
    import re
    return re.findall(r'"(\w+)"\s*:\s*(\d+(?:\.\d+)?)', body_text)


# ── Endpoint identification ────────────────────────────────────────────────────

def identify_racy_endpoints(
    traffic_log: List[Dict[str, Any]],
    form_endpoints: List[Dict[str, Any]],
    base_url: str,
) -> List[RacyEndpoint]:
    seen: set = set()
    candidates: List[RacyEndpoint] = []

    for entry in traffic_log:
        url    = str(entry.get("url") or "")
        method = str(entry.get("method") or "GET").upper()
        body   = entry.get("body") or {}
        if isinstance(body, str):
            try:
                import json as _json
                body = _json.loads(body)
            except Exception:
                body = {}
        reason = _url_is_racy(url, method)
        if reason and url not in seen:
            seen.add(url)
            candidates.append(RacyEndpoint(url=url, method=method,
                                           body=body, reason=reason))

    for form in form_endpoints:
        url    = str(form.get("url") or "")
        method = str(form.get("method") or "POST").upper()
        fields = form.get("fields") or []
        body   = {f.get("name", "field"): "test" for f in fields
                  if f.get("name") and f.get("type") not in ("submit", "button")}
        reason = _url_is_racy(url, method)
        if reason and url not in seen:
            seen.add(url)
            candidates.append(RacyEndpoint(url=url, method=method,
                                           body=body, reason=reason))

    return candidates[:10]  # cap to avoid flooding


# ── Burst testing ──────────────────────────────────────────────────────────────

async def _single_request(
    session: httpx.AsyncClient,
    endpoint: RacyEndpoint,
    cookies: Dict[str, str],
) -> Optional[httpx.Response]:
    try:
        if endpoint.method in ("POST", "PUT", "PATCH"):
            return await session.request(
                endpoint.method, endpoint.url,
                data=endpoint.body, cookies=cookies, timeout=12,
            )
        else:
            return await session.request(
                endpoint.method, endpoint.url,
                params=endpoint.body, cookies=cookies, timeout=12,
            )
    except Exception:
        return None


async def _burst(
    session: httpx.AsyncClient,
    endpoint: RacyEndpoint,
    cookies: Dict[str, str],
    n: int = _BURST_COUNT,
) -> List[Optional[httpx.Response]]:
    """Fire n truly-concurrent requests to endpoint."""
    tasks = [asyncio.create_task(_single_request(session, endpoint, cookies))
             for _ in range(n)]
    return list(await asyncio.gather(*tasks, return_exceptions=False))


def _analyze_burst(
    endpoint: RacyEndpoint,
    responses: List[Optional[httpx.Response]],
) -> Optional[Dict[str, Any]]:
    """
    Analyse burst results for race condition indicators:
    - More than 1 success (2xx) for a one-shot endpoint
    - Numeric field divergence (different amounts in different responses)
    """
    successes = [r for r in responses if r is not None and 200 <= r.status_code < 300]
    if len(successes) <= 1:
        return None

    evidence_parts = [f"{len(successes)}/{len(responses)} requests succeeded"]

    # Check for numeric divergence (double-spend indicator)
    numeric_sets: Dict[str, set] = {}
    for r in successes:
        for fname, fval in _extract_numeric_fields(r.text):
            numeric_sets.setdefault(fname, set()).add(fval)

    divergent = {k: v for k, v in numeric_sets.items() if len(v) > 1}
    if divergent:
        evidence_parts.append(f"Divergent fields: {divergent}")
        severity = "CRITICAL"
    else:
        severity = "HIGH"

    evidence = " | ".join(evidence_parts)
    return _make_finding(
        severity,
        f"Race Condition (TOCTOU): {endpoint.url} — {evidence}. "
        f"Reason: {endpoint.reason}",
        url=endpoint.url,
        evidence=evidence,
    )


# ── Timing side-channel ────────────────────────────────────────────────────────

async def test_timing_sidechannel(
    session: httpx.AsyncClient,
    url: str,
    param: str,
    valid_val: str,
    invalid_val: str,
    cookies: Dict[str, str],
    n: int = 10,
) -> Optional[Dict[str, Any]]:
    """
    Measures response-time delta for valid vs. invalid parameter values.
    >100ms delta → timing oracle (user enumeration / side-channel).
    """
    async def _timed_get(val: str) -> float:
        t0 = time.perf_counter()
        try:
            await session.get(url, params={param: val}, cookies=cookies, timeout=12)
        except Exception:
            pass
        return time.perf_counter() - t0

    valid_times   = [await _timed_get(valid_val)   for _ in range(n)]
    invalid_times = [await _timed_get(invalid_val) for _ in range(n)]

    if len(valid_times) < 3 or len(invalid_times) < 3:
        return None

    delta = abs(statistics.mean(valid_times) - statistics.mean(invalid_times))
    if delta < _TIMING_THRESHOLD_S:
        return None

    evidence = (
        f"valid_mean={statistics.mean(valid_times)*1000:.0f}ms "
        f"invalid_mean={statistics.mean(invalid_times)*1000:.0f}ms "
        f"delta={delta*1000:.0f}ms"
    )
    return _make_finding(
        "MEDIUM",
        f"Timing Side-Channel at {url}: parameter '{param}' reveals valid/invalid "
        f"values via response-time difference ({delta*1000:.0f}ms). "
        f"Enables user enumeration.",
        url=url,
        evidence=evidence,
    )


# ── Main entry point ───────────────────────────────────────────────────────────

async def run_rift(
    crawler_result: Dict[str, Any],
    base_url: str,
    session_cookies: Dict[str, str],
    broadcast_fn: Optional[Callable],
    timeout: float = 90.0,
) -> List[Dict[str, Any]]:
    """
    RIFT: find race conditions and timing side-channels in the target application.

    Returns a list of findings in Phantom AI standard format.
    """

    async def push(msg: str):
        if broadcast_fn:
            try:
                await broadcast_fn({"type": "rift_log", "message": msg, "target": base_url})
            except Exception:
                pass

    await push("⚡ RIFT: scanning for race conditions and timing side-channels…")

    findings: List[Dict[str, Any]] = []
    traffic_log    = list(crawler_result.get("traffic_log") or [])
    form_endpoints = list(crawler_result.get("form_endpoints") or [])
    visited_urls   = list(crawler_result.get("visited_urls") or [])

    # ── Step 1: Identify racy endpoints ───────────────────────────────────────
    racy = identify_racy_endpoints(traffic_log, form_endpoints, base_url)
    if not racy:
        await push("⚡ RIFT: no racy endpoints identified — skipping burst test")
    else:
        await push(f"⚡ RIFT: identified {len(racy)} racy endpoint(s) for burst testing")

    # ── Step 2: Burst test ─────────────────────────────────────────────────────
    limits = httpx.Limits(max_connections=25, max_keepalive_connections=10)
    async with httpx.AsyncClient(
        follow_redirects=True,
        verify=False,
        limits=limits,
    ) as session:
        # Race-condition bursts
        for ep in racy:
            await push(f"⚡   racing {ep.method} {ep.url} ({_BURST_COUNT} concurrent) — {ep.reason}")
            try:
                responses = await asyncio.wait_for(
                    _burst(session, ep, session_cookies),
                    timeout=30.0,
                )
                finding = _analyze_burst(ep, responses)
                if finding:
                    findings.append(finding)
                    await push(f"🔥 RIFT FINDING [{finding['severity']}]: {finding['description'][:120]}")
                else:
                    await push(f"⚡   no race condition detected at {ep.url}")
            except asyncio.TimeoutError:
                await push(f"⚡   burst timed out at {ep.url}")
            except Exception as e:
                await push(f"⚡   burst error at {ep.url}: {e}")

        # ── Step 3: Timing side-channel probes ────────────────────────────────
        await push("⚡ RIFT: probing for timing side-channels (user enumeration)…")
        login_paths = [
            base_url.rstrip("/") + p
            for p in ["/login", "/signin", "/auth/login", "/users/login",
                      "/api/login", "/api/auth", "/account/login"]
        ] + [u for u in visited_urls if any(kw in u.lower() for kw in ("login", "signin", "auth"))]

        for url in login_paths[:5]:
            for param in _TIMING_CANDIDATE_PARAMS[:3]:
                try:
                    finding = await asyncio.wait_for(
                        test_timing_sidechannel(
                            session, url, param,
                            valid_val="admin",
                            invalid_val="__no_such_user_phantom__",
                            cookies={},
                            n=6,
                        ),
                        timeout=20.0,
                    )
                    if finding:
                        findings.append(finding)
                        await push(f"🔥 RIFT FINDING [{finding['severity']}]: {finding['description'][:120]}")
                        break  # one finding per URL is enough
                except (asyncio.TimeoutError, Exception):
                    continue

    await push(f"⚡ RIFT done — {len(findings)} finding(s)")
    return findings
