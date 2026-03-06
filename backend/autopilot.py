"""
PHANTOM AI v3 — Autopilot scan engine.

This module provides a single async entry point:
    run_autopilot_scan(config: dict) -> dict

It performs:
  1) Browser-assisted crawl (Playwright when available, HTTP fallback otherwise)
  2) Optional auth automation (register/login best-effort)
  3) Multi-tool scan orchestration (nuclei, nmap, whatweb, nikto, sqlmap, ffuf, gobuster, feroxbuster)
  4) JavaScript static inspection and lightweight CVE hinting
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urldefrag, urlparse

import httpx


DEFAULT_AUTOPILOT_TOOLS = [
    "whatweb",
    "nmap",
    "nuclei",
    "nikto",
    "sqlmap",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "searchsploit",
]

WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/local/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]

AUTH_LOGIN_PATHS = [
    "/login",
    "/login.php",
    "/signin",
    "/users/login",
    "/auth/login",
    "/account/login",
]

AUTH_REGISTER_PATHS = [
    "/register",
    "/register.php",
    "/signup",
    "/users/register",
    "/auth/register",
    "/account/register",
]

JS_SINK_RULES = [
    ("MEDIUM", r"\beval\s*\(", "Unsafe sink: eval() usage in JavaScript"),
    ("MEDIUM", r"\bdocument\.write\s*\(", "Unsafe sink: document.write() usage"),
    ("MEDIUM", r"\.innerHTML\s*=", "Unsafe sink: direct innerHTML assignment"),
    ("MEDIUM", r"\bsetTimeout\s*\(\s*['\"]", "Potential string-based setTimeout execution"),
]

JS_SECRET_RULES = [
    ("HIGH", r"AKIA[0-9A-Z]{16}", "Potential AWS access key exposed in JavaScript"),
    ("HIGH", r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Potential API key exposed in JavaScript"),
    ("HIGH", r"(?i)secret\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Potential hardcoded secret in JavaScript"),
    ("MEDIUM", r"(?i)token\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]", "Potential hardcoded token in JavaScript"),
]

JS_LIB_PATTERNS = [
    ("jquery", r"jquery[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("angularjs", r"angular[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("react", r"react[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("vue", r"vue[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
]

TECH_HINT_PATTERNS = [
    ("nginx", r"nginx[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("php", r"PHP[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("apache", r"Apache[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("openssl", r"OpenSSL[/ ]([0-9]+\.[0-9]+(?:\.[0-9a-z]+)?)"),
    ("openssh", r"OpenSSH[ /]([0-9]+\.[0-9]+(?:p[0-9]+)?)"),
]

HTTP_BODY_SAMPLE = 2500
HTTP_HEADER_ALLOWLIST = {
    "host",
    "content-type",
    "content-length",
    "cookie",
    "authorization",
    "x-requested-with",
    "origin",
    "referer",
    "accept",
    "user-agent",
    "server",
    "set-cookie",
    "location",
    "cache-control",
}

REQUEST_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _normalize_target(raw_target: str) -> Tuple[str, str, str]:
    raw = (raw_target or "").strip()
    if not raw:
        raise ValueError("target is required")
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError(f"invalid target: {raw_target}")
    host = parsed.hostname
    port = f":{parsed.port}" if parsed.port else ""
    base = f"{parsed.scheme}://{host}{port}"
    return base.rstrip("/"), host, parsed.scheme


def _same_origin(url: str, host: str) -> bool:
    p = urlparse(url)
    return bool(p.scheme in ("http", "https") and p.hostname == host)


def _normalize_in_scope_url(base_url: str, href: str, host: str) -> Optional[str]:
    if not href:
        return None
    h = href.strip()
    if not h:
        return None
    if h.startswith(("javascript:", "mailto:", "tel:")):
        return None
    resolved = urljoin(base_url, h)
    resolved, _ = urldefrag(resolved)
    if not _same_origin(resolved, host):
        return None
    p = urlparse(resolved)
    if p.scheme not in ("http", "https"):
        return None
    path = p.path or "/"
    query = f"?{p.query}" if p.query else ""
    return f"{p.scheme}://{p.netloc}{path}{query}"


def _dedupe(items: List[str], limit: Optional[int] = None) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for item in items:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out


def _truncate(text: str, n: int = 14000) -> str:
    t = str(text or "")
    return t if len(t) <= n else f"{t[:n]}\n...[truncated]"


def _wordlist_path() -> Optional[str]:
    for p in WORDLIST_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def _module_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _safe_headers(headers: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if headers is None:
        return out
    if isinstance(headers, dict):
        items = headers.items()
    elif hasattr(headers, "items"):
        items = headers.items()
    else:
        return out
    for k, v in items:
        key = str(k or "").strip().lower()
        if not key:
            continue
        if key in HTTP_HEADER_ALLOWLIST or key.startswith("x-"):
            out[key] = _truncate(str(v or ""), 260)
    return out


def _safe_body(value: Any, n: int = HTTP_BODY_SAMPLE) -> str:
    return _truncate(str(value or ""), n)


def _extract_attr(attrs: str, attr_name: str) -> str:
    m = re.search(rf"""\b{re.escape(attr_name)}\s*=\s*["']([^"']+)["']""", attrs or "", re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _extract_forms(html: str, base_url: str, host: str, max_forms: int = 80) -> List[Dict[str, Any]]:
    forms: List[Dict[str, Any]] = []
    for fm in re.finditer(r"""<form\b([^>]*)>(.*?)</form>""", html or "", re.IGNORECASE | re.DOTALL):
        attrs = fm.group(1) or ""
        inner = fm.group(2) or ""
        action = _extract_attr(attrs, "action")
        method = (_extract_attr(attrs, "method") or "get").lower()
        if method not in ("get", "post"):
            method = "get"
        target = _normalize_in_scope_url(base_url, action or base_url, host) or _normalize_in_scope_url(base_url, base_url, host)
        if not target:
            continue

        fields: List[Dict[str, str]] = []
        for im in re.finditer(r"""<input\b([^>]*)>""", inner, re.IGNORECASE | re.DOTALL):
            iattrs = im.group(1) or ""
            name = _extract_attr(iattrs, "name")
            typ = (_extract_attr(iattrs, "type") or "text").lower()
            if not name and typ not in ("email", "password", "search"):
                continue
            if typ in ("submit", "button", "reset", "file"):
                continue
            val = _extract_attr(iattrs, "value")
            fields.append({"name": name or typ, "type": typ, "value": val})

        for tm in re.finditer(r"""<textarea\b([^>]*)>""", inner, re.IGNORECASE | re.DOTALL):
            tattrs = tm.group(1) or ""
            name = _extract_attr(tattrs, "name")
            if name:
                fields.append({"name": name, "type": "textarea", "value": ""})

        forms.append({
            "method": method,
            "url": target,
            "fields": fields[:60],
        })
        if len(forms) >= max_forms:
            break
    return forms


def _build_form_payload(fields: List[Dict[str, str]], username: str, password: str, email: str) -> Dict[str, str]:
    payload: Dict[str, str] = {}
    for f in fields[:30]:
        name = str(f.get("name") or "").strip()
        if not name:
            continue
        lname = name.lower()
        ftype = str(f.get("type") or "").lower()
        cur = str(f.get("value") or "").strip()

        if "pass" in lname or ftype == "password":
            payload[name] = password
        elif "email" in lname or ftype == "email":
            payload[name] = email
        elif any(x in lname for x in ["user", "login", "name"]):
            payload[name] = username
        elif any(x in lname for x in ["search", "query", "q"]):
            payload[name] = "phantom scan"
        elif cur:
            payload[name] = cur[:120]
        else:
            payload[name] = "phantom-test"
    return payload


def _normalize_captured_requests(
    base_url: str,
    host: str,
    captured_requests: Any,
    limit: int = 600,
) -> List[Dict[str, Any]]:
    if not isinstance(captured_requests, list):
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for raw in captured_requests:
        if not isinstance(raw, dict):
            continue
        normalized_url = _normalize_in_scope_url(base_url, str(raw.get("url") or ""), host)
        if not normalized_url:
            continue
        method = str(raw.get("method") or "GET").upper()
        if method not in REQUEST_METHODS:
            method = "GET"
        req_body = _safe_body(raw.get("body") or raw.get("request_body") or "", HTTP_BODY_SAMPLE)
        key = f"{method}|{normalized_url}|{req_body[:120]}"
        if key in seen:
            continue
        seen.add(key)
        status_raw = raw.get("status")
        if status_raw in (None, ""):
            status_raw = raw.get("response_status")
        if status_raw in (None, "") and isinstance(raw.get("response"), dict):
            status_raw = raw.get("response", {}).get("status")
        try:
            status_val = int(status_raw or 0)
        except Exception:
            status_val = 0
        out.append({
            "source": "proxy-history",
            "method": method,
            "url": normalized_url,
            "status": status_val,
            "request_headers": _safe_headers(raw.get("headers") or raw.get("request_headers") or {}),
            "request_body": req_body,
            "response_headers": _safe_headers(raw.get("response_headers") or raw.get("response", {}).get("headers") or {}),
            "response_preview": _safe_body(raw.get("response_body") or raw.get("response", {}).get("body") or "", HTTP_BODY_SAMPLE),
        })
        if len(out) >= max(20, min(limit, 2000)):
            break
    return out


def _merge_traffic_logs(*chunks: Any, limit: int = 2000) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for chunk in chunks:
        if not isinstance(chunk, list):
            continue
        for item in chunk:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or "GET").upper()
            url = str(item.get("url") or "")
            req_body = _safe_body(item.get("request_body") or "", 220)
            key = f"{method}|{url}|{req_body}"
            if key in seen:
                continue
            seen.add(key)
            try:
                status_val = int(item.get("status") or 0)
            except Exception:
                status_val = 0
            out.append({
                "source": str(item.get("source") or "crawler"),
                "method": method,
                "url": url,
                "status": status_val,
                "request_headers": _safe_headers(item.get("request_headers") or {}),
                "request_body": _safe_body(item.get("request_body") or "", HTTP_BODY_SAMPLE),
                "response_headers": _safe_headers(item.get("response_headers") or {}),
                "response_preview": _safe_body(item.get("response_preview") or "", HTTP_BODY_SAMPLE),
            })
            if len(out) >= limit:
                return out
    return out


def _build_exploit_evidence(traffic_log: List[Dict[str, Any]], tool_runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    suspicious: List[Dict[str, Any]] = []
    markers = [
        ("SQLi-payload", r"(union\s+select|or\s+1=1|sleep\(|benchmark\()"),
        ("XSS-payload", r"(<script|onerror=|javascript:)"),
        ("Traversal-payload", r"(\.\./|\.\.\\)"),
        ("Command-injection-payload", r"(;|\|\||`|\$\()"),
    ]
    for item in traffic_log:
        blob = f"{item.get('url')}\n{item.get('request_body')}".lower()
        hit = None
        for name, pat in markers:
            if re.search(pat, blob, re.IGNORECASE):
                hit = name
                break
        if not hit and (item.get("status") or 0) < 400:
            continue
        suspicious.append({
            "signal": hit or "HTTP-error-response",
            "method": item.get("method"),
            "url": item.get("url"),
            "status": item.get("status"),
            "request_body": _safe_body(item.get("request_body") or "", 800),
            "response_preview": _safe_body(item.get("response_preview") or "", 800),
        })
        if len(suspicious) >= 60:
            break

    tool_hits: List[Dict[str, str]] = []
    for run in tool_runs:
        tool = str(run.get("tool") or "")
        out = str(run.get("output") or "")
        for line in out.splitlines():
            t = line.strip()
            if not t:
                continue
            if re.search(r"\[(critical|high|medium|low|info)\]", t, re.IGNORECASE) or re.search(r"CVE-\d{4}-\d{4,7}", t, re.IGNORECASE):
                tool_hits.append({"tool": tool, "line": _truncate(t, 220)})
            if len(tool_hits) >= 180:
                break
        if len(tool_hits) >= 180:
            break

    return {
        "suspicious_http_events": suspicious,
        "tool_signals": tool_hits,
        "counts": {
            "http_events": len(suspicious),
            "tool_signals": len(tool_hits),
        },
    }


def _normalize_workflow_profile(profile: Any) -> Dict[str, Any]:
    p = profile if isinstance(profile, dict) else {}

    def _as_list(val: Any) -> List[str]:
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        if isinstance(val, str):
            return [s.strip() for s in val.split(",") if s.strip()]
        return []

    return {
        "name": str(p.get("name") or "").strip(),
        "login_path": str(p.get("login_path") or "").strip() or None,
        "register_path": str(p.get("register_path") or "").strip() or None,
        "username_selector": str(p.get("username_selector") or "").strip() or None,
        "email_selector": str(p.get("email_selector") or "").strip() or None,
        "password_selector": str(p.get("password_selector") or "").strip() or None,
        "confirm_password_selector": str(p.get("confirm_password_selector") or "").strip() or None,
        "submit_selector": str(p.get("submit_selector") or "").strip() or None,
        "auth_success_markers": _as_list(p.get("auth_success_markers")),
        "auth_fail_markers": _as_list(p.get("auth_fail_markers")),
        "post_login_paths": _as_list(p.get("post_login_paths")),
        "allow_paths": _as_list(p.get("allow_paths")),
        "skip_paths": _as_list(p.get("skip_paths")),
    }


def inspect_dependencies() -> Dict[str, Any]:
    tools = {
        name: {"available": shutil.which(name) is not None, "path": shutil.which(name) or ""}
        for name in ["nuclei", "nmap", "whatweb", "nikto", "sqlmap", "ffuf", "gobuster", "feroxbuster", "searchsploit"]
    }
    return {
        "python_modules": {
            "playwright": _module_available("playwright"),
            "bs4": _module_available("bs4"),
            "httpx": _module_available("httpx"),
        },
        "tools": tools,
        "wordlist": _wordlist_path() or "",
    }


async def _run_cmd(tool: str, args: List[str], timeout: int = 120) -> Dict[str, Any]:
    start = time.time()
    exe = shutil.which(tool)
    if not exe:
        return {
            "tool": tool,
            "args": args,
            "cmd": f"{tool} {' '.join(args)}",
            "available": False,
            "code": -127,
            "duration_s": 0.0,
            "output": f"{tool}: command not found",
        }

    try:
        proc = await asyncio.create_subprocess_exec(
            exe,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {
                "tool": tool,
                "args": args,
                "cmd": f"{tool} {' '.join(args)}",
                "available": True,
                "code": -1,
                "duration_s": round(time.time() - start, 2),
                "output": f"[timeout after {timeout}s]",
            }

        out = (stdout or b"").decode("utf-8", errors="replace") + (stderr or b"").decode("utf-8", errors="replace")
        out = out.strip() or f"[{tool}] completed with no output"
        return {
            "tool": tool,
            "args": args,
            "cmd": f"{tool} {' '.join(args)}",
            "available": True,
            "code": int(proc.returncode or 0),
            "duration_s": round(time.time() - start, 2),
            "output": _truncate(out),
        }
    except Exception as e:
        return {
            "tool": tool,
            "args": args,
            "cmd": f"{tool} {' '.join(args)}",
            "available": True,
            "code": -1,
            "duration_s": round(time.time() - start, 2),
            "output": _truncate(str(e)),
        }


async def _crawl_httpx(
    base_url: str,
    host: str,
    max_pages: int,
    timeout_s: int,
    username: str,
    password: str,
    email: str,
    login_path: Optional[str],
    register_path: Optional[str],
    workflow_profile: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    wf = _normalize_workflow_profile(workflow_profile or {})
    login_attempted = False
    login_success = False
    register_attempted = False
    register_success = False
    errors: List[str] = []

    visited: List[str] = []
    queue: List[str] = [base_url]
    scripts: List[str] = []
    pages: List[Dict[str, Any]] = []
    api_endpoints: List[str] = []
    form_endpoints: List[Dict[str, Any]] = []
    form_submissions: List[Dict[str, Any]] = []
    traffic_log: List[Dict[str, Any]] = []
    submitted_form_keys: Set[str] = set()

    allow_paths = [p.lower() for p in (wf.get("allow_paths") or [])]
    skip_paths = [p.lower() for p in (wf.get("skip_paths") or [])]
    auth_success_markers = [m.lower() for m in (wf.get("auth_success_markers") or ["logout", "sign out", "welcome"])]
    auth_fail_markers = [m.lower() for m in (wf.get("auth_fail_markers") or ["invalid", "incorrect", "failed", "error"])]

    def in_scope_path(url: str) -> bool:
        path_q = f"{urlparse(url).path}?{urlparse(url).query}".lower()
        if any(s in path_q for s in skip_paths):
            return False
        if allow_paths and not any(a in path_q for a in allow_paths):
            return False
        return True

    def push_traffic(
        method: str,
        url: str,
        status: int,
        request_headers: Any = None,
        request_body: Any = "",
        response_headers: Any = None,
        response_preview: Any = "",
        source: str = "httpx",
    ) -> None:
        if not _same_origin(url, host):
            return
        if len(traffic_log) >= 2500:
            return
        traffic_log.append({
            "source": source,
            "method": str(method or "GET").upper(),
            "url": url,
            "status": int(status or 0),
            "request_headers": _safe_headers(request_headers or {}),
            "request_body": _safe_body(request_body, HTTP_BODY_SAMPLE),
            "response_headers": _safe_headers(response_headers or {}),
            "response_preview": _safe_body(response_preview, HTTP_BODY_SAMPLE),
        })

    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True, verify=False) as client:
        register_urls = []
        if register_path:
            register_urls.append(_normalize_in_scope_url(base_url, register_path, host) or "")
        if wf.get("register_path"):
            register_urls.append(_normalize_in_scope_url(base_url, wf.get("register_path"), host) or "")
        register_urls += [_normalize_in_scope_url(base_url, p, host) or "" for p in AUTH_REGISTER_PATHS]
        register_urls = [u for u in _dedupe(register_urls) if u]
        for ru in register_urls[:3]:
            try:
                r = await client.get(ru)
                push_traffic("GET", ru, r.status_code, r.request.headers, "", r.headers, r.text, source="auth-register-discovery")
                body = (r.text or "").lower()
                if "password" not in body and "register" not in body and "sign up" not in body:
                    continue
                register_attempted = True
                payloads = [
                    {"username": username, "password": password, "email": email},
                    {"user": username, "pass": password, "email": email},
                    {"login": username, "password": password, "email": email},
                ]
                for payload in payloads:
                    pr = await client.post(ru, data=payload)
                    push_traffic("POST", ru, pr.status_code, pr.request.headers, payload, pr.headers, pr.text, source="auth-register")
                    b = (pr.text or "").lower()
                    if any(m in b for m in ["already exists", "account created", "successful"]):
                        register_success = True
                        break
                    if "login" in b and "register" not in b:
                        register_success = True
                        break
                if register_success:
                    break
            except Exception as e:
                errors.append(f"httpx register error at {ru}: {e}")

        # Best-effort login bootstrap for known login routes.
        login_urls = []
        if login_path:
            login_urls.append(_normalize_in_scope_url(base_url, login_path, host) or "")
        if wf.get("login_path"):
            login_urls.append(_normalize_in_scope_url(base_url, wf.get("login_path"), host) or "")
        login_urls += [_normalize_in_scope_url(base_url, p, host) or "" for p in AUTH_LOGIN_PATHS]
        login_urls = [u for u in _dedupe(login_urls) if u]
        for lu in login_urls[:4]:
            try:
                r = await client.get(lu)
                push_traffic("GET", lu, r.status_code, r.request.headers, "", r.headers, r.text, source="auth-login-discovery")
                body = (r.text or "").lower()
                if "password" not in body:
                    continue
                login_attempted = True
                payloads = [
                    {"username": username, "password": password},
                    {"email": email, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "password": password},
                    {"username": username, "password": password, "Login": "Login"},
                ]
                for payload in payloads:
                    pr = await client.post(lu, data=payload)
                    push_traffic("POST", lu, pr.status_code, pr.request.headers, payload, pr.headers, pr.text, source="auth-login")
                    b = (pr.text or "").lower()
                    if any(marker in b for marker in auth_success_markers):
                        login_success = True
                        break
                    if any(marker in b for marker in auth_fail_markers):
                        continue
                    if "password" not in b and pr.status_code < 500:
                        login_success = True
                        break
                if login_success:
                    break
            except Exception as e:
                errors.append(f"httpx login error at {lu}: {e}")

        for p in wf.get("post_login_paths") or []:
            u = _normalize_in_scope_url(base_url, p, host)
            if u and u not in queue:
                queue.append(u)

        while queue and len(visited) < max_pages:
            current = queue.pop(0)
            if current in visited:
                continue
            if not in_scope_path(current):
                continue
            try:
                resp = await client.get(current)
                push_traffic("GET", current, resp.status_code, resp.request.headers, "", resp.headers, resp.text, source="crawl")
                text = resp.text or ""
                ltext = text.lower()
                visited.append(current)
                pages.append({"url": current, "status": resp.status_code, "title": _extract_title(text)})

                scripts.extend(_extract_script_srcs(text, current, host))
                links = _extract_links(text, current, host)
                for u in links:
                    if u not in visited and u not in queue:
                        if not in_scope_path(u):
                            continue
                        queue.append(u)

                forms = _extract_forms(text, current, host, max_forms=50)
                for form in forms:
                    f_url = str(form.get("url") or "")
                    method = str(form.get("method") or "get").lower()
                    fields = form.get("fields") or []
                    field_names = [str(x.get("name") or "") for x in fields]
                    form_endpoints.append({
                        "method": method.upper(),
                        "url": f_url,
                        "fields": field_names[:25],
                    })
                    fkey = f"{method}|{f_url}|{','.join(field_names[:20])}"
                    if fkey in submitted_form_keys:
                        continue
                    if len(form_submissions) >= 80:
                        continue
                    if not in_scope_path(f_url):
                        continue
                    if "logout" in f_url.lower():
                        continue

                    payload = _build_form_payload(fields, username, password, email)
                    try:
                        if method == "post":
                            pr = await client.post(f_url, data=payload)
                            push_traffic("POST", f_url, pr.status_code, pr.request.headers, payload, pr.headers, pr.text, source="form-submit")
                        else:
                            pr = await client.get(f_url, params=payload)
                            push_traffic("GET", f_url, pr.status_code, pr.request.headers, payload, pr.headers, pr.text, source="form-submit")
                        submitted_form_keys.add(fkey)
                        form_submissions.append({
                            "method": method.upper(),
                            "url": f_url,
                            "status": int(pr.status_code),
                            "payload": payload,
                        })
                        pr_url = _normalize_in_scope_url(base_url, str(pr.url), host)
                        if pr_url and pr_url not in visited and pr_url not in queue and in_scope_path(pr_url):
                            queue.append(pr_url)
                    except Exception as form_err:
                        errors.append(f"httpx form submit error at {f_url}: {form_err}")

                if "/api/" in current or any(k in current for k in ["?id=", "?q=", "?search="]):
                    api_endpoints.append(current)
                if "fetch(" in text or "xmlhttprequest" in ltext:
                    for endpoint in _extract_fetch_targets(text, current, host):
                        api_endpoints.append(endpoint)
            except Exception as e:
                errors.append(f"httpx crawl error at {current}: {e}")

    merged_forms = []
    form_seen: Set[str] = set()
    for item in form_endpoints:
        key = f"{item.get('method')}|{item.get('url')}|{','.join(item.get('fields') or [])}"
        if key in form_seen:
            continue
        form_seen.add(key)
        merged_forms.append(item)
        if len(merged_forms) >= 400:
            break

    return {
        "engine": "httpx-fallback",
        "workflow_profile": wf.get("name") or "",
        "visited_urls": _dedupe(visited, 1200),
        "pages": pages[:1200],
        "api_endpoints": _dedupe(api_endpoints, 800),
        "js_urls": _dedupe(scripts, 800),
        "form_endpoints": merged_forms,
        "form_submissions": form_submissions[:300],
        "traffic_log": _merge_traffic_logs(traffic_log, limit=2000),
        "auth": {
            "register_attempted": register_attempted,
            "register_success": register_success,
            "login_attempted": login_attempted,
            "login_success": login_success,
            "relogin_count": 0,
            "username": username,
            "email": email,
            "password": password,
        },
        "errors": errors[:120],
    }


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:140]


def _extract_links(html: str, base_url: str, host: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"""href=['"]([^'"]+)['"]""", html or "", re.IGNORECASE):
        u = _normalize_in_scope_url(base_url, m.group(1), host)
        if u:
            out.append(u)
    for m in re.finditer(r"""action=['"]([^'"]+)['"]""", html or "", re.IGNORECASE):
        u = _normalize_in_scope_url(base_url, m.group(1), host)
        if u:
            out.append(u)
    return _dedupe(out, 1500)


def _extract_script_srcs(html: str, base_url: str, host: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"""<script[^>]+src=['"]([^'"]+)['"]""", html or "", re.IGNORECASE):
        u = _normalize_in_scope_url(base_url, m.group(1), host)
        if u:
            out.append(u)
    return _dedupe(out, 1200)


def _extract_fetch_targets(text: str, base_url: str, host: str) -> List[str]:
    out: List[str] = []
    patterns = [
        r"""fetch\(\s*['"]([^'"]+)['"]""",
        r"""open\(\s*['"](GET|POST|PUT|DELETE)['"]\s*,\s*['"]([^'"]+)['"]""",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text or "", re.IGNORECASE):
            raw = m.group(1) if len(m.groups()) == 1 else m.group(2)
            u = _normalize_in_scope_url(base_url, raw, host)
            if u:
                out.append(u)
    return _dedupe(out, 600)


async def _crawl_playwright(
    base_url: str,
    host: str,
    max_pages: int,
    timeout_ms: int,
    username: str,
    password: str,
    email: str,
    headless: bool,
    proxy_server: Optional[str],
    login_path: Optional[str],
    register_path: Optional[str],
    workflow_profile: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    from playwright.async_api import async_playwright

    wf = _normalize_workflow_profile(workflow_profile or {})
    visited: List[str] = []
    queue: List[str] = [base_url]
    pages: List[Dict[str, Any]] = []
    js_urls: List[str] = []
    api_endpoints: List[str] = []
    errors: List[str] = []
    relogin_count = 0

    login_attempted = False
    login_success = False
    register_attempted = False
    register_success = False
    active_login_url = None

    request_log: List[Dict[str, Any]] = []
    form_endpoints: List[Dict[str, Any]] = []
    form_submissions: List[Dict[str, Any]] = []
    exercised_form_keys: Set[str] = set()
    allow_paths = [p.lower() for p in (wf.get("allow_paths") or [])]
    skip_paths = [p.lower() for p in (wf.get("skip_paths") or [])]
    auth_success_markers = [m.lower() for m in (wf.get("auth_success_markers") or ["logout", "sign out", "welcome"])]
    auth_fail_markers = [m.lower() for m in (wf.get("auth_fail_markers") or ["invalid", "incorrect", "failed", "error"])]

    def in_scope_path(url: str) -> bool:
        parsed = urlparse(url)
        path_q = f"{parsed.path}?{parsed.query}".lower()
        if any(s in path_q for s in skip_paths):
            return False
        if allow_paths and not any(a in path_q for a in allow_paths):
            return False
        return True

    async with async_playwright() as p:
        launch_kwargs: Dict[str, Any] = {"headless": headless}
        browser = await p.chromium.launch(**launch_kwargs)
        context_kwargs: Dict[str, Any] = {"ignore_https_errors": True}
        if proxy_server:
            context_kwargs["proxy"] = {"server": proxy_server}
        context = await browser.new_context(**context_kwargs)
        page = await context.new_page()

        def req_post_data(req) -> str:
            try:
                data = req.post_data
                if callable(data):
                    data = data()
                return _safe_body(data, HTTP_BODY_SAMPLE)
            except Exception:
                return ""

        def on_request(req):
            if len(request_log) >= 6000:
                return
            request_log.append({
                "source": "playwright",
                "method": str(req.method or "GET").upper(),
                "url": str(req.url or ""),
                "resource_type": str(req.resource_type or ""),
                "status": 0,
                "request_headers": _safe_headers(req.headers),
                "request_body": req_post_data(req),
                "response_headers": {},
                "response_preview": "",
            })

        async def on_response_async(resp):
            req = resp.request
            method = str(req.method or "GET").upper()
            url = str(req.url or "")
            for item in reversed(request_log):
                if item.get("status") not in (0, None):
                    continue
                if item.get("method") != method or item.get("url") != url:
                    continue
                item["status"] = int(resp.status or 0)
                try:
                    item["response_headers"] = _safe_headers(resp.headers)
                except Exception:
                    item["response_headers"] = {}
                try:
                    hdrs = resp.headers or {}
                    ctype = str(hdrs.get("content-type") or "").lower()
                    if any(x in ctype for x in ("json", "text", "html", "xml", "javascript")):
                        item["response_preview"] = _safe_body(await resp.text(), HTTP_BODY_SAMPLE)
                except Exception:
                    pass
                break

        page.on("request", on_request)
        page.on("response", lambda resp: asyncio.create_task(on_response_async(resp)))

        async def safe_goto(url: str) -> bool:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                return True
            except Exception as e:
                errors.append(f"goto failed {url}: {e}")
                return False

        async def fill_first(selectors: List[str], value: str) -> bool:
            for sel in selectors:
                try:
                    el = await page.query_selector(sel)
                    if not el:
                        continue
                    await el.fill("")
                    await el.fill(value)
                    return True
                except Exception:
                    continue
            return False

        async def submit_form() -> bool:
            submit_selectors = [
                "form button[type='submit']",
                "button[type='submit']",
                "form input[type='submit']",
                "input[type='submit']",
            ]
            if wf.get("submit_selector"):
                submit_selectors = [wf["submit_selector"], *submit_selectors]
            for sel in submit_selectors:
                try:
                    el = await page.query_selector(sel)
                    if el:
                        await el.click()
                        await page.wait_for_timeout(900)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=5000)
                        except Exception:
                            pass
                        return True
                except Exception:
                    continue
            try:
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(900)
                return True
            except Exception:
                return False

        async def try_register(url: str) -> bool:
            nonlocal register_attempted
            if not await safe_goto(url):
                return False
            register_attempted = True
            filled = 0
            email_selectors = ["input[type='email']", "input[name*='email' i]", "input[id*='email' i]"]
            user_selectors = ["input[name*='user' i]", "input[id*='user' i]", "input[name='username']"]
            pass_selectors = ["input[type='password']", "input[name*='pass' i]", "input[id*='pass' i]"]
            confirm_selectors = ["input[name*='confirm' i]", "input[id*='confirm' i]"]
            if wf.get("email_selector"):
                email_selectors = [wf["email_selector"], *email_selectors]
            if wf.get("username_selector"):
                user_selectors = [wf["username_selector"], *user_selectors]
            if wf.get("password_selector"):
                pass_selectors = [wf["password_selector"], *pass_selectors]
            if wf.get("confirm_password_selector"):
                confirm_selectors = [wf["confirm_password_selector"], *confirm_selectors]

            if await fill_first(email_selectors, email):
                filled += 1
            if await fill_first(user_selectors, username):
                filled += 1
            if await fill_first(pass_selectors, password):
                filled += 1
            await fill_first(confirm_selectors, password)
            if filled < 2:
                return False
            await submit_form()
            html = (await page.content()).lower()
            if any(marker in html for marker in auth_success_markers):
                return True
            if any(marker in html for marker in auth_fail_markers):
                return False
            if "already exists" in html or "successful" in html or "account created" in html:
                return True
            if "login" in page.url.lower() and "register" not in page.url.lower():
                return True
            return False

        async def try_login(url: str) -> bool:
            nonlocal login_attempted
            if not await safe_goto(url):
                return False
            login_attempted = True
            filled = 0
            email_selectors = ["input[type='email']", "input[name*='email' i]", "input[id*='email' i]"]
            user_selectors = ["input[name*='user' i]", "input[id*='user' i]", "input[name='username']", "input[name='login']"]
            pass_selectors = ["input[type='password']", "input[name*='pass' i]", "input[id*='pass' i]"]
            if wf.get("email_selector"):
                email_selectors = [wf["email_selector"], *email_selectors]
            if wf.get("username_selector"):
                user_selectors = [wf["username_selector"], *user_selectors]
            if wf.get("password_selector"):
                pass_selectors = [wf["password_selector"], *pass_selectors]

            if await fill_first(email_selectors, email):
                filled += 1
            if await fill_first(user_selectors, username):
                filled += 1
            if await fill_first(pass_selectors, password):
                filled += 1
            if filled < 2:
                return False
            await submit_form()
            html = (await page.content()).lower()
            has_password = await page.query_selector("input[type='password']") is not None
            if any(marker in html for marker in auth_fail_markers):
                return False
            if any(marker in html for marker in auth_success_markers):
                return True
            if not has_password and ("logout" in html or "sign out" in html or "welcome" in html):
                return True
            if "login" not in page.url.lower() and not has_password:
                return True
            return False

        register_urls = []
        if register_path:
            register_urls.append(_normalize_in_scope_url(base_url, register_path, host) or "")
        if wf.get("register_path"):
            register_urls.append(_normalize_in_scope_url(base_url, wf.get("register_path"), host) or "")
        register_urls += [_normalize_in_scope_url(base_url, p, host) or "" for p in AUTH_REGISTER_PATHS]
        for ru in [u for u in _dedupe(register_urls) if u][:5]:
            try:
                if await try_register(ru):
                    register_success = True
                    break
            except Exception as e:
                errors.append(f"register error at {ru}: {e}")

        login_urls = []
        if login_path:
            login_urls.append(_normalize_in_scope_url(base_url, login_path, host) or "")
        if wf.get("login_path"):
            login_urls.append(_normalize_in_scope_url(base_url, wf.get("login_path"), host) or "")
        login_urls += [_normalize_in_scope_url(base_url, p, host) or "" for p in AUTH_LOGIN_PATHS]
        for lu in [u for u in _dedupe(login_urls) if u][:6]:
            try:
                if await try_login(lu):
                    login_success = True
                    active_login_url = lu
                    break
            except Exception as e:
                errors.append(f"login error at {lu}: {e}")

        if login_success:
            for p in wf.get("post_login_paths") or []:
                u = _normalize_in_scope_url(base_url, p, host)
                if u and u not in queue:
                    queue.append(u)

        while queue and len(visited) < max_pages:
            current = queue.pop(0)
            if current in visited:
                continue
            if not in_scope_path(current):
                continue
            if not await safe_goto(current):
                continue

            cur = page.url
            in_scope = _normalize_in_scope_url(base_url, cur, host)
            if not in_scope:
                continue
            if in_scope in visited:
                continue

            html = await page.content()
            lhtml = html.lower()

            if login_success and "login" in urlparse(cur).path.lower() and active_login_url and relogin_count < 4:
                ok = await try_login(active_login_url)
                if ok:
                    relogin_count += 1
                    if not await safe_goto(current):
                        continue
                    html = await page.content()
                    lhtml = html.lower()

            visited.append(in_scope)
            title = (await page.title())[:140]
            pages.append({"url": in_scope, "title": title, "status": 200})

            try:
                hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href') || '')")
            except Exception:
                hrefs = []
            try:
                actions = await page.eval_on_selector_all("form[action]", "els => els.map(e => e.getAttribute('action') || '')")
            except Exception:
                actions = []
            try:
                srcs = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src || '')")
            except Exception:
                srcs = []
            try:
                forms = await page.eval_on_selector_all(
                    "form",
                    """forms => forms.map(f => ({
                        method: (f.getAttribute('method') || 'get').toLowerCase(),
                        action: f.getAttribute('action') || '',
                        fields: Array.from(f.querySelectorAll('input,textarea,select')).map(el => ({
                            name: el.getAttribute('name') || '',
                            type: (el.getAttribute('type') || el.tagName || 'text').toLowerCase()
                        }))
                    }))""",
                )
            except Exception:
                forms = []

            for raw in [*hrefs, *actions]:
                u = _normalize_in_scope_url(in_scope, raw, host)
                if u and u not in visited and u not in queue:
                    if not in_scope_path(u):
                        continue
                    queue.append(u)
            for src in srcs:
                u = _normalize_in_scope_url(in_scope, src, host)
                if u:
                    js_urls.append(u)

            if "/api/" in in_scope or any(k in in_scope for k in ["?id=", "?q=", "?search="]):
                api_endpoints.append(in_scope)
            if "fetch(" in html or "xmlhttprequest" in lhtml:
                api_endpoints.extend(_extract_fetch_targets(html, in_scope, host))

            try:
                form_locators = page.locator("form")
                form_locator_count = await form_locators.count()
            except Exception:
                form_locators = None
                form_locator_count = 0

            for fi, fm in enumerate(forms[:20]):
                method = str(fm.get("method") or "get").lower()
                if method not in ("get", "post"):
                    method = "get"
                action = str(fm.get("action") or "")
                f_url = _normalize_in_scope_url(in_scope, action or in_scope, host) or in_scope
                if not in_scope_path(f_url):
                    continue
                field_names = [str(f.get("name") or "") for f in (fm.get("fields") or []) if str(f.get("name") or "")]
                form_endpoints.append({
                    "method": method.upper(),
                    "url": f_url,
                    "fields": field_names[:25],
                })

                if fi >= form_locator_count or not form_locators:
                    continue
                if len(form_submissions) >= 100:
                    continue
                if "logout" in f_url.lower():
                    continue
                f_key = f"{method}|{f_url}|{','.join(field_names[:25])}"
                if f_key in exercised_form_keys:
                    continue

                try:
                    form_el = form_locators.nth(fi)
                    touched = 0
                    input_els = form_el.locator("input,textarea")
                    input_count = await input_els.count()
                    for ii in range(min(input_count, 25)):
                        iel = input_els.nth(ii)
                        itype = str((await iel.get_attribute("type")) or "text").lower()
                        iname = str((await iel.get_attribute("name")) or "")
                        if itype in ("submit", "button", "reset", "file", "checkbox", "radio", "hidden"):
                            continue
                        lname = iname.lower()
                        if "pass" in lname or itype == "password":
                            val = password
                        elif "email" in lname or itype == "email":
                            val = email
                        elif any(x in lname for x in ["user", "login", "name"]):
                            val = username
                        elif any(x in lname for x in ["search", "query", "q"]):
                            val = "phantom scan"
                        else:
                            val = "phantom-test"
                        try:
                            await iel.fill("")
                            await iel.fill(val)
                            touched += 1
                        except Exception:
                            continue

                    select_els = form_el.locator("select")
                    select_count = await select_els.count()
                    for si in range(min(select_count, 6)):
                        try:
                            options = await select_els.nth(si).locator("option").all()
                            if len(options) > 1:
                                await select_els.nth(si).select_option(index=1)
                            elif len(options) == 1:
                                await select_els.nth(si).select_option(index=0)
                        except Exception:
                            continue

                    if touched == 0 and select_count == 0:
                        continue

                    submit_btn = form_el.locator("button[type='submit'],input[type='submit']")
                    if await submit_btn.count() > 0:
                        await submit_btn.first.click()
                    else:
                        await form_el.evaluate("f => f.submit()")
                    await page.wait_for_timeout(700)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass

                    hit_status = 0
                    for tr in reversed(request_log):
                        if tr.get("method") == method.upper() and str(tr.get("url") or "").startswith(f_url):
                            hit_status = int(tr.get("status") or 0)
                            break
                    form_submissions.append({
                        "method": method.upper(),
                        "url": f_url,
                        "status": hit_status,
                        "fields": field_names[:25],
                    })
                    exercised_form_keys.add(f_key)

                    post_url = _normalize_in_scope_url(base_url, page.url, host)
                    if post_url and post_url not in visited and post_url not in queue and in_scope_path(post_url):
                        queue.append(post_url)
                except Exception as form_err:
                    errors.append(f"playwright form submit error at {f_url}: {form_err}")

        await context.close()
        await browser.close()

    request_items: List[Dict[str, Any]] = [r for r in request_log if _same_origin(str(r.get("url") or ""), host)]
    for req in request_items:
        u = req.get("url") or ""
        rt = str(req.get("resource_type") or "")
        if rt in ("fetch", "xhr") or "/api/" in u or str(req.get("method") or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            api_endpoints.append(u)
    dedup_forms: List[Dict[str, Any]] = []
    seen_forms: Set[str] = set()
    for form in form_endpoints:
        key = f"{form.get('method')}|{form.get('url')}|{','.join(form.get('fields') or [])}"
        if key in seen_forms:
            continue
        seen_forms.add(key)
        dedup_forms.append(form)
        if len(dedup_forms) >= 400:
            break

    return {
        "engine": "playwright",
        "workflow_profile": wf.get("name") or "",
        "visited_urls": _dedupe(visited, 1500),
        "pages": pages[:1500],
        "api_endpoints": _dedupe(api_endpoints, 1200),
        "js_urls": _dedupe(js_urls, 1200),
        "form_endpoints": dedup_forms,
        "form_submissions": form_submissions[:300],
        "traffic_log": _merge_traffic_logs(request_items, limit=2000),
        "auth": {
            "register_attempted": register_attempted,
            "register_success": register_success,
            "login_attempted": login_attempted,
            "login_success": login_success,
            "relogin_count": relogin_count,
            "username": username,
            "email": email,
            "password": password,
        },
        "errors": errors[:200],
    }


async def _analyze_js(js_urls: List[str], timeout_s: int = 15, max_files: int = 30) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    tech_hints: List[Dict[str, str]] = []
    analyzed: List[str] = []
    errors: List[str] = []

    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True, verify=False) as client:
        for js_url in js_urls[:max_files]:
            try:
                resp = await client.get(js_url)
                if resp.status_code >= 400:
                    continue
                body = resp.text or ""
                analyzed.append(js_url)
                snippet = body[:200000]
                for sev, pat, msg in [*JS_SINK_RULES, *JS_SECRET_RULES]:
                    if re.search(pat, snippet, re.IGNORECASE):
                        findings.append({
                            "severity": sev,
                            "description": f"{msg} — {js_url}",
                            "tool": "js-audit",
                        })
                lowered_url = js_url.lower()
                lowered_body = snippet.lower()
                for lib, pat in JS_LIB_PATTERNS:
                    m_url = re.search(pat, lowered_url, re.IGNORECASE)
                    m_body = re.search(pat, lowered_body, re.IGNORECASE)
                    ver = None
                    if m_url:
                        ver = m_url.group(1)
                    elif m_body:
                        ver = m_body.group(1)
                    if ver:
                        tech_hints.append({"product": lib, "version": ver})
            except Exception as e:
                errors.append(f"js fetch failed {js_url}: {e}")

    # Deduplicate findings and tech hints.
    uniq_findings = []
    seen_f = set()
    for f in findings:
        k = f"{f['severity']}|{f['description']}"
        if k in seen_f:
            continue
        seen_f.add(k)
        uniq_findings.append(f)

    uniq_hints = []
    seen_h = set()
    for h in tech_hints:
        k = f"{h.get('product')}|{h.get('version')}"
        if k in seen_h:
            continue
        seen_h.add(k)
        uniq_hints.append(h)

    return {
        "files_analyzed": analyzed,
        "findings": uniq_findings,
        "technology_hints": uniq_hints,
        "errors": errors[:100],
    }


def _extract_tech_hints_from_outputs(tool_runs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    hints: List[Dict[str, str]] = []
    for run in tool_runs:
        out = run.get("output") or ""
        for product, pattern in TECH_HINT_PATTERNS:
            for m in re.finditer(pattern, out, re.IGNORECASE):
                hints.append({"product": product, "version": m.group(1)})
    uniq = []
    seen = set()
    for h in hints:
        k = f"{h.get('product')}|{h.get('version')}"
        if k in seen:
            continue
        seen.add(k)
        uniq.append(h)
    return uniq


def _build_tool_plan(
    base_url: str,
    host: str,
    discovered_urls: List[str],
    max_tool_timeout: int,
    selected_tools: Set[str],
) -> Tuple[List[Tuple[str, List[str], int]], List[str]]:
    plan: List[Tuple[str, List[str], int]] = []
    temp_files: List[str] = []
    wl = _wordlist_path()

    if "whatweb" in selected_tools:
        plan.append(("whatweb", [base_url, "-v", "--log-verbose=/dev/stdout"], min(max_tool_timeout, 120)))
    if "nmap" in selected_tools:
        plan.append(("nmap", ["-Pn", "--unprivileged", "-sV", "-sC", "--open", "-T4", "--top-ports", "1000", host], min(max_tool_timeout, 240)))
    if "nuclei" in selected_tools:
        plan.append(("nuclei", ["-u", base_url, "-as", "-severity", "critical,high,medium,low,info", "-silent", "-jsonl", "-duc", "-no-color"], min(max_tool_timeout, 300)))
        scope_urls = _dedupe([u for u in discovered_urls if u], 400)
        if scope_urls:
            f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", prefix="phantom-autopilot-urls-")
            with f:
                for u in scope_urls:
                    f.write(f"{u}\n")
            temp_files.append(f.name)
            plan.append(("nuclei", ["-l", f.name, "-as", "-severity", "critical,high,medium,low,info", "-silent", "-jsonl", "-duc", "-no-color"], min(max_tool_timeout, 360)))
    if "nikto" in selected_tools:
        plan.append(("nikto", ["-h", base_url, "-nointeractive"], min(max_tool_timeout, 300)))
    if "sqlmap" in selected_tools:
        injectable = next((u for u in discovered_urls if "?" in u and "=" in u), f"{base_url}/")
        plan.append(("sqlmap", ["-u", injectable, "--batch", "--level=2", "--risk=1", "--random-agent", "--crawl=2"], min(max_tool_timeout, 240)))
    if "ffuf" in selected_tools and wl:
        plan.append(("ffuf", ["-u", f"{base_url}/FUZZ", "-w", wl, "-mc", "200,204,301,302,403", "-t", "40", "-s"], min(max_tool_timeout, 180)))
    if "gobuster" in selected_tools and wl:
        plan.append(("gobuster", ["dir", "-u", base_url, "-w", wl, "-q", "-t", "30", "-x", "php,html,js,txt,bak,env"], min(max_tool_timeout, 180)))
    if "feroxbuster" in selected_tools and wl:
        plan.append(("feroxbuster", ["--url", base_url, "--wordlist", wl, "--quiet", "--no-recursion"], min(max_tool_timeout, 180)))

    return plan, temp_files


async def _searchsploit_for_hints(hints: List[Dict[str, str]], timeout_s: int) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    if shutil.which("searchsploit") is None:
        return runs
    for hint in hints[:8]:
        product = hint.get("product") or ""
        version = hint.get("version") or ""
        if not product or not version:
            continue
        q = f"{product} {version}"
        res = await _run_cmd("searchsploit", ["--json", q], timeout=min(timeout_s, 60))
        res["query"] = q
        runs.append(res)
    return runs


async def run_autopilot_scan(config: Dict[str, Any]) -> Dict[str, Any]:
    started = time.time()
    started_at = _now_iso()
    base_url, host, scheme = _normalize_target(str(config.get("target") or ""))

    username = str(config.get("username") or f"phantom_{int(started) % 100000}")
    password = str(config.get("password") or f"Phantom!{datetime.utcnow().year}!123")
    email = str(config.get("email") or f"{username}@local.test")
    max_pages = max(3, min(int(config.get("max_pages") or 40), 300))
    headless = bool(config.get("headless", True))
    use_proxy = bool(config.get("use_proxy", True))
    proxy_url = str(config.get("proxy_url") or "http://127.0.0.1:8888").strip()
    timeout_per_tool = max(30, min(int(config.get("timeout_per_tool") or 180), 900))
    login_path = (str(config.get("login_path") or "").strip() or None)
    register_path = (str(config.get("register_path") or "").strip() or None)
    workflow_profile = _normalize_workflow_profile(config.get("workflow_profile") or {})
    if not login_path:
        login_path = workflow_profile.get("login_path")
    if not register_path:
        register_path = workflow_profile.get("register_path")
    js_audit = bool(config.get("js_audit", True))
    proxy_history_limit = max(20, min(int(config.get("proxy_history_limit") or 400), 2000))
    captured_traffic = _normalize_captured_requests(
        base_url=base_url,
        host=host,
        captured_requests=config.get("captured_requests") or [],
        limit=proxy_history_limit,
    )

    selected_tools = set(config.get("tools") or DEFAULT_AUTOPILOT_TOOLS)
    deps = inspect_dependencies()
    logs: List[str] = []
    manual_findings: List[Dict[str, str]] = []
    if captured_traffic:
        logs.append(f"proxy-history: loaded {len(captured_traffic)} captured requests")

    crawler_result: Dict[str, Any]
    if deps["python_modules"].get("playwright"):
        logs.append("crawler: playwright enabled")
        try:
            crawler_result = await _crawl_playwright(
                base_url=base_url,
                host=host,
                max_pages=max_pages,
                timeout_ms=12000,
                username=username,
                password=password,
                email=email,
                headless=headless,
                proxy_server=(proxy_url if use_proxy else None),
                login_path=login_path,
                register_path=register_path,
                workflow_profile=workflow_profile,
            )
        except Exception as e:
            logs.append(f"crawler: playwright failed, falling back to httpx ({e})")
            manual_findings.append({
                "severity": "MEDIUM",
                "description": f"Playwright crawler failed, fallback crawler used: {e}",
                "tool": "crawler",
            })
            crawler_result = await _crawl_httpx(
                base_url=base_url,
                host=host,
                max_pages=max_pages,
                timeout_s=15,
                username=username,
                password=password,
                email=email,
                login_path=login_path,
                register_path=register_path,
                workflow_profile=workflow_profile,
            )
    else:
        logs.append("crawler: playwright not installed, using httpx fallback")
        manual_findings.append({
            "severity": "MEDIUM",
            "description": "Playwright not installed; using HTTP crawler fallback with limited form interaction.",
            "tool": "crawler",
        })
        crawler_result = await _crawl_httpx(
            base_url=base_url,
            host=host,
            max_pages=max_pages,
            timeout_s=15,
            username=username,
            password=password,
            email=email,
            login_path=login_path,
            register_path=register_path,
                workflow_profile=workflow_profile,
            )

    crawler_result["traffic_log"] = _merge_traffic_logs(captured_traffic, crawler_result.get("traffic_log") or [], limit=2200)
    traffic_urls = [str(t.get("url") or "") for t in (crawler_result.get("traffic_log") or []) if str(t.get("url") or "")]
    form_urls = [str(x.get("url") or "") for x in (crawler_result.get("form_endpoints") or []) if str(x.get("url") or "")]
    discovered_urls = _dedupe(
        [
            base_url,
            *(crawler_result.get("visited_urls") or []),
            *(crawler_result.get("api_endpoints") or []),
            *form_urls,
            *traffic_urls,
        ],
        1400,
    )
    js_urls = _dedupe(crawler_result.get("js_urls") or [], 1200)

    js_result = {"files_analyzed": [], "findings": [], "technology_hints": [], "errors": []}
    if js_audit and js_urls:
        logs.append(f"js-audit: analyzing {min(len(js_urls), 30)} script files")
        js_result = await _analyze_js(js_urls, timeout_s=15, max_files=30)

    plan, temp_files = _build_tool_plan(
        base_url=base_url,
        host=host,
        discovered_urls=discovered_urls,
        max_tool_timeout=timeout_per_tool,
        selected_tools=selected_tools,
    )

    tool_runs: List[Dict[str, Any]] = []
    for tool, args, timeout in plan:
        logs.append(f"tool: running {tool}")
        tool_runs.append(await _run_cmd(tool, args, timeout=timeout))

    tech_hints = _extract_tech_hints_from_outputs(tool_runs)
    tech_hints.extend(js_result.get("technology_hints") or [])
    # Deduplicate merged hints.
    dedup_hints = []
    seen_hint = set()
    for hint in tech_hints:
        k = f"{hint.get('product')}|{hint.get('version')}"
        if k in seen_hint:
            continue
        seen_hint.add(k)
        dedup_hints.append(hint)
    tech_hints = dedup_hints

    if "searchsploit" in selected_tools and tech_hints:
        logs.append(f"tool: running searchsploit on {min(len(tech_hints), 8)} technology hints")
        tool_runs.extend(await _searchsploit_for_hints(tech_hints, timeout_per_tool))

    for tf in temp_files:
        try:
            os.unlink(tf)
        except Exception:
            pass

    duration_s = round(time.time() - started, 2)
    ended_at = _now_iso()

    # Additional high-level findings from autopilot quality signals.
    auth = crawler_result.get("auth") or {}
    traffic_log = crawler_result.get("traffic_log") or []
    post_requests_seen = sum(1 for t in traffic_log if str(t.get("method") or "").upper() in {"POST", "PUT", "PATCH", "DELETE"})
    if auth.get("login_attempted") and not auth.get("login_success"):
        manual_findings.append({
            "severity": "MEDIUM",
            "description": "Login attempt was made but did not confirm a persistent authenticated session.",
            "tool": "crawler",
        })
    if len(discovered_urls) < 2:
        manual_findings.append({
            "severity": "MEDIUM",
            "description": "Crawler discovered very few in-scope URLs; coverage may be limited.",
            "tool": "crawler",
        })
    if post_requests_seen == 0:
        manual_findings.append({
            "severity": "MEDIUM",
            "description": "No POST/PUT/PATCH/DELETE requests were observed; coverage may miss state-changing endpoints.",
            "tool": "crawler",
        })

    exploit_evidence = _build_exploit_evidence(traffic_log=traffic_log, tool_runs=tool_runs)

    return {
        "ok": True,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_s": duration_s,
        "target": base_url,
        "host": host,
        "scheme": scheme,
        "dependencies": deps,
        "crawler": crawler_result,
        "js_audit": js_result,
        "tool_runs": tool_runs,
        "technology_hints": tech_hints,
        "manual_findings": manual_findings,
        "exploit_evidence": exploit_evidence,
        "logs": logs[:400],
        "summary": {
            "urls_discovered": len(discovered_urls),
            "api_endpoints": len(crawler_result.get("api_endpoints") or []),
            "js_files": len(js_urls),
            "http_traffic_events": len(traffic_log),
            "form_endpoints": len(crawler_result.get("form_endpoints") or []),
            "form_submissions": len(crawler_result.get("form_submissions") or []),
            "post_requests_seen": post_requests_seen,
            "tools_executed": len(tool_runs),
            "playwright_enabled": bool(deps["python_modules"].get("playwright")),
            "workflow_profile": workflow_profile.get("name") or config.get("workflow_profile_name") or "",
        },
    }
