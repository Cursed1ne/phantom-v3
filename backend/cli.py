#!/usr/bin/env python3
"""
PHANTOM AI v3 — Single Command CLI Orchestrator
─────────────────────────────────────────────────
One command runs the full pentest pipeline:
  scan → proxy → browser crawl → multi-tool scan → AI agents → report + graph

Usage:
  python3 backend/cli.py scan http://target.com
  python3 backend/cli.py scan http://target.com --agents all --out ./reports/
  python3 backend/cli.py scan http://target.com --no-browser --report all
  python3 backend/cli.py train                   # retrain LLM on latest findings
  python3 backend/cli.py status                  # check backend + Ollama health

Also accessible via npm:
  npm run scan -- http://target.com
"""

import argparse
import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
import websockets

# ── Defaults ──────────────────────────────────────────────────────────────────
BACKEND_URL = os.environ.get("PHANTOM_BACKEND", "http://localhost:8000")
WS_URL      = os.environ.get("PHANTOM_WS",      "ws://localhost:8000")
DEFAULT_OUT = Path("./reports")

# ── Color helpers (ANSI, skipped if not a TTY) ────────────────────────────────
IS_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if not IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

RED     = lambda t: _c("91", t)
ORANGE  = lambda t: _c("33", t)
YELLOW  = lambda t: _c("93", t)
GREEN   = lambda t: _c("92", t)
BLUE    = lambda t: _c("94", t)
CYAN    = lambda t: _c("96", t)
BOLD    = lambda t: _c("1",  t)
DIM     = lambda t: _c("2",  t)

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     DIM,
}

PHANTOM_BANNER = """
╔═══════════════════════════════════════════════════╗
║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗   ║
║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝   ║
║   ██████╔╝███████║███████║██╔██╗ ██║   ██║      ║
║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║      ║
║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║      ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝      ║
║          PHANTOM AI v3 — Autonomous Pentest       ║
╚═══════════════════════════════════════════════════╝
"""


# ── Backend management ────────────────────────────────────────────────────────

def _backend_alive() -> bool:
    try:
        resp = httpx.get(f"{BACKEND_URL}/health", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def _ollama_alive() -> bool:
    try:
        resp = httpx.get("http://localhost:11434/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def _active_model() -> str:
    try:
        resp = httpx.get(f"{BACKEND_URL}/ollama/active-model", timeout=3)
        return resp.json().get("model", "llama3.1")
    except Exception:
        return "llama3.1"


def _start_backend() -> Optional[subprocess.Popen]:
    """Start uvicorn in the background if not already running."""
    if _backend_alive():
        return None

    print(CYAN("  Starting Phantom backend..."))
    backend_dir = Path(__file__).parent
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "0.0.0.0", "--port", "8000",
         "--ws-ping-interval", "20", "--ws-ping-timeout", "30"],
        cwd=str(backend_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Poll until healthy (max 20s)
    for _ in range(40):
        time.sleep(0.5)
        if _backend_alive():
            print(GREEN("  ✓ Backend ready"))
            return proc
    print(ORANGE("  ⚠ Backend did not respond in 20s, continuing anyway"))
    return proc


# ── Report generation ─────────────────────────────────────────────────────────

def _generate_html_report(
    target: str,
    findings: List[Dict],
    graph: Dict,
    session_id: str,
    out_dir: Path,
) -> Path:
    """Generate a standalone HTML pentest report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = urlparse(target).hostname or target.replace("http://","").replace("https://","").split("/")[0]

    # Severity counts
    counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
    for f in findings:
        counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"), 0) + 1

    risk = graph.get("risk_score", 0.0)

    # Finding rows
    rows_html = ""
    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO"))):
        sev   = f.get("severity","INFO")
        desc  = f.get("description","")
        tool  = f.get("tool","")
        agent = f.get("agent","")
        cvss  = f.get("cvss",0)
        sev_colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",   "LOW": "#2563eb", "INFO": "#6b7280"
        }
        color = sev_colors.get(sev,"#6b7280")
        rows_html += (
            f'<tr><td><span class="badge" style="background:{color}">{sev}</span></td>'
            f'<td>{desc}</td><td>{tool}</td><td>{agent}</td>'
            f'<td>{cvss:.1f}</td></tr>\n'
        )

    # Attack path summary
    paths = graph.get("attack_paths", [])
    path_html = ""
    if paths:
        path_html = "<h3>Top Exploitation Path</h3><ol>"
        nodes_by_id = {n["id"]: n for n in graph.get("nodes", [])}
        for node_id in paths[0]:
            node = nodes_by_id.get(node_id, {})
            label = node.get("label", node_id)
            phase = node.get("phase_label", "")
            path_html += f"<li><strong>{label}</strong> <em>({phase})</em></li>"
        path_html += "</ol>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phantom AI — Pentest Report: {host}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }}
  h1   {{ color:#38bdf8; margin-bottom:4px; }}
  h2   {{ color:#94a3b8; border-bottom:1px solid #334155; padding-bottom:8px; }}
  h3   {{ color:#cbd5e1; }}
  .meta  {{ color:#64748b; font-size:13px; margin-bottom:32px; }}
  .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:32px; }}
  .stat  {{ background:#1e293b; border-radius:8px; padding:16px 24px; text-align:center; min-width:100px; }}
  .stat .val {{ font-size:28px; font-weight:700; }}
  .stat .lbl {{ font-size:12px; color:#94a3b8; text-transform:uppercase; }}
  .critical .val {{ color:#dc2626; }}
  .high     .val {{ color:#ea580c; }}
  .medium   .val {{ color:#ca8a04; }}
  .low      .val {{ color:#2563eb; }}
  .info     .val {{ color:#6b7280; }}
  .risk     .val {{ color:#38bdf8; }}
  table  {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; }}
  th     {{ background:#0f172a; color:#94a3b8; text-align:left; padding:10px 14px; font-size:12px; text-transform:uppercase; }}
  td     {{ padding:10px 14px; border-top:1px solid #334155; vertical-align:top; font-size:14px; }}
  tr:hover {{ background:#283040; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; white-space:nowrap; }}
  .graph-summary {{ background:#1e293b; border-radius:8px; padding:20px; margin-bottom:24px; }}
  .phase-chain {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin:16px 0; }}
  .phase {{ padding:6px 14px; border-radius:6px; font-size:13px; font-weight:600; }}
  .phase.initial    {{ background:#1d4ed8; }}
  .phase.foothold   {{ background:#c2410c; }}
  .phase.escalation {{ background:#b91c1c; }}
  .phase.impact     {{ background:#111827; border:1px solid #374151; }}
  .arrow {{ color:#64748b; font-size:18px; }}
  ol li {{ margin:6px 0; }}
  footer {{ margin-top:40px; color:#334155; font-size:12px; text-align:center; }}
</style>
</head>
<body>
<h1>🔍 Phantom AI — Penetration Test Report</h1>
<div class="meta">
  Target: <strong>{target}</strong> &nbsp;|&nbsp;
  Session: <code>{session_id}</code> &nbsp;|&nbsp;
  Generated: {now}
</div>

<h2>Executive Summary</h2>
<div class="stats">
  <div class="stat critical"><div class="val">{counts["CRITICAL"]}</div><div class="lbl">Critical</div></div>
  <div class="stat high">   <div class="val">{counts["HIGH"]}</div>   <div class="lbl">High</div></div>
  <div class="stat medium"> <div class="val">{counts["MEDIUM"]}</div> <div class="lbl">Medium</div></div>
  <div class="stat low">    <div class="val">{counts["LOW"]}</div>    <div class="lbl">Low</div></div>
  <div class="stat info">   <div class="val">{counts["INFO"]}</div>   <div class="lbl">Info</div></div>
  <div class="stat risk">   <div class="val">{risk:.1f}</div>         <div class="lbl">Risk Score</div></div>
</div>

<h2>Attack Chain</h2>
<div class="graph-summary">
  <div style="color:#94a3b8;margin-bottom:12px;">{graph.get("summary","")}</div>
  <div class="phase-chain">
"""
    phase_counts = graph.get("phase_counts", {})
    for phase, label, bg in [
        ("initial",    "Initial Access",       "initial"),
        ("foothold",   "Foothold",             "foothold"),
        ("escalation", "Privilege Escalation", "escalation"),
        ("impact",     "Impact",               "impact"),
    ]:
        n = phase_counts.get(phase, 0)
        if n > 0:
            html += f'    <div class="phase {bg}">{label} ({n})</div><div class="arrow">→</div>\n'

    html += f"""  </div>
  {path_html}
</div>

<h2>All Findings ({len(findings)})</h2>
<table>
<thead><tr>
  <th>Severity</th><th>Description</th><th>Tool</th><th>Agent</th><th>CVSS</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>

<footer>
  Generated by Phantom AI v3 — Autonomous Penetration Testing Platform<br>
  <em>This report is confidential. For authorized security testing only.</em>
</footer>
</body>
</html>"""

    out_dir.mkdir(parents=True, exist_ok=True)
    safe_host = re.sub(r"[^\w\-.]", "_", host)[:40]
    date_str  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = out_dir / f"phantom_{safe_host}_{date_str}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


# ── Terminal summary table ─────────────────────────────────────────────────────

def _print_summary(findings: List[Dict], graph: Dict, report_path: Optional[Path]):
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_f = sorted(findings, key=lambda f: sev_order.get(f.get("severity","INFO"), 5))

    print()
    print(BOLD("┌─────────────────────────────────────────────────────────────────────────┐"))
    print(BOLD("│                         SCAN COMPLETE — FINDINGS                        │"))
    print(BOLD("└─────────────────────────────────────────────────────────────────────────┘"))
    print()

    if not findings:
        print(GREEN("  ✓ No findings. Target appears clean."))
    else:
        print(f"  {'SEV':<10} {'TOOL':<15} {'DESCRIPTION':<60}")
        print(f"  {'─'*10} {'─'*15} {'─'*60}")
        for f in sorted_f[:30]:
            sev   = f.get("severity","INFO")
            desc  = f.get("description","")[:57] + ("…" if len(f.get("description","")) > 57 else "")
            tool  = (f.get("tool") or "")[:13]
            color = SEV_COLOR.get(sev, DIM)
            print(f"  {color(f'{sev:<10}')} {tool:<15} {desc}")

        if len(findings) > 30:
            print(DIM(f"\n  ... and {len(findings)-30} more findings in the report"))

    print()
    summary = graph.get("summary", "")
    if summary:
        print(CYAN(f"  ⚡ {summary}"))

    risk = graph.get("risk_score", 0.0)
    risk_label = "CRITICAL" if risk >= 8 else "HIGH" if risk >= 5 else "MEDIUM" if risk >= 3 else "LOW"
    risk_color = SEV_COLOR.get(risk_label, DIM)
    print(f"\n  Risk Score: {risk_color(f'{risk:.1f}/10  [{risk_label}]')}")

    if report_path:
        print(f"\n  {GREEN('✓')} Report: {BOLD(str(report_path))}")
    print()


# ── Core scan command ─────────────────────────────────────────────────────────

async def _do_scan(args):
    target    = args.target
    out_dir   = Path(args.out)
    no_browser = args.no_browser
    report_fmt = args.report
    agents_arg = args.agents

    # Agent selection
    ALL_AGENTS = ["planner","recon","web","identity","network","cloud","exploit"]
    if agents_arg == "all":
        agents = ALL_AGENTS
    else:
        agents = [a.strip() for a in agents_arg.split(",") if a.strip() in ALL_AGENTS]
        if not agents:
            agents = ["recon","web","network","exploit"]

    print(PHANTOM_BANNER)
    print(BOLD(f"  Target:  {target}"))
    print(BOLD(f"  Agents:  {', '.join(agents)}"))
    print(BOLD(f"  Out:     {out_dir}"))
    print()

    # 1. Check Ollama
    if not _ollama_alive():
        print(ORANGE("  ⚠ Ollama is not running. Starting..."))
        subprocess.Popen(["ollama","serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            time.sleep(0.5)
            if _ollama_alive():
                print(GREEN("  ✓ Ollama started"))
                break
        else:
            print(ORANGE("  ⚠ Ollama did not start — agents will fail gracefully"))

    # 2. Start backend
    backend_proc = _start_backend()
    model = _active_model()
    print(CYAN(f"  Model:   {model}"))
    print()

    session_id = None
    all_findings: List[Dict] = []

    try:
        async with httpx.AsyncClient(timeout=30) as http:
            # 3. Create session
            resp = await http.post(f"{BACKEND_URL}/sessions", json={
                "target": target, "target_type": "web",
                "agents": agents, "model": model,
            })
            session_id = resp.json().get("id") or resp.json().get("session_id")
            print(DIM(f"  Session: {session_id}"))
            print()

            # 4. Autopilot scan (browser crawl + tool chain) — runs in background
            if not no_browser:
                print(CYAN("  [1/3] Launching browser scan + tool chain..."))
                auto_task = asyncio.create_task(http.post(f"{BACKEND_URL}/autopilot/run", json={
                    "target":          target,
                    "headless":        True,
                    "use_proxy":       False,   # don't require proxy for CLI mode
                    "max_pages":       40,
                    "timeout_per_tool": 120,
                    "tools":           ["whatweb","nmap","nuclei","nikto","gobuster"],
                }, timeout=900))
            else:
                auto_task = None
                print(DIM("  [1/3] Skipping browser scan (--no-browser)"))

            # 5. Agent loop via WebSocket
            print(CYAN("  [2/3] Launching AI agents..."))
            print()

            try:
                ws_url_full = f"{WS_URL}/ws/agent"
                async with websockets.connect(ws_url_full, ping_interval=20, ping_timeout=30) as ws:
                    # Send config
                    await ws.send(json.dumps({
                        "target":     target,
                        "type":       "web",
                        "model":      model,
                        "depth":      getattr(args, "depth", "standard"),
                        "max_iter":   getattr(args, "max_iter", 8),
                        "agents":     agents,
                        "session_id": session_id,
                    }))

                    print(DIM("  Streaming agent output (press Ctrl+C to stop early):\n"))
                    current_agent = ""
                    done = False

                    while not done:
                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=300)
                            msg = json.loads(raw)
                            mtype = msg.get("type","")

                            if mtype == "agent_start":
                                a = msg.get("agent","?")
                                if a != current_agent:
                                    current_agent = a
                                    print(f"\n  {BOLD(BLUE(f'▶ Agent: {a.upper()}'))} (model: {msg.get('model','?')})")

                            elif mtype == "agent_token":
                                token = msg.get("token","")
                                print(token, end="", flush=True)

                            elif mtype == "agent_action":
                                tool = msg.get("tool","?")
                                print(f"\n  {CYAN(f'⚙ Tool: {tool}')}", end="")

                            elif mtype == "agent_nudge":
                                print(f"\n  {YELLOW('⟳ Forcing tool call...')}", end="")

                            elif mtype == "agent_findings":
                                new_f = msg.get("findings",[])
                                all_findings.extend(new_f)
                                for f in new_f:
                                    sev   = f.get("severity","INFO")
                                    desc  = f.get("description","")[:80]
                                    color = SEV_COLOR.get(sev, DIM)
                                    print(f"\n  {color(f'  [{sev}]')} {desc}")

                            elif mtype == "agent_done":
                                print(f"\n  {GREEN('✓')} {msg.get('agent','?')} done — {msg.get('findings',0)} findings")

                            elif mtype == "session_done":
                                done = True
                                print(f"\n\n  {GREEN('✓ All agents complete')}")

                        except asyncio.TimeoutError:
                            print(ORANGE("\n  ⚠ Agent stream timeout — moving on"))
                            break
                        except websockets.exceptions.ConnectionClosed:
                            break

            except Exception as ws_err:
                print(ORANGE(f"\n  ⚠ WebSocket error: {ws_err}"))

            # Wait for autopilot if it was started
            if auto_task:
                print(f"\n  {CYAN('[1/3] Waiting for tool scan to finish...')}")
                try:
                    auto_resp = await asyncio.wait_for(auto_task, timeout=600)
                    auto_data = auto_resp.json()
                    auto_findings = auto_data.get("findings", [])
                    all_findings.extend(auto_findings)
                    print(GREEN(f"  ✓ Tool scan: {len(auto_findings)} findings"))
                except Exception as ae:
                    print(ORANGE(f"  ⚠ Tool scan failed: {ae}"))

            # 6. Fetch all DB findings for this session
            if session_id:
                try:
                    resp = await http.get(f"{BACKEND_URL}/findings/{session_id}")
                    db_findings = resp.json().get("findings", [])
                    # Merge, de-duplicate by (severity, description[:60])
                    seen_keys = {f"{f.get('severity')}|{f.get('description','')[:60]}" for f in all_findings}
                    for f in db_findings:
                        k = f"{f.get('severity')}|{f.get('description','')[:60]}"
                        if k not in seen_keys:
                            all_findings.append(f)
                            seen_keys.add(k)
                except Exception:
                    pass

            # 7. Build exploitation graph
            print(CYAN("\n  [3/3] Building exploitation graph..."))
            graph: Dict = {}
            try:
                resp = await http.post(f"{BACKEND_URL}/graph/build", json={
                    "findings": all_findings,
                    "target":   target,
                }, timeout=30)
                graph = resp.json()
                print(GREEN(f"  ✓ Graph: {len(graph.get('nodes',[]))} nodes, "
                             f"{len(graph.get('attack_paths',[]))} attack path(s)"))
            except Exception as ge:
                print(ORANGE(f"  ⚠ Graph build failed: {ge}"))
                graph = {"nodes":[], "edges":[], "attack_paths":[], "risk_score":0.0, "summary":""}

    except KeyboardInterrupt:
        print(ORANGE("\n\n  ⚡ Interrupted — saving partial results..."))
    except Exception as e:
        print(RED(f"\n  ✗ Error: {e}"))

    # 8. Generate report(s)
    report_path = None
    if all_findings and report_fmt in ("html", "all"):
        try:
            report_path = _generate_html_report(
                target, all_findings, graph,
                session_id or "cli-scan", out_dir
            )
        except Exception as re_err:
            print(ORANGE(f"  ⚠ HTML report failed: {re_err}"))

    if report_fmt in ("json", "all"):
        out_dir.mkdir(parents=True, exist_ok=True)
        host = urlparse(target).hostname or target.replace("http://","").replace("https://","").split("/")[0]
        json_path = out_dir / f"phantom_{re.sub(r'[^\\w\\-.]','_',host)[:40]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_path.write_text(json.dumps({
            "target": target, "session_id": session_id,
            "findings": all_findings, "graph": graph,
            "generated_at": datetime.now().isoformat(),
        }, indent=2))
        print(GREEN(f"  ✓ JSON: {json_path}"))

    # Also save graph JSON separately
    if graph and report_fmt in ("all",):
        out_dir.mkdir(parents=True, exist_ok=True)
        host = urlparse(target).hostname or "target"
        g_path = out_dir / f"phantom_graph_{re.sub(r'[^\\w\\-.]','_',host)[:40]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        g_path.write_text(json.dumps(graph, indent=2))
        print(GREEN(f"  ✓ Graph JSON: {g_path}"))

    # 9. Print summary
    _print_summary(all_findings, graph, report_path)

    # 10. Clean up backend if we started it
    if backend_proc:
        try:
            backend_proc.terminate()
        except Exception:
            pass


# ── Train command ─────────────────────────────────────────────────────────────

async def _do_train(args):
    print(CYAN("  Triggering LLM training on verified findings..."))
    _start_backend()
    try:
        async with httpx.AsyncClient(timeout=30) as http:
            model = _active_model()
            resp  = await http.post(f"{BACKEND_URL}/ollama/train", json={
                "model_name":   "phantom-security:latest",
                "base_model":   model,
                "max_findings": 500,
            }, timeout=900)
            data = resp.json()
            print(GREEN(f"  ✓ Training complete"))
            print(f"  Model:    {data.get('model_name')}")
            print(f"  Examples: {data.get('examples')}")
            print(f"  Output:   {(data.get('output','')[:300])}")
    except Exception as e:
        print(RED(f"  ✗ Training failed: {e}"))


# ── Status command ────────────────────────────────────────────────────────────

async def _do_status(args):
    print(BOLD("\n  Phantom AI v3 — System Status\n"))
    checks = [
        ("Backend API",   _backend_alive()),
        ("Ollama LLM",    _ollama_alive()),
    ]

    # Check tools
    import shutil
    for tool in ["nmap","nuclei","nikto","sqlmap","gobuster","ffuf","subfinder","whatweb"]:
        checks.append((f"Tool: {tool}", shutil.which(tool) is not None))

    for name, ok in checks:
        icon = GREEN("✓") if ok else RED("✗")
        print(f"  {icon}  {name}")

    if _backend_alive():
        model = _active_model()
        print(f"\n  Active model: {CYAN(model)}")

        try:
            async with httpx.AsyncClient(timeout=5) as http:
                resp = await http.get(f"{BACKEND_URL}/ollama/training-history")
                runs = resp.json().get("runs",[])
                if runs:
                    last = runs[0]
                    print(f"  Last training: {last.get('status')} — {last.get('created_at','?')[:19]}")
        except Exception:
            pass
    print()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="phantom",
        description="Phantom AI v3 — Autonomous Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 backend/cli.py scan http://target.com
  python3 backend/cli.py scan http://target.com --agents all --out ./reports/ --report all
  python3 backend/cli.py scan http://target.com --no-browser --agents recon,web,network
  python3 backend/cli.py train
  python3 backend/cli.py status
        """
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan ──
    scan_p = sub.add_parser("scan", help="Run full autonomous scan")
    scan_p.add_argument("target",       help="Target URL (e.g. http://example.com)")
    scan_p.add_argument("--agents",     default="recon,web,network,exploit",
                        help="Agents to run: 'all' or comma-separated list")
    scan_p.add_argument("--out",        default="./reports", help="Output directory")
    scan_p.add_argument("--report",     default="html", choices=["html","json","sarif","all"],
                        help="Report format(s)")
    scan_p.add_argument("--no-browser", action="store_true",
                        help="Skip Playwright browser crawl, run tools only")
    scan_p.add_argument("--depth",      default="standard",
                        choices=["quick","standard","deep"], help="Scan depth")
    scan_p.add_argument("--max-iter",   type=int, default=8,
                        help="Max iterations per agent (default: 8)")

    # ── train ──
    train_p = sub.add_parser("train", help="Retrain LLM on latest verified findings")

    # ── status ──
    status_p = sub.add_parser("status", help="Check backend, Ollama, and tool health")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(_do_scan(args))
    elif args.command == "train":
        asyncio.run(_do_train(args))
    elif args.command == "status":
        asyncio.run(_do_status(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
