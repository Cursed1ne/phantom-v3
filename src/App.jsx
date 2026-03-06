// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PHANTOM AI v3 — App.jsx Part 1: Bridge, Constants, Utilities          ║
// ╚══════════════════════════════════════════════════════════════════════════╝
import { useState, useEffect, useRef, useMemo } from 'react';
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';

// ── Electron bridge (falls back gracefully in browser) ────────────────────
const E            = window.phantom || null;
const IS_ELECTRON  = !!E?.isElectron;
const BACKEND      = `http://localhost:${E?.BACKEND_PORT || 8000}`;
const WS_URL       = `ws://localhost:${E?.WS_PORT       || 8001}`;

// Unified API — uses Electron IPC when available, REST otherwise
const API = {
  proxy: {
    status:  ()    => E ? E.proxy.status()   : fetch(`${BACKEND}/proxy/status`).then(r => r.json()),
    history: (n)   => E ? E.proxy.history(n) : Promise.resolve([]),
    clear:   ()    => E ? E.proxy.clear()    : Promise.resolve({ ok: true }),
    replay:  (req) => E
      ? E.proxy.replay(req)
      : fetch(`${BACKEND}/proxy/replay`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(req) }).then(r=>r.json()),
    intercept: {
      toggle:  (en)       => E ? E.proxy.intercept.toggle(en)           : Promise.resolve({ intercept: false }),
      forward: (id, opts) => E ? E.proxy.intercept.forward(id, opts)    : Promise.resolve({ ok: true }),
      drop:    (id)       => E ? E.proxy.intercept.drop(id)             : Promise.resolve({ ok: true }),
      queue:   ()         => E ? E.proxy.intercept.queue()              : Promise.resolve([]),
    },
  },
  cert: {
    path:    ()    => E ? E.cert.path()      : Promise.resolve({ path: '', exists: false }),
    read:    ()    => E ? E.cert.read()      : Promise.resolve({ ok: false, error: 'Not in Electron' }),
    install: ()    => E ? E.cert.install()   : Promise.resolve({ ok: true }),
    reveal:  ()    => E ? E.cert.reveal()    : Promise.resolve({ ok: false }),
  },
  ollama: {
    start: () => E ? E.ollama.start() : Promise.resolve({ ok: false, error: 'Not in Electron' }),
    train: async (payload) => {
      const r = await fetch(`${BACKEND}/ollama/train`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || {}),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const detail = data?.detail || `HTTP ${r.status}`;
        throw new Error(detail);
      }
      return data;
    },
  },
  tool: {
    // Run a real CLI tool via Electron IPC, or simulate when in browser
    run: (tool, args, timeout) =>
      E
        ? E.tool.run(tool, args, timeout)
        : Promise.resolve({ output: simulateOutput(tool, args), code: 0 }),
  },
  dialog: {
    save: (content, name, filters) =>
      E
        ? E.dialog.save(content, name, filters)
        : (downloadBlob(content, name), Promise.resolve({ ok: true })),
  },
  autopilot: {
    deps: async () => {
      const r = await fetch(`${BACKEND}/autopilot/deps`);
      return r.json();
    },
    profiles: async () => {
      const r = await fetch(`${BACKEND}/autopilot/profiles`);
      return r.json();
    },
    saveProfile: async (payload) => {
      const r = await fetch(`${BACKEND}/autopilot/profiles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || {}),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data?.detail || `HTTP ${r.status}`);
      return data;
    },
    deleteProfile: async (profileId) => {
      const r = await fetch(`${BACKEND}/autopilot/profiles/${profileId}`, {
        method: 'DELETE',
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data?.detail || `HTTP ${r.status}`);
      return data;
    },
    run: async (payload) => {
      const r = await fetch(`${BACKEND}/autopilot/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || {}),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const detail = data?.detail || `HTTP ${r.status}`;
        throw new Error(detail);
      }
      return data;
    },
  },
  shell: { open: url => E ? E.shell.open(url) : window.open(url, '_blank') },
};

function downloadBlob(content, name) {
  const a   = document.createElement('a');
  const ext = name?.split('.').pop() || 'html';
  a.href    = URL.createObjectURL(new Blob([content], { type: ext === 'json' ? 'application/json' : 'text/html' }));
  a.download = name || 'report.html';
  a.click();
}

// ── Ollama streaming helper ───────────────────────────────────────────────
async function* streamOllama(messages, model, systemPrompt) {
  try {
    const resp = await fetch('http://localhost:11434/api/chat', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream:  true,
        system:  systemPrompt,
        options: { temperature: 0.15, num_predict: 1800 },
      }),
    });
    if (!resp.ok) throw new Error(`Ollama HTTP ${resp.status}`);
    const reader = resp.body.getReader();
    const dec    = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const line of dec.decode(value).split('\n').filter(Boolean)) {
        try {
          const obj = JSON.parse(line);
          if (obj?.message?.content) yield obj.message.content;
          if (obj.done) return;
        } catch {}
      }
    }
  } catch (err) {
    yield `\n[OLLAMA ERROR: ${err.message} — is "ollama serve" running?]\n`;
  }
}

// ── Agent definitions ──────────────────────────────────────────────────────
const AGENTS = {
  planner:  { id: 'planner',  icon: '🧩', name: 'Planner',  color: '#8b5cf6', desc: 'Master orchestrator — delegates tasks to specialist agents' },
  recon:    { id: 'recon',    icon: '🔭', name: 'Recon',    color: '#06b6d4', desc: 'Asset discovery, OSINT, subdomain enumeration' },
  web:      { id: 'web',      icon: '🌐', name: 'Web',      color: '#f59e0b', desc: 'Application testing: OWASP Top 10, injection, SSRF' },
  identity: { id: 'identity', icon: '🔐', name: 'Identity', color: '#ec4899', desc: 'Auth flows, JWT, OAuth/OIDC, SSO, session analysis' },
  network:  { id: 'network',  icon: '🗺', name: 'Network',  color: '#3b82f6', desc: 'Infrastructure scanning, SMB, service enumeration' },
  cloud:    { id: 'cloud',    icon: '☁',  name: 'Cloud',    color: '#10b981', desc: 'AWS/GCP/Azure posture, kube-hunter, IAM analysis' },
  exploit:  { id: 'exploit',  icon: '💥', name: 'Exploit',  color: '#ef4444', desc: 'Risk validation, CVE mapping, Metasploit modules' },
};
const AGENT_ORDER = ['planner', 'recon', 'web', 'identity', 'network', 'cloud', 'exploit'];

// ── Wordlist paths (Homebrew / Kali / Parrot locations) ──────────────────
const WL = {
  dirbuster_small:  '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
  dirbuster_medium: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
  dirbuster_big:    '/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt',
  rockyou:          '/usr/share/wordlists/rockyou.txt',
  seclists_common:  '/usr/share/seclists/Discovery/Web-Content/common.txt',
  seclists_api:     '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
};

// ── Tool registry ─────────────────────────────────────────────────────────
const TOOLS = {
  // Recon
  subfinder:     { agent: 'recon',    icon: '🔍', brew: 'subfinder' },
  amass:         { agent: 'recon',    icon: '🌐', brew: 'amass' },
  theHarvester:  { agent: 'recon',    icon: '📧', pip: 'theHarvester' },
  whatweb:       { agent: 'recon',    icon: '🔬', brew: 'whatweb' },
  // Web
  nuclei:        { agent: 'web',      icon: '☢',  brew: 'nuclei' },
  nikto:         { agent: 'web',      icon: '🕷',  brew: 'nikto' },
  sqlmap:        { agent: 'web',      icon: '💉', pip: 'sqlmap' },
  gobuster:      { agent: 'web',      icon: '📂', brew: 'gobuster', wl: true },
  ffuf:          { agent: 'web',      icon: '⚡', brew: 'ffuf',     wl: true },
  feroxbuster:   { agent: 'web',      icon: '🦀', brew: 'feroxbuster', wl: true },
  // Identity
  jwt_tool:      { agent: 'identity', icon: '🎫', pip: 'jwt_tool' },
  hydra:         { agent: 'identity', icon: '🐍', brew: 'hydra',  wl: true },
  // Network
  nmap:          { agent: 'network',  icon: '🗺', brew: 'nmap' },
  masscan:       { agent: 'network',  icon: '⚡', brew: 'masscan' },
  smbmap:        { agent: 'network',  icon: '📁', pip: 'smbmap' },
  enum4linux:    { agent: 'network',  icon: '🐧', brew: 'enum4linux' },
  crackmapexec:  { agent: 'network',  icon: '🗝', pip: 'crackmapexec' },
  // Cloud
  scoutsuite:    { agent: 'cloud',    icon: '🔭', pip: 'scoutsuite' },
  prowler:       { agent: 'cloud',    icon: '🦁', pip: 'prowler' },
  kubehunter:    { agent: 'cloud',    icon: '🚀', pip: 'kube-hunter' },
  pacu:          { agent: 'cloud',    icon: '☁',  pip: 'pacu' },
  // Exploit
  searchsploit:  { agent: 'exploit',  icon: '🔎', brew: 'exploitdb' },
  hashcat:       { agent: 'exploit',  icon: '🔐', brew: 'hashcat', wl: true },
  john:          { agent: 'exploit',  icon: '🔓', brew: 'john',    wl: true },
};

// ── Severity helpers ───────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg: '#1a0505', fg: '#f87171', bd: '#7f1d1d', order: 4, cvss: 9.5 },
  HIGH:     { bg: '#1a0d05', fg: '#fb923c', bd: '#7c2d12', order: 3, cvss: 7.5 },
  MEDIUM:   { bg: '#1a1505', fg: '#fbbf24', bd: '#713f12', order: 2, cvss: 5.0 },
  LOW:      { bg: '#051a0d', fg: '#34d399', bd: '#064e3b', order: 1, cvss: 3.0 },
  INFO:     { bg: '#050f1a', fg: '#60a5fa', bd: '#1e3a5f', order: 0, cvss: 1.0 },
};
const sevOrder = s => SEV[s]?.order ?? 0;

// ── Simulated tool output (used when Electron IPC returns "not found") ────
function simulateOutput(toolId, target = 'target.com') {
  const t = Array.isArray(target) ? target[target.indexOf('-u') + 1] || target.join(' ') : String(target);
  const SIM = {
    subfinder:    `api.${t}\ndev.${t}\nstaging.${t}\njenkins.${t}\nadmin.${t}\n[HIGH] jenkins.${t} — CI/CD pipeline exposed\n[HIGH] staging.${t} — relaxed security controls`,
    nmap:         `PORT     STATE SERVICE  VERSION\n22/tcp   open  ssh      OpenSSH 8.9\n80/tcp   open  http     nginx 1.24\n443/tcp  open  https    nginx 1.24\n3306/tcp open  mysql    MySQL 8.0.33\n6379/tcp open  redis    Redis 7.0 (no auth)\n[CRITICAL] Redis 6379 — unauthenticated, data exposed\n[HIGH] MySQL 3306 — externally reachable\n[MEDIUM] OpenSSH — CBC cipher suites detected`,
    nuclei:       `[CRITICAL][cve-2021-44228] Log4Shell on ${t}:8080\n[CRITICAL][cve-2022-22965] Spring4Shell confirmed\n[HIGH][exposed-git] /.git/HEAD accessible — source code leak\n[HIGH][phpmyadmin] phpMyAdmin panel without auth at /pma\n[MEDIUM][cors-wildcard] CORS allows any origin\n[MEDIUM][no-csp] Content-Security-Policy header missing\n[LOW][server-version] Version disclosure: nginx 1.24.0`,
    nikto:        `+ Server: nginx/1.24.0\n[CRITICAL] /backup.sql — Database dump accessible (84 KB)\n[HIGH] /.git/ — Version control directory exposed\n[HIGH] /admin/ — Admin panel, no rate limiting\n[MEDIUM] X-Frame-Options missing — clickjacking risk\n[MEDIUM] Strict-Transport-Security not set\n[LOW] X-Content-Type-Options not set`,
    gobuster:     `/admin          [301] → /admin/\n/api            [200]\n/.git           [403]\n/backup         [200] size=84.2KB\n/.env           [200] — environment variables\n/uploads        [200]\n/debug          [200] — debug endpoint active\n[CRITICAL] /.env — plaintext secrets (DB_PASS, API_KEY found)\n[HIGH] /backup — sensitive data directory\n[HIGH] /debug — debug mode active in production`,
    sqlmap:       `[CRITICAL] GET param 'id' — UNION-based SQLi confirmed\n[CRITICAL] POST param 'search' — Time-based blind SQLi\nDB: app_production | User: webapp@localhost | Privileges: DBA\nDumped table: admin_users (3 rows)\n  admin:$2b$12$X9k... (bcrypt)\n  superadmin:$2b$12$R7m...\nDumped table: api_keys (5 rows)\n[CRITICAL] INTO OUTFILE write access — potential RCE via webshell`,
    hydra:        `[22][ssh] host: ${t}  login: admin     password: password123\n[22][ssh] host: ${t}  login: ubuntu    password: ubuntu2024\n[22][ssh] host: ${t}  login: root      password: toor\n[HIGH] 3 SSH credentials found via dictionary attack\n[HIGH] Weak default credentials present`,
    scoutsuite:   `[CRITICAL] S3 bucket PUBLIC: ${t}-backups (143 objects, 4.2 GB)\n[CRITICAL] IAM user 'deploy-user' has AdministratorAccess policy\n[HIGH] Security group 'default' allows 0.0.0.0/0 → port 22\n[HIGH] CloudTrail logging disabled in us-west-2\n[MEDIUM] MFA not enforced on root account\n[MEDIUM] 14 IAM access keys unused >90 days\n[LOW] S3 server-side encryption not enabled on 3 buckets`,
    searchsploit: `nginx 1.24   | Request Smuggling (CVE-2023-44487)    | CVSS 7.5\nMySQL 8.0.33 | Stack Overflow  (CVE-2023-22028)    | CVSS 7.5\nOpenSSH 8.9  | regreSSHion RCE (CVE-2024-6387)    | CVSS 8.1\n[HIGH] CVE-2024-6387 — Unauthenticated RCE via signal handler race`,
    enum4linux:   `[+] OS: Windows Server 2019 (Build 17763)\n[+] Users: administrator, backup, service, guest\n[HIGH] Null session permitted — enumerate users/shares without auth\n[HIGH] Password policy: minimum length = 0 (no policy)\n[MEDIUM] Guest account enabled\n[MEDIUM] SMB signing not required — relay attacks possible`,
    masscan:      `Discovered open port 22/tcp on ${t}\nDiscovered open port 80/tcp on ${t}\nDiscovered open port 443/tcp on ${t}\nDiscovered open port 8080/tcp on ${t}\nDiscovered open port 27017/tcp on ${t}\n[HIGH] MongoDB 27017 — likely unauthenticated`,
  };
  return SIM[toolId] || `[${toolId}] scan of ${t} complete.\n[MEDIUM] Manual review recommended for full coverage.`;
}

// ── Extract structured findings from raw tool output ─────────────────────
function extractFindings(output, tool, agentId, iter, targetHost = '') {
  const findings = [];
  const CVSS = { CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5.5, LOW: 3.5, INFO: 1.0 };
  const seen = new Set();
  const normalizeSev = raw => {
    const s = String(raw || '').trim().toUpperCase();
    return CVSS[s] != null ? s : '';
  };
  const pushFinding = (sevRaw, descRaw, cvssOverride = null) => {
    const sev = normalizeSev(sevRaw);
    const desc = String(descRaw || '').replace(/\s+/g, ' ').trim().slice(0, 220);
    if (!sev || desc.length < 4) return;
    const k = `${sev}|${desc}`;
    if (seen.has(k)) return;
    seen.add(k);
    findings.push({
      id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      sev,
      cvss: cvssOverride ?? CVSS[sev],
      desc,
      tool,
      agent: agentId,
      iter,
      ts: new Date().toISOString(),
      _target: targetHost || undefined,
    });
  };

  // Parse nuclei JSONL output: one JSON object per line
  if (tool === 'nuclei') {
    output.split('\n').forEach(line => {
      const t = line.trim();
      if (!t) return;
      if (t.startsWith('{') && t.endsWith('}')) {
        try {
          const obj = JSON.parse(t);
          const sev = obj?.info?.severity || obj?.severity;
          const name = obj?.info?.name || obj?.['template-id'] || 'Nuclei finding';
          const where = obj?.['matched-at'] || obj?.host || obj?.url || '';
          pushFinding(sev, `${name}${where ? ` — ${where}` : ''}`);
          return;
        } catch {}
      }
      const plain = t.match(/^(\S+)\s+\[([^\]]+)\]\s+\[(critical|high|medium|low|info)\]/i);
      if (plain) {
        pushFinding(plain[3], `${plain[2]} — ${plain[1]}`);
        return;
      }
      const sevMatch = t.match(/\[(critical|high|medium|low|info)\]/i);
      if (sevMatch) {
        const cleaned = t.replace(/\[[^\]]+\]/g, ' ').replace(/\s+/g, ' ').trim();
        pushFinding(sevMatch[1], cleaned || t);
      }
    });
  }

  // Parse nmap/masscan lines for risky ports and known CVEs
  if (tool === 'nmap' || tool === 'masscan') {
    const portRisk = {
      21: ['MEDIUM', 'FTP exposed'],
      23: ['HIGH', 'Telnet exposed'],
      3306: ['HIGH', 'MySQL exposed'],
      5432: ['HIGH', 'PostgreSQL exposed'],
      6379: ['CRITICAL', 'Redis exposed'],
      9200: ['HIGH', 'Elasticsearch exposed'],
      27017: ['HIGH', 'MongoDB exposed'],
      11211: ['HIGH', 'Memcached exposed'],
    };
    output.split('\n').forEach(line => {
      let m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/i);
      if (!m) m = line.match(/Discovered open port (\d+)\/(tcp|udp)/i);
      if (m) {
        const port = Number(m[1]);
        const service = m[3] || 'service';
        const risk = portRisk[port];
        if (risk) pushFinding(risk[0], `${risk[1]} (${port}/${m[2]} ${service})`);
        else pushFinding('INFO', `Open port detected (${port}/${m[2]} ${service})`);
      }
      const cve = line.match(/(CVE-\d{4}-\d{4,7})/i);
      if (cve) pushFinding('HIGH', `Known vulnerability reference: ${cve[1]}`);
    });
  }

  // Generic [SEVERITY] tagged line parser fallback
  if (tool !== 'nuclei') {
    [['CRITICAL', 9.5], ['HIGH', 7.5], ['MEDIUM', 5.5], ['LOW', 3.5], ['INFO', 1.0]].forEach(([sev, cvss]) => {
      const re = new RegExp(`\\[${sev}\\]([^\\n]{4,240})`, 'gi');
      let m;
      while ((m = re.exec(output)) !== null) {
        pushFinding(sev, m[1], cvss);
      }
    });
  }

  return findings;
}

// ── Build tool command arguments for each tool+target combo ──────────────
function buildArgs(toolId, host) {
  const raw = String(host || '').trim();
  const noProto = raw.replace(/^https?:\/\//i, '');
  const hostOnly = noProto.split('/')[0].split(':')[0] || raw;
  const webBase = /^https?:\/\//i.test(raw)
    ? raw.replace(/\/+$/, '')
    : `https://${hostOnly}`;
  const wm = WL.dirbuster_medium, ry = WL.rockyou;
  const map = {
    subfinder:    ['subfinder',    ['-d', hostOnly, '-silent', '-all']],
    amass:        ['amass',        ['enum', '-d', hostOnly, '-passive']],
    theHarvester: ['theHarvester', ['-d', hostOnly, '-b', 'all', '-l', '50']],
    whatweb:      ['whatweb',      [webBase, '-v']],
    nuclei:       ['nuclei',       ['-u', webBase, '-as', '-severity', 'critical,high,medium,low,info', '-silent', '-jsonl', '-duc', '-no-color']],
    nikto:        ['nikto',        ['-h', webBase, '-nointeractive']],
    sqlmap:       ['sqlmap',       ['-u', `${webBase}/`, '-crawl=2', '--batch', '--level=3', '--risk=2', '--random-agent']],
    gobuster:     ['gobuster',     ['dir', '-u', webBase, '-w', wm, '-q', '-t', '50', '-x', 'php,html,js,txt,bak,sql,env']],
    ffuf:         ['ffuf',         ['-u', `${webBase}/FUZZ`, '-w', wm, '-mc', '200,204,301,403', '-t', '100', '-silent']],
    feroxbuster:  ['feroxbuster',  ['--url', webBase, '--wordlist', wm, '--quiet']],
    nmap:         ['nmap',         ['-Pn', '--unprivileged', '-sV', '-sC', '--open', '-T4', '--top-ports', '1000', hostOnly]],
    masscan:      ['masscan',      [hostOnly, '-p', '0-65535', '--rate', '10000']],
    smbmap:       ['smbmap',       ['-H', hostOnly]],
    enum4linux:   ['enum4linux',   ['-a', hostOnly]],
    crackmapexec: ['crackmapexec', ['smb', hostOnly]],
    hydra:        ['hydra',        ['-l', 'root', '-P', ry, hostOnly, 'ssh', '-t', '4', '-f']],
    hydra_ssh:    ['hydra',        ['-l', 'root', '-P', ry, hostOnly, 'ssh', '-t', '4', '-f']],
    jwt_tool:     ['jwt_tool',     ['-t', webBase, '--all']],
    scoutsuite:   ['scout',        ['aws', '--report-name', 'phantom-scout']],
    prowler:      ['prowler',      ['aws', '--output-formats', 'json']],
    kubehunter:   ['kube-hunter',  ['--remote', hostOnly, '--report', 'json']],
    searchsploit: ['searchsploit', ['--json', hostOnly]],
    hashcat:      ['hashcat',      ['-a', '0', '-m', '0', 'hashes.txt', ry, '--quiet', '--show']],
    john:         ['john',         [`--wordlist=${ry}`, '--format=auto', 'hashes.txt']],
  };
  return map[toolId] || ['curl', ['-sI', webBase]];
}

// ── JWT decoder / analyser ────────────────────────────────────────────────
const JWT = {
  decode(token) {
    try {
      const parts = token.trim().split('.');
      if (parts.length < 2) return { error: 'Not a valid JWT (needs 3 dot-separated parts)' };
      const b64 = s => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '=');
      const header  = JSON.parse(atob(b64(parts[0])));
      const payload = JSON.parse(atob(b64(parts[1])));
      const issues  = [];
      const alg     = (header.alg || '').toLowerCase();
      if (alg === 'none')         issues.push({ sev: 'CRITICAL', msg: 'Algorithm "none" — signature is not verified!' });
      if (alg.startsWith('hs'))   issues.push({ sev: 'HIGH',     msg: `${alg.toUpperCase()} symmetric — crack with: hashcat -a 0 -m 16500 jwt.txt ${WL.rockyou}` });
      if (!payload.exp)           issues.push({ sev: 'MEDIUM',   msg: 'No expiry (exp) — token lives forever' });
      if (!payload.iss)           issues.push({ sev: 'LOW',      msg: 'No issuer (iss) — token forgery risk' });
      if (!payload.jti)           issues.push({ sev: 'LOW',      msg: 'No JTI — replay attacks possible' });
      if (payload.exp && payload.iat && payload.exp - payload.iat > 86400 * 30)
        issues.push({ sev: 'MEDIUM', msg: `Long TTL: ${Math.round((payload.exp - payload.iat) / 86400)} days` });
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) issues.push({ sev: 'INFO', msg: 'Token is expired' });
      return { header, payload, signature: parts[2], issues };
    } catch (e) { return { error: e.message }; }
  },
  forgeNone(payload) {
    const enc = obj => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ ...payload, role: 'admin', admin: true })}.`;
  },
};

// ── Codec (encoder/decoder) ───────────────────────────────────────────────
const Codec = {
  b64e:  s => { try { return btoa(unescape(encodeURIComponent(s))); } catch { return 'encoding error'; } },
  b64d:  s => { try { return decodeURIComponent(escape(atob(s)));  } catch { return 'invalid base64'; } },
  urle:  s => encodeURIComponent(s),
  urld:  s => { try { return decodeURIComponent(s); } catch { return 'invalid URL encoding'; } },
  hexe:  s => Array.from(s).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
  hexd:  s => { try { return s.match(/.{1,2}/g)?.map(b => String.fromCharCode(parseInt(b, 16))).join('') || ''; } catch { return 'invalid hex'; } },
  rot13: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))),
  htmle: s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
};

// ── Shared UI components ──────────────────────────────────────────────────

/** Coloured severity badge — matches index.css .sev-badge */
function SevBadge({ sev }) {
  return <span className={`sev-badge sev-${sev}`}>{sev}</span>;
}

/** Section header with icon strip and optional right-side action */
function SectionHeader({ icon, title, subtitle, color = '#ff4500', action }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 16, gap: 11 }}>
      <div style={{
        width: 34, height: 34, borderRadius: 9,
        background: `${color}18`, border: `1px solid ${color}30`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 16, flexShrink: 0,
      }}>{icon}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 11, fontWeight: 700, color, letterSpacing: 2 }}>{title}</div>
        {subtitle && <div style={{ fontSize: 10, color: '#666', marginTop: 2 }}>{subtitle}</div>}
      </div>
      {action}
    </div>
  );
}

/** Single metric stat card */
function StatCard({ label, value, color = '#ff4500', sub, icon }) {
  return (
    <div className="stat-card" style={{ '--card-accent': color }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="stat-number" style={{ color }}>{value}</div>
          <div className="stat-label">{label}</div>
          {sub && <div style={{ fontSize: 10, color: '#555', marginTop: 3 }}>{sub}</div>}
        </div>
        {icon && <div style={{ fontSize: 22, opacity: 0.3 }}>{icon}</div>}
      </div>
    </div>
  );
}

/** Primary action button */
function Btn({ children, onClick, disabled, color = '#ff4500', style = {} }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      padding: '10px 18px', borderRadius: 8, border: 'none',
      background: `linear-gradient(135deg, ${color}bb, ${color})`,
      color: 'white', fontFamily: 'var(--font-mono)', fontSize: 10,
      fontWeight: 700, letterSpacing: 2, cursor: 'pointer',
      boxShadow: `0 3px 12px ${color}30`, ...style,
    }}>{children}</button>
  );
}

/** Ghost / outline button */
function GhostBtn({ children, onClick, disabled, color = '#666', style = {} }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      padding: '8px 14px', borderRadius: 7, fontFamily: 'var(--font-mono)',
      fontSize: 10, fontWeight: 700, background: 'transparent',
      border: `1px solid ${color}40`, color, cursor: 'pointer', ...style,
    }}>{children}</button>
  );
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PHANTOM AI v3 — App.jsx Part 2: Nav + Title bar + Dashboard + Targets ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// Navigation items
const NAV = [
  { id: 'dashboard', icon: '◈',  label: 'Dash'    },
  { id: 'targets',   icon: '🎯', label: 'Targets' },
  { id: 'agents',    icon: '⬡',  label: 'Agents'  },
  { id: 'autopilot', icon: '🕷', label: 'Auto'    },
  { id: 'proxy',     icon: '🔀', label: 'Proxy'   },
  { id: 'repeater',  icon: '↺',  label: 'Repeat'  },
  { id: 'network',   icon: '🗺', label: 'Net'     },
  { id: 'identity',  icon: '🔐', label: 'ID'      },
  { id: 'cloud',     icon: '☁',  label: 'Cloud'   },
  { id: 'graph',     icon: '◎',  label: 'Graph'   },
  { id: 'developer', icon: '🛠', label: 'Dev'     },
  { id: 'intel',     icon: '🧠', label: 'Intel'   },
  { id: 'findings',  icon: '💥', label: 'Finds'   },
  { id: 'report',    icon: '📄', label: 'Report'  },
  { id: 'settings',  icon: '⚙',  label: 'Config'  },
];

// ── Phase indicator text colours ──────────────────────────────────────────
const PHASE_CFG = {
  idle:     { color: '#44445a', label: 'DORMANT'  },
  running:  { color: '#f59e0b', label: 'SCANNING' },
  paused:   { color: '#3b82f6', label: 'PAUSED'   },
  complete: { color: '#10b981', label: 'COMPLETE'  },
};

// ── Title bar ─────────────────────────────────────────────────────────────
function TitleBar({ view, setView, findings, proxyFlagged, phase, running,
                    progress, ollamaOk, modelName, agents }) {
  const pc    = PHASE_CFG[phase] || PHASE_CFG.idle;
  const fCrit = findings.filter(f => f.sev === 'CRITICAL').length;
  const fHigh = findings.filter(f => f.sev === 'HIGH').length;
  const activeCount = Object.values(agents).filter(a => a.status === 'running').length;

  return (
    <div style={{
      height: 46, background: '#08080f', borderBottom: '1px solid #1e1e30',
      display: 'flex', alignItems: 'center', padding: '0 14px',
      WebkitAppRegion: 'drag', flexShrink: 0, position: 'relative', zIndex: 10,
      boxShadow: '0 1px 20px rgba(0,0,0,0.6)',
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, WebkitAppRegion: 'no-drag', flexShrink: 0 }}>
        <div style={{
          width: 30, height: 30, borderRadius: 8, flexShrink: 0,
          background: 'linear-gradient(135deg,#cc3700,#ff4500)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 14, boxShadow: '0 0 14px rgba(255,69,0,0.4)',
          fontFamily: 'var(--font-display)', color: 'white', fontWeight: 900,
        }}>⬡</div>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 11, fontWeight: 900, color: '#ff4500', letterSpacing: 3, lineHeight: 1 }}>PHANTOM AI</div>
          <div style={{ fontSize: 7.5, color: '#44445a', letterSpacing: 2, fontFamily: 'var(--font-mono)' }}>v3 · AUTONOMOUS PENTEST PLATFORM</div>
        </div>
      </div>

      {/* Phase pill */}
      <div style={{
        marginLeft: 14, display: 'flex', alignItems: 'center', gap: 6,
        padding: '3px 11px', borderRadius: 14, WebkitAppRegion: 'no-drag',
        background: `${pc.color}12`, border: `1px solid ${pc.color}30`,
      }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: pc.color, animation: running ? 'pulse 1.2s ease infinite' : 'none' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: pc.color, letterSpacing: 2, fontWeight: 700 }}>{pc.label}</span>
      </div>

      {/* Live counters */}
      <div style={{ display: 'flex', gap: 18, marginLeft: 14, WebkitAppRegion: 'no-drag' }}>
        {[
          ['CRIT',   fCrit,            '#ef4444'],
          ['HIGH',   fHigh,            '#fb923c'],
          ['TOTAL',  findings.length,  '#ff4500'],
          ['ACTIVE', activeCount,      '#10b981'],
        ].map(([l, v, c]) => (
          <div key={l} style={{ textAlign: 'center' }}>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 17, fontWeight: 700, color: c, lineHeight: 1 }}>{v}</div>
            <div style={{ fontSize: 7, color: '#44445a', letterSpacing: 1.5, fontFamily: 'var(--font-mono)' }}>{l}</div>
          </div>
        ))}
      </div>

      {/* Progress bar — only visible while scanning */}
      {running && (
        <div style={{ width: 180, marginLeft: 14, WebkitAppRegion: 'no-drag' }}>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <div style={{ fontSize: 8, color: '#44445a', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{progress}% complete</div>
        </div>
      )}

      {/* Right status chips */}
      <div style={{ marginLeft: 'auto', display: 'flex', gap: 7, WebkitAppRegion: 'no-drag' }}>
        <span style={{
          fontSize: 9.5, padding: '3px 10px', borderRadius: 10, fontFamily: 'var(--font-mono)',
          background: ollamaOk ? '#10b98112' : '#ef444415',
          color:      ollamaOk ? '#10b981'   : '#ef4444',
          border:     `1px solid ${ollamaOk ? '#10b98130' : '#ef444430'}`,
        }}>
          {ollamaOk ? `● ${modelName.split(':')[0]}` : '○ OLLAMA OFFLINE'}
        </span>
        <span style={{ fontSize: 9.5, padding: '3px 10px', borderRadius: 10, background: '#1e1e3020', color: '#555', fontFamily: 'var(--font-mono)', border: '1px solid #1e1e30' }}>
          🔀 :8888
        </span>
        {proxyFlagged > 0 && (
          <span onClick={() => setView('proxy')} style={{
            fontSize: 9.5, padding: '3px 10px', borderRadius: 10, cursor: 'pointer',
            background: '#ff450015', color: '#ff4500', border: '1px solid #ff450030', fontFamily: 'var(--font-mono)',
          }}>⚠ {proxyFlagged}</span>
        )}
      </div>
    </div>
  );
}

// ── Sidebar nav ───────────────────────────────────────────────────────────
function Sidebar({ view, setView, findingsCount, proxyFlaggedCount }) {
  return (
    <nav style={{
      width: 64, background: '#08080f', borderRight: '1px solid #1e1e30',
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      paddingTop: 8, gap: 3, flexShrink: 0,
    }}>
      {NAV.map(n => {
        const active = view === n.id;
        const badge  = (n.id === 'findings' && findingsCount > 0)
                    || (n.id === 'proxy'    && proxyFlaggedCount > 0);
        return (
          <button key={n.id} title={n.id} onClick={() => setView(n.id)}
            className={`nav-btn${active ? ' active' : ''}`}>
            <span className="nav-icon">{n.icon}</span>
            <span className="nav-label">{n.label}</span>
            {badge && (
              <span className="nav-badge">
                {n.id === 'findings' ? (findingsCount > 99 ? '99+' : findingsCount) : proxyFlaggedCount}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}

// ── Dashboard view ────────────────────────────────────────────────────────
function DashboardView({ findings, agentStatus, running, ollamaOk, setView }) {
  const fCrit = findings.filter(f => f.sev === 'CRITICAL').length;
  const fHigh = findings.filter(f => f.sev === 'HIGH').length;
  const fMed  = findings.filter(f => f.sev === 'MEDIUM').length;
  const fLow  = findings.filter(f => f.sev === 'LOW').length;
  const risk  = Math.min(10, fCrit * 2.5 + fHigh * 1.2 + fMed * 0.4 + fLow * 0.1).toFixed(1);

  const agentBarData = AGENT_ORDER.map(a => ({
    name: AGENTS[a].name,
    findings: findings.filter(f => f.agent === a).length,
    fill: AGENTS[a].color,
  }));

  const sevPieData = [
    { name: 'CRITICAL', value: fCrit, fill: '#ef4444' },
    { name: 'HIGH',     value: fHigh, fill: '#fb923c' },
    { name: 'MEDIUM',   value: fMed,  fill: '#fbbf24' },
    { name: 'LOW',      value: fLow,  fill: '#34d399' },
  ].filter(d => d.value > 0);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 18 }}>
      <SectionHeader icon="◈" title="SECURITY DASHBOARD" subtitle={`${findings.length} findings · Risk score ${risk}/10`} />

      {/* Stat row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10, marginBottom: 18 }}>
        <StatCard label="CRITICAL" value={fCrit} color="#ef4444" icon="💀" />
        <StatCard label="HIGH"     value={fHigh} color="#fb923c" icon="🔴" />
        <StatCard label="MEDIUM"   value={fMed}  color="#fbbf24" icon="⚠"  />
        <StatCard label="LOW"      value={fLow}  color="#34d399" icon="ℹ"  />
        <StatCard label="RISK SCORE" value={risk} color={parseFloat(risk) >= 8 ? '#ef4444' : parseFloat(risk) >= 5 ? '#fb923c' : '#fbbf24'} sub="/10 max" />
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12, marginBottom: 14 }}>
        <div className="card">
          <div className="card-header">Findings by Agent</div>
          <div style={{ padding: 14, height: 190 }}>
            {findings.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={agentBarData} margin={{ top: 4, right: 4, bottom: 0, left: -22 }}>
                  <XAxis dataKey="name" tick={{ fill: '#666', fontSize: 9.5, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#555', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f0f1a', border: '1px solid #1e1e30', borderRadius: 7, fontFamily: 'JetBrains Mono', fontSize: 11 }} />
                  <Bar dataKey="findings" radius={[5, 5, 0, 0]}>
                    {agentBarData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#44445a', fontSize: 12 }}>
                Run a scan to populate
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">Severity Split</div>
          <div style={{ padding: 14, height: 190 }}>
            {sevPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevPieData} dataKey="value" cx="50%" cy="50%" innerRadius={44} outerRadius={72} paddingAngle={3}>
                    {sevPieData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0f0f1a', border: '1px solid #1e1e30', borderRadius: 7, fontFamily: 'JetBrains Mono', fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#44445a', fontSize: 12 }}>No data</div>
            )}
          </div>
        </div>
      </div>

      {/* Agent grid */}
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-header">Agent Status Grid</div>
        <div style={{ padding: 14, display: 'grid', gridTemplateColumns: 'repeat(7,1fr)', gap: 10 }}>
          {AGENT_ORDER.map(a => {
            const ag  = AGENTS[a];
            const st  = agentStatus[a] || {};
            const sc  = { idle: '#33334a', thinking: '#8b5cf6', running: '#f59e0b', complete: '#10b981', error: '#ef4444' };
            const col = sc[st.status] || sc.idle;
            return (
              <div key={a} style={{
                textAlign: 'center', padding: '12px 6px', borderRadius: 10,
                background: 'var(--bg-surface)', border: `1px solid ${col}22`,
              }}>
                <div style={{ fontSize: 20, marginBottom: 4 }}>{ag.icon}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, fontWeight: 700, color: ag.color, letterSpacing: 1, marginBottom: 3 }}>{ag.name}</div>
                <div style={{ fontSize: 8, color: col, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>{(st.status || 'idle').toUpperCase()}</div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700, color: ag.color }}>
                  {findings.filter(f => f.agent === a).length}
                </div>
                <div style={{ fontSize: 7, color: '#44445a', fontFamily: 'var(--font-mono)' }}>FINDINGS</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Critical findings quick list */}
      {fCrit > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <div className="card-header" style={{ color: '#ef4444' }}>💀 Critical — Immediate Action Required</div>
          <div style={{ padding: 10 }}>
            {findings.filter(f => f.sev === 'CRITICAL').slice(0, 6).map((f, i) => (
              <div key={i} style={{
                display: 'flex', gap: 10, padding: '9px 12px', borderRadius: 8,
                marginBottom: 5, background: '#1a0505', border: '1px solid rgba(127,29,29,0.3)', alignItems: 'flex-start',
              }}>
                <SevBadge sev="CRITICAL" />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12.5, color: '#e8e8f0', lineHeight: 1.4 }}>{f.desc}</div>
                  <div style={{ fontSize: 9.5, color: '#555', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{f.agent} · {f.tool} · iter #{f.iter}</div>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#f87171', fontWeight: 700, whiteSpace: 'nowrap' }}>CVSS {f.cvss}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {findings.length === 0 && !running && (
        <div style={{
          textAlign: 'center', padding: 60, borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
        }}>
          <div style={{ fontSize: 64, opacity: 0.15, marginBottom: 12 }}>⬡</div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 13, color: '#ff4500', letterSpacing: 3, marginBottom: 10 }}>PHANTOM DORMANT</div>
          <div style={{ fontSize: 13, color: '#555', lineHeight: 1.9 }}>Add targets → go to Agents → Launch scan</div>
          {!ollamaOk && (
            <div style={{
              marginTop: 18, display: 'inline-block', padding: '10px 18px',
              background: '#1a0505', border: '1px solid #7f1d1d', borderRadius: 8,
              fontSize: 11, color: '#f87171', fontFamily: 'var(--font-mono)',
            }}>
              ⚠ Ollama offline → run: <strong>ollama serve &amp;&amp; ollama pull llama3.1</strong>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Targets view ──────────────────────────────────────────────────────────
function TargetsView({ targets, setTargets, activeTarget, setActiveTarget, findings }) {
  const [host,  setHost]  = useState('');
  const [type,  setType]  = useState('web');
  const [label, setLabel] = useState('');
  const [scope, setScope] = useState('');

  function addTarget() {
    if (!host.trim()) return;
    setTargets(p => [...p, {
      id:    Date.now(),
      host:  host.trim(),
      type, label: label || host.trim(), scope: scope || host.trim(),
      added: new Date().toISOString(),
    }]);
    setHost(''); setLabel(''); setScope('');
  }

  const typeIcon = t => ({ web: '🌐', api: '⚡', network: '🗺', cloud: '☁', mobile: '📱', iot: '🔌' }[t] || '🎯');

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 18 }}>
      <SectionHeader icon="🎯" title="TARGET MANAGER" subtitle="Define scope, hosts, IP ranges, cloud accounts" />
      <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 14 }}>

        {/* Add form */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="card" style={{ padding: 16 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#ff4500', letterSpacing: 2, fontWeight: 700, marginBottom: 13 }}>ADD TARGET</div>

            {[
              { label: 'HOST / IP / CIDR', value: host, set: setHost, ph: 'example.com | 192.168.1.0/24', mono: true },
              { label: 'LABEL',            value: label, set: setLabel, ph: 'Production, Staging, Lab...' },
              { label: 'SCOPE NOTES',      value: scope, set: setScope, ph: 'In-scope paths, exclusions...' },
            ].map(({ label: l, value, set, ph, mono }) => (
              <div key={l} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', letterSpacing: 1, marginBottom: 4 }}>{l}</div>
                <input value={value} onChange={e => set(e.target.value)}
                  placeholder={ph} onKeyDown={e => e.key === 'Enter' && addTarget()}
                  style={{ width: '100%', padding: '8px 11px', fontSize: 12, fontFamily: mono ? 'var(--font-mono)' : 'var(--font-sans)' }} />
              </div>
            ))}

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', letterSpacing: 1, marginBottom: 5 }}>TYPE</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 5 }}>
                {[['web','🌐 Web'],['api','⚡ API'],['network','🗺 Net'],['cloud','☁ Cloud'],['mobile','📱 Mobile'],['iot','🔌 IoT']].map(([v, l]) => (
                  <button key={v} onClick={() => setType(v)} style={{
                    padding: '7px 4px', borderRadius: 6, fontSize: 10, cursor: 'pointer',
                    border: `1px solid ${type === v ? '#ff450040' : '#1e1e30'}`,
                    background: type === v ? '#ff450012' : 'transparent',
                    color: type === v ? '#ff4500' : '#555', fontWeight: type === v ? 700 : 400,
                  }}>{l}</button>
                ))}
              </div>
            </div>

            <Btn onClick={addTarget} style={{ width: '100%', padding: 11 }}>+ ADD TO SCOPE</Btn>
          </div>

          {/* Credentials vault */}
          <div className="card" style={{ padding: 16 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#8b5cf6', letterSpacing: 2, fontWeight: 700, marginBottom: 10 }}>CREDENTIALS VAULT</div>
            <div style={{ fontSize: 11, color: '#555', lineHeight: 1.8, marginBottom: 10 }}>
              Optional credentials for authenticated testing. Stored in local encrypted vault — never transmitted externally.
            </div>
            {['SSH Key / Password', 'HTTP Basic Auth', 'API Token / Bearer', 'AWS Access Keys', 'OAuth Client Secret'].map(l => (
              <div key={l} style={{ display: 'flex', gap: 7, marginBottom: 6, alignItems: 'center' }}>
                <span style={{ fontSize: 9.5, color: '#555', fontFamily: 'var(--font-mono)', minWidth: 110 }}>{l}</span>
                <input placeholder="not set" type="password"
                  style={{ flex: 1, padding: '6px 9px', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
                <GhostBtn style={{ padding: '5px 10px', fontSize: 9 }}>Save</GhostBtn>
              </div>
            ))}
          </div>
        </div>

        {/* Target list */}
        <div>
          <div className="card">
            <div className="card-header">IN-SCOPE TARGETS ({targets.length})</div>
            <div style={{ padding: 8 }}>
              {targets.length === 0 && (
                <div style={{ padding: 40, textAlign: 'center', color: '#44445a', fontSize: 12 }}>No targets yet — add one above</div>
              )}
              {targets.map((t, i) => (
                <div key={t.id} onClick={() => setActiveTarget(i)} style={{
                  padding: '12px 14px', borderRadius: 9, marginBottom: 6, cursor: 'pointer',
                  background: activeTarget === i ? '#ff450010' : 'var(--bg-surface)',
                  border: `1px solid ${activeTarget === i ? '#ff450035' : 'var(--border)'}`,
                  transition: 'all 0.12s',
                }}>
                  <div style={{ display: 'flex', gap: 9, alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 16 }}>{typeIcon(t.type)}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: activeTarget === i ? '#ff4500' : '#e8e8f0', fontWeight: 600, flex: 1 }}>{t.host}</span>
                    <span style={{
                      fontSize: 8.5, padding: '2px 7px', borderRadius: 4, fontFamily: 'var(--font-mono)', fontWeight: 700,
                      background: activeTarget === i ? '#ff450018' : '#1e1e30',
                      color: activeTarget === i ? '#ff4500' : '#555',
                      border: `1px solid ${activeTarget === i ? '#ff450035' : '#1e1e30'}`,
                    }}>{t.type.toUpperCase()}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#555', fontFamily: 'var(--font-mono)' }}>
                    <span>{t.label}</span>
                    <span>{findings.filter(f => f._target === t.host).length || 0} findings</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Proxy view ────────────────────────────────────────────────────────────
function ProxyView({ proxyReqs, setProxyReqs, onSendToRepeater }) {
  const [selected,        setSelected]        = useState(null);
  const [filter,          setFilter]          = useState('');
  const [flagOnly,        setFlagOnly]        = useState(false);
  const [intercept,       setIntercept]       = useState(false);
  const [heldReqs,        setHeldReqs]        = useState([]);
  const [certMsg,         setCertMsg]         = useState('');
  const [analyzing,       setAnalyzing]       = useState(false);
  const [analysisFindings, setAnalysisFindings] = useState([]);

  // Poll intercept queue when intercept mode is on
  useEffect(() => {
    if (!intercept) { setHeldReqs([]); return; }
    const id = setInterval(async () => {
      const q = await API.proxy.intercept.queue().catch(() => []);
      setHeldReqs(q);
    }, 500);
    return () => clearInterval(id);
  }, [intercept]);

  async function toggleIntercept() {
    const r = await API.proxy.intercept.toggle(!intercept);
    setIntercept(r?.intercept ?? !intercept);
    if (!r?.intercept) setHeldReqs([]);
  }

  function clearHistory() { setProxyReqs([]); API.proxy.clear(); setSelected(null); }

  async function installCert() {
    setCertMsg('Installing…');
    const r = await API.cert.install();
    setCertMsg(r.ok ? `✓ Installed (${r.scope || 'keychain'})` : `✗ ${r.error || 'Failed'}`);
    setTimeout(() => setCertMsg(''), 5000);
  }

  async function analyzeTraffic() {
    setAnalyzing(true);
    setAnalysisFindings([]);
    try {
      const history = proxyReqs.slice(0, 50).map(r => ({
        url: r.url, method: r.method, body: r.body || '',
        requestHeaders: r.headers || {}, responseBody: r.response?.body || '',
        flagged: r.flagged, vulns: r.vulns || [],
      }));
      const resp = await fetch('http://localhost:8000/proxy/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ history }),
      });
      const data = await resp.json();
      setAnalysisFindings(data.findings || []);
    } catch (e) {
      setAnalysisFindings([{ severity: 'INFO', description: `Analysis failed: ${e.message}` }]);
    } finally {
      setAnalyzing(false);
    }
  }

  async function exportTrafficEvidence() {
    const flagged = proxyReqs.filter(r => r.flagged);
    const payload = { generated_at: new Date().toISOString(), total_requests: proxyReqs.length, flagged_requests: flagged.length,
      entries: flagged.map(r => ({ id:r.id, method:r.method, url:r.url, timestamp:r.timestamp, tls:!!r.tls, vulns:r.vulns||[],
        request:{ headers:r.headers||{}, body:r.body||'' }, response:{ status:r.response?.status||0, headers:r.response?.headers||{}, body:r.response?.body||'' } })) };
    await API.dialog.save(JSON.stringify(payload,null,2), `proxy-evidence-${Date.now()}.json`, [{ name:'JSON', extensions:['json'] }]);
  }

  const list = proxyReqs.filter(r => {
    if (flagOnly && !r.flagged) return false;
    if (filter && !r.url?.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });
  const flaggedCount = proxyReqs.filter(r => r.flagged).length;
  const methodColor  = m => ({ POST:'#fb923c', PUT:'#fbbf24', DELETE:'#ef4444', PATCH:'#8b5cf6' }[m] || '#3b82f6');

  return (
    <div style={{ flex:1, display:'flex', overflow:'hidden', flexDirection:'column' }}>

      {/* Intercept held-requests banner */}
      {intercept && heldReqs.length > 0 && (
        <div style={{ background:'#1a0a00', borderBottom:'2px solid #ff4500', padding:'8px 14px', display:'flex', gap:8, alignItems:'center', flexShrink:0 }}>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'#ff4500', fontWeight:700 }}>⏸ {heldReqs.length} HELD</span>
          {heldReqs.map(r => (
            <div key={r.id} style={{ display:'flex', gap:4, alignItems:'center', background:'#ff450015', border:'1px solid #ff450030', borderRadius:5, padding:'3px 8px' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'#fb923c' }}>{r.method}</span>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'#aaa', maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{r.url}</span>
              <button onClick={() => API.proxy.intercept.forward(r.id,{}).then(() => setHeldReqs(p=>p.filter(x=>x.id!==r.id)))}
                style={{ fontFamily:'var(--font-mono)', fontSize:9, padding:'1px 6px', background:'#10b98120', color:'#10b981', border:'1px solid #10b98130', borderRadius:3, cursor:'pointer' }}>
                FWD
              </button>
              <button onClick={() => API.proxy.intercept.drop(r.id).then(() => setHeldReqs(p=>p.filter(x=>x.id!==r.id)))}
                style={{ fontFamily:'var(--font-mono)', fontSize:9, padding:'1px 6px', background:'#ef444420', color:'#ef4444', border:'1px solid #ef444430', borderRadius:3, cursor:'pointer' }}>
                DROP
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
        {/* Request list */}
        <div style={{ width:390, background:'#08080f', borderRight:'1px solid #1e1e30', display:'flex', flexDirection:'column', flexShrink:0 }}>
          {/* Toolbar */}
          <div style={{ padding:'8px 12px', background:'#0f0f1a', borderBottom:'1px solid #1e1e30', display:'flex', gap:6, alignItems:'center', flexWrap:'wrap' }}>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#ff4500', fontWeight:700, letterSpacing:1.5 }}>PROXY</span>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, padding:'2px 7px', borderRadius:4, background:'#10b98112', color:'#10b981', border:'1px solid #10b98130' }}>:8888</span>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, padding:'2px 6px', borderRadius:4, background:'#1e1e30', color:'#666' }}>{proxyReqs.length}</span>
            {/* Intercept toggle */}
            <button onClick={toggleIntercept} title="Pause requests for inspection" style={{
              fontSize:8.5, padding:'3px 8px', borderRadius:5, cursor:'pointer',
              border:`1px solid ${intercept ? '#f59e0b40' : '#1e1e30'}`,
              background: intercept ? '#f59e0b18' : 'transparent',
              color: intercept ? '#f59e0b' : '#555', fontFamily:'var(--font-mono)',
            }}>⏸ {intercept ? 'INTERCEPT ON' : 'Intercept'}</button>
            <button onClick={() => setFlagOnly(p=>!p)} style={{
              fontSize:8.5, padding:'3px 8px', borderRadius:5, cursor:'pointer',
              border:`1px solid ${flagOnly?'#ff450040':'#1e1e30'}`, background:flagOnly?'#ff450012':'transparent',
              color:flagOnly?'#ff4500':'#555', fontFamily:'var(--font-mono)',
            }}>⚠ {flaggedCount}</button>
            <button onClick={exportTrafficEvidence} style={{ fontSize:8.5, padding:'3px 8px', borderRadius:5, cursor:'pointer', border:'1px solid #ec489940', background:'#ec489912', color:'#ec4899', fontFamily:'var(--font-mono)' }}>Export</button>
            <button onClick={installCert} title="Install CA Certificate in system keychain" style={{ fontSize:8.5, padding:'3px 8px', borderRadius:5, cursor:'pointer', border:'1px solid #f59e0b30', background:'#f59e0b10', color:'#f59e0b', fontFamily:'var(--font-mono)' }}>
              {certMsg || 'Install CA'}
            </button>
            <button onClick={analyzing ? undefined : analyzeTraffic} title="AI analysis of captured traffic for vulnerabilities" style={{ fontSize:8.5, padding:'3px 8px', borderRadius:5, cursor: analyzing ? 'wait' : 'pointer', border:'1px solid #8b5cf640', background:'#8b5cf612', color:'#8b5cf6', fontFamily:'var(--font-mono)' }}>
              {analyzing ? '⟳ Analyzing…' : '🧠 Analyze'}
            </button>
            <button onClick={clearHistory} style={{ marginLeft:'auto', fontSize:8.5, padding:'3px 8px', borderRadius:5, cursor:'pointer', border:'1px solid #1e1e30', background:'transparent', color:'#555', fontFamily:'var(--font-mono)' }}>Clear</button>
          </div>
          {analysisFindings.length > 0 && (
            <div style={{ padding:'8px 12px', background:'#0d0d1f', borderBottom:'1px solid #1e1e30' }}>
              <div style={{ fontFamily:'var(--font-mono)', fontSize:8, color:'#8b5cf6', marginBottom:5, letterSpacing:1.5 }}>AI ANALYSIS — {analysisFindings.length} FINDINGS</div>
              {analysisFindings.map((f, i) => (
                <div key={i} style={{ display:'flex', gap:6, alignItems:'flex-start', marginBottom:3 }}>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:8, padding:'1px 5px', borderRadius:3, background: f.severity==='CRITICAL'?'#ef444420':f.severity==='HIGH'?'#f9731620':'#8b5cf620', color: f.severity==='CRITICAL'?'#ef4444':f.severity==='HIGH'?'#fb923c':'#8b5cf6', whiteSpace:'nowrap', flexShrink:0 }}>
                    {f.severity}
                  </span>
                  <span style={{ fontSize:10, color:'#c0c0e0' }}>{f.description}</span>
                </div>
              ))}
            </div>
          )}
          <div style={{ padding:'6px 10px', borderBottom:'1px solid #141420' }}>
            <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter by URL…"
              style={{ width:'100%', padding:'6px 10px', fontSize:11.5 }} />
          </div>
          <div style={{ flex:1, overflowY:'auto' }}>
            {list.length === 0 && (
              <div style={{ padding:40, textAlign:'center', color:'#44445a', fontSize:12, lineHeight:1.9 }}>
                No traffic yet.<br/>Set browser proxy to<br/>
                <strong style={{ color:'#ff4500', fontFamily:'var(--font-mono)' }}>127.0.0.1:8888</strong><br/><br/>
                Then click <strong style={{ color:'#f59e0b' }}>Install CA</strong> above.
              </div>
            )}
            {list.map(r => (
              <div key={r.id} onClick={() => setSelected(r)} style={{
                padding:'8px 12px', borderBottom:'1px solid #141420', cursor:'pointer',
                background: selected?.id===r.id ? '#ff450010' : 'transparent',
                borderLeft:`3px solid ${r.flagged ? (r.maxSev==='CRITICAL'?'#ef4444':'#fb923c') : 'transparent'}`,
              }}>
                <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:3 }}>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, fontWeight:700, padding:'1px 5px', borderRadius:3,
                    background:`${methodColor(r.method)}18`, color:methodColor(r.method), border:`1px solid ${methodColor(r.method)}30` }}>
                    {r.method}
                  </span>
                  {r.response?.status && (
                    <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5,
                      color:r.response.status>=500?'#ef4444':r.response.status>=400?'#fb923c':'#10b981' }}>
                      {r.response.status}
                    </span>
                  )}
                  {r.tls && <span style={{ fontFamily:'var(--font-mono)', fontSize:7.5, color:'#10b981', padding:'1px 4px', border:'1px solid #10b98130', borderRadius:2 }}>TLS</span>}
                  {r.flagged && <span style={{ marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:8, color:SEV[r.maxSev]?.fg||'#fb923c' }}>⚠ {r.vulns?.[0]?.type}</span>}
                </div>
                <div style={{ fontSize:11, color:'#666', fontFamily:'var(--font-mono)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                  {r.url?.substring(0,55)}
                </div>
              </div>
            ))}
          </div>
          <div style={{ padding:'7px 12px', borderTop:'1px solid #1e1e30', fontSize:7.5, color:'#33334a', fontFamily:'var(--font-mono)', textAlign:'center', lineHeight:1.8 }}>
            HTTPS MITM · Auto-cert per host · Intercept · Replay<br/>Detects: SQLi XSS SSTI RCE LFI JWT AWS APIKey
          </div>
        </div>

        {/* Request detail */}
        <div style={{ flex:1, overflowY:'auto', padding:14 }}>
          {!selected ? (
            <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'100%', flexDirection:'column', gap:10, color:'#33334a' }}>
              <span style={{ fontSize:52 }}>🔀</span>
              <span style={{ fontSize:13 }}>Select a request to inspect</span>
            </div>
          ) : (
            <>
              {/* Action bar */}
              <div style={{ display:'flex', gap:8, marginBottom:12 }}>
                <button onClick={() => onSendToRepeater && onSendToRepeater(selected)} style={{
                  fontFamily:'var(--font-mono)', fontSize:10, padding:'6px 14px', borderRadius:6, cursor:'pointer',
                  background:'#3b82f620', color:'#3b82f6', border:'1px solid #3b82f640',
                }}>↺ Send to Repeater</button>
                {selected.flagged && (
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:10, padding:'6px 14px', borderRadius:6,
                    background:'#ef444415', color:'#ef4444', border:'1px solid #ef444430' }}>
                    🚨 {selected.maxSev} · {selected.vulns?.map(v=>v.type).join(' · ')}
                  </span>
                )}
              </div>

              {selected.flagged && (
                <div style={{ background:'#1a0505', border:'1px solid #7f1d1d40', borderRadius:'var(--radius-lg)', padding:14, marginBottom:12 }}>
                  <div style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#ef4444', letterSpacing:2, marginBottom:8, fontWeight:700 }}>🚨 DETECTED PATTERNS</div>
                  <div style={{ display:'flex', gap:7, flexWrap:'wrap' }}>
                    {selected.vulns?.map((v,i) => (
                      <span key={i} style={{ display:'flex', gap:6, alignItems:'center', background:`${SEV[v.sev]?.bg}`, border:`1px solid ${SEV[v.sev]?.bd}40`, borderRadius:5, padding:'4px 10px' }}>
                        <SevBadge sev={v.sev} />
                        <span style={{ fontSize:11, color:SEV[v.sev]?.fg, fontWeight:600 }}>{v.type}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="card" style={{ marginBottom:12 }}>
                <div className="card-header">REQUEST</div>
                <div style={{ padding:14 }}>
                  <div style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'#ff8040', marginBottom:10, wordBreak:'break-all' }}>
                    {selected.method} {selected.url}
                  </div>
                  <pre className="terminal" style={{ maxHeight:160, fontSize:11 }}>{JSON.stringify(selected.headers,null,2)}</pre>
                  {selected.body && <pre className="terminal" style={{ maxHeight:110, marginTop:8, borderColor:'#fbbf2425', color:'#fbbf24' }}>{selected.body}</pre>}
                </div>
              </div>

              {selected.response && (
                <div className="card">
                  <div className="card-header">RESPONSE <span style={{ color:selected.response.status>=400?'#ef4444':'#10b981' }}>{selected.response.status}</span></div>
                  <div style={{ padding:14 }}>
                    <pre className="terminal" style={{ maxHeight:300, color:'#6ee7b7', borderColor:'#10b98120' }}>{selected.response.body}</pre>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Repeater view ─────────────────────────────────────────────────────────
function RepeaterView({ initialRequest }) {
  const [method,   setMethod]   = useState(initialRequest?.method  || 'GET');
  const [url,      setUrl]      = useState(initialRequest?.url     || '');
  const [headers,  setHeaders]  = useState(initialRequest ? JSON.stringify(initialRequest.headers||{},null,2) : '{\n  "User-Agent": "Phantom-Repeater/3.0"\n}');
  const [body,     setBody]     = useState(initialRequest?.body    || '');
  const [response, setResponse] = useState(null);
  const [loading,  setLoading]  = useState(false);
  const [history,  setHistory]  = useState([]);
  const [selHist,  setSelHist]  = useState(null);
  const [elapsed,  setElapsed]  = useState(null);

  // When parent passes a new initialRequest (Send to Repeater)
  useEffect(() => {
    if (!initialRequest) return;
    setMethod(initialRequest.method  || 'GET');
    setUrl(initialRequest.url        || '');
    setHeaders(JSON.stringify(initialRequest.headers||{},null,2));
    setBody(initialRequest.body      || '');
    setResponse(null);
    setElapsed(null);
  }, [initialRequest]);

  async function sendRequest() {
    if (!url.trim()) return;
    setLoading(true);
    setResponse(null);
    let parsedHeaders = {};
    try { parsedHeaders = JSON.parse(headers); } catch { parsedHeaders = {}; }
    const t0 = Date.now();
    const r  = await API.proxy.replay({ method, url, headers: parsedHeaders, body: body || undefined });
    const ms = Date.now() - t0;
    setLoading(false);
    setElapsed(r.elapsed_ms || ms);
    setResponse(r);
    if (r.ok) {
      setHistory(prev => [{ id: Date.now(), method, url, status:r.status, elapsed_ms:r.elapsed_ms||ms, ts:new Date().toISOString() }, ...prev.slice(0,49)]);
    }
  }

  const statusColor = s => s >= 500 ? '#ef4444' : s >= 400 ? '#fb923c' : s >= 300 ? '#fbbf24' : '#10b981';
  const METHODS     = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'];

  return (
    <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
      {/* History sidebar */}
      <div style={{ width:220, background:'#08080f', borderRight:'1px solid #1e1e30', display:'flex', flexDirection:'column', flexShrink:0 }}>
        <div style={{ padding:'8px 12px', background:'#0f0f1a', borderBottom:'1px solid #1e1e30' }}>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#3b82f6', fontWeight:700, letterSpacing:1.5 }}>↺ REPEATER</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, marginLeft:8, color:'#555' }}>HISTORY</span>
        </div>
        <div style={{ flex:1, overflowY:'auto' }}>
          {history.length === 0 && (
            <div style={{ padding:20, textAlign:'center', color:'#33334a', fontSize:11 }}>Send a request to start</div>
          )}
          {history.map(h => (
            <div key={h.id} onClick={() => setSelHist(h)} style={{
              padding:'8px 12px', borderBottom:'1px solid #141420', cursor:'pointer',
              background: selHist?.id===h.id ? '#3b82f610' : 'transparent',
            }}>
              <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:3 }}>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:8, color:'#3b82f6' }}>{h.method}</span>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:statusColor(h.status) }}>{h.status}</span>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:8, color:'#555', marginLeft:'auto' }}>{h.elapsed_ms}ms</span>
              </div>
              <div style={{ fontSize:10, color:'#555', fontFamily:'var(--font-mono)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                {h.url?.replace(/^https?:\/\/[^/]+/,'')?.substring(0,28) || '/'}
              </div>
            </div>
          ))}
        </div>
        {history.length > 0 && (
          <button onClick={() => { setHistory([]); setSelHist(null); }} style={{ margin:8, fontFamily:'var(--font-mono)', fontSize:9, padding:'5px', borderRadius:5, border:'1px solid #1e1e30', background:'transparent', color:'#555', cursor:'pointer' }}>Clear history</button>
        )}
      </div>

      {/* Main panel */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>

        {/* Request builder */}
        <div style={{ padding:12, borderBottom:'1px solid #1e1e30', display:'flex', gap:8, alignItems:'center', background:'#0a0a14', flexShrink:0 }}>
          <select value={method} onChange={e=>setMethod(e.target.value)} style={{
            fontFamily:'var(--font-mono)', fontSize:11, padding:'6px 10px', borderRadius:6,
            background:'#0f0f1a', border:'1px solid #1e1e30', color:'#fb923c', cursor:'pointer', width:90,
          }}>
            {METHODS.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
          <input value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&sendRequest()}
            placeholder="https://target.com/api/endpoint"
            style={{ flex:1, padding:'7px 12px', fontSize:12, fontFamily:'var(--font-mono)', borderRadius:6 }} />
          <button onClick={sendRequest} disabled={loading || !url.trim()} style={{
            fontFamily:'var(--font-mono)', fontSize:11, padding:'7px 18px', borderRadius:6, cursor:'pointer',
            background: loading ? '#1e1e30' : '#3b82f6', color: loading ? '#555' : '#fff',
            border:'none', fontWeight:700, minWidth:70,
          }}>{loading ? '…' : '▶ Send'}</button>
          {elapsed !== null && <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'#555' }}>{elapsed}ms</span>}
        </div>

        {/* Headers + Body / Response split */}
        <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
          {/* Left: request editor */}
          <div style={{ flex:1, display:'flex', flexDirection:'column', borderRight:'1px solid #1e1e30', overflow:'hidden' }}>
            <div style={{ padding:'6px 12px', background:'#0c0c18', borderBottom:'1px solid #141420' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#3b82f6', letterSpacing:1.5 }}>HEADERS (JSON)</span>
            </div>
            <textarea value={headers} onChange={e=>setHeaders(e.target.value)} spellCheck={false}
              style={{ flex:'0 0 160px', resize:'none', padding:10, fontFamily:'var(--font-mono)', fontSize:11.5,
                background:'#080810', border:'none', borderBottom:'1px solid #1e1e30', color:'#a5b4fc', outline:'none' }} />
            <div style={{ padding:'6px 12px', background:'#0c0c18', borderBottom:'1px solid #141420' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#fbbf24', letterSpacing:1.5 }}>BODY</span>
            </div>
            <textarea value={body} onChange={e=>setBody(e.target.value)} spellCheck={false}
              placeholder="Request body (JSON, form data, XML…)"
              style={{ flex:1, resize:'none', padding:10, fontFamily:'var(--font-mono)', fontSize:11.5,
                background:'#080810', border:'none', color:'#fbbf24', outline:'none' }} />
          </div>

          {/* Right: response */}
          <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
            <div style={{ padding:'6px 12px', background:'#0c0c18', borderBottom:'1px solid #141420', display:'flex', gap:10, alignItems:'center' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#10b981', letterSpacing:1.5 }}>RESPONSE</span>
              {response?.ok && (
                <>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:10, color:statusColor(response.status), fontWeight:700 }}>{response.status}</span>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'#555' }}>{response.elapsed_ms||elapsed}ms</span>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'#555' }}>{(response.body?.length||0).toLocaleString()} chars</span>
                </>
              )}
              {response && !response.ok && <span style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'#ef4444' }}>ERROR: {response.error}</span>}
            </div>
            <div style={{ padding:'6px 12px', background:'#0c0c18', borderBottom:'1px solid #141420' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#555', letterSpacing:1.5 }}>HEADERS</span>
            </div>
            {response?.headers && (
              <pre style={{ flex:'0 0 110px', margin:0, padding:10, fontFamily:'var(--font-mono)', fontSize:10.5,
                background:'#06060e', borderBottom:'1px solid #1e1e30', color:'#8b8bad', overflowY:'auto' }}>
                {Object.entries(response.headers).map(([k,v])=>`${k}: ${v}`).join('\n')}
              </pre>
            )}
            <div style={{ padding:'6px 12px', background:'#0c0c18', borderBottom:'1px solid #141420' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:8.5, color:'#555', letterSpacing:1.5 }}>BODY</span>
            </div>
            <pre style={{ flex:1, margin:0, padding:12, fontFamily:'var(--font-mono)', fontSize:11.5,
              background:'#06060e', color:'#6ee7b7', overflowY:'auto', whiteSpace:'pre-wrap', wordBreak:'break-all' }}>
              {loading ? '⏳ Sending…' : response?.ok ? response.body : response ? `Error: ${response.error}` : 'Response will appear here…'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PHANTOM AI v3 — App.jsx Part 3: Agents view + step renderer           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── Agent step renderer ───────────────────────────────────────────────────
// Renders each agent reasoning step (thought, action, observation, finding, done)
function AgentStep({ step }) {
  const ag   = AGENTS[step.agentId] || { icon: '?', name: 'Unknown', color: '#666' };
  const acol = ag.color;

  if (step.type === 'thought') return (
    <div className="anim-fadeup" style={{
      background: '#0d0d1a', borderLeft: `3px solid ${acol}`, borderRadius: 'var(--radius)',
      border: `1px solid ${acol}22`, padding: '10px 14px', marginBottom: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
        <span style={{ fontSize: 13 }}>{ag.icon}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, fontWeight: 700, color: acol, letterSpacing: 1.5 }}>
          {ag.name.toUpperCase()} REASONING
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#33334a', marginLeft: 'auto' }}>
          iter {step.iter} · {step._t}
        </span>
      </div>
      <div style={{ fontSize: 12.5, color: '#c0c0e0', lineHeight: 1.8 }}>{step.thought}</div>
      {step.hypothesis && (
        <div style={{ background: `${acol}0e`, borderRadius: 6, padding: '7px 11px', borderLeft: `2px solid ${acol}50`, marginTop: 8 }}>
          <div style={{ fontSize: 8, letterSpacing: 2, color: acol, fontFamily: 'var(--font-mono)', marginBottom: 3, fontWeight: 700 }}>HYPOTHESIS</div>
          <div style={{ fontSize: 11.5, color: `${acol}cc`, lineHeight: 1.7 }}>{step.hypothesis}</div>
        </div>
      )}
    </div>
  );

  if (step.type === 'action') return (
    <div className="anim-fadeup" style={{
      background: '#0f0f0a', borderLeft: '3px solid #ff4500',
      border: '1px solid #ff450025', borderRadius: 'var(--radius)', padding: '9px 14px', marginBottom: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
        <span style={{ fontSize: 13 }}>{ag.icon}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#ff4500', letterSpacing: 1.5, fontWeight: 700 }}>EXECUTING TOOL</span>
        <SevBadge sev="HIGH" />
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 8, color: '#33334a' }}>iter {step.iter}</span>
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12.5, color: '#ff8040', fontWeight: 700 }}>$ {step.toolId}</div>
      {step.reason && <div style={{ fontSize: 11, color: '#666', marginTop: 5, fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>{step.reason.substring(0, 140)}</div>}
    </div>
  );

  if (step.type === 'observation') return (
    <div className="anim-fadeup" style={{
      background: '#06100a', borderLeft: '3px solid #10b981',
      border: '1px solid #10b98120', borderRadius: 'var(--radius)', padding: '9px 14px', marginBottom: 8,
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#10b981', letterSpacing: 1.5, marginBottom: 7, fontWeight: 700 }}>
        OUTPUT — {step.toolId}
      </div>
      <pre style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, color: '#6ee7b7', lineHeight: 1.8,
        whiteSpace: 'pre-wrap', background: '#030805', padding: '9px 11px',
        borderRadius: 6, maxHeight: 230, overflowY: 'auto',
        border: '1px solid #10b98115',
      }}>{step.output}</pre>
    </div>
  );

  if (step.type === 'findings') return (
    <div className="anim-fadeup" style={{
      background: '#0f0505', borderLeft: '3px solid #dc2626',
      border: '1px solid #dc262630', borderRadius: 'var(--radius)', padding: '9px 14px', marginBottom: 8,
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#ef4444', letterSpacing: 1.5, marginBottom: 8, fontWeight: 700 }}>
        💥 {step.findings.length} FINDING{step.findings.length !== 1 ? 'S' : ''} EXTRACTED
      </div>
      {step.findings.map((f, i) => (
        <div key={i} style={{
          display: 'flex', gap: 9, background: '#0a0a0f',
          borderRadius: 6, padding: '7px 11px', marginBottom: 5,
          border: `1px solid ${SEV[f.sev]?.bd || '#333'}35`, alignItems: 'flex-start',
        }}>
          <SevBadge sev={f.sev} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: '#e8e8f0', lineHeight: 1.45 }}>{f.desc}</div>
            <div style={{ fontSize: 9, color: '#555', fontFamily: 'var(--font-mono)', marginTop: 2 }}>cvss:{f.cvss} · {f.tool}</div>
          </div>
        </div>
      ))}
    </div>
  );

  if (step.type === 'error') return (
    <div className="anim-fadeup" style={{
      background: '#1a0505', borderLeft: '3px solid #ef4444',
      border: '1px solid #ef444440', borderRadius: 'var(--radius)', padding: '9px 14px', marginBottom: 8,
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#ef4444', letterSpacing: 1.5, marginBottom: 7, fontWeight: 700 }}>
        ERROR{step.toolId ? ` — ${step.toolId}` : ''}
      </div>
      <pre style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, color: '#fca5a5', lineHeight: 1.8,
        whiteSpace: 'pre-wrap', background: '#120708', padding: '9px 11px',
        borderRadius: 6, maxHeight: 210, overflowY: 'auto',
        border: '1px solid #7f1d1d50',
      }}>{step.message || 'Unknown error'}</pre>
    </div>
  );

  if (step.type === 'done') return (
    <div className="anim-fadeup" style={{
      background: 'linear-gradient(135deg,#0f0f0a,#050f0a)',
      border: `2px solid ${acol}35`, borderRadius: 'var(--radius-lg)', padding: '14px 16px', marginBottom: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 9 }}>
        <div style={{
          width: 30, height: 30, borderRadius: '50%',
          background: `${acol}18`, border: `1.5px solid ${acol}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, flexShrink: 0,
        }}>{ag.icon}</div>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: acol, fontWeight: 700, letterSpacing: 2 }}>{ag.name.toUpperCase()} COMPLETE</div>
          <div style={{ fontSize: 10, color: '#555', marginTop: 1 }}>{step.totalFindings} findings · {step.iter} iterations</div>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <SevBadge sev={step.totalFindings > 3 ? 'HIGH' : step.totalFindings > 0 ? 'MEDIUM' : 'INFO'} />
        </div>
      </div>
      {step.summary && (
        <pre style={{
          fontSize: 11, color: '#a0a0c0', fontFamily: 'var(--font-mono)',
          lineHeight: 1.8, whiteSpace: 'pre-wrap', background: '#0a0a0f',
          padding: '10px 12px', borderRadius: 7, maxHeight: 190, overflowY: 'auto', border: '1px solid #1e1e30',
        }}>{step.summary}</pre>
      )}
    </div>
  );

  return null;
}

// ── Agents view ───────────────────────────────────────────────────────────
function AgentsView({
  targets, activeTarget, setActiveTarget,
  model, setModel, models,
  maxIter, setMaxIter,
  scanDepth, setScanDepth,
  activeAgents, setActiveAgents,
  agentStatus, findings,
  agentSteps, liveText,
  running, paused,
  onLaunch, onStop, onPause,
  reportReady, setView,
}) {
  const logEndRef = useRef(null);
  const liveTextSnapshot = useMemo(() => JSON.stringify(liveText), [liveText]);

  // Auto-scroll log to bottom as new steps arrive
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [agentSteps.length, liveTextSnapshot]);

  const statusColor = { idle: '#33334a', thinking: '#8b5cf6', running: '#f59e0b', complete: '#10b981', error: '#ef4444' };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

      {/* ── Control sidebar ── */}
      <aside style={{
        width: 292, background: '#08080f', borderRight: '1px solid #1e1e30',
        overflowY: 'auto', flexShrink: 0, padding: 14, display: 'flex', flexDirection: 'column', gap: 12,
      }}>
        <SectionHeader icon="⬡" title="AGENT CONTROL" subtitle="7-agent autonomous system" color="#ff4500" />

        {/* Target selector */}
        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 5, letterSpacing: 1 }}>TARGET</div>
          <select value={activeTarget} onChange={e => setActiveTarget(Number(e.target.value))}
            style={{ width: '100%', padding: '8px 10px', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
            {targets.map((t, i) => <option key={t.id} value={i}>{t.host} ({t.type})</option>)}
          </select>
        </div>

        {/* LLM model */}
        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 5, letterSpacing: 1 }}>LOCAL LLM MODEL</div>
          {models.length > 0
            ? <select value={model} onChange={e => setModel(e.target.value)} style={{ width: '100%', padding: '8px 10px', fontSize: 12 }}>
                {models.map(m => <option key={m}>{m}</option>)}
              </select>
            : <input value={model} onChange={e => setModel(e.target.value)}
                style={{ width: '100%', padding: '8px 10px', fontSize: 12, fontFamily: 'var(--font-mono)' }}
                placeholder="llama3.1" />
          }
        </div>

        {/* Scan depth */}
        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 6, letterSpacing: 1 }}>SCAN DEPTH</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 5 }}>
            {[['quick', 'Quick'], ['standard', 'Standard'], ['deep', 'Deep']].map(([v, l]) => (
              <button key={v} onClick={() => setScanDepth(v)} style={{
                padding: '7px 4px', borderRadius: 6, fontSize: 10, cursor: 'pointer',
                border: `1px solid ${scanDepth === v ? '#ff450040' : '#1e1e30'}`,
                background: scanDepth === v ? '#ff450012' : 'transparent',
                color: scanDepth === v ? '#ff4500' : '#555', fontWeight: scanDepth === v ? 700 : 400,
              }}>{l}</button>
            ))}
          </div>
        </div>

        {/* Iteration count */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
            <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', letterSpacing: 1 }}>ITERATIONS / AGENT</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: '#ff4500', fontWeight: 700 }}>{maxIter}</span>
          </div>
          <input type="range" min={3} max={20} value={maxIter} onChange={e => setMaxIter(Number(e.target.value))}
            style={{ width: '100%', accentColor: '#ff4500' }} />
        </div>

        {/* Agent checkboxes */}
        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 8, letterSpacing: 1 }}>ACTIVE AGENTS ({activeAgents.size})</div>
          {AGENT_ORDER.map(a => {
            const ag     = AGENTS[a];
            const isOn   = activeAgents.has(a);
            const st     = agentStatus[a] || {};
            const scol   = statusColor[st.status] || statusColor.idle;
            return (
              <div key={a} onClick={() => !running && setActiveAgents(prev => {
                const n = new Set(prev);
                n.has(a) ? n.delete(a) : n.add(a);
                return n;
              })} style={{
                display: 'flex', alignItems: 'center', gap: 9, padding: '8px 10px',
                borderRadius: 8, marginBottom: 4, cursor: running ? 'default' : 'pointer',
                background: isOn ? `${ag.color}0e` : 'transparent',
                border: `1px solid ${isOn ? `${ag.color}28` : '#1e1e30'}`,
                transition: 'all 0.12s',
              }}>
                {/* Checkbox */}
                <div style={{
                  width: 16, height: 16, borderRadius: 4, flexShrink: 0,
                  border: `1.5px solid ${isOn ? ag.color : '#33334a'}`,
                  background: isOn ? `${ag.color}18` : 'transparent',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {isOn && <span style={{ fontSize: 9, color: ag.color }}>✓</span>}
                </div>
                <span style={{ fontSize: 14 }}>{ag.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11.5, fontWeight: 600, color: isOn ? ag.color : '#555' }}>{ag.name}</div>
                  {st.status && st.status !== 'idle' && (
                    <div style={{ fontSize: 8, fontFamily: 'var(--font-mono)', color: scol }}>{st.status} · iter {st.iter || 0}</div>
                  )}
                </div>
                {/* Finding count */}
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 15, color: ag.color, fontWeight: 700 }}>
                  {findings.filter(f => f.agent === a).length}
                </div>
              </div>
            );
          })}
        </div>

        {/* Action buttons */}
        {!running ? (
          <Btn onClick={onLaunch} style={{ padding: 14, letterSpacing: 3, boxShadow: '0 4px 20px rgba(255,69,0,0.25)' }}>
            ⬡ LAUNCH {activeAgents.size} AGENTS
          </Btn>
        ) : (
          <div style={{ display: 'flex', gap: 7 }}>
            <GhostBtn onClick={onPause} color={paused ? '#10b981' : '#fbbf24'} style={{ flex: 1, padding: 10, fontWeight: 700, fontSize: 10 }}>
              {paused ? '▶ RESUME' : '⏸ PAUSE'}
            </GhostBtn>
            <GhostBtn onClick={onStop} color="#ef4444" style={{ flex: 1, padding: 10, fontWeight: 700, fontSize: 10 }}>
              ■ STOP
            </GhostBtn>
          </div>
        )}

        {reportReady && (
          <GhostBtn onClick={() => setView('report')} color="#8b5cf6" style={{ padding: 10, fontWeight: 700, fontSize: 10, width: '100%' }}>
            📄 VIEW REPORT
          </GhostBtn>
        )}

        {/* Wordlist reference */}
        <div style={{ padding: '10px 12px', background: '#0a0a0f', borderRadius: 8, border: '1px solid #1e1e30' }}>
          <div style={{ fontSize: 8, letterSpacing: 1.5, color: '#33334a', fontFamily: 'var(--font-mono)', marginBottom: 7, fontWeight: 700 }}>WORDLIST PATHS</div>
          {Object.entries(WL).map(([k, v]) => (
            <div key={k} style={{ fontSize: 9, color: '#44445a', fontFamily: 'var(--font-mono)', marginBottom: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v}>
              {v.split('/').pop()}
            </div>
          ))}
        </div>
      </aside>

      {/* ── Live log pane ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Streaming LLM preview strip */}
        {Object.entries(liveText).some(([, t]) => t) && (
          <div style={{
            padding: '7px 14px', background: '#0c0c18', borderBottom: '1px solid #1e1e30',
            flexShrink: 0, maxHeight: 58, overflow: 'hidden',
            display: 'flex', gap: 12, alignItems: 'center',
          }}>
            {Object.entries(liveText).filter(([, t]) => t).map(([aId, text]) => (
              <div key={aId} style={{ display: 'flex', gap: 7, alignItems: 'center', minWidth: 0, flex: 1 }}>
                <span style={{ color: AGENTS[aId]?.color, fontSize: 13, flexShrink: 0 }}>{AGENTS[aId]?.icon}</span>
                <span className="stream-cursor" style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: '#7878a0',
                  lineHeight: 1.6, overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis',
                }}>{text.slice(-180)}</span>
              </div>
            ))}
          </div>
        )}

        {/* Steps list */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
          {agentSteps.length === 0 && !running ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', height: '80%', gap: 14, opacity: 0.2,
            }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 68, color: '#ff4500', lineHeight: 1 }}>⬡</div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 13, color: '#ff4500', letterSpacing: 4 }}>ALL AGENTS DORMANT</div>
              <div style={{ fontSize: 12, color: '#555', textAlign: 'center', lineHeight: 1.9, maxWidth: 420 }}>
                Configure agents in the sidebar and click Launch.<br />
                7 specialized agents run in parallel — each with memory, learning, and tool access.
              </div>
            </div>
          ) : (
            agentSteps.map(s => <AgentStep key={s._id} step={s} />)
          )}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
}
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PHANTOM AI v3 — App.jsx Part 4: Network, Identity, Cloud views        ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── Network view ──────────────────────────────────────────────────────────
function NetworkView({ defaultHost, onNewFindings }) {
  const [target,  setTarget]  = useState(defaultHost || '');
  const [tool,    setTool]    = useState('nmap');
  const [output,  setOutput]  = useState('');
  const [running, setRunning] = useState(false);
  const [ports,   setPorts]   = useState([]);

  async function runScan() {
    if (!target.trim()) return;
    setRunning(true); setOutput(''); setPorts([]);
    const [cmd, args] = buildArgs(tool, target.trim());
    const res   = await API.tool.run(cmd, args, 120);
    const out   = res.output || simulateOutput(tool, target.trim());
    setOutput(out);
    // Parse port table from nmap/masscan output
    const portRe = /(\d+)\/(tcp|udp)\s+open\s+(\S+)/g;
    const found  = [];
    let m;
    while ((m = portRe.exec(out)) !== null) found.push({ port: m[1], proto: m[2], service: m[3] });
    setPorts(found);
    // Surface structured findings back to the global list
    const newF = extractFindings(out, tool, 'network', 1, target.trim());
    if (newF.length) onNewFindings(newF);
    setRunning(false);
  }

  const netTools = ['nmap', 'masscan', 'smbmap', 'enum4linux', 'crackmapexec'];

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {/* Sidebar */}
      <div style={{ width: 300, background: '#08080f', borderRight: '1px solid #1e1e30', padding: 16, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto', flexShrink: 0 }}>
        <SectionHeader icon="🗺" title="NETWORK SCANNER" subtitle="nmap · masscan · smbmap · enum4linux · CME" color="#3b82f6" />

        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 5, letterSpacing: 1 }}>TARGET HOST / CIDR</div>
          <input value={target} onChange={e => setTarget(e.target.value)}
            placeholder="192.168.1.1 | 10.0.0.0/24 | host.com"
            style={{ width: '100%', padding: '9px 11px', fontSize: 12.5, fontFamily: 'var(--font-mono)' }} />
        </div>

        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 6, letterSpacing: 1 }}>TOOL</div>
          {netTools.map(t => (
            <button key={t} onClick={() => setTool(t)} style={{
              display: 'block', width: '100%', padding: '8px 12px', borderRadius: 7, marginBottom: 4,
              border: `1px solid ${tool === t ? '#3b82f635' : '#1e1e30'}`,
              background: tool === t ? '#3b82f610' : 'transparent',
              color: tool === t ? '#3b82f6' : '#555', textAlign: 'left', fontSize: 11.5,
              fontFamily: 'var(--font-mono)', cursor: 'pointer', fontWeight: tool === t ? 700 : 400,
            }}>
              {TOOLS[t]?.icon || '⚙'} {t}
            </button>
          ))}
        </div>

        <Btn onClick={runScan} disabled={running} color="#1d4ed8" style={{ padding: 12, width: '100%', letterSpacing: 2 }}>
          {running ? '⟳ SCANNING...' : '🗺 RUN SCAN'}
        </Btn>

        {/* Discovered ports */}
        {ports.length > 0 && (
          <div>
            <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', letterSpacing: 1, marginBottom: 7 }}>OPEN PORTS ({ports.length})</div>
            {ports.map((p, i) => (
              <div key={i} style={{ display: 'flex', gap: 9, padding: '6px 10px', borderRadius: 6, marginBottom: 3, background: '#0a0f1a', border: '1px solid #1e3a5f30' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#3b82f6', fontWeight: 700, minWidth: 60 }}>{p.port}/{p.proto}</span>
                <span style={{ fontSize: 11, color: '#888' }}>{p.service}</span>
              </div>
            ))}
          </div>
        )}

        {/* Quick command reference */}
        <div style={{ padding: '10px 12px', background: '#0a0a0f', borderRadius: 8, border: '1px solid #1e1e30' }}>
          <div style={{ fontSize: 8, letterSpacing: 1.5, color: '#33334a', fontFamily: 'var(--font-mono)', marginBottom: 7, fontWeight: 700 }}>QUICK COMMANDS</div>
          {[
            `nmap -sV -sC --open -T4 ${target || 'HOST'}`,
            `nmap -p- --script vuln ${target || 'HOST'}`,
            `masscan ${target || 'HOST'} -p0-65535 --rate 10000`,
            `enum4linux -a ${target || 'HOST'}`,
          ].map((c, i) => (
            <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#555', marginBottom: 4, lineHeight: 1.6 }}>{c}</div>
          ))}
        </div>
      </div>

      {/* Output terminal */}
      <div style={{ flex: 1, overflow: 'auto', padding: 14 }}>
        <pre className="terminal" style={{ minHeight: '95%' }}>
          {output || `// Network scanner ready\n// Tools: nmap, masscan, smbmap, enum4linux, crackmapexec\n\n// Usage examples:\n// nmap -sV -sC --open -T4 TARGET\n// masscan TARGET -p0-65535 --rate 10000\n// enum4linux -a TARGET\n// smbmap -H TARGET\n// crackmapexec smb TARGET`}
        </pre>
      </div>
    </div>
  );
}

// ── Identity / Auth view ──────────────────────────────────────────────────
function IdentityView({ defaultHost }) {
  // JWT sub-panel
  const [jwtToken,  setJwtToken]  = useState('');
  const [jwtResult, setJwtResult] = useState(null);
  // Codec sub-panel
  const [codecMode, setCodecMode] = useState('b64e');
  const [codecIn,   setCodecIn]   = useState('');
  const [codecOut,  setCodecOut]  = useState('');
  function analyseJWT() {
    if (!jwtToken.trim()) return;
    setJwtResult(JWT.decode(jwtToken.trim()));
  }

  function runCodec() {
    const fn = Codec[codecMode] || (s => s);
    setCodecOut(fn(codecIn));
  }

  const OAUTH_CHECKS = [
    { sev: 'CRITICAL', label: 'redirect_uri open redirect', cmd: `curl -v "https://${defaultHost || 'TARGET'}/oauth/authorize?client_id=app&redirect_uri=https://evil.com&response_type=code"` },
    { sev: 'HIGH',     label: 'State param missing (CSRF)', cmd: `curl -v "https://${defaultHost || 'TARGET'}/oauth/authorize?state=&client_id=app&response_type=code"` },
    { sev: 'HIGH',     label: 'Token in URL fragment leak', cmd: `curl -sI "https://${defaultHost || 'TARGET'}/callback?token=abc123" | grep Referer` },
    { sev: 'MEDIUM',   label: 'Scope over-grant check',    cmd: `curl "https://${defaultHost || 'TARGET'}/oauth/token" -d "scope=*&..."` },
    { sev: 'MEDIUM',   label: 'PKCE enforcement',          cmd: `curl -v "https://${defaultHost || 'TARGET'}/oauth/authorize?response_type=code" (no code_challenge)` },
    { sev: 'HIGH',     label: 'JWT alg:none attack',       cmd: 'jwt_tool TOKEN -X a' },
    { sev: 'HIGH',     label: 'RS256 → HS256 confusion',   cmd: 'jwt_tool TOKEN -X k --pub-key pubkey.pem' },
    { sev: 'HIGH',     label: 'Blank HMAC secret',         cmd: `hashcat -a 3 -m 16500 token.jwt ""` },
    { sev: 'HIGH',     label: 'RockYou HMAC crack',        cmd: `hashcat -a 0 -m 16500 token.jwt ${WL.rockyou}` },
    { sev: 'MEDIUM',   label: 'Session fixation test',     cmd: `curl -b "PHPSESSID=FIXED" "https://${defaultHost || 'TARGET'}/login" -d "user=admin&pass=test"` },
    { sev: 'MEDIUM',   label: 'Cookie flags check',        cmd: `curl -sI "https://${defaultHost || 'TARGET'}" | grep -i set-cookie` },
  ];

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
      <SectionHeader icon="🔐" title="IDENTITY & AUTH TESTING" subtitle="JWT · OAuth/OIDC · SAML · Sessions · SSO misconfig detection" color="#ec4899" />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

        {/* JWT Analyser */}
        <div className="card" style={{ gridColumn: '1 / -1' }}>
          <div className="card-header" style={{ color: '#ec4899' }}>🎫 JWT DECODER + EXPLOIT ASSIST</div>
          <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 5, letterSpacing: 1 }}>PASTE TOKEN</div>
              <textarea value={jwtToken} onChange={e => setJwtToken(e.target.value)} rows={5}
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                style={{ width: '100%', padding: 9, resize: 'none', fontSize: 11, fontFamily: 'var(--font-mono)', lineHeight: 1.65 }} />
              <div style={{ display: 'flex', gap: 7, marginTop: 8 }}>
                <Btn onClick={analyseJWT} color="#7c3aed" style={{ flex: 1 }}>DECODE + ANALYZE</Btn>
                <GhostBtn onClick={() => jwtResult?.payload && setJwtResult(p => ({
                  ...p, forged: JWT.forgeNone(p.payload),
                }))} color="#ff4500" style={{ flex: 1 }}>FORGE (alg:none)</GhostBtn>
              </div>
              <div style={{ marginTop: 10, padding: '9px 11px', background: '#0a0a0f', borderRadius: 7, border: '1px solid #1e1e30' }}>
                <div style={{ fontSize: 8, color: '#33334a', fontFamily: 'var(--font-mono)', letterSpacing: 1.5, marginBottom: 5, fontWeight: 700 }}>CRACK HMAC SECRET</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9.5, color: '#ff4500', lineHeight: 1.8 }}>
                  hashcat -a 0 -m 16500 token.jwt {WL.rockyou}<br />
                  jwt_tool TOKEN -C -d {WL.rockyou}
                </div>
              </div>
            </div>
            <div>
              {jwtResult?.error && (
                <div style={{ padding: 11, background: '#1a0505', border: '1px solid #7f1d1d40', borderRadius: 8, color: '#f87171', fontSize: 12 }}>
                  {jwtResult.error}
                </div>
              )}
              {jwtResult && !jwtResult.error && (
                <>
                  {/* Issues */}
                  {jwtResult.issues?.map((iss, i) => (
                    <div key={i} style={{
                      display: 'flex', gap: 8, padding: '7px 10px', borderRadius: 6,
                      marginBottom: 5, background: SEV[iss.sev]?.bg, border: `1px solid ${SEV[iss.sev]?.bd}35`, alignItems: 'center',
                    }}>
                      <SevBadge sev={iss.sev} />
                      <span style={{ fontSize: 11.5, color: SEV[iss.sev]?.fg }}>{iss.msg}</span>
                    </div>
                  ))}
                  <pre className="terminal" style={{ maxHeight: 160, fontSize: 10.5, marginTop: 8 }}>
                    {JSON.stringify({ header: jwtResult.header, payload: jwtResult.payload }, null, 2)}
                  </pre>
                  {jwtResult.forged && (
                    <div style={{ marginTop: 8, background: '#1a0505', border: '1px solid #7f1d1d40', borderRadius: 8, padding: 11 }}>
                      <div style={{ fontSize: 8, letterSpacing: 2, color: '#ef4444', fontFamily: 'var(--font-mono)', marginBottom: 5, fontWeight: 700 }}>FORGED TOKEN — ALG:NONE</div>
                      <pre style={{ fontSize: 10, color: '#f87171', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', whiteSpace: 'pre-wrap', userSelect: 'all' }}>
                        {jwtResult.forged}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {/* OAuth / SSO checklist */}
        <div className="card">
          <div className="card-header" style={{ color: '#ec4899' }}>🔑 OAUTH / OIDC / SAML CHECKLIST</div>
          <div style={{ padding: 12, overflowY: 'auto', maxHeight: 420 }}>
            {OAUTH_CHECKS.map((c, i) => (
              <div key={i} style={{ marginBottom: 9, padding: '9px 11px', background: 'var(--bg-surface)', borderRadius: 7, border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                  <SevBadge sev={c.sev} />
                  <span style={{ fontSize: 11.5, fontWeight: 600, color: '#e8e8f0' }}>{c.label}</span>
                </div>
                <pre style={{ fontSize: 9.5, color: '#555', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6 }}>{c.cmd}</pre>
              </div>
            ))}
          </div>
        </div>

        {/* Codec panel */}
        <div className="card">
          <div className="card-header">🔄 ENCODER / DECODER</div>
          <div style={{ padding: 14 }}>
            <div style={{ display: 'flex', gap: 5, marginBottom: 10, flexWrap: 'wrap' }}>
              {[
                ['b64e', 'Base64 Enc'], ['b64d', 'Base64 Dec'],
                ['urle', 'URL Enc'],    ['urld', 'URL Dec'],
                ['hexe', 'Hex Enc'],    ['hexd', 'Hex Dec'],
                ['rot13', 'ROT13'],     ['htmle', 'HTML Enc'],
              ].map(([v, l]) => (
                <button key={v} onClick={() => setCodecMode(v)} style={{
                  padding: '4px 9px', borderRadius: 5, fontSize: 9.5, cursor: 'pointer',
                  border: `1px solid ${codecMode === v ? '#ff450040' : '#1e1e30'}`,
                  background: codecMode === v ? '#ff450012' : 'transparent',
                  color: codecMode === v ? '#ff4500' : '#555', fontFamily: 'var(--font-mono)', fontWeight: codecMode === v ? 700 : 400,
                }}>{l}</button>
              ))}
            </div>
            <textarea value={codecIn} onChange={e => setCodecIn(e.target.value)} rows={4}
              placeholder="Input to transform..."
              style={{ width: '100%', padding: 9, borderRadius: 7, fontSize: 12, fontFamily: 'var(--font-mono)', resize: 'none', marginBottom: 8, lineHeight: 1.65 }} />
            <GhostBtn onClick={runCodec} color="#ff4500" style={{ width: '100%', padding: 9, marginBottom: 10, fontWeight: 700, fontSize: 10 }}>TRANSFORM →</GhostBtn>
            {codecOut && (
              <pre className="terminal" style={{ userSelect: 'all', wordBreak: 'break-all', color: '#fbbf24' }}>{codecOut}</pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Cloud view ─────────────────────────────────────────────────────────────
function CloudView({ defaultHost, onNewFindings }) {
  const [provider, setProvider] = useState('aws');
  const [output,   setOutput]   = useState('');
  const [running,  setRunning]  = useState(false);
  const [findings, setLocalF]   = useState([]);

  async function runScan() {
    setRunning(true); setOutput(''); setLocalF([]);
    const toolMap = {
      aws:   ['scout',       ['aws',   '--report-name', 'phantom-scout']],
      gcp:   ['scout',       ['gcp',   '--report-name', 'phantom-scout']],
      azure: ['prowler',     ['azure']],
      k8s:   ['kube-hunter', ['--remote', defaultHost || 'localhost', '--report', 'json']],
    };
    const [cmd, args] = toolMap[provider] || ['prowler', ['aws']];
    const res  = await API.tool.run(cmd, args, 240);
    const out  = res.output || simulateOutput('scoutsuite', defaultHost || 'cloud-target');
    setOutput(out);
    const newF = extractFindings(out, 'cloud_scan', 'cloud', 1, defaultHost || '');
    setLocalF(newF);
    if (newF.length) onNewFindings(newF);
    setRunning(false);
  }

  const AWS_CHECKS = [
    'S3 buckets with public ACL', 'IAM root access keys active',
    'MFA not enforced on all users', 'CloudTrail disabled in any region',
    'Security Hub not enabled', 'GuardDuty inactive',
    'Default VPC security groups open', 'Secrets in EC2 user-data',
    'RDS publicly accessible', 'Lambda env vars with secrets',
    'ECS task roles over-permissive', 'ECR images without scanning',
  ];

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
      <SectionHeader icon="☁" title="CLOUD SECURITY POSTURE" subtitle="AWS · GCP · Azure · Kubernetes — ScoutSuite · Prowler · kube-hunter · Pacu" color="#10b981" />
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 14 }}>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Provider picker */}
          <div className="card" style={{ padding: 14 }}>
            <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 9, letterSpacing: 1 }}>CLOUD PROVIDER</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 13 }}>
              {[['aws', 'AWS', '#ff9900'], ['gcp', 'GCP', '#4285f4'], ['azure', 'Azure', '#0089d6'], ['k8s', 'Kubernetes', '#326ce5']].map(([v, l, c]) => (
                <button key={v} onClick={() => setProvider(v)} style={{
                  padding: '9px 6px', borderRadius: 8, cursor: 'pointer',
                  border: `1px solid ${provider === v ? `${c}45` : '#1e1e30'}`,
                  background: provider === v ? `${c}12` : 'transparent',
                  color: provider === v ? c : '#555', fontSize: 12, fontWeight: provider === v ? 700 : 400,
                }}>{l}</button>
              ))}
            </div>
            <Btn onClick={runScan} disabled={running} color="#065f46" style={{ width: '100%', padding: 12, letterSpacing: 2 }}>
              {running ? '⟳ SCANNING CLOUD...' : '☁ RUN POSTURE SCAN'}
            </Btn>
          </div>

          {/* Local findings */}
          {findings.length > 0 && (
            <div className="card">
              <div className="card-header" style={{ color: '#10b981' }}>Cloud Findings ({findings.length})</div>
              <div style={{ padding: 8, maxHeight: 280, overflowY: 'auto' }}>
                {findings.map((f, i) => (
                  <div key={i} style={{ padding: '8px 10px', borderRadius: 7, marginBottom: 4, background: SEV[f.sev]?.bg, border: `1px solid ${SEV[f.sev]?.bd}30` }}>
                    <SevBadge sev={f.sev} />
                    <div style={{ fontSize: 11, color: SEV[f.sev]?.fg, marginTop: 4, lineHeight: 1.5 }}>{f.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AWS checklist */}
          <div className="card">
            <div className="card-header">AWS CIS Checks</div>
            <div style={{ padding: 12 }}>
              {AWS_CHECKS.map((c, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: '6px 8px', borderRadius: 5, marginBottom: 3, background: 'var(--bg-surface)', border: '1px solid var(--border)', alignItems: 'center' }}>
                  <div style={{ width: 14, height: 14, borderRadius: '50%', border: '1.5px solid #1e1e30', flexShrink: 0 }} />
                  <span style={{ fontSize: 11, color: '#555' }}>{c}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Output */}
        <div>
          <pre className="terminal" style={{ minHeight: '65vh' }}>
            {output || `// Cloud Security Posture Management\n// Providers: AWS · GCP · Azure · Kubernetes\n\n// Tools used:\n//   scout     — ScoutSuite multi-cloud audit\n//   prowler   — AWS/Azure/GCP CIS benchmarks\n//   kube-hunter — Kubernetes attack surface\n//   pacu      — AWS exploitation framework\n\n// Install:\n//   pip3 install scoutsuite prowler kube-hunter pacu --break-system-packages\n\n// AWS quick checks (CLI):\n//   aws s3api list-buckets\n//   aws iam generate-credential-report\n//   aws cloudtrail describe-trails\n//   aws guardduty list-detectors`}
          </pre>
        </div>
      </div>
    </div>
  );
}

// ── Autopilot view ─────────────────────────────────────────────────────────
function AutopilotView({ defaultHost, onNewFindings }) {
  const TOOL_CHAIN = ['whatweb', 'nmap', 'nuclei', 'nikto', 'sqlmap', 'ffuf', 'gobuster', 'feroxbuster', 'searchsploit'];
  const [target, setTarget] = useState(defaultHost || '');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [loginPath, setLoginPath] = useState('');
  const [registerPath, setRegisterPath] = useState('');
  const [maxPages, setMaxPages] = useState(40);
  const [toolTimeout, setToolTimeout] = useState(180);
  const [headless, setHeadless] = useState(true);
  const [useProxy, setUseProxy] = useState(true);
  const [proxyUrl, setProxyUrl] = useState('http://127.0.0.1:8888');
  const [usernameSelector, setUsernameSelector] = useState('');
  const [emailSelector, setEmailSelector] = useState('');
  const [passwordSelector, setPasswordSelector] = useState('');
  const [confirmPasswordSelector, setConfirmPasswordSelector] = useState('');
  const [submitSelector, setSubmitSelector] = useState('');
  const [successMarkers, setSuccessMarkers] = useState('logout,sign out,welcome');
  const [failMarkers, setFailMarkers] = useState('invalid,incorrect,failed,error');
  const [postLoginPaths, setPostLoginPaths] = useState('');
  const [allowPaths, setAllowPaths] = useState('');
  const [skipPaths, setSkipPaths] = useState('logout,signout');
  const [running, setRunning] = useState(false);
  const [deps, setDeps] = useState(null);
  const [error, setError] = useState('');
  const [counts, setCounts] = useState({});
  const [report, setReport] = useState(null);
  const [output, setOutput] = useState('');
  const [tools, setTools] = useState(() => Object.fromEntries(TOOL_CHAIN.map(t => [t, true])));
  const [profiles, setProfiles] = useState([]);
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [profileName, setProfileName] = useState('');
  const [profileTargetMatch, setProfileTargetMatch] = useState('');
  const [profileDesc, setProfileDesc] = useState('');
  const [trainingBusy, setTrainingBusy] = useState(false);
  const [trainModelName, setTrainModelName] = useState('phantom-security:latest');
  const [trainBaseModel, setTrainBaseModel] = useState('llama3.1:latest');
  const [trainMsg, setTrainMsg] = useState('');
  const [lastRun, setLastRun] = useState(null);
  const [includeProxySeeds, setIncludeProxySeeds] = useState(true);
  const [proxySeedLimit, setProxySeedLimit] = useState(300);
  const [certPathHint, setCertPathHint] = useState('');

  useEffect(() => {
    if (!target && defaultHost) setTarget(defaultHost);
  }, [defaultHost, target]);

  useEffect(() => {
    checkDeps();
    loadProfiles();
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      if (!E?.cert) return;
      try {
        const info = await API.cert.path();
        const path = typeof info === 'string' ? info : info?.path;
        if (alive && path) setCertPathHint(path);
      } catch {}
    })();
    return () => { alive = false; };
  }, []);

  const selectedTools = TOOL_CHAIN.filter(t => tools[t]);

  const proxySetupCommands = useMemo(() => {
    const certPath = certPathHint || '$HOME/Library/Application Support/Phantom AI/certs/ca.crt';
    const pxy = proxyUrl.trim() || 'http://127.0.0.1:8888';
    return [
      `security add-trusted-cert -d -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" "${certPath}"`,
      `networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8888`,
      `networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8888`,
      `open -na "Google Chrome" --args --proxy-server="${pxy}"`,
    ].join('\n');
  }, [certPathHint, proxyUrl]);

  function csvToList(v) {
    return String(v || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }

  function buildWorkflowProfilePayload() {
    return {
      name: profileName.trim() || undefined,
      login_path: loginPath.trim() || undefined,
      register_path: registerPath.trim() || undefined,
      username_selector: usernameSelector.trim() || undefined,
      email_selector: emailSelector.trim() || undefined,
      password_selector: passwordSelector.trim() || undefined,
      confirm_password_selector: confirmPasswordSelector.trim() || undefined,
      submit_selector: submitSelector.trim() || undefined,
      auth_success_markers: csvToList(successMarkers),
      auth_fail_markers: csvToList(failMarkers),
      post_login_paths: csvToList(postLoginPaths),
      allow_paths: csvToList(allowPaths),
      skip_paths: csvToList(skipPaths),
    };
  }

  async function checkDeps() {
    try {
      const d = await API.autopilot.deps();
      setDeps(d);
    } catch {
      setDeps(null);
    }
  }

  async function loadProfiles() {
    try {
      const r = await API.autopilot.profiles();
      setProfiles(r?.profiles || []);
    } catch {
      setProfiles([]);
    }
  }

  function toggleTool(tool) {
    setTools(prev => ({ ...prev, [tool]: !prev[tool] }));
  }

  function applyProfile(profile) {
    if (!profile) return;
    const cfg = profile.config || {};
    setSelectedProfileId(profile.id || '');
    setProfileName(profile.name || '');
    setProfileTargetMatch(profile.target_match || '');
    setProfileDesc(profile.description || '');
    setLoginPath(cfg.login_path || '');
    setRegisterPath(cfg.register_path || '');
    setUsernameSelector(cfg.username_selector || '');
    setEmailSelector(cfg.email_selector || '');
    setPasswordSelector(cfg.password_selector || '');
    setConfirmPasswordSelector(cfg.confirm_password_selector || '');
    setSubmitSelector(cfg.submit_selector || '');
    setSuccessMarkers((cfg.auth_success_markers || []).join(','));
    setFailMarkers((cfg.auth_fail_markers || []).join(','));
    setPostLoginPaths((cfg.post_login_paths || []).join(','));
    setAllowPaths((cfg.allow_paths || []).join(','));
    setSkipPaths((cfg.skip_paths || []).join(','));
  }

  async function saveProfile() {
    if (!profileName.trim()) {
      setError('Profile name is required.');
      return;
    }
    setError('');
    try {
      const res = await API.autopilot.saveProfile({
        id: selectedProfileId || undefined,
        name: profileName.trim(),
        description: profileDesc.trim() || undefined,
        target_match: profileTargetMatch.trim() || undefined,
        config: buildWorkflowProfilePayload(),
      });
      if (res?.profile?.id) setSelectedProfileId(res.profile.id);
      await loadProfiles();
      setTrainMsg(`Workflow profile saved: ${res?.profile?.name || profileName.trim()}`);
    } catch (e) {
      setError(String(e?.message || e || 'Could not save profile'));
    }
  }

  async function deleteProfile() {
    if (!selectedProfileId) return;
    try {
      await API.autopilot.deleteProfile(selectedProfileId);
      setSelectedProfileId('');
      setProfileName('');
      setProfileTargetMatch('');
      setProfileDesc('');
      await loadProfiles();
      setTrainMsg('Workflow profile deleted.');
    } catch (e) {
      setError(String(e?.message || e || 'Could not delete profile'));
    }
  }

  async function trainOllama() {
    setTrainingBusy(true);
    setTrainMsg('');
    setError('');
    try {
      const res = await API.ollama.train({
        model_name: trainModelName.trim() || 'phantom-security:latest',
        base_model: trainBaseModel.trim() || 'llama3.1:latest',
        max_findings: 300,
        include_workflows: true,
      });
      setTrainMsg(
        `Ollama model trained: ${res.model_name} (examples=${res.examples}, workflows=${res.profiles_used})`
      );
    } catch (e) {
      setError(String(e?.message || e || 'Ollama training failed'));
    } finally {
      setTrainingBusy(false);
    }
  }

  async function runAutopilot() {
    if (!target.trim()) return;
    if (selectedTools.length === 0) {
      setError('Enable at least one tool in the chain.');
      return;
    }

    setRunning(true);
    setError('');
    setCounts({});
    setReport(null);
    setLastRun(null);
    setOutput('// Autopilot starting...\n');

    try {
      let capturedRequests = [];
      if (includeProxySeeds && E?.proxy) {
        try {
          const hist = await API.proxy.history(Number(proxySeedLimit) || 300);
          capturedRequests = (hist || []).slice(0, Number(proxySeedLimit) || 300).map(r => ({
            method: r.method,
            url: r.url,
            headers: r.headers || {},
            body: r.body || '',
            response_status: r.response?.status || 0,
            response_headers: r.response?.headers || {},
            response_body: r.response?.body || '',
          }));
        } catch {}
      }

      const res = await API.autopilot.run({
        target: target.trim(),
        username: username.trim() || undefined,
        password: password || undefined,
        email: email.trim() || undefined,
        max_pages: Number(maxPages) || 40,
        timeout_per_tool: Number(toolTimeout) || 180,
        headless,
        use_proxy: useProxy,
        proxy_url: proxyUrl.trim() || 'http://127.0.0.1:8888',
        login_path: loginPath.trim() || undefined,
        register_path: registerPath.trim() || undefined,
        profile_id: selectedProfileId || undefined,
        workflow_profile: buildWorkflowProfilePayload(),
        captured_requests: capturedRequests,
        proxy_history_limit: Number(proxySeedLimit) || 400,
        js_audit: true,
        tools: selectedTools,
      });

      setReport(res.report || null);
      setCounts(res.counts || {});
      setLastRun(res);

      const mapped = (res.findings || []).map((f, i) => ({
        id: f.id || `${Date.now()}-${i}`,
        sev: String(f.severity || 'INFO').toUpperCase(),
        cvss: Number(f.cvss || 0),
        desc: String(f.description || '').slice(0, 220),
        tool: f.tool || 'autopilot',
        agent: f.agent || 'web',
        iter: 1,
        ts: f.created_at || new Date().toISOString(),
        _target: target.trim(),
      }));
      if (mapped.length) onNewFindings(mapped);

      const lines = [];
      lines.push(`Session: ${res.session_id || '-'}`);
      lines.push(`Risk score: ${res.risk_score ?? '-'}`);
      lines.push(`Findings: ${(res.findings || []).length}`);
      if (res?.profile?.name) lines.push(`Workflow profile: ${res.profile.name}`);
      lines.push('');
      lines.push('=== COVERAGE ===');
      lines.push(`URLs discovered: ${res?.report?.summary?.urls_discovered || 0}`);
      lines.push(`API endpoints: ${res?.report?.summary?.api_endpoints || 0}`);
      lines.push(`Traffic events: ${res?.report?.summary?.http_traffic_events || 0}`);
      lines.push(`Form endpoints: ${res?.report?.summary?.form_endpoints || 0}`);
      lines.push(`Form submissions: ${res?.report?.summary?.form_submissions || 0}`);
      lines.push(`POST/PUT/PATCH/DELETE observed: ${res?.report?.summary?.post_requests_seen || 0}`);
      lines.push('');
      lines.push('=== ENGINE LOG ===');
      (res.report?.logs || []).forEach(l => lines.push(`- ${l}`));
      lines.push('');
      lines.push('=== TOOL RUNS ===');
      (res.report?.tool_runs || []).forEach(r => {
        lines.push(`$ ${r.cmd || r.tool}`);
        lines.push(`[code=${r.code} duration=${r.duration_s}s available=${r.available !== false}]`);
        lines.push((r.output || '').slice(0, 1600));
        lines.push('');
      });
      if ((res.report?.crawler?.form_submissions || []).length) {
        lines.push('=== FORM SUBMISSIONS (SAMPLE) ===');
        res.report.crawler.form_submissions.slice(0, 20).forEach(f => {
          lines.push(`[${f.method}] ${f.url} -> status=${f.status || 0}`);
        });
        lines.push('');
      }
      if ((res.report?.crawler?.traffic_log || []).length) {
        lines.push('=== TRAFFIC (REQUEST/RESPONSE SAMPLE) ===');
        res.report.crawler.traffic_log.slice(0, 30).forEach(t => {
          lines.push(`[${t.method} ${t.status || 0}] ${t.url}`);
          if (t.request_body) lines.push(`  req: ${String(t.request_body).slice(0, 180)}`);
          if (t.response_preview) lines.push(`  res: ${String(t.response_preview).slice(0, 180)}`);
        });
        lines.push('');
      }
      const ev = res.report?.exploit_evidence;
      if (ev?.counts) {
        lines.push('=== EXPLOIT EVIDENCE ===');
        lines.push(`HTTP evidence events: ${ev.counts.http_events || 0}`);
        lines.push(`Tool evidence lines: ${ev.counts.tool_signals || 0}`);
        (ev?.suspicious_http_events || []).slice(0, 15).forEach(h => {
          lines.push(`- [${h.method} ${h.status || 0}] ${h.signal} :: ${h.url}`);
        });
        (ev?.tool_signals || []).slice(0, 15).forEach(s => {
          lines.push(`- [${s.tool}] ${s.line}`);
        });
        lines.push('');
      }
      if ((res.report?.crawler?.errors || []).length) {
        lines.push('=== CRAWLER ERRORS ===');
        res.report.crawler.errors.slice(0, 20).forEach(e => lines.push(`- ${e}`));
        lines.push('');
      }
      setOutput(lines.join('\n').slice(0, 100000));
    } catch (e) {
      const msg = String(e?.message || e || 'Autopilot failed');
      setError(msg);
      setOutput(`// Autopilot failed\n${msg}`);
    } finally {
      setRunning(false);
      checkDeps();
      loadProfiles();
    }
  }

  async function exportReport() {
    if (!report) return;
    const payload = JSON.stringify(report, null, 2);
    await API.dialog.save(
      payload,
      `autopilot-report-${Date.now()}.json`,
      [{ name: 'JSON', extensions: ['json'] }],
    );
  }

  async function exportDetailedReport() {
    if (!lastRun) return;
    const payload = {
      generated_at: new Date().toISOString(),
      session_id: lastRun.session_id,
      risk_score: lastRun.risk_score,
      counts: lastRun.counts,
      profile: lastRun.profile,
      findings: lastRun.findings || [],
      report: lastRun.report || {},
      exploit_evidence: lastRun.report?.exploit_evidence || {},
      traffic_log: lastRun.report?.crawler?.traffic_log || [],
      form_submissions: lastRun.report?.crawler?.form_submissions || [],
    };
    await API.dialog.save(
      JSON.stringify(payload, null, 2),
      `autopilot-detailed-${Date.now()}.json`,
      [{ name: 'JSON', extensions: ['json'] }],
    );
  }

  async function copyProxyCommands() {
    try {
      await navigator.clipboard.writeText(proxySetupCommands);
      setTrainMsg('Proxy/CA setup commands copied.');
    } catch {
      setError('Could not copy proxy setup commands.');
    }
  }

  const depPlaywright = deps?.python_modules?.playwright;
  const depWordlist = deps?.wordlist || '';
  const sevCards = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      <div style={{
        width: 330, background: '#08080f', borderRight: '1px solid #1e1e30',
        padding: 16, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12, flexShrink: 0,
      }}>
        <SectionHeader icon="🕷" title="AUTOPILOT SCANNER" subtitle="Browser crawl + auth + OWASP/CVE toolchain" color="#14b8a6" />

        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 5, letterSpacing: 1 }}>TARGET URL / HOST</div>
          <input value={target} onChange={e => setTarget(e.target.value)} placeholder="https://target.example"
            style={{ width: '100%', padding: '9px 11px', fontSize: 12.5, fontFamily: 'var(--font-mono)' }} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder="username"
            style={{ width: '100%', padding: '8px 10px', fontSize: 11.5, fontFamily: 'var(--font-mono)' }} />
          <input value={email} onChange={e => setEmail(e.target.value)} placeholder="email"
            style={{ width: '100%', padding: '8px 10px', fontSize: 11.5, fontFamily: 'var(--font-mono)' }} />
        </div>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="password (optional; auto-generated if empty)"
          style={{ width: '100%', padding: '8px 10px', fontSize: 11.5, fontFamily: 'var(--font-mono)' }} />

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
          <input value={loginPath} onChange={e => setLoginPath(e.target.value)} placeholder="login path (e.g. /login.php)"
            style={{ width: '100%', padding: '8px 10px', fontSize: 10.5, fontFamily: 'var(--font-mono)' }} />
          <input value={registerPath} onChange={e => setRegisterPath(e.target.value)} placeholder="register path"
            style={{ width: '100%', padding: '8px 10px', fontSize: 10.5, fontFamily: 'var(--font-mono)' }} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
          <div>
            <div style={{ fontSize: 8, color: '#555', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>MAX PAGES</div>
            <input type="number" min={3} max={300} value={maxPages} onChange={e => setMaxPages(e.target.value)}
              style={{ width: '100%', padding: '7px 9px', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
          </div>
          <div>
            <div style={{ fontSize: 8, color: '#555', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>TOOL TIMEOUT (s)</div>
            <input type="number" min={30} max={900} value={toolTimeout} onChange={e => setToolTimeout(e.target.value)}
              style={{ width: '100%', padding: '7px 9px', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
          </div>
        </div>

        <div>
          <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 6, letterSpacing: 1 }}>TOOL CHAIN</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 5 }}>
            {TOOL_CHAIN.map(t => (
              <button key={t} onClick={() => toggleTool(t)} style={{
                padding: '6px 8px', borderRadius: 6, cursor: 'pointer', textAlign: 'left',
                border: `1px solid ${tools[t] ? '#14b8a640' : '#1e1e30'}`,
                background: tools[t] ? '#14b8a610' : 'transparent',
                color: tools[t] ? '#14b8a6' : '#666',
                fontFamily: 'var(--font-mono)', fontSize: 10.5,
              }}>
                {tools[t] ? '✓' : '○'} {t}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
          <button onClick={() => setHeadless(v => !v)} style={{
            padding: '8px 10px', borderRadius: 7, cursor: 'pointer',
            border: `1px solid ${headless ? '#14b8a640' : '#1e1e30'}`,
            background: headless ? '#14b8a610' : 'transparent',
            color: headless ? '#14b8a6' : '#666', fontFamily: 'var(--font-mono)', fontSize: 10.5,
          }}>Headless: {headless ? 'ON' : 'OFF'}</button>
          <button onClick={() => setUseProxy(v => !v)} style={{
            padding: '8px 10px', borderRadius: 7, cursor: 'pointer',
            border: `1px solid ${useProxy ? '#3b82f640' : '#1e1e30'}`,
            background: useProxy ? '#3b82f610' : 'transparent',
            color: useProxy ? '#3b82f6' : '#666', fontFamily: 'var(--font-mono)', fontSize: 10.5,
          }}>Proxy: {useProxy ? 'ON' : 'OFF'}</button>
        </div>

        <input value={proxyUrl} onChange={e => setProxyUrl(e.target.value)} placeholder="http://127.0.0.1:8888"
          style={{ width: '100%', padding: '8px 10px', fontSize: 11, fontFamily: 'var(--font-mono)' }} />

        <div style={{ padding: '9px 10px', borderRadius: 8, border: '1px solid #1e1e30', background: '#0a0a0f' }}>
          <div style={{ fontSize: 8.5, color: '#555', fontFamily: 'var(--font-mono)', letterSpacing: 1.2, marginBottom: 6 }}>PROXY TRAFFIC FEED</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 6 }}>
            <button onClick={() => setIncludeProxySeeds(v => !v)} style={{
              padding: '7px 8px', borderRadius: 7, cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10,
              border: `1px solid ${includeProxySeeds ? '#ec489940' : '#1e1e30'}`,
              background: includeProxySeeds ? '#ec489912' : 'transparent',
              color: includeProxySeeds ? '#ec4899' : '#666',
            }}>
              Proxy seeds: {includeProxySeeds ? 'ON' : 'OFF'}
            </button>
            <input type="number" min={20} max={2000} value={proxySeedLimit} onChange={e => setProxySeedLimit(e.target.value)}
              placeholder="history limit"
              style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)' }} />
          </div>
          <GhostBtn onClick={copyProxyCommands} color="#06b6d4" style={{ width: '100%', marginBottom: 6 }}>
            COPY CA + PROXY COMMANDS
          </GhostBtn>
          <pre className="terminal" style={{ maxHeight: 90, fontSize: 9.2 }}>{proxySetupCommands}</pre>
        </div>

        <div style={{ padding: '10px 12px', borderRadius: 8, border: '1px solid #1e1e30', background: '#0a0f14' }}>
          <div style={{ fontSize: 8, color: '#44445a', letterSpacing: 1.3, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>WORKFLOW PROFILE</div>
          <select value={selectedProfileId} onChange={e => {
            const id = e.target.value;
            setSelectedProfileId(id);
            const prof = profiles.find(p => p.id === id);
            if (prof) applyProfile(prof);
          }} style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>
            <option value="">(No saved profile)</option>
            {profiles.map(p => <option key={p.id} value={p.id}>{p.name}{p.target_match ? ` — ${p.target_match}` : ''}</option>)}
          </select>
          <input value={profileName} onChange={e => setProfileName(e.target.value)} placeholder="profile name"
            style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)', marginBottom: 6 }} />
          <input value={profileTargetMatch} onChange={e => setProfileTargetMatch(e.target.value)} placeholder="target match (hostname substring)"
            style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)', marginBottom: 6 }} />
          <input value={profileDesc} onChange={e => setProfileDesc(e.target.value)} placeholder="description"
            style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)', marginBottom: 6 }} />
          <details style={{ marginBottom: 6 }}>
            <summary style={{ fontSize: 10, color: '#14b8a6', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>Advanced selectors and rules</summary>
            <div style={{ marginTop: 7, display: 'grid', gap: 6 }}>
              <input value={usernameSelector} onChange={e => setUsernameSelector(e.target.value)} placeholder="username selector"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={emailSelector} onChange={e => setEmailSelector(e.target.value)} placeholder="email selector"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={passwordSelector} onChange={e => setPasswordSelector(e.target.value)} placeholder="password selector"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={confirmPasswordSelector} onChange={e => setConfirmPasswordSelector(e.target.value)} placeholder="confirm password selector"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={submitSelector} onChange={e => setSubmitSelector(e.target.value)} placeholder="submit selector"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={successMarkers} onChange={e => setSuccessMarkers(e.target.value)} placeholder="success markers csv"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={failMarkers} onChange={e => setFailMarkers(e.target.value)} placeholder="fail markers csv"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={postLoginPaths} onChange={e => setPostLoginPaths(e.target.value)} placeholder="post-login paths csv"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={allowPaths} onChange={e => setAllowPaths(e.target.value)} placeholder="allow paths csv"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <input value={skipPaths} onChange={e => setSkipPaths(e.target.value)} placeholder="skip paths csv"
                style={{ width: '100%', padding: '7px 8px', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
            </div>
          </details>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
            <GhostBtn onClick={saveProfile} color="#14b8a6" style={{ width: '100%', padding: 7 }}>SAVE PROFILE</GhostBtn>
            <GhostBtn onClick={deleteProfile} color="#ef4444" style={{ width: '100%', padding: 7 }} disabled={!selectedProfileId}>DELETE PROFILE</GhostBtn>
          </div>
        </div>

        <Btn onClick={runAutopilot} disabled={running} color="#0f766e" style={{ width: '100%', padding: 12 }}>
          {running ? '⟳ AUTOPILOT RUNNING...' : '🚀 RUN AUTOPILOT'}
        </Btn>
        <GhostBtn onClick={exportReport} disabled={!report} color="#14b8a6" style={{ width: '100%' }}>
          EXPORT AUTOPILOT REPORT
        </GhostBtn>
        <GhostBtn onClick={exportDetailedReport} disabled={!lastRun} color="#ec4899" style={{ width: '100%' }}>
          EXPORT DETAILED EXPLOIT REPORT
        </GhostBtn>

        <div style={{ padding: '10px 12px', background: '#0a0f14', borderRadius: 8, border: '1px solid #1e1e30' }}>
          <div style={{ fontSize: 8, color: '#44445a', letterSpacing: 1.3, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>TRAIN OLLAMA</div>
          <input value={trainModelName} onChange={e => setTrainModelName(e.target.value)} placeholder="model name (e.g. phantom-security:latest)"
            style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)', marginBottom: 6 }} />
          <input value={trainBaseModel} onChange={e => setTrainBaseModel(e.target.value)} placeholder="base model (e.g. llama3.1:latest)"
            style={{ width: '100%', padding: '7px 8px', fontSize: 10.5, fontFamily: 'var(--font-mono)', marginBottom: 6 }} />
          <Btn onClick={trainOllama} disabled={trainingBusy} color="#ec4899" style={{ width: '100%', padding: 10 }}>
            {trainingBusy ? '⟳ TRAINING MODEL...' : '🧠 TRAIN OLLAMA FROM FINDINGS'}
          </Btn>
          {trainMsg ? (
            <div style={{ marginTop: 6, fontSize: 10.5, color: '#10b981', lineHeight: 1.6, fontFamily: 'var(--font-mono)' }}>
              {trainMsg}
            </div>
          ) : null}
        </div>

        <div style={{ padding: '10px 12px', background: '#0a0a0f', borderRadius: 8, border: '1px solid #1e1e30' }}>
          <div style={{ fontSize: 8, color: '#44445a', letterSpacing: 1.3, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>DEPENDENCY STATUS</div>
          <div style={{ fontSize: 10.5, color: depPlaywright ? '#10b981' : '#f59e0b', lineHeight: 1.7 }}>
            Playwright: {depPlaywright ? 'ready' : 'missing (HTTP fallback mode)'}
          </div>
          <div style={{ fontSize: 10.5, color: depWordlist ? '#10b981' : '#f59e0b', lineHeight: 1.7 }}>
            Wordlist: {depWordlist || 'missing (ffuf/gobuster/ferox may be skipped)'}
          </div>
        </div>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
        <SectionHeader icon="📡" title="AUTOPILOT OUTPUT" subtitle="Crawl graph, tool chain output, consolidated findings" color="#14b8a6" />

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8, marginBottom: 12 }}>
          {sevCards.map(s => (
            <div key={s} style={{ padding: '9px 10px', borderRadius: 8, border: '1px solid #1e1e30', background: '#0a0a0f' }}>
              <div style={{ fontFamily: 'var(--font-display)', color: SEV[s]?.fg || '#aaa', fontSize: 18, lineHeight: 1 }}>{counts?.[s] || 0}</div>
              <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', letterSpacing: 1.3 }}>{s}</div>
            </div>
          ))}
        </div>

        {error && (
          <div style={{ marginBottom: 10, padding: '9px 11px', borderRadius: 8, background: '#1a0505', border: '1px solid #7f1d1d40', color: '#f87171', fontSize: 12 }}>
            {error}
          </div>
        )}

        {report && (
          <div style={{ marginBottom: 10, padding: '9px 11px', borderRadius: 8, background: '#0a0f14', border: '1px solid #134e4a40', color: '#8bdad3', fontSize: 11, fontFamily: 'var(--font-mono)', lineHeight: 1.75 }}>
            Engine: {report?.crawler?.engine || '-'} | URLs: {report?.summary?.urls_discovered || 0} | API: {report?.summary?.api_endpoints || 0} | JS: {report?.summary?.js_files || 0} | Forms: {report?.summary?.form_submissions || 0} | Traffic: {report?.summary?.http_traffic_events || 0} | Tools: {report?.summary?.tools_executed || 0}
          </div>
        )}

        <pre className="terminal" style={{ minHeight: '68vh' }}>
          {output || `// Autopilot ready\n// Features:\n//   - Browser crawl + auth attempts + relogin handling\n//   - Nuclei / Nmap / WhatWeb / Nikto / SQLMap / FFUF / Gobuster / Ferox / Searchsploit\n//   - JS sink/secret inspection + technology/CVE hinting\n//   - Findings auto-ingested into global findings store`}
        </pre>
      </div>
    </div>
  );
}
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PHANTOM AI v3 — App.jsx Part 5: Graph, Intel, Findings, Report,       ║
// ║                                  Settings views                         ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── Attack Graph view ─────────────────────────────────────────────────────
// Renders a simple SVG-based force-directed graph built from findings.
// Each tool becomes a node connected to the target root node, and each
// finding is a leaf node connected to its tool.
// Kill-chain phase colors (matches graph_builder.py PHASE_META)
const KILL_CHAIN_COLORS = {
  root:       '#1e3a5f',
  initial:    '#3b82f6',
  foothold:   '#f97316',
  escalation: '#ef4444',
  impact:     '#111827',
  unknown:    '#6b7280',
};

function GraphView({ findings, targetHost }) {
  const canvasRef = useRef(null);
  const [selected, setSelected]           = useState(null);
  const [zoom, setZoom]                   = useState(1);
  const [pan, setPan]                     = useState({ x: 80, y: 60 });
  const [drag, setDrag]                   = useState(null);
  const [killChainData, setKillChainData] = useState(null);  // backend-computed graph
  const [buildingGraph, setBuildingGraph] = useState(false);
  const [graphError, setGraphError]       = useState('');
  const WORLD_W = 1600;
  const WORLD_H = 980;

  const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

  // Build exploitation graph from backend
  async function buildExploitationGraph() {
    setBuildingGraph(true);
    setGraphError('');
    try {
      const resp = await fetch('http://localhost:8000/graph/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings, target: targetHost }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setKillChainData(data);
    } catch (e) {
      setGraphError(`Graph build failed: ${e.message}`);
    } finally {
      setBuildingGraph(false);
    }
  }

  // Build graph nodes and edges from findings
  const { nodes, edges } = useMemo(() => {
    const ns   = [];
    const es   = [];
    const W    = WORLD_W, H = WORLD_H;

    // Root target node — always centred
    ns.push({ id: 'target', label: targetHost || 'target', type: 'target', x: W / 2, y: H / 2 });

    // One node per unique tool, arranged in a ring around the target
    const toolsSeen = [...new Set(findings.map(f => f.tool))];
    toolsSeen.forEach((tool, ti) => {
      const angle = (ti / toolsSeen.length) * Math.PI * 2 - Math.PI / 2;
      const r     = 180;
      const x     = W / 2 + Math.cos(angle) * r;
      const y     = H / 2 + Math.sin(angle) * r;
      ns.push({ id: `t_${tool}`, label: tool, type: 'tool', x, y, tool });
      es.push({ from: 'target', to: `t_${tool}` });
    });

    // One node per finding, clustered around its tool
    findings.forEach((f, fi) => {
      const toolNode = ns.find(n => n.tool === f.tool);
      if (!toolNode) return;
      const spread   = (fi % 8) * (Math.PI * 2 / 8);
      const dist     = 70 + (fi % 3) * 25;
      const x        = toolNode.x + Math.cos(spread) * dist;
      const y        = toolNode.y + Math.sin(spread) * dist;
      const nid      = `f_${f.id}`;
      ns.push({ id: nid, label: f.desc.substring(0, 28) + '…', type: 'finding', sev: f.sev, x, y, finding: f });
      es.push({ from: `t_${f.tool}`, to: nid });
    });

    return { nodes: ns, edges: es };
  }, [findings, targetHost]);

  useEffect(() => {
    setSelected(null);
  }, [targetHost, findings.length]);

  function resetView() {
    setZoom(1);
    setPan({ x: 80, y: 60 });
  }

  function zoomBy(multiplier) {
    setZoom(prev => clamp(prev * multiplier, 0.25, 3.6));
  }

  function onWheel(e) {
    e.preventDefault();
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const px = e.clientX - rect.left;
    const py = e.clientY - rect.top;
    const scale = e.deltaY < 0 ? 1.12 : 0.88;
    const nextZoom = clamp(zoom * scale, 0.25, 3.6);
    const worldX = (px - pan.x) / zoom;
    const worldY = (py - pan.y) / zoom;
    setZoom(nextZoom);
    setPan({
      x: px - worldX * nextZoom,
      y: py - worldY * nextZoom,
    });
  }

  function onPointerDown(e) {
    if (e.button !== 0) return;
    setDrag({
      x: e.clientX,
      y: e.clientY,
      panX: pan.x,
      panY: pan.y,
    });
  }

  function onPointerMove(e) {
    if (!drag) return;
    setPan({
      x: drag.panX + (e.clientX - drag.x),
      y: drag.panY + (e.clientY - drag.y),
    });
  }

  function onPointerUp() {
    if (drag) setDrag(null);
  }

  const nodeColor = n => {
    // Kill-chain phase color takes priority when backend graph is loaded
    if (n.phase && KILL_CHAIN_COLORS[n.phase]) return KILL_CHAIN_COLORS[n.phase];
    if (n.type === 'target')  return '#ff4500';
    if (n.type === 'tool')    return AGENTS[TOOLS[n.tool]?.agent]?.color || '#8b5cf6';
    return SEV[n.sev]?.fg || '#60a5fa';
  };
  const nodeRadius = n => n.type === 'target' || n.is_root ? 22 : n.type === 'tool' ? 15 : 9;

  // Use backend kill-chain layout if available, else local tool-ring layout
  const displayNodes = killChainData ? (() => {
    const W = WORLD_W, H = WORLD_H;
    const phaseX = { root: W/2, initial: W*0.2, foothold: W*0.4, escalation: W*0.65, impact: W*0.85, unknown: W*0.5 };
    return (killChainData.nodes || []).map((n, i) => ({
      ...n,
      x: phaseX[n.phase] ?? W/2,
      y: H * 0.2 + (i % 6) * (H * 0.12),
    }));
  })() : nodes;
  const displayEdges = killChainData ? (killChainData.edges || []) : edges;

  return (
    <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '10px 16px', background: '#08080f', borderBottom: '1px solid #1e1e30', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
        <SectionHeader icon="◎" title="ATTACK GRAPH" subtitle={`${displayNodes.length} nodes · ${displayEdges.length} edges · kill-chain mapping`} color="#8b5cf6" />
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          {graphError && <span style={{ fontSize: 11, color: '#ef4444' }}>{graphError}</span>}
          {killChainData && (
            <span style={{ fontSize: 10, color: '#6b7280', fontFamily: 'var(--font-mono)' }}>
              Risk: {killChainData.risk_score?.toFixed(1)}/10
            </span>
          )}
          <button
            onClick={buildingGraph ? undefined : buildExploitationGraph}
            style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid #8b5cf6', background: buildingGraph ? '#1e1e30' : '#1e1e30', color: '#8b5cf6', cursor: buildingGraph ? 'wait' : 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10, whiteSpace: 'nowrap' }}
          >
            {buildingGraph ? '⟳ Building…' : '⚡ Build Exploit Graph'}
          </button>
          {killChainData && (
            <button
              onClick={() => setKillChainData(null)}
              style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid #333', background: 'transparent', color: '#666', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10 }}
            >
              Reset
            </button>
          )}
        </div>
      </div>
      {killChainData?.summary && (
        <div style={{ padding: '6px 16px', background: '#0a0a14', fontSize: 11, color: '#64748b', borderBottom: '1px solid #1e1e30' }}>
          {killChainData.summary}
        </div>
      )}

      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {displayNodes.length <= 1 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', flexDirection: 'column', gap: 12, opacity: 0.25 }}>
            <div style={{ fontSize: 70, color: '#8b5cf6' }}>◎</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 13, color: '#8b5cf6', letterSpacing: 3 }}>NO GRAPH DATA</div>
            <div style={{ fontSize: 12, color: '#555' }}>Run agents or click "Build Exploit Graph" to map the attack chain</div>
          </div>
        ) : (
          <div
            ref={canvasRef}
            style={{ width: '100%', height: '100%', cursor: drag ? 'grabbing' : 'grab' }}
            onWheel={onWheel}
            onMouseDown={onPointerDown}
            onMouseMove={onPointerMove}
            onMouseUp={onPointerUp}
            onMouseLeave={onPointerUp}
          >
            <svg width="100%" height="100%" className="graph-canvas">
              <defs>
                <marker id="arrow" markerWidth="8" markerHeight="7" refX="8" refY="3.5" orient="auto">
                  <polygon points="0 0,8 3.5,0 7" fill="#8b5cf630" />
                </marker>
              </defs>
              <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
                {/* Edges */}
                {displayEdges.map((e, i) => {
                  const from = displayNodes.find(n => n.id === (e.from || e.source));
                  const to   = displayNodes.find(n => n.id === (e.to   || e.target));
                  if (!from || !to) return null;
                  const edgeColor = from.phase ? (KILL_CHAIN_COLORS[from.phase] || '#8b5cf6') : '#8b5cf6';
                  return (
                    <line key={i}
                      x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={`${edgeColor}40`} strokeWidth={1.5} markerEnd="url(#arrow)" />
                  );
                })}
                {/* Nodes */}
                {displayNodes.map(n => {
                  const col = nodeColor(n);
                  const r   = nodeRadius(n);
                  const sel = selected?.id === n.id;
                  const icon = n.is_root || n.type === 'target' ? '⬡' : n.phase === 'initial' ? '◉' : n.phase === 'foothold' ? '▲' : n.phase === 'escalation' ? '⚡' : n.phase === 'impact' ? '☠' : n.type === 'tool' ? '⚙' : '!';
                  return (
                    <g key={n.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(n)}>
                      <circle cx={n.x} cy={n.y} r={r + 5} fill={`${col}0c`} stroke={`${col}18`} strokeWidth={1} />
                      <circle cx={n.x} cy={n.y} r={r} fill={`${col}20`} stroke={col} strokeWidth={sel ? 2.5 : 1.5} />
                      <text x={n.x} y={n.y + 4} textAnchor="middle" fill={col}
                        fontSize={n.is_root || n.type === 'target' ? 12 : 10} fontFamily="JetBrains Mono" fontWeight="700">
                        {icon}
                      </text>
                      <text x={n.x} y={n.y + r + 12} textAnchor="middle" fill="#666" fontSize={8} fontFamily="JetBrains Mono">
                        {(n.label || '').substring(0, 20)}
                      </text>
                      {n.phase && n.phase !== 'root' && (
                        <text x={n.x} y={n.y + r + 22} textAnchor="middle" fill={col} fontSize={7} fontFamily="JetBrains Mono" opacity="0.7">
                          {n.phase}
                        </text>
                      )}
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
        )}

        <div style={{
          position: 'absolute', top: 14, right: 16, zIndex: 2,
          display: 'flex', alignItems: 'center', gap: 6,
          background: '#0f0f1a', border: '1px solid #1e1e30', borderRadius: 8, padding: '5px 7px',
        }}>
          <button onClick={() => zoomBy(1.15)} style={{ padding: '3px 8px', borderRadius: 6, border: '1px solid #1e1e30', background: '#111122', color: '#8b5cf6', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>+</button>
          <button onClick={() => zoomBy(0.87)} style={{ padding: '3px 8px', borderRadius: 6, border: '1px solid #1e1e30', background: '#111122', color: '#8b5cf6', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>-</button>
          <button onClick={resetView} style={{ padding: '3px 8px', borderRadius: 6, border: '1px solid #1e1e30', background: '#111122', color: '#8b5cf6', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10 }}>Reset</button>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#555' }}>{Math.round(zoom * 100)}%</span>
        </div>

        {/* Selected node info panel */}
        {selected && (
          <div style={{
            position: 'absolute', bottom: 16, right: 16, width: 310,
            background: '#0f0f1a', border: '1px solid #8b5cf635',
            borderRadius: 'var(--radius-lg)', padding: 14,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#8b5cf6', letterSpacing: 2, fontWeight: 700 }}>NODE DETAIL</div>
              <button onClick={() => setSelected(null)} style={{ marginLeft: 'auto', background: 'transparent', border: 'none', color: '#555', fontSize: 15, cursor: 'pointer' }}>×</button>
            </div>
            <div style={{ fontSize: 11.5, color: '#e8e8f0', lineHeight: 1.85 }}>
              {selected.phase_label && <div><span style={{ color: '#555' }}>Phase: </span><span style={{ color: KILL_CHAIN_COLORS[selected.phase] || '#8b5cf6' }}>{selected.phase_label}</span></div>}
              <div><span style={{ color: '#555' }}>Label: </span>{selected.label}</div>
              {(selected.sev || selected.severity) && <div><span style={{ color: '#555' }}>Severity: </span><SevBadge sev={selected.sev || selected.severity} /></div>}
              {selected.tool && <div><span style={{ color: '#555' }}>Tool: </span>{selected.tool}</div>}
              {selected.cvss !== undefined && <div><span style={{ color: '#555' }}>CVSS: </span>{selected.cvss}</div>}
              {selected.description && (
                <div style={{ marginTop: 7, fontSize: 10.5, color: '#c0c0e0', lineHeight: 1.7 }}>{selected.description}</div>
              )}
              {selected.finding && (
                <div style={{ marginTop: 7, fontSize: 10.5, color: '#888', lineHeight: 1.7 }}>
                  <div>Tool: {selected.finding.tool}</div>
                  <div>Agent: {selected.finding.agent}</div>
                  <div>CVSS: {selected.finding.cvss}</div>
                  <div style={{ marginTop: 5, color: '#c0c0e0' }}>{selected.finding.desc}</div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const DEV_FIX_CATALOG = [
  {
    id: 'sqli',
    title: 'SQL Injection',
    match: /(sql\s*injection|sqli|union\s+select|into outfile|database dump)/i,
    fix: 'Use parameterized queries or ORM bind parameters for all SQL calls.',
    requirements: 'Enforce prepared statements and DB least-privilege accounts.',
    verify: "Add integration tests with payloads like \"' OR 1=1 --\" and assert no query shape changes.",
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting',
    match: /(xss|innerhtml|document\.write|script tag|onerror=|javascript:)/i,
    fix: 'Apply context-aware output encoding and sanitize untrusted HTML before rendering.',
    requirements: 'Enable CSP with nonce/hash and block inline script execution.',
    verify: 'Run reflected/stored XSS payload suites and assert encoding in rendered DOM.',
  },
  {
    id: 'auth',
    title: 'Authentication and Session',
    match: /(jwt|token|broken auth|login|session|default login|credential)/i,
    fix: 'Strengthen auth flows: strict session handling, token validation, MFA/rate limiting.',
    requirements: 'Rotate secrets, pin JWT algorithms, reject weak/default credentials.',
    verify: 'Test token tampering, brute-force lockouts, and session invalidation on logout.',
  },
  {
    id: 'idor',
    title: 'Access Control / IDOR',
    match: /(idor|insecure direct object|authorization|access control|privilege)/i,
    fix: 'Add server-side authorization checks on every object/resource access.',
    requirements: 'Centralize permission middleware and deny by default.',
    verify: 'Attempt cross-user object access and confirm consistent 403 responses.',
  },
  {
    id: 'path',
    title: 'Path Traversal / File Inclusion',
    match: /(path traversal|lfi|rfi|\.\.\/|php:\/\/|file:\/\/)/i,
    fix: 'Normalize/canonicalize paths and enforce allowlisted root directories.',
    requirements: 'Disable dangerous file wrappers and avoid dynamic include paths.',
    verify: 'Probe traversal payloads and ensure sanitized path stays in approved base dir.',
  },
  {
    id: 'headers',
    title: 'Security Headers / CORS',
    match: /(csp|cors|x-frame-options|hsts|x-content-type-options|header missing)/i,
    fix: 'Set strict browser security headers and remove wildcard CORS in production.',
    requirements: 'Enforce environment-specific header policy via middleware.',
    verify: 'Automate header checks in CI/CD and fail build on regression.',
  },
  {
    id: 'deps',
    title: 'Vulnerable Dependencies / CVE',
    match: /(cve-\d{4}-\d+|vulnerable library|version disclosure|log4shell|spring4shell)/i,
    fix: 'Upgrade vulnerable packages and remove unsupported transitive versions.',
    requirements: 'Maintain an SBOM and continuous dependency scanning gate.',
    verify: 'Re-scan after upgrade and assert CVE identifiers no longer match.',
  },
  {
    id: 'generic',
    title: 'General Hardening',
    match: /./i,
    fix: 'Reduce exposed attack surface, add input validation, and harden defaults.',
    requirements: 'Adopt secure coding checklist and mandatory security code review.',
    verify: 'Run OWASP regression suite and compare against previous baseline.',
  },
];

// ── Developer remediation view ────────────────────────────────────────────
function DeveloperView({ findings, proxyReqs, targetHost }) {

  const flaggedReqs = useMemo(() => (proxyReqs || []).filter(r => r.flagged), [proxyReqs]);

  const remediation = useMemo(() => {
    const bucket = new Map();

    function pickCatalog(text) {
      const t = String(text || '');
      return DEV_FIX_CATALOG.find(x => x.id !== 'generic' && x.match.test(t)) || DEV_FIX_CATALOG.find(x => x.id === 'generic');
    }

    function upsertIssue({ text, sev, source, request }) {
      const cat = pickCatalog(text);
      const existing = bucket.get(cat.id);
      const entry = {
        id: cat.id,
        title: cat.title,
        maxSev: sev || 'INFO',
        count: 0,
        fix: cat.fix,
        requirements: cat.requirements,
        verify: cat.verify,
        examples: [],
        sources: new Set(),
        requests: [],
      };
      const cur = existing || entry;
      cur.count += 1;
      cur.sources.add(source || 'scan');
      if (sevOrder(sev) > sevOrder(cur.maxSev)) cur.maxSev = sev;
      if (text && cur.examples.length < 4 && !cur.examples.includes(text)) cur.examples.push(text);
      if (request && cur.requests.length < 4) cur.requests.push(request);
      bucket.set(cat.id, cur);
    }

    (findings || []).forEach(f => {
      upsertIssue({
        text: f.desc || '',
        sev: f.sev || 'INFO',
        source: `${f.agent || 'agent'}:${f.tool || 'tool'}`,
      });
    });

    flaggedReqs.forEach(r => {
      (r.vulns || []).forEach(v => {
        upsertIssue({
          text: `${v.type || 'signal'} ${r.url || ''}`,
          sev: v.sev || 'MEDIUM',
          source: 'proxy-traffic',
          request: r,
        });
      });
    });

    return [...bucket.values()]
      .map(i => ({ ...i, sources: [...i.sources] }))
      .sort((a, b) => (sevOrder(b.maxSev) - sevOrder(a.maxSev)) || (b.count - a.count));
  }, [findings, flaggedReqs]);

  async function exportDeveloperPlan() {
    const md = [
      '# PHANTOM Developer Remediation Plan',
      '',
      `Target: ${targetHost || 'unknown'}`,
      `Generated: ${new Date().toISOString()}`,
      `Issues: ${remediation.length}`,
      '',
      ...remediation.flatMap((r, idx) => ([
        `## ${idx + 1}. ${r.title} [${r.maxSev}]`,
        `Count: ${r.count}`,
        `Sources: ${r.sources.join(', ') || '-'}`,
        `Fix: ${r.fix}`,
        `Requirements: ${r.requirements}`,
        `Verification: ${r.verify}`,
        ...(r.examples || []).slice(0, 3).map(ex => `- Evidence: ${ex}`),
        '',
      ])),
    ].join('\n');
    await API.dialog.save(md, `developer-remediation-${Date.now()}.md`, [{ name: 'Markdown', extensions: ['md'] }]);
  }

  async function exportExploitEvidence() {
    const payload = {
      target: targetHost || '',
      generated_at: new Date().toISOString(),
      flagged_requests: flaggedReqs.map(r => ({
        id: r.id,
        method: r.method,
        url: r.url,
        tls: !!r.tls,
        timestamp: r.timestamp,
        flagged: !!r.flagged,
        vulns: r.vulns || [],
        request: {
          headers: r.headers || {},
          body: r.body || '',
        },
        response: {
          status: r.response?.status || 0,
          headers: r.response?.headers || {},
          body: r.response?.body || '',
        },
      })),
    };
    await API.dialog.save(
      JSON.stringify(payload, null, 2),
      `exploit-evidence-${Date.now()}.json`,
      [{ name: 'JSON', extensions: ['json'] }],
    );
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
      <SectionHeader icon="🛠" title="DEVELOPER REMEDIATION" subtitle="Actionable code fixes, security requirements, and exploit request/response evidence" color="#06b6d4" />

      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        <Btn onClick={exportDeveloperPlan} color="#0891b2">⬇ Export Developer Plan</Btn>
        <GhostBtn onClick={exportExploitEvidence} color="#ec4899">⬇ Export Exploit Evidence</GhostBtn>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 12 }}>
        <div>
          {remediation.length === 0 ? (
            <div className="card" style={{ padding: 20, color: '#555', lineHeight: 1.8 }}>
              No remediation items yet. Run scans or capture proxy traffic first.
            </div>
          ) : remediation.map(item => (
            <div key={item.id} className="card" style={{ marginBottom: 10 }}>
              <div className="card-header" style={{ color: SEV[item.maxSev]?.fg || '#6ee7b7' }}>
                {item.title} · {item.count} signal{item.count !== 1 ? 's' : ''}
              </div>
              <div style={{ padding: 12, fontSize: 11.5, lineHeight: 1.8 }}>
                <div style={{ marginBottom: 6 }}><SevBadge sev={item.maxSev} /></div>
                <div><span style={{ color: '#666' }}>Fix: </span>{item.fix}</div>
                <div><span style={{ color: '#666' }}>Requirement: </span>{item.requirements}</div>
                <div><span style={{ color: '#666' }}>Verification: </span>{item.verify}</div>
                {(item.examples || []).length > 0 && (
                  <pre className="terminal" style={{ marginTop: 8, maxHeight: 110, fontSize: 10 }}>
                    {(item.examples || []).slice(0, 3).join('\n')}
                  </pre>
                )}
              </div>
            </div>
          ))}
        </div>

        <div>
          <div className="card">
            <div className="card-header" style={{ color: '#ec4899' }}>EXPLOIT REQUEST/RESPONSE EVIDENCE ({flaggedReqs.length})</div>
            <div style={{ padding: 10, maxHeight: '72vh', overflowY: 'auto' }}>
              {flaggedReqs.length === 0 ? (
                <div style={{ color: '#555', lineHeight: 1.8, fontSize: 11.5 }}>
                  No flagged proxy requests yet.<br />
                  Route browser traffic through `127.0.0.1:8888`, login, and exercise the app.
                </div>
              ) : flaggedReqs.slice(0, 40).map(req => (
                <div key={req.id} style={{ border: '1px solid #1e1e30', borderRadius: 8, padding: 8, marginBottom: 8, background: '#0a0a0f' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#fb923c' }}>{req.method}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#10b981' }}>{req.response?.status || '-'}</span>
                    <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 8, color: '#555' }}>{req.timestamp ? new Date(req.timestamp).toLocaleTimeString() : ''}</span>
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9.5, color: '#8b5cf6', marginBottom: 6, wordBreak: 'break-all' }}>{req.url}</div>
                  <pre className="terminal" style={{ maxHeight: 70, fontSize: 9.5, marginBottom: 6 }}>{req.body || '(no request body)'}</pre>
                  <pre className="terminal" style={{ maxHeight: 90, fontSize: 9.5, color: '#6ee7b7' }}>{req.response?.body || '(no response body)'}</pre>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Intelligence / Memory view ────────────────────────────────────────────
function IntelView({ learned, onClearLearned }) {
  const [activeModel,    setActiveModel]    = useState('');
  const [trainingRuns,   setTrainingRuns]   = useState([]);
  const [training,       setTraining]       = useState(false);
  const [trainMsg,       setTrainMsg]       = useState('');

  useEffect(() => {
    // Fetch active model + training history on mount
    fetch('http://localhost:8000/ollama/active-model').then(r => r.json()).then(d => setActiveModel(d.model || '')).catch(() => {});
    fetch('http://localhost:8000/ollama/training-history').then(r => r.json()).then(d => setTrainingRuns(d.runs || [])).catch(() => {});
  }, []);

  async function triggerTrain() {
    setTraining(true);
    setTrainMsg('Training…');
    try {
      const resp = await fetch('http://localhost:8000/ollama/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_name: 'phantom-security:latest', base_model: activeModel || 'llama3.1', max_findings: 500 }),
      });
      const data = await resp.json();
      setTrainMsg(`✓ Done — ${data.examples || 0} examples`);
      fetch('http://localhost:8000/ollama/training-history').then(r => r.json()).then(d => setTrainingRuns(d.runs || [])).catch(() => {});
    } catch (e) {
      setTrainMsg(`✗ ${e.message}`);
    } finally {
      setTraining(false);
      setTimeout(() => setTrainMsg(''), 6000);
    }
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
      <SectionHeader icon="🧠" title="INTELLIGENCE & MEMORY" subtitle="Chroma vector DB · Redis cache · Neo4j attack graph · Local pattern learning" color="#8b5cf6" />

      {/* Active LLM model + training status */}
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-header" style={{ color: '#8b5cf6' }}>ACTIVE LLM MODEL</div>
        <div style={{ padding: '12px 16px', display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: '#10b981' }}>
            {activeModel || 'Detecting…'}
          </div>
          <div style={{ padding: '2px 8px', borderRadius: 4, background: '#10b98115', border: '1px solid #10b98130', fontFamily: 'var(--font-mono)', fontSize: 9, color: '#10b981' }}>
            Auto-training: ON
          </div>
          <button
            onClick={training ? undefined : triggerTrain}
            style={{ marginLeft: 'auto', padding: '4px 12px', borderRadius: 6, border: '1px solid #8b5cf640', background: '#8b5cf615', color: '#8b5cf6', cursor: training ? 'wait' : 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10 }}
          >
            {trainMsg || (training ? '⟳ Training…' : '⚡ Train Now')}
          </button>
        </div>
        {trainingRuns.length > 0 && (
          <div style={{ padding: '0 16px 12px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#33334a', letterSpacing: 1.5, marginBottom: 6 }}>TRAINING HISTORY</div>
            {trainingRuns.slice(0, 5).map((run, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4, fontSize: 10, color: '#888' }}>
                <span style={{ color: run.status === 'success' ? '#10b981' : '#ef4444', fontFamily: 'var(--font-mono)', fontSize: 9 }}>
                  {run.status === 'success' ? '✓' : '✗'}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', color: '#8b5cf6', fontSize: 9 }}>{run.model_name}</span>
                <span style={{ color: '#555' }}>{(run.created_at || '').slice(0, 16)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

        {/* Memory system status */}
        <div className="card">
          <div className="card-header" style={{ color: '#8b5cf6' }}>MEMORY SYSTEM STATUS</div>
          <div style={{ padding: 14 }}>
            {[
              { name: 'Redis',      label: 'Short-term state',     desc: 'Live scan state, agent queues, session data',        color: '#ef4444', port: 6379, docker: true  },
              { name: 'Chroma',     label: 'Vector DB (semantic)', desc: 'Embedding-based pattern matching across scans',       color: '#f59e0b', port: 8000, docker: true  },
              { name: 'Neo4j',      label: 'Attack graph DB',      desc: 'Privilege paths, lateral movement, blast radius',    color: '#10b981', port: 7474, docker: true  },
              { name: 'PostgreSQL', label: 'Findings store',       desc: 'Full findings and session history with relationships',color: '#3b82f6', port: 5432, docker: true  },
              { name: 'SQLite',     label: 'Local fallback',       desc: 'Offline mode — always available, no Docker needed',  color: '#8b5cf6', port: null, docker: false },
            ].map(m => (
              <div key={m.name} style={{
                display: 'flex', gap: 12, padding: '11px', borderRadius: 9,
                marginBottom: 8, background: 'var(--bg-surface)', border: `1px solid ${m.color}20`,
              }}>
                <div style={{
                  width: 38, height: 38, borderRadius: 9,
                  background: `${m.color}15`, border: `1px solid ${m.color}30`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color: m.color, flexShrink: 0,
                }}>{m.name.slice(0, 2)}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: m.color, fontWeight: 700 }}>{m.name}</div>
                  <div style={{ fontSize: 10, color: '#888', marginTop: 1 }}>{m.label}</div>
                  <div style={{ fontSize: 9, color: '#44445a', marginTop: 1 }}>{m.desc}</div>
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  {m.docker && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: m.color, padding: '2px 7px', borderRadius: 4, background: `${m.color}12`, border: `1px solid ${m.color}30`, marginBottom: 3 }}>Docker</div>}
                  {m.port && <div style={{ fontSize: 8, color: '#33334a', fontFamily: 'var(--font-mono)' }}>:{m.port}</div>}
                </div>
              </div>
            ))}
            <div style={{ padding: '10px 12px', background: '#0a0a0f', borderRadius: 8, border: '1px solid #1e1e30', marginTop: 6 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#33334a', letterSpacing: 1, marginBottom: 5 }}>START ALL SERVICES</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: '#ff4500' }}>docker-compose up -d</div>
            </div>
          </div>
        </div>

        {/* Learned patterns */}
        <div className="card">
          <div className="card-header" style={{ color: '#8b5cf6' }}>LEARNED PATTERNS ({learned.length})</div>
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: 440, padding: 8 }}>
            {learned.length === 0 && (
              <div style={{ padding: 36, textAlign: 'center', color: '#33334a', fontSize: 12, lineHeight: 1.9 }}>
                No patterns yet.<br />Run scans to train the learning engine.
              </div>
            )}
            {[...learned].sort((a, b) => b.count - a.count).map((p, i) => (
              <div key={i} style={{
                display: 'flex', gap: 10, padding: '9px 11px', borderRadius: 8,
                marginBottom: 5, background: 'var(--bg-surface)', border: '1px solid #8b5cf618', alignItems: 'center',
              }}>
                <div style={{
                  width: 28, height: 28, borderRadius: '50%',
                  background: 'linear-gradient(135deg,#7c3aed,#8b5cf6)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'white', fontSize: 10, fontWeight: 700, flexShrink: 0,
                }}>{p.count}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: '#e8e8f0', lineHeight: 1.35, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.pattern}</div>
                  <div style={{ fontSize: 9, color: '#555', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{p.vuln} · {p.agent || '—'} · {new Date(p.last).toLocaleDateString()}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{ padding: '10px 12px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
            <GhostBtn onClick={onClearLearned} color="#ef4444" style={{ flex: 1, padding: '7px', fontSize: 9 }}>Clear Learning</GhostBtn>
            <div style={{ flex: 2, fontSize: 10, color: '#44445a', display: 'flex', alignItems: 'center', paddingLeft: 8 }}>Auto-injected into LLM prompts</div>
          </div>
        </div>

        {/* Docker compose snippet */}
        <div className="card" style={{ gridColumn: '1 / -1' }}>
          <div className="card-header">DOCKER DATA LAYER — QUICK REFERENCE</div>
          <pre className="terminal" style={{ maxHeight: 210, fontSize: 11 }}>{`# Start all data services (run from project root)
docker-compose -f docker/docker-compose.yml up -d

# Services started:
#  phantom_redis    → localhost:6379  (state cache)
#  phantom_neo4j    → localhost:7474  (attack graph — user: neo4j / pass: phantom123)
#  phantom_chroma   → localhost:8001  (vector embeddings)
#  phantom_postgres → localhost:5432  (findings DB — user: phantom / pass: phantom)

# Health check:
docker-compose ps
docker exec phantom_redis redis-cli ping          # → PONG
docker exec phantom_neo4j cypher-shell -u neo4j -p phantom123 "RETURN 1"`}</pre>
        </div>
      </div>
    </div>
  );
}

// ── Findings view ──────────────────────────────────────────────────────────
function FindingsView({ findings, activeAgents, usedTools, learned, proxyReqs = [] }) {
  const fCrit = findings.filter(f => f.sev === 'CRITICAL').length;
  const fHigh = findings.filter(f => f.sev === 'HIGH').length;
  const fMed  = findings.filter(f => f.sev === 'MEDIUM').length;
  const fLow  = findings.filter(f => f.sev === 'LOW').length;
  const risk  = Math.min(10, fCrit * 2.5 + fHigh * 1.2 + fMed * 0.4 + fLow * 0.1).toFixed(1);

  const sorted = [...findings].sort((a, b) => sevOrder(b.sev) - sevOrder(a.sev));
  const flaggedReqs = (proxyReqs || []).filter(r => r.flagged);

  const agentData = AGENT_ORDER.map(a => ({
    name: AGENTS[a].name, findings: findings.filter(f => f.agent === a).length, fill: AGENTS[a].color,
  }));

  function buildHTML(type) {
    const now    = new Date().toLocaleString();
    const critF  = findings.filter(f => f.sev === 'CRITICAL');
    const highF  = findings.filter(f => f.sev === 'HIGH');

    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>PHANTOM AI v3 — ${type === 'exec' ? 'Executive' : 'Technical'} Report</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e8e8f0;min-height:100vh}
.cover{background:linear-gradient(135deg,#1a0505,#0a0a1f);padding:56px 60px;border-bottom:3px solid #ff4500;position:relative;overflow:hidden}
.cover::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 20% 50%,rgba(255,69,0,0.1) 0%,transparent 60%)}
.cover h1{font-family:'Orbitron';font-size:30px;letter-spacing:4px;color:#ff4500;position:relative}
.cover .sub{font-family:'JetBrains Mono';font-size:12px;color:#555;letter-spacing:2px;margin-top:6px}
.cover .meta{margin-top:20px;display:flex;gap:16px;flex-wrap:wrap}
.cover .meta span{font-family:'JetBrains Mono';font-size:10px;color:#666;padding:3px 10px;border:1px solid #333;border-radius:4px}
.wrap{max-width:1100px;margin:0 auto;padding:40px 56px}
.sec{font-family:'Orbitron';font-size:9px;letter-spacing:3px;color:#ff4500;margin:32px 0 14px;padding-bottom:7px;border-bottom:1px solid rgba(255,69,0,0.2)}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:22px}
.sc{border-radius:10px;padding:18px;text-align:center;border:1px solid}
.sc-num{font-family:'Orbitron';font-size:44px;font-weight:900;line-height:1}
.sc-lbl{font-family:'JetBrains Mono';font-size:8px;letter-spacing:3px;margin-top:4px;opacity:.6}
.sc-C{background:#1a0505;border-color:#7f1d1d;color:#f87171}
.sc-H{background:#1a0d05;border-color:#7c2d12;color:#fb923c}
.sc-M{background:#1a1505;border-color:#713f12;color:#fbbf24}
.sc-L{background:#051a0d;border-color:#064e3b;color:#34d399}
.badge{font-family:'JetBrains Mono';font-size:8.5px;font-weight:700;letter-spacing:1.5px;padding:2px 8px;border-radius:4px;border:1px solid;white-space:nowrap}
.b-C{background:#1a0505;color:#f87171;border-color:#7f1d1d}
.b-H{background:#1a0d05;color:#fb923c;border-color:#7c2d12}
.b-M{background:#1a1505;color:#fbbf24;border-color:#713f12}
.b-L{background:#051a0d;color:#34d399;border-color:#064e3b}
.finding{border:1px solid #1e1e30;border-radius:8px;margin-bottom:7px;overflow:hidden}
.fh{padding:10px 14px;display:flex;align-items:center;gap:10px;background:#0f0f1a}
.fb{padding:9px 14px;font-size:11px;color:#666;line-height:1.7;border-top:1px solid #1e1e30}
table{width:100%;border-collapse:collapse;font-size:11px}
th{background:#0f0f1a;padding:8px 12px;text-align:left;font-family:'JetBrains Mono';font-size:8px;letter-spacing:2px;color:#555;border-bottom:1px solid #1e1e30}
td{padding:9px 12px;border-bottom:1px solid #141420}
tr:hover td{background:#0f0f1a}
.risk{font-family:'Orbitron';font-size:72px;font-weight:900;color:${parseFloat(risk) >= 8 ? '#f87171' : parseFloat(risk) >= 5 ? '#fb923c' : '#fbbf24'};line-height:1}
footer{text-align:center;padding:22px;font-family:'JetBrains Mono';font-size:9px;color:#33334a;border-top:1px solid #1e1e30;margin-top:36px}
</style></head><body>
<div class="cover">
  <h1>PHANTOM AI v3</h1>
  <div class="sub">${type === 'exec' ? 'EXECUTIVE SECURITY REPORT' : 'TECHNICAL PENETRATION TEST REPORT'}</div>
  <div class="meta">
    <span>DATE: ${now}</span>
    <span>AGENTS: ${[...activeAgents].join(', ')}</span>
    <span>TOOLS: ${usedTools.join(', ') || 'simulated'}</span>
    <span>FINDINGS: ${findings.length}</span>
  </div>
</div>
<div class="wrap">
  ${type === 'exec' ? `<div class="sec">RISK OVERVIEW</div>
  <div style="display:flex;gap:32px;align-items:center;margin-bottom:24px">
    <div style="text-align:center"><div class="risk">${risk}</div>
    <div style="font-family:'JetBrains Mono';font-size:9px;letter-spacing:3px;color:#555;margin-top:4px">RISK SCORE / 10</div></div>
    <p style="font-size:14px;line-height:1.9;color:#888;flex:1">
      This autonomous security assessment identified <strong style="color:#ff4500">${findings.length} vulnerabilities</strong>
      including <strong style="color:#f87171">${fCrit} critical</strong> and <strong style="color:#fb923c">${fHigh} high</strong> severity issues.
      ${fCrit > 0 ? 'Critical findings require immediate remediation to prevent system compromise or data breach.' : ''}
    </p>
  </div>` : ''}
  <div class="grid4">
    <div class="sc sc-C"><div class="sc-num">${fCrit}</div><div class="sc-lbl">CRITICAL</div></div>
    <div class="sc sc-H"><div class="sc-num">${fHigh}</div><div class="sc-lbl">HIGH</div></div>
    <div class="sc sc-M"><div class="sc-num">${fMed}</div><div class="sc-lbl">MEDIUM</div></div>
    <div class="sc sc-L"><div class="sc-num">${fLow}</div><div class="sc-lbl">LOW</div></div>
  </div>
  <div class="sec">CRITICAL & HIGH FINDINGS</div>
  ${[...critF, ...highF].map(f => `<div class="finding">
    <div class="fh">
      <span class="badge b-${f.sev[0]}">${f.sev}</span>
      <strong>${f.desc.substring(0, 120)}</strong>
      <span style="margin-left:auto;font-family:'JetBrains Mono';font-size:9.5px;color:#555">${f.agent} · ${f.tool}</span>
    </div>
    <div class="fb">CVSS: ${f.cvss} · Agent: ${f.agent} · Tool: ${f.tool} · Iteration #${f.iter} · ${new Date(f.ts).toLocaleTimeString()}</div>
  </div>`).join('')}
  <div class="sec">ALL FINDINGS</div>
  <table><thead><tr><th>SEV</th><th>DESCRIPTION</th><th>AGENT</th><th>TOOL</th><th>CVSS</th><th>ITER</th></tr></thead><tbody>
  ${sorted.map(f => `<tr>
    <td><span class="badge b-${f.sev[0]}">${f.sev}</span></td>
    <td>${f.desc.substring(0, 130)}</td>
    <td style="font-family:monospace;font-size:10px;color:#666">${f.agent}</td>
    <td style="font-family:monospace;font-size:10px;color:#666">${f.tool}</td>
    <td style="font-family:monospace;color:${f.cvss >= 9 ? '#f87171' : f.cvss >= 7 ? '#fb923c' : '#fbbf24'};font-weight:700">${f.cvss}</td>
    <td style="font-family:monospace;color:#444">#${f.iter}</td>
  </tr>`).join('')}
  </tbody></table>
  <footer>PHANTOM AI v3 · Autonomous Pentest Platform · ${new Date().toLocaleDateString()} · For authorized testing only</footer>
</div></body></html>`;
  }

  function buildSARIF() {
    return JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'Phantom AI v3', version: '3.0.0', rules: [] } },
        results: sorted.map(f => ({
          ruleId: `phantom/${f.sev.toLowerCase()}`,
          level: f.sev === 'CRITICAL' || f.sev === 'HIGH' ? 'error' : 'warning',
          message: { text: f.desc },
          properties: { agent: f.agent, tool: f.tool, cvss: f.cvss },
        })),
      }],
    }, null, 2);
  }

  function buildExploitEvidenceJSON() {
    return JSON.stringify({
      generated_at: new Date().toISOString(),
      findings_total: findings.length,
      flagged_requests_total: flaggedReqs.length,
      findings: sorted.map(f => ({
        severity: f.sev,
        description: f.desc,
        agent: f.agent,
        tool: f.tool,
        cvss: f.cvss,
        iter: f.iter,
        timestamp: f.ts,
      })),
      exploit_requests: flaggedReqs.map(r => ({
        id: r.id,
        method: r.method,
        url: r.url,
        timestamp: r.timestamp,
        tls: !!r.tls,
        vulns: r.vulns || [],
        request: {
          headers: r.headers || {},
          body: r.body || '',
        },
        response: {
          status: r.response?.status || 0,
          headers: r.response?.headers || {},
          body: r.response?.body || '',
        },
      })),
    }, null, 2);
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
      <SectionHeader icon="💥" title="FINDINGS DATABASE" subtitle={`${findings.length} total · Risk score ${risk}/10 · CVSS-based prioritization`} color="#ef4444" />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10, marginBottom: 16 }}>
        <StatCard label="CRITICAL" value={fCrit} color="#ef4444" icon="💀" />
        <StatCard label="HIGH"     value={fHigh} color="#fb923c" icon="🔴" />
        <StatCard label="MEDIUM"   value={fMed}  color="#fbbf24" icon="⚠"  />
        <StatCard label="LOW"      value={fLow}  color="#34d399" icon="ℹ"  />
        <StatCard label="RISK"     value={risk}  color={parseFloat(risk) >= 8 ? '#ef4444' : '#fb923c'} sub="/10 max" />
      </div>

      {/* Chart */}
      {findings.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <div className="card-header">Distribution by Agent</div>
          <div style={{ padding: 14, height: 150 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={agentData} margin={{ top: 0, right: 0, bottom: 0, left: -22 }}>
                <XAxis dataKey="name" tick={{ fill: '#666', fontSize: 9.5, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#555', fontSize: 9 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0f0f1a', border: '1px solid #1e1e30', borderRadius: 7, fontFamily: 'JetBrains Mono', fontSize: 11 }} />
                <Bar dataKey="findings" radius={[5, 5, 0, 0]}>{agentData.map((d, i) => <Cell key={i} fill={d.fill} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Export buttons */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        <Btn onClick={() => API.dialog.save(buildHTML('exec'), `phantom_executive_${Date.now()}.html`)} color="#cc3700">
          ⬇ Executive Report
        </Btn>
        <Btn onClick={() => API.dialog.save(buildHTML('tech'), `phantom_technical_${Date.now()}.html`)} color="#7c2d12">
          ⬇ Technical Report
        </Btn>
        <GhostBtn onClick={() => API.dialog.save(buildSARIF(), `phantom_${Date.now()}.sarif.json`)} color="#3b82f6">
          ⬇ SARIF JSON
        </GhostBtn>
        <GhostBtn onClick={() => API.dialog.save(JSON.stringify({ findings, metadata: { date: new Date().toISOString(), agents: [...activeAgents], tools: usedTools, risk } }, null, 2), `phantom_raw_${Date.now()}.json`)} color="#555">
          ⬇ Raw JSON
        </GhostBtn>
        <GhostBtn onClick={() => API.dialog.save(buildExploitEvidenceJSON(), `phantom_exploit_evidence_${Date.now()}.json`)} color="#ec4899">
          ⬇ Exploit Evidence (Req/Resp)
        </GhostBtn>
      </div>

      {/* Findings table */}
      {findings.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 56, background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', color: '#33334a' }}>
          No findings yet — launch agents to scan
        </div>
      ) : (
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                {['SEV', 'VULNERABILITY', 'AGENT', 'TOOL', 'CVSS', 'ITER', 'TIME'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {sorted.map((f, i) => (
                <tr key={i}>
                  <td><SevBadge sev={f.sev} /></td>
                  <td style={{ maxWidth: 360, color: '#e8e8f0' }}>{f.desc}</td>
                  <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: AGENTS[f.agent]?.color || '#888' }}>{f.agent}</span></td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#666' }}>{f.tool}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: f.cvss >= 9 ? '#ef4444' : f.cvss >= 7 ? '#fb923c' : '#fbbf24', fontWeight: 700 }}>{f.cvss}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#44445a' }}>#{f.iter}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#33334a' }}>{new Date(f.ts).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Settings view ─────────────────────────────────────────────────────────
function SettingsView({ ollamaOk, models, model, setModel, onCheck }) {
  const [paths, setPaths] = useState(null);
  const [certPath, setCertPath] = useState('');
  const [certMsg, setCertMsg] = useState('');
  useEffect(() => { if (E) E.paths().then(setPaths); }, []);
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const info = await API.cert.path();
        const path = typeof info === 'string' ? info : info?.path;
        if (alive && path) setCertPath(path);
      } catch {}
    })();
    return () => { alive = false; };
  }, []);

  async function startOllama() {
    const res = await API.ollama.start();
    setCertMsg(res?.ok ? 'Ollama start requested. Re-test connection in 1-2 seconds.' : `Could not start Ollama: ${res?.error || 'unknown error'}`);
  }

  async function installCert() {
    const res = await API.cert.install();
    if (res?.path) setCertPath(res.path);
    setCertMsg(res?.ok
      ? `CA installed (${res.scope || 'keychain'}).`
      : `CA install failed: ${res?.error || 'unknown error'}`);
  }

  async function revealCert() {
    const res = await API.cert.reveal();
    if (res?.path) setCertPath(res.path);
    setCertMsg(res?.ok
      ? `Opened in Finder: ${res.path}`
      : `Could not open CA file: ${res?.path || '(unknown path)'}`);
  }

  async function downloadCert() {
    const cert = await API.cert.read();
    if (!cert?.ok) {
      setCertMsg(`Could not read CA certificate: ${cert?.error || 'unknown error'}`);
      return;
    }
    const saved = await API.dialog.save(
      cert.pem,
      'phantom-ca.crt',
      [{ name: 'Certificate', extensions: ['crt', 'pem'] }],
    );
    if (saved?.canceled) {
      setCertMsg('CA download canceled.');
      return;
    }
    setCertMsg(`CA saved: ${saved?.path || 'done'}`);
  }

  const setupCommands = useMemo(() => {
    const cp = certPath || `${paths?.certsDir || '$HOME/.config'}/ca.crt`;
    return [
      `# 1) Trust Phantom local CA`,
      `security add-trusted-cert -d -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" "${cp}"`,
      ``,
      `# 2) Configure macOS proxy (replace "Wi-Fi" if needed)`,
      `networksetup -listallnetworkservices`,
      `networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8888`,
      `networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8888`,
      ``,
      `# 3) Launch browser routed through proxy`,
      `open -na "Google Chrome" --args --proxy-server="http://127.0.0.1:8888"`,
      ``,
      `# 4) Disable proxy when done`,
      `networksetup -setwebproxystate "Wi-Fi" off`,
      `networksetup -setsecurewebproxystate "Wi-Fi" off`,
    ].join('\n');
  }, [certPath, paths]);

  async function copySetupCommands() {
    try {
      await navigator.clipboard.writeText(setupCommands);
      setCertMsg('Proxy/CA setup commands copied.');
    } catch {
      setCertMsg('Clipboard copy failed. Use the command block below.');
    }
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
      <SectionHeader icon="⚙" title="SETTINGS & CONFIGURATION" subtitle="Ollama · Proxy CA · Data stores · System info" />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, maxWidth: 920 }}>

        {/* Ollama */}
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#ff4500', letterSpacing: 2, fontWeight: 700, marginBottom: 13 }}>LOCAL LLM — OLLAMA</div>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', marginBottom: 4, letterSpacing: 1 }}>OLLAMA URL</div>
            <input defaultValue="http://localhost:11434" style={{ width: '100%', padding: '8px 11px', fontSize: 12, fontFamily: 'var(--font-mono)' }} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
            <Btn onClick={onCheck}>TEST CONNECTION</Btn>
            <GhostBtn onClick={startOllama} color="#10b981">START OLLAMA</GhostBtn>
          </div>
          <div style={{
            padding: '9px 12px', borderRadius: 8, marginBottom: 12,
            background: ollamaOk ? '#065f4612' : '#1a050512',
            border: `1px solid ${ollamaOk ? '#10b98130' : '#7f1d1d30'}`,
            fontSize: 11.5, color: ollamaOk ? '#10b981' : '#f87171', fontFamily: 'var(--font-mono)',
          }}>
            {ollamaOk ? `✓ Connected · ${models.length} model${models.length !== 1 ? 's' : ''}` : '✗ Offline — run: ollama serve'}
          </div>
          {models.length > 0 && (
            <div>
              <div style={{ fontSize: 8.5, color: '#666', fontFamily: 'var(--font-mono)', letterSpacing: 1, marginBottom: 7 }}>AVAILABLE MODELS</div>
              {models.map(m => (
                <div key={m} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 9px', borderRadius: 6, marginBottom: 3, background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                  <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', flexShrink: 0 }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, flex: 1 }}>{m}</span>
                  <GhostBtn onClick={() => setModel(m)} color={model === m ? '#ff4500' : '#555'} style={{ padding: '3px 9px', fontSize: 8.5 }}>
                    {model === m ? 'ACTIVE' : 'USE'}
                  </GhostBtn>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Proxy & Certs */}
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#ff4500', letterSpacing: 2, fontWeight: 700, marginBottom: 12 }}>HTTPS PROXY & CA CERTIFICATE</div>
          <div style={{ fontSize: 12, color: '#666', lineHeight: 1.9, marginBottom: 13 }}>
            Phantom intercepts HTTPS traffic on <strong style={{ color: '#ff4500', fontFamily: 'var(--font-mono)' }}>localhost:8888</strong> using a per-host MITM CA.
            Install the root certificate to avoid browser warnings.
          </div>
          <Btn onClick={installCert} style={{ width: '100%', marginBottom: 8 }}>🔐 Install CA (macOS Keychain)</Btn>
          <GhostBtn onClick={revealCert} style={{ width: '100%', marginBottom: 8 }}>📁 Show Certificate in Finder</GhostBtn>
          <GhostBtn onClick={downloadCert} style={{ width: '100%', marginBottom: 12 }} color="#3b82f6">⬇ Download CA Certificate</GhostBtn>
          <GhostBtn onClick={copySetupCommands} style={{ width: '100%', marginBottom: 12 }} color="#06b6d4">📋 Copy Setup Commands</GhostBtn>
          <div style={{ padding: '9px 12px', background: '#0a0a0f', borderRadius: 8, border: '1px solid #1e1e30', fontSize: 10.5, color: '#555', fontFamily: 'var(--font-mono)', lineHeight: 1.85 }}>
            macOS browser setup:<br />
            System Settings → Network → Proxies<br />
            HTTP Proxy: 127.0.0.1 Port: 8888
          </div>
          <pre className="terminal" style={{ marginTop: 8, maxHeight: 150, fontSize: 9.5 }}>{setupCommands}</pre>
          <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, background: '#05070f', border: '1px solid #1e1e30', fontSize: 10, color: '#6b7280', fontFamily: 'var(--font-mono)', lineHeight: 1.7 }}>
            CA path: {certPath || `${paths?.certsDir || '~/.config'}/ca.crt`}
            {certMsg ? <><br />Status: {certMsg}</> : null}
          </div>
        </div>

        {/* System info */}
        <div className="card" style={{ padding: 16, gridColumn: '1 / -1' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8.5, color: '#8b5cf6', letterSpacing: 2, fontWeight: 700, marginBottom: 12 }}>SYSTEM INFORMATION</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
            {[
              ['App Version',   '3.0.0',               '#ff4500'],
              ['Agent Count',   '7 parallel',           '#10b981'],
              ['Data Layers',   'Redis+Neo4j+Chroma+PG','#8b5cf6'],
              ['HTTPS Proxy',   ':8888 MITM',           '#3b82f6'],
              ['WS Feed',       ':8001 live',           '#f59e0b'],
              ['Backend',       ':8000 FastAPI',         '#06b6d4'],
              ['LLM Engine',    'Ollama local',         '#ec4899'],
              ['Platform',      IS_ELECTRON ? 'Electron' : 'Browser', '#94a3b8'],
            ].map(([k, v, c]) => (
              <div key={k} style={{ padding: '11px 13px', borderRadius: 8, background: 'var(--bg-surface)', border: `1px solid ${c}20` }}>
                <div style={{ fontSize: 8, letterSpacing: 2, color: '#33334a', fontFamily: 'var(--font-mono)', marginBottom: 5 }}>{k}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, color: c, fontWeight: 600 }}>{v}</div>
              </div>
            ))}
          </div>
          {paths && (
            <div style={{ marginTop: 12, padding: '9px 12px', background: '#0a0a0f', borderRadius: 8, border: '1px solid #1e1e30' }}>
              <div style={{ fontSize: 8.5, color: '#33334a', fontFamily: 'var(--font-mono)', letterSpacing: 1, marginBottom: 7 }}>FILE PATHS</div>
              {Object.entries(paths).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 10, marginBottom: 3 }}>
                  <span style={{ fontSize: 9.5, color: '#555', fontFamily: 'var(--font-mono)', minWidth: 80 }}>{k}</span>
                  <span style={{ fontSize: 9.5, color: '#44445a', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PHANTOM AI v3 — App.jsx Part 6: Root App component + agent engine     ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── Main App component ────────────────────────────────────────────────────
export default function PhantomApp() {
  // ── Navigation ──────────────────────────────────────────────────────────
  const [view, setView] = useState('dashboard');

  // ── Targets ─────────────────────────────────────────────────────────────
  const [targets,       setTargets]      = useState([{ id: 1, host: 'testphp.vulnweb.com', type: 'web', label: 'Demo Target' }]);
  const [activeTarget,  setActiveTarget] = useState(0);

  // ── Findings (global, accumulated across all agents) ─────────────────────
  const [findings,  setFindings]  = useState([]);
  const findingsRef = useRef([]);   // mutable ref for agent closures

  // ── Proxy ────────────────────────────────────────────────────────────────
  const [proxyReqs, setProxyReqs] = useState([]);

  // ── Ollama ───────────────────────────────────────────────────────────────
  const [ollamaOk,  setOllamaOk]  = useState(false);
  const [models,    setModels]    = useState([]);
  const [model,     setModel]     = useState('llama3.1');

  // ── Agent/scan state ──────────────────────────────────────────────────────
  const [agentStatus, setAgentStatus] = useState(
    Object.fromEntries(AGENT_ORDER.map(a => [a, { status: 'idle', iter: 0, findings: 0 }]))
  );
  const [agentSteps,   setAgentSteps]   = useState([]);
  const [liveText,     setLiveText]     = useState({});
  const [running,      setRunning]      = useState(false);
  const [paused,       setPaused]       = useState(false);
  const [phase,        setPhase]        = useState('idle');
  const [progress,     setProgress]     = useState(0);
  const [maxIter,      setMaxIter]      = useState(10);
  const [scanDepth,    setScanDepth]    = useState('standard');
  const [activeAgents, setActiveAgents] = useState(new Set(AGENT_ORDER));
  const [usedTools,    setUsedTools]    = useState([]);
  const [reportReady,  setReportReady]  = useState(false);

  // ── Intelligence (learned patterns, persisted in localStorage) ────────────
  const [learned, setLearned] = useState(() => {
    try { return JSON.parse(localStorage.getItem('phantom_v3_learned') || '[]'); } catch { return []; }
  });

  // ── Repeater state ────────────────────────────────────────────────────────
  const [repeaterRequest, setRepeaterRequest] = useState(null);

  // ── Abort / pause refs (used inside async agent loops) ───────────────────
  const abortRef = useRef(false);
  const pauseRef = useRef(false);

  // ── On mount: connect Ollama, connect proxy WebSocket, listen for IPC ────
  useEffect(() => {
    checkOllama();
    connectProxyWS();
    if (E) {
      E.on('nav', setView);
      E.on('cmd', handleCmd);
    }
    return () => { if (E) { E.off('nav'); E.off('cmd'); } };
  }, []); // eslint-disable-line

  function handleCmd(cmd) {
    if (cmd === 'new-scan')     { resetScan(); setView('agents'); }
    if (cmd === 'stop-all')     { abortRef.current = true; pauseRef.current = false; }
    if (cmd === 'export')       { setView('findings'); }
    if (cmd === 'install-cert') { API.cert.install(); }
    if (cmd === 'clear-proxy')  { setProxyReqs([]); API.proxy.clear(); }
  }

  async function checkOllama() {
    try {
      const r   = await fetch('http://localhost:11434/api/tags', { signal: AbortSignal.timeout(3000) });
      const d   = await r.json();
      const ms  = (d.models || []).map(m => m.name);
      setModels(ms);
      setOllamaOk(true);
      if (ms.length) setModel(ms[0]);
      return true;
    } catch {
      setOllamaOk(false);
      return false;
    }
  }

  function connectProxyWS() {
    try {
      const ws = new WebSocket(WS_URL);
      ws.onmessage = e => {
        try {
          const m = JSON.parse(e.data);
          if (m.type === 'proxy_request' || m.type === 'proxy_response') {
            setProxyReqs(prev => {
              const idx = prev.findIndex(r => r.id === m.request.id);
              if (idx >= 0) { const n = [...prev]; n[idx] = m.request; return n; }
              return [m.request, ...prev].slice(0, 1000);
            });
          }
        } catch {}
      };
      ws.onerror = () => {};
    } catch {}
  }

  // ── Persist learned patterns to localStorage whenever they change ─────────
  useEffect(() => {
    try { localStorage.setItem('phantom_v3_learned', JSON.stringify(learned.slice(0, 300))); } catch {}
  }, [learned]);

  function savePattern(pattern, vuln, agent) {
    setLearned(prev => {
      const existing = prev.find(p => p.pattern === pattern);
      return existing
        ? prev.map(p => p.pattern === pattern ? { ...p, count: p.count + 1, last: new Date().toISOString() } : p)
        : [...prev, { pattern, vuln, agent, count: 1, last: new Date().toISOString() }];
    });
  }

  // ── Build the LLM system prompt for a specific agent ─────────────────────
  // This is what gives each agent its unique personality, toolset, and context.
  function buildSystemPrompt(agentId) {
    const target    = targets[activeTarget]?.host || 'localhost';
    const tType     = targets[activeTarget]?.type  || 'web';
    const topLearn  = [...learned].sort((a, b) => b.count - a.count).slice(0, 8);
    const learnCtx  = topLearn.length
      ? '\n\nLEARNED PATTERNS (inject into strategy):\n' + topLearn.map(p => `  • ${p.pattern} [seen ${p.count}×]`).join('\n')
      : '';
    const otherF    = findingsRef.current.filter(f => f.agent !== agentId);
    const sharedCtx = otherF.length
      ? '\n\nFINDINGS FROM OTHER AGENTS:\n' + otherF.slice(0, 6).map(f => `  [${f.sev}] ${f.desc.substring(0, 80)}`).join('\n')
      : '';

    const personas = {
      planner:
        `You are the PHANTOM PLANNER — master strategist for an autonomous penetration test.\n` +
        `Target: ${target} | Type: ${tType} | Depth: ${scanDepth}\n` +
        `ROLE: Analyse the overall attack surface and delegate specific tasks to specialist agents.\n` +
        `Format each response:\n  THOUGHT: <strategic reasoning>\n  STRATEGY: <overall attack plan>\n  DELEGATE: <agent> — <specific task>\n  DONE: true/false`,
      recon:
        `You are the PHANTOM RECON agent — elite asset discovery and OSINT specialist.\n` +
        `Target: ${target}\nTools: subfinder, amass, theHarvester, whatweb, whois\n` +
        `Mission: Enumerate subdomains, IP ranges, technologies, exposed services, org structure.\n` +
        `Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <toolname> | REASON: ...\nWhen done: DONE: true | SUMMARY: <key findings>`,
      web:
        `You are the PHANTOM WEB agent — web application security specialist (OWASP Top 10 expert).\n` +
        `Target: https://${target}\nTools: nuclei, nikto, sqlmap, gobuster, ffuf, feroxbuster, whatweb\n` +
        `Wordlists: DirBuster medium (${WL.dirbuster_medium}), RockYou for auth.\n` +
        `Test: SQL injection, XSS, SSRF, XXE, IDOR, broken auth, path traversal, RCE.\n` +
        `Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <toolname> | REASON: ...\nWhen done: DONE: true | SUMMARY: <key findings>`,
      identity:
        `You are the PHANTOM IDENTITY agent — authentication and authorization specialist.\n` +
        `Target: ${target}\nTools: jwt_tool, hydra, curl\n` +
        `Mission: Test login endpoints, MFA, JWT tokens (alg:none, HMAC crack), OAuth/OIDC misconfigs, session fixation.\n` +
        `HMAC crack: hashcat -a 0 -m 16500 token.jwt ${WL.rockyou}\n` +
        `Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <toolname> | FINDING: ...\nWhen done: DONE: true`,
      network:
        `You are the PHANTOM NETWORK agent — infrastructure and network security specialist.\n` +
        `Target: ${target}\nTools: nmap, masscan, smbmap, enum4linux, crackmapexec\n` +
        `Mission: Port scan, service enumeration, SMB null sessions, password policies, lateral movement paths.\n` +
        `Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <toolname> | REASON: ...\nWhen done: DONE: true`,
      cloud:
        `You are the PHANTOM CLOUD agent — cloud security and posture management specialist.\n` +
        `Target: ${target}\nTools: scout (ScoutSuite), prowler, kube-hunter, pacu\n` +
        `Mission: S3 public buckets, IAM over-permissions, security groups, CloudTrail gaps, secrets in metadata.\n` +
        `Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <toolname> | REASON: ...\nWhen done: DONE: true`,
      exploit:
        `You are the PHANTOM EXPLOIT ANALYST — risk validation and proof-of-concept specialist.\n` +
        `Target: ${target}\nTools: searchsploit, hashcat, john\n` +
        `Mission: Validate findings, map CVEs, assess exploitability, estimate blast radius. SAFE MODE — no destructive payloads.\n` +
        `Format: THOUGHT: ... | CVE: ... | CVSS: ... | EXPLOITABLE: true/false | ACTION: <toolname>\nWhen done: DONE: true`,
    };

    return `${personas[agentId] || personas.recon}${learnCtx}${sharedCtx}\n\nMax iterations: ${maxIter}. Stop when you have sufficient findings or reach the limit.`;
  }

  // ── Per-agent reasoning loop ───────────────────────────────────────────────
  // This implements the Discover → Analyse → Hypothesize → Validate → Learn cycle.
  async function runAgent(agentId) {
    const target  = targets[activeTarget]?.host || 'localhost';
    const history = [{ role: 'user', content: `Begin ${AGENTS[agentId].name} assessment of ${target}. Depth: ${scanDepth}. Max ${maxIter} iterations.` }];

    function addStep(step) {
      setAgentSteps(p => [...p, { ...step, agentId, _id: Date.now() + Math.random(), _t: new Date().toLocaleTimeString() }]);
    }
    function setStatus(status, extra = {}) {
      setAgentStatus(p => ({ ...p, [agentId]: { ...p[agentId], status, ...extra } }));
    }

    setStatus('thinking', { iter: 0 });

    for (let i = 1; i <= maxIter && !abortRef.current; i++) {
      // Respect pause
      while (pauseRef.current && !abortRef.current) await new Promise(r => setTimeout(r, 300));
      if (abortRef.current) break;

      setStatus('thinking', { iter: i });

      // ── Stream LLM reasoning ──
      let full = '';
      setLiveText(p => ({ ...p, [agentId]: '' }));
      for await (const token of streamOllama(history, model, buildSystemPrompt(agentId))) {
        if (abortRef.current) break;
        full += token;
        // Show only the tail so the strip doesn't grow unbounded
        const tail = full.slice(-200);
        setLiveText(p => ({ ...p, [agentId]: tail }));
      }
      setLiveText(p => ({ ...p, [agentId]: '' }));

      // ── Parse structured fields from LLM output ──
      const thought    = full.match(/THOUGHT:\s*([\s\S]*?)(?=HYPOTHESIS:|ACTION:|DONE:|STRATEGY:|$)/i)?.[1]?.trim() || '';
      const hypothesis = full.match(/HYPOTHESIS:\s*([\s\S]*?)(?=ACTION:|REASON:|DONE:|$)/i)?.[1]?.trim() || '';
      const actionRaw  = full.match(/ACTION:\s*(\S+)/i)?.[1]?.trim() || '';
      const reason     = full.match(/REASON:\s*([\s\S]*?)(?=DONE:|$)/i)?.[1]?.trim() || '';
      const summary    = full.match(/SUMMARY:\s*([\s\S]*)$/i)?.[1]?.trim() || '';
      const done       = /DONE:\s*true/i.test(full);

      if (thought) addStep({ type: 'thought', thought, hypothesis, iter: i });
      if (done)    {
        addStep({ type: 'done', summary, iter: i, totalFindings: findingsRef.current.filter(f => f.agent === agentId).length });
        setStatus('complete', { iter: i });
        break;
      }

      // ── Map action name to an agent-appropriate tool ──
      const agentTools = Object.keys(TOOLS).filter(t => TOOLS[t].agent === agentId);
      const alias = {
        scout: 'scoutsuite',
        scoutsuite: 'scoutsuite',
        theharvester: 'theHarvester',
        'jwt-tool': 'jwt_tool',
        jwttool: 'jwt_tool',
        'kube-hunter': 'kubehunter',
        kube_hunter: 'kubehunter',
        hydra_ssh: 'hydra',
      };
      const sourceText = `${actionRaw} ${reason} ${full}`.toLowerCase();
      const tokens = sourceText.replace(/[^a-z0-9_-]+/g, ' ').split(/\s+/).filter(Boolean);
      let toolId = null;
      for (const tok of tokens) {
        const mapped = alias[tok] || tok;
        const hit = agentTools.find(t => t.toLowerCase() === mapped.toLowerCase());
        if (hit) { toolId = hit; break; }
      }
      if (!toolId) {
        toolId = agentTools.find(t => sourceText.includes(t.toLowerCase())) || null;
      }
      if (!toolId && agentTools.length) {
        toolId = agentTools[(i - 1) % agentTools.length];
      }
      if (!toolId) {
        addStep({
          type: 'done',
          summary: summary || 'No executable tool required for this agent.',
          iter: i,
          totalFindings: findingsRef.current.filter(f => f.agent === agentId).length,
        });
        setStatus('complete', { iter: i });
        break;
      }

      addStep({ type: 'action', toolId, reason, iter: i });
      setStatus('running', { iter: i, currentTool: toolId });
      setUsedTools(p => [...new Set([...p, toolId])]);

      // Brief pause so the UI can breathe between steps
      await new Promise(r => setTimeout(r, 200 + Math.random() * 400));

      // ── Execute tool (real via IPC, simulated in browser) ──
      const [cmd, args] = buildArgs(toolId, target);
      const result = await API.tool.run(cmd, args, 90);
      let output = (result?.output || '').trim();
      const failed = result?.code !== 0 || !output;
      if (failed && !IS_ELECTRON) {
        output = simulateOutput(toolId, target);
      }
      if (failed && IS_ELECTRON) {
        const msg = output || `${cmd} failed with code ${result?.code ?? -1}`;
        addStep({ type: 'error', toolId, message: msg, iter: i });
      }
      if (!output) output = `[${toolId}] no output`;

      addStep({ type: 'observation', toolId, output, iter: i });

      // ── Extract findings and persist them ──
      const newFindings = extractFindings(output, toolId, agentId, i, target);
      if (newFindings.length) {
        findingsRef.current = [...findingsRef.current, ...newFindings];
        setFindings([...findingsRef.current]);
        addStep({ type: 'findings', findings: newFindings, iter: i });
        // Teach the learning engine: "gobuster → CRITICAL on web target"
        newFindings.forEach(f =>
          savePattern(`${toolId} → ${f.sev} on ${targets[activeTarget]?.type || 'web'}`, f.sev, agentId)
        );
        setStatus('running', { iter: i, findings: findingsRef.current.filter(f => f.agent === agentId).length });
      }

      // ── Update conversation history ──
      history.push({ role: 'assistant', content: full });
      history.push({ role: 'user', content: `TOOL OUTPUT [${toolId}]:\n${output.substring(0, 2500)}\n\nFindings so far: ${findingsRef.current.filter(f => f.agent === agentId).length}. Continue.` });

      // Keep history bounded to avoid context overflow
      if (history.length > 28) history.splice(2, 2);
    }

    setStatus('complete');
  }

  // ── Launch the full 7-agent scan ─────────────────────────────────────────
  // Strategy: Planner runs first (serial), then specialist agents run 3 at a time
  // in parallel batches. Exploit analyst runs last to validate everything.
  async function launchAll() {
    abortRef.current  = false;
    pauseRef.current  = false;
    findingsRef.current = [];

    setRunning(true); setPaused(false); setPhase('running');
    setAgentSteps([]); setFindings([]); setUsedTools([]);
    setProgress(0); setReportReady(false);
    setAgentStatus(Object.fromEntries(AGENT_ORDER.map(a => [a, { status: 'idle', iter: 0, findings: 0 }])));

    const active  = AGENT_ORDER.filter(a => activeAgents.has(a));
    const workers = active.filter(a => a !== 'planner' && a !== 'exploit');

    let llmReady = ollamaOk;
    if (!llmReady) {
      const started = await API.ollama.start().catch(() => ({ ok: false }));
      if (started?.ok) {
        await new Promise(r => setTimeout(r, 1200));
        llmReady = await checkOllama();
      }
      if (!llmReady) {
        setAgentSteps(prev => [...prev, {
          agentId: 'planner',
          type: 'error',
          iter: 0,
          message: 'Ollama is offline. Scan will continue in fallback mode with deterministic tool execution.',
          _id: Date.now() + Math.random(),
          _t: new Date().toLocaleTimeString(),
        }]);
      }
    }

    try {
      // Phase 1: Planner sets strategy (10% progress)
      if (active.includes('planner')) {
        await runAgent('planner');
        setProgress(10);
      }

      // Phase 2: Parallel specialist agents in batches of 3 (10%→80%)
      const batchSize = 3;
      for (let i = 0; i < workers.length; i += batchSize) {
        const batch = workers.slice(i, i + batchSize);
        await Promise.all(batch.map(a => runAgent(a)));
        setProgress(10 + Math.round(((i + batchSize) / workers.length) * 70));
      }

      // Phase 3: Exploit analyst validates all gathered findings (80%→100%)
      if (active.includes('exploit')) {
        await runAgent('exploit');
        setProgress(100);
      } else {
        setProgress(100);
      }
    } catch (err) {
      console.error('Agent error:', err);
    }

    setRunning(false); setPhase('complete'); setReportReady(true);
  }

  function resetScan() {
    abortRef.current = true;
    pauseRef.current = false;
    setRunning(false); setPaused(false); setPhase('idle'); setProgress(0); setReportReady(false);
    setAgentSteps([]); setUsedTools([]);
    setAgentStatus(Object.fromEntries(AGENT_ORDER.map(a => [a, { status: 'idle', iter: 0, findings: 0 }])));
  }

  function stopAll()     { abortRef.current = true;  pauseRef.current = false; setPaused(false); setRunning(false); setPhase('idle'); }
  function togglePause() { pauseRef.current = !pauseRef.current; setPaused(p => !p); setPhase(p => p === 'paused' ? 'running' : 'paused'); }
  function addFindings(f) { findingsRef.current = [...findingsRef.current, ...f]; setFindings([...findingsRef.current]); }

  // ── Derived state ────────────────────────────────────────────────────────
  const flaggedProxyReqs = proxyReqs.filter(r => r.flagged);
  const targetHost       = targets[activeTarget]?.host || 'localhost';

  // ╔════════════════════════════════════════════════════════════════════════╗
  // ║  RENDER                                                                ║
  // ╚════════════════════════════════════════════════════════════════════════╝
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-base)', overflow: 'hidden', position: 'relative' }}>
      {/* Subtle dot-grid texture overlay */}
      <div className="dot-grid" style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      {/* Title bar */}
      <TitleBar
        view={view} setView={setView}
        findings={findings}
        proxyFlagged={flaggedProxyReqs.length}
        phase={phase} running={running} progress={progress}
        ollamaOk={ollamaOk} modelName={model}
        agents={agentStatus}
      />

      {/* Main content area */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative', zIndex: 1 }}>
        <Sidebar view={view} setView={setView} findingsCount={findings.length} proxyFlaggedCount={flaggedProxyReqs.length} />

        {/* View router */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
          {view === 'dashboard' && <DashboardView findings={findings} agentStatus={agentStatus} running={running} ollamaOk={ollamaOk} setView={setView} />}
          {view === 'targets'   && <TargetsView targets={targets} setTargets={setTargets} activeTarget={activeTarget} setActiveTarget={setActiveTarget} findings={findings} />}
          {view === 'agents'    && (
            <AgentsView
              targets={targets} activeTarget={activeTarget} setActiveTarget={setActiveTarget}
              model={model} setModel={setModel} models={models}
              maxIter={maxIter} setMaxIter={setMaxIter}
              scanDepth={scanDepth} setScanDepth={setScanDepth}
              activeAgents={activeAgents} setActiveAgents={setActiveAgents}
              agentStatus={agentStatus} findings={findings}
              agentSteps={agentSteps} liveText={liveText}
              running={running} paused={paused}
              onLaunch={launchAll} onStop={stopAll} onPause={togglePause}
              reportReady={reportReady} setView={setView}
            />
          )}
          {view === 'autopilot' && <AutopilotView defaultHost={targetHost} onNewFindings={addFindings} />}
          {view === 'proxy'    && <ProxyView proxyReqs={proxyReqs} setProxyReqs={setProxyReqs}
              onSendToRepeater={req => { setRepeaterRequest({ ...req, _ts: Date.now() }); setView('repeater'); }} />}
          {view === 'repeater' && <RepeaterView initialRequest={repeaterRequest} />}
          {view === 'network'  && <NetworkView defaultHost={targetHost} onNewFindings={addFindings} />}
          {view === 'identity' && <IdentityView defaultHost={targetHost} />}
          {view === 'cloud'    && <CloudView defaultHost={targetHost} onNewFindings={addFindings} />}
          {view === 'graph'    && <GraphView findings={findings} targetHost={targetHost} />}
          {view === 'developer' && <DeveloperView findings={findings} proxyReqs={proxyReqs} targetHost={targetHost} />}
          {view === 'intel'    && <IntelView learned={learned} onClearLearned={() => { setLearned([]); localStorage.removeItem('phantom_v3_learned'); }} />}
          {view === 'findings' && <FindingsView findings={findings} activeAgents={activeAgents} usedTools={usedTools} learned={learned} proxyReqs={proxyReqs} />}
          {view === 'report'   && <FindingsView findings={findings} activeAgents={activeAgents} usedTools={usedTools} learned={learned} proxyReqs={proxyReqs} />}
          {view === 'settings' && <SettingsView ollamaOk={ollamaOk} models={models} model={model} setModel={setModel} onCheck={checkOllama} />}
        </div>
      </div>
    </div>
  );
}
