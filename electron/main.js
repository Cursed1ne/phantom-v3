/**
 * PHANTOM AI v3 — Electron Main
 * HTTPS Proxy · IPC bridge · Backend launcher · WebSocket live feed
 * Fixed: proxy error handling, port fallback, cert install timeout,
 *        per-host cert persistence, intercept queue, request replay.
 */
const { app, BrowserWindow, ipcMain, Menu, shell, dialog } = require('electron');
const path   = require('path');
const fs     = require('fs');
const http   = require('http');
const https  = require('https');
const net    = require('net');
const urlMod = require('url');
const { spawn, exec } = require('child_process');
const { WebSocketServer } = require('ws');
const forge  = require('node-forge');
const log    = require('electron-log');
const Store  = require('electron-store');

const isDev      = !!process.env.ELECTRON_START_URL || !app.isPackaged;
const userData   = app.getPath('userData');
const certsDir   = path.join(userData, 'certs');
const hostCertsDir = path.join(certsDir, 'hosts'); // persisted per-host certs
const dbPath     = path.join(userData, 'phantom.db');
const caCertPath = path.join(certsDir, 'ca.crt');
[certsDir, hostCertsDir].forEach(d => fs.mkdirSync(d, { recursive: true }));

const store = new Store({ defaults: { proxyPort:8888, backendPort:8000, wsPort:8001 } });
let PROXY_PORT     = store.get('proxyPort');
const BACKEND_PORT = store.get('backendPort');
const WS_PORT      = store.get('wsPort');

if (log.transports?.file) {
  log.transports.file.resolvePathFn = () => path.join(userData, 'phantom.log');
}

let win = null, proxy = null, backendProc = null, wss = null;
const proxyHist = [];

// ── Intercept queue ──────────────────────────────────────────────────
// When interceptMode is true, requests are held here until forwarded or dropped.
let interceptMode = false;
const interceptQueue = new Map(); // id → { req, res, rd, resolve }

// ── CA cert (generate once, persist forever) ─────────────────────────
function ensureCA() {
  const kp = path.join(certsDir,'ca.key'), cp = path.join(certsDir,'ca.crt');
  if (fs.existsSync(kp) && fs.existsSync(cp)) {
    try {
      return { key: fs.readFileSync(kp,'utf8'), cert: fs.readFileSync(cp,'utf8') };
    } catch(e) {
      log.warn('CA read failed, regenerating:', e.message);
    }
  }
  log.info('Generating new CA certificate...');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  const attrs = [
    { name:'commonName',     value:'Phantom AI CA v3' },
    { name:'organizationName', value:'PHANTOM Security' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name:'basicConstraints', cA:true },
    { name:'keyUsage', keyCertSign:true, cRLSign:true },
    { name:'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const kPem = forge.pki.privateKeyToPem(keys.privateKey);
  const cPem = forge.pki.certificateToPem(cert);
  fs.writeFileSync(kp, kPem, { mode: 0o600 });
  fs.writeFileSync(cp, cPem, { mode: 0o644 });
  log.info('CA certificate created:', cp);
  return { key: kPem, cert: cPem };
}

function ensureCAFilePath() {
  ensureCA();
  return caCertPath;
}

function revealPath(p) {
  if (typeof shell.showItemInFolder === 'function') return shell.showItemInFolder(p);
  if (typeof shell.showItemInFinder === 'function') return shell.showItemInFinder(p);
  if (typeof shell.openPath === 'function') { shell.openPath(path.dirname(p)); return true; }
  return false;
}

// ── Per-host cert (persisted to disk so they survive restarts) ────────
const certMemCache = new Map();

function genHostCert(host, ca) {
  // 1. memory cache
  if (certMemCache.has(host)) return certMemCache.get(host);

  // 2. disk cache
  const hkp = path.join(hostCertsDir, `${host}.key`);
  const hcp = path.join(hostCertsDir, `${host}.crt`);
  if (fs.existsSync(hkp) && fs.existsSync(hcp)) {
    try {
      const r = { key: fs.readFileSync(hkp,'utf8'), cert: fs.readFileSync(hcp,'utf8') };
      certMemCache.set(host, r);
      return r;
    } catch(e) { /* fall through to regenerate */ }
  }

  // 3. generate & persist
  const keys    = forge.pki.rsa.generateKeyPair(2048);
  const cert    = forge.pki.createCertificate();
  const caCert  = forge.pki.certificateFromPem(ca.cert);
  const caKey   = forge.pki.privateKeyFromPem(ca.key);
  cert.publicKey    = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject([{ name:'commonName', value: host }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([{
    name:'subjectAltName',
    altNames:[{ type:2, value: host }]
  }]);
  cert.sign(caKey, forge.md.sha256.create());

  const r = {
    key:  forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
  try {
    fs.writeFileSync(hkp, r.key,  { mode: 0o600 });
    fs.writeFileSync(hcp, r.cert, { mode: 0o644 });
  } catch(e) { /* non-fatal */ }
  certMemCache.set(host, r);
  return r;
}

// ── Vulnerability pattern matcher ─────────────────────────────────────
const VULN_RE = [
  { re: /(\bOR\b.*=|UNION[\s+]SELECT|sleep\s*\()/i,          type:'SQLi',    sev:'CRITICAL' },
  { re: /<script[\s>]|javascript:|onerror\s*=/i,              type:'XSS',     sev:'HIGH'     },
  { re: /\.\.\//,                                              type:'Path',    sev:'HIGH'     },
  { re: /file:\/\/|php:\/\//i,                                type:'LFI',     sev:'CRITICAL' },
  { re: /\$\{[^}]+\}|\{\{[^}]+\}\}/,                         type:'SSTI',    sev:'CRITICAL' },
  { re: /AKIA[0-9A-Z]{16}|AWS_ACCESS_KEY/,                   type:'AWS',     sev:'CRITICAL' },
  { re: /Bearer [A-Za-z0-9\-_.]{20,}/,                       type:'JWT',     sev:'HIGH'     },
  { re: /api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}/i,   type:'APIKey',  sev:'HIGH'     },
];

function analyzeReq(r) {
  const t = r.url + (r.body || '') + JSON.stringify(r.headers || {});
  r.vulns   = VULN_RE.filter(p => p.re.test(t)).map(p => ({ type:p.type, sev:p.sev }));
  r.flagged = r.vulns.length > 0;
  r.maxSev  = r.vulns.reduce((best, v) => {
    const order = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFO:0 };
    return (order[v.sev] || 0) > (order[best] || 0) ? v.sev : best;
  }, '');
}

function bcast(d) {
  if (!wss) return;
  const m = JSON.stringify(d);
  wss.clients.forEach(c => { if (c.readyState === 1) c.send(m); });
}

// ── Core request handler (shared between HTTP and HTTPS interception) ─
function handleCapturedRequest(rd, rawBody, forward) {
  rd.body = rawBody.slice(0, 4000);
  analyzeReq(rd);
  proxyHist.unshift(rd);
  if (proxyHist.length > 2000) proxyHist.pop();
  bcast({ type:'proxy_request', request:{ ...rd, body: rd.body.slice(0,400) } });

  if (interceptMode) {
    // Hold the request — UI will call proxy:intercept:forward or proxy:intercept:drop
    return new Promise(resolve => {
      interceptQueue.set(rd.id, { rd, rawBody, resolve, forward });
      bcast({ type:'proxy_intercept', request:{ ...rd, body: rd.body } });
    });
  }
  return forward(rawBody);
}

// ── Proxy builder ─────────────────────────────────────────────────────
function buildProxy(ca) {
  const srv = http.createServer((req, res) => {
    const rd = {
      id: Date.now() + '-' + Math.random().toString(36).slice(2),
      method: req.method, url: req.url, headers: req.headers,
      timestamp: new Date().toISOString(),
      body:'', response:null, flagged:false, vulns:[], tls:false, maxSev:'',
    };
    let b = '';
    req.on('data', c => b += c);
    req.on('error', () => res.end());
    req.on('end', async () => {
      const forward = (body) => new Promise(resolve => {
        const o = urlMod.parse(req.url);
        o.method  = req.method;
        o.headers = { ...req.headers };
        const pr = http.request(o, pRes => {
          let rb = '';
          pRes.on('data', c => rb += c);
          pRes.on('error', () => resolve());
          pRes.on('end', () => {
            rd.response = { status:pRes.statusCode, headers:pRes.headers, body:rb.slice(0,4000) };
            bcast({ type:'proxy_response', request:{ ...rd, response:{ ...rd.response, body:rd.response.body.slice(0,400) } } });
            res.writeHead(pRes.statusCode, pRes.headers);
            res.end(rb);
            resolve();
          });
        });
        pr.on('error', () => { try { res.end(); } catch{} resolve(); });
        if (body) pr.write(body);
        pr.end();
      });
      await handleCapturedRequest(rd, b, forward);
    });
  });

  srv.on('connect', (req, sock, head) => {
    const [host, ps] = (req.url || ':443').split(':');
    const port = parseInt(ps) || 443;
    let hc;
    try { hc = genHostCert(host, ca); }
    catch(e) { log.warn('genHostCert failed for', host, e.message); sock.destroy(); return; }

    sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const tls = new https.Server({ key: hc.key, cert: hc.cert }, (hReq, hRes) => {
      const rd = {
        id: Date.now() + '-' + Math.random().toString(36).slice(2),
        method: hReq.method, url: `https://${host}${hReq.url}`, headers: hReq.headers,
        timestamp: new Date().toISOString(),
        body:'', response:null, flagged:false, vulns:[], tls:true, maxSev:'',
      };
      let b = '';
      hReq.on('data', c => b += c);
      hReq.on('error', () => hRes.end());
      hReq.on('end', async () => {
        const forward = (body) => new Promise(resolve => {
          const o = { hostname:host, port, path:hReq.url, method:hReq.method,
                      headers:{ ...hReq.headers }, rejectUnauthorized:false };
          const pr = https.request(o, pRes => {
            let rb = '';
            pRes.on('data', c => rb += c);
            pRes.on('error', () => resolve());
            pRes.on('end', () => {
              rd.response = { status:pRes.statusCode, headers:pRes.headers, body:rb.slice(0,4000) };
              bcast({ type:'proxy_response', request:{ ...rd, response:{ ...rd.response, body:rd.response.body.slice(0,400) } } });
              hRes.writeHead(pRes.statusCode, pRes.headers);
              hRes.end(rb);
              resolve();
            });
          });
          pr.on('error', () => { try { hRes.end(); } catch{} resolve(); });
          if (body) pr.write(body);
          pr.end();
        });
        await handleCapturedRequest(rd, b, forward);
      });
    });

    tls.on('error', () => { try { sock.destroy(); } catch{} });

    tls.listen(0, '127.0.0.1', () => {
      const ls = net.connect(tls.address().port, '127.0.0.1', () => {
        ls.write(head);
        sock.pipe(ls);
        ls.pipe(sock);
      });
      ls.on('error', () => { try { sock.destroy(); } catch{} });
    });
  });

  srv.on('error', err => log.error('Proxy server error:', err.message));
  return srv;
}

// ── Proxy startup with port fallback ─────────────────────────────────
function startProxy(ca, port, attempt = 0) {
  if (attempt > 5) { log.error('Could not bind proxy on any port'); return; }
  const srv = buildProxy(ca);
  srv.listen(port, '0.0.0.0', () => {
    PROXY_PORT = port;
    store.set('proxyPort', port);
    log.info(`Proxy :${port}`);
    bcast({ type:'proxy_started', port });
  });
  srv.on('error', err => {
    if (err.code === 'EADDRINUSE') {
      log.warn(`Port ${port} in use, trying ${port + 1}`);
      srv.close();
      startProxy(ca, port + 1, attempt + 1);
    } else {
      log.error('Proxy bind error:', err.message);
    }
  });
  proxy = srv;
}

function startBackend() {
  const script = isDev
    ? path.join(__dirname, '..', 'backend', 'main.py')
    : path.join(process.resourcesPath, 'backend', 'main.py');
  if (!fs.existsSync(script)) { log.warn('No backend:', script); return; }
  const py = process.platform === 'win32' ? 'python' : 'python3';
  backendProc = spawn(py, [script], {
    env: { ...process.env, PHANTOM_DB: dbPath, PHANTOM_PORT: String(BACKEND_PORT) },
    cwd: path.dirname(script),
  });
  backendProc.stdout.on('data', d => log.info('[py]', d.toString().trim()));
  backendProc.stderr.on('data', d => log.warn('[py]', d.toString().trim()));
  backendProc.on('error', err => log.error('[py] spawn error:', err.message));
}

// ── exec with timeout helper ──────────────────────────────────────────
function execWithTimeout(cmd, timeoutMs = 10000) {
  return new Promise(resolve => {
    let settled = false;
    const done = (ok, out, err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ ok, output: (out || '').trim(), error: (err || '').trim() });
    };
    const child = exec(cmd, (err, stdout, stderr) => {
      done(!err, stdout, stderr || (err && err.message));
    });
    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
      done(false, '', 'Command timed out');
    }, timeoutMs);
  });
}

function registerIPC() {
  // ── Proxy ──────────────────────────────────────────────────────────
  ipcMain.handle('proxy:status',  ()    => ({ port: PROXY_PORT, count: proxyHist.length, intercept: interceptMode }));
  ipcMain.handle('proxy:history', (_, n) => proxyHist.slice(0, n || 500));
  ipcMain.handle('proxy:clear',   ()    => { proxyHist.length = 0; return { ok:true }; });

  // Toggle intercept mode on/off
  ipcMain.handle('proxy:intercept:toggle', (_, enable) => {
    interceptMode = (enable === undefined) ? !interceptMode : !!enable;
    if (!interceptMode) {
      // drop all queued requests
      interceptQueue.forEach(({ resolve }) => resolve());
      interceptQueue.clear();
    }
    bcast({ type:'proxy_intercept_mode', enabled: interceptMode });
    return { intercept: interceptMode };
  });

  // Forward an intercepted request (optionally with modified body/headers)
  ipcMain.handle('proxy:intercept:forward', (_, { id, body, headers }) => {
    const item = interceptQueue.get(id);
    if (!item) return { ok:false, error:'Not in queue' };
    interceptQueue.delete(id);
    // Apply edits
    if (headers) item.rd.headers = headers;
    const forwardBody = body !== undefined ? body : item.rawBody;
    item.forward(forwardBody);
    return { ok: true };
  });

  // Drop an intercepted request
  ipcMain.handle('proxy:intercept:drop', (_, id) => {
    const item = interceptQueue.get(id);
    if (!item) return { ok:false };
    interceptQueue.delete(id);
    item.resolve(); // just resolve without forwarding
    return { ok: true };
  });

  // Get all currently queued (held) requests
  ipcMain.handle('proxy:intercept:queue', () =>
    [...interceptQueue.values()].map(({ rd }) => ({ ...rd }))
  );

  // Replay a request (send directly from Electron, return response)
  ipcMain.handle('proxy:replay', (_, { method, url, headers, body }) => new Promise(resolve => {
    try {
      const parsed = urlMod.parse(url);
      const isHttps = parsed.protocol === 'https:';
      const opts = {
        hostname: parsed.hostname,
        port:     parsed.port || (isHttps ? 443 : 80),
        path:     parsed.path || '/',
        method:   (method || 'GET').toUpperCase(),
        headers:  headers || {},
        rejectUnauthorized: false,
      };
      const req = (isHttps ? https : http).request(opts, res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve({
          ok: true,
          status:  res.statusCode,
          headers: res.headers,
          body:    data.slice(0, 8000),
        }));
        res.on('error', err => resolve({ ok:false, error: err.message }));
      });
      req.on('error', err => resolve({ ok:false, error: err.message }));
      const timer = setTimeout(() => { try { req.destroy(); } catch{} resolve({ ok:false, error:'Timeout' }); }, 30000);
      req.on('response', () => clearTimeout(timer));
      if (body) req.write(body);
      req.end();
    } catch(e) {
      resolve({ ok:false, error: e.message });
    }
  }));

  // ── Certs ──────────────────────────────────────────────────────────
  ipcMain.handle('cert:path',   () => ({ path: ensureCAFilePath(), exists: fs.existsSync(caCertPath) }));
  ipcMain.handle('cert:read',   () => {
    const p = ensureCAFilePath();
    if (!fs.existsSync(p)) return { ok:false, path:p, error:'Certificate file not found' };
    return { ok:true, path:p, pem: fs.readFileSync(p, 'utf8') };
  });
  ipcMain.handle('cert:reveal', () => {
    const p = ensureCAFilePath();
    return { ok: fs.existsSync(p) ? revealPath(p) : false, path:p, exists: fs.existsSync(p) };
  });
  ipcMain.handle('cert:install', () => new Promise(async resolve => {
    const certPath = ensureCAFilePath();
    if (!fs.existsSync(certPath)) {
      resolve({ ok:false, error:'CA certificate file not found. Restart Phantom to regenerate.' });
      return;
    }

    // macOS: pre-check → osascript elevation → login keychain fallback → clipboard + instructions
    if (process.platform === 'darwin') {
      // 1. Pre-check: already trusted? (exit 0 = already good, skip re-install)
      const check = await execWithTimeout(`security verify-cert -c "${certPath}"`, 5000);
      if (check.ok) {
        resolve({ ok:true, path:certPath, scope:'already trusted' });
        return;
      }

      // 2. osascript elevation — shows native macOS "enter password" dialog
      const esc = certPath.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      const osa = `osascript -e 'do shell script "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \\"${esc}\\"" with administrator privileges'`;
      const r = await execWithTimeout(osa, 60000); // 60s — user needs time to type password
      if (r.ok) {
        resolve({ ok:true, path:certPath, scope:'system keychain (elevated)' });
        return;
      }
      log.warn('cert:install osascript failed:', r.error);

      // 3. Login keychain fallback (no admin needed, works for current user)
      const loginKC = path.join(app.getPath('home'), 'Library', 'Keychains', 'login.keychain-db');
      const r2 = await execWithTimeout(`security add-trusted-cert -d -r trustRoot -k "${loginKC}" "${certPath}"`, 10000);
      if (r2.ok) {
        resolve({ ok:true, path:certPath, scope:'login keychain' });
        return;
      }
      log.warn('cert:install login keychain failed:', r2.error);

      // 4. Copy cert path to clipboard + surface manual command
      try { require('child_process').execSync(`echo "${certPath}" | pbcopy`); } catch {}
      const manualCmd = `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${certPath}"`;
      resolve({
        ok: false, path: certPath,
        error: `Automatic install failed. Cert path copied to clipboard.\n\nRun manually in Terminal:\n${manualCmd}`,
        manualCmd,
      });
      return;
    }

    // Linux
    if (process.platform === 'linux') {
      const r = await execWithTimeout(`certutil -d sql:${path.join(app.getPath('home'),'.pki/nssdb')} -A -t "C,," -n "Phantom AI CA" -i "${certPath}"`, 10000);
      resolve(r.ok ? { ok:true, path:certPath } : { ok:false, path:certPath, error: r.error });
      return;
    }

    // Windows
    if (process.platform === 'win32') {
      const r = await execWithTimeout(`certutil -addstore -f "ROOT" "${certPath}"`, 15000);
      resolve(r.ok ? { ok:true, path:certPath } : { ok:false, path:certPath, error: r.error });
      return;
    }

    resolve({ ok:false, error:'Unsupported platform: '+process.platform });
  }));

  // ── Ollama ──────────────────────────────────────────────────────────
  ipcMain.handle('ollama:start', () => new Promise(resolve => {
    try {
      const p = spawn('ollama', ['serve'], { detached:true, stdio:'ignore', shell: process.platform==='win32' });
      p.on('error', err => resolve({ ok:false, error:err.message }));
      p.unref();
      setTimeout(() => resolve({ ok:true }), 300);
    } catch(err) {
      resolve({ ok:false, error: err?.message || String(err) });
    }
  }));

  // ── Tool runner ─────────────────────────────────────────────────────
  ipcMain.handle('tool:run', async (_, { tool, args, timeout }) => new Promise(r => {
    let o = '', e = '', settled = false;
    let timer = null;
    const done = payload => { if (settled) return; settled = true; if (timer) clearTimeout(timer); r(payload); };
    const p = spawn(tool, args || [], { env: process.env, shell: process.platform==='win32' });
    p.stdout.on('data', d => o += d);
    p.stderr.on('data', d => e += d);
    p.on('close', c => {
      const combined = `${o}${e}`.trim();
      done({ output: (combined || `[${tool}] completed with no output.`).slice(0,10000), code:c });
    });
    p.on('error', () => done({ output:`${tool}: not found`, code:-1 }));
    timer = setTimeout(() => { try { p.kill(); } catch{} done({ output:(o||e||'[timeout]').slice(0,10000), code:-1 }); }, (timeout||120)*1000);
  }));

  // ── Misc ────────────────────────────────────────────────────────────
  ipcMain.handle('dialog:save', async (_, { content, name, filters }) => {
    const res = await dialog.showSaveDialog(win, {
      defaultPath: path.join(app.getPath('downloads'), name || 'report.html'),
      filters: filters || [{ name:'All', extensions:['*'] }],
    });
    if (!res.canceled) { fs.writeFileSync(res.filePath, content); return { path: res.filePath }; }
    return { canceled: true };
  });

  ipcMain.handle('app:paths',  ()      => ({ userData, downloads: app.getPath('downloads'), certsDir, dbPath }));
  ipcMain.handle('app:config', (_, k,v) => { if (v !== undefined) store.set(k,v); return store.get(k); });
  ipcMain.handle('shell:open',   (_, u) => shell.openExternal(u));
  ipcMain.handle('shell:reveal', (_, p) => revealPath(p));
}

function createWindow() {
  win = new BrowserWindow({
    width:1600, height:960, minWidth:1200, minHeight:700,
    titleBarStyle: process.platform==='darwin' ? 'hiddenInset' : 'default',
    trafficLightPosition: { x:14, y:16 },
    backgroundColor:'#0a0a0f', show:false,
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      nodeIntegration:  false,
      contextIsolation: true,
      webSecurity:      false,
    },
  });
  const startUrl = process.env.ELECTRON_START_URL
    || urlMod.format({ pathname: path.join(__dirname,'..','build','index.html'), protocol:'file:', slashes:true });
  win.loadURL(startUrl);
  win.once('ready-to-show', () => {
    win.show();
    if (isDev) win.webContents.openDevTools({ mode:'detach' });
  });
  win.on('close', e => { if (process.platform==='darwin') { e.preventDefault(); win.hide(); } });
}

app.whenReady().then(() => {
  const ca = ensureCA();

  // Start proxy with fallback ports
  startProxy(ca, PROXY_PORT);

  // WebSocket server for live agent output
  wss = new WebSocketServer({ port: WS_PORT });
  wss.on('connection', ws => {
    ws.on('error', () => {});
    // Send current proxy port so UI can display it
    ws.send(JSON.stringify({ type:'proxy_port', port: PROXY_PORT }));
  });
  wss.on('error', err => log.error('WSS error:', err.message));

  startBackend();
  registerIPC();
  createWindow();

  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label:'Phantom AI', submenu:[{ role:'about' },{ type:'separator' },{ role:'quit' }] },
    { label:'Scan', submenu:[
      { label:'New Scan',  accelerator:'CmdOrCtrl+N', click:()=>win?.webContents.send('cmd','new-scan') },
      { label:'Stop All',  accelerator:'CmdOrCtrl+.', click:()=>win?.webContents.send('cmd','stop-all') },
    ]},
    { label:'Proxy', submenu:[
      { label:'Install CA',   click:()=>win?.webContents.send('cmd','install-cert') },
      { label:'Clear History',click:()=>win?.webContents.send('cmd','clear-proxy') },
      { label:'Toggle Intercept', click:()=>win?.webContents.send('cmd','toggle-intercept') },
    ]},
    { role:'viewMenu' }, { role:'windowMenu' },
  ]));
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate',          () => { if (!win) createWindow(); else win.show(); });
app.on('before-quit',       () => {
  try { backendProc?.kill(); } catch{}
  try { proxy?.close(); }      catch{}
  try { wss?.close(); }         catch{}
});
