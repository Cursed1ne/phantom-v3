const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('phantom', {
  version:'3.0.0', isElectron:true, WS_PORT:8001, BACKEND_PORT:8000,
  proxy: {
    status:  ()    => ipcRenderer.invoke('proxy:status'),
    history: (n)   => ipcRenderer.invoke('proxy:history', n),
    clear:   ()    => ipcRenderer.invoke('proxy:clear'),
    replay:  (req) => ipcRenderer.invoke('proxy:replay', req),
    intercept: {
      toggle:  (en)       => ipcRenderer.invoke('proxy:intercept:toggle', en),
      forward: (id, opts) => ipcRenderer.invoke('proxy:intercept:forward', { id, ...opts }),
      drop:    (id)       => ipcRenderer.invoke('proxy:intercept:drop', id),
      queue:   ()         => ipcRenderer.invoke('proxy:intercept:queue'),
    },
  },
  cert: {
    path:    () => ipcRenderer.invoke('cert:path'),
    read:    () => ipcRenderer.invoke('cert:read'),
    reveal:  () => ipcRenderer.invoke('cert:reveal'),
    install: () => ipcRenderer.invoke('cert:install'),
  },
  ollama: { start: () => ipcRenderer.invoke('ollama:start') },
  tool:   { run: (t,a,to) => ipcRenderer.invoke('tool:run', { tool:t, args:a, timeout:to }) },
  dialog: { save: (c,n,f) => ipcRenderer.invoke('dialog:save', { content:c, name:n, filters:f }) },
  shell:  { open: (u) => ipcRenderer.invoke('shell:open', u), reveal: (p) => ipcRenderer.invoke('shell:reveal', p) },
  paths:  ()    => ipcRenderer.invoke('app:paths'),
  config: (k,v) => ipcRenderer.invoke('app:config', k, v),
  on:     (ch, fn) => ipcRenderer.on(ch, (_, d) => fn(d)),
  off:    (ch)     => ipcRenderer.removeAllListeners(ch),
});
