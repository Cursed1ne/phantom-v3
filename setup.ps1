################################################################################
#  PHANTOM AI v3 -- Windows Setup & Launcher
#  Author : Doshan
#  Usage  : .\setup.ps1    (run as Administrator for best results)
#  Tested : Windows 10/11 (PowerShell 5.1+ / PowerShell 7+)
################################################################################

$Host.UI.RawUI.WindowTitle = "Phantom AI v3 -- Windows Setup"

# ── Colours ───────────────────────────────────────────────────────────────────
function Ok   ($msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green  }
function Warn ($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Info ($msg) { Write-Host "  [-->]  $msg" -ForegroundColor Cyan   }
function Fail ($msg) { Write-Host "  [ERR]  $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  ==========================================" -ForegroundColor Cyan
Write-Host "   ⬡  PHANTOM AI v3  --  Windows Launcher  " -ForegroundColor Cyan
Write-Host "  ==========================================" -ForegroundColor Cyan
Write-Host "     Patent Pending (C) Doshan              " -ForegroundColor DarkCyan
Write-Host ""

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ROOT

# ── Helper: check if a command exists ─────────────────────────────────────────
function Has ($cmd) { return ($null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)) }

# ── Helper: install via winget ────────────────────────────────────────────────
function WinGet-Install ($id, $name) {
    if (Has "winget") {
        Info "Installing $name via winget..."
        winget install --id $id --silent --accept-source-agreements --accept-package-agreements 2>$null
        if ($LASTEXITCODE -eq 0) { Ok "$name installed" }
        else                     { Warn "$name winget install failed -- install manually: https://winget.run/$id" }
    } else {
        Warn "winget not available. Install $name manually."
    }
}

# ── 1. winget (Windows Package Manager) ──────────────────────────────────────
Info "Checking winget..."
if (-not (Has "winget")) {
    Warn "winget not found. Install it from the Microsoft Store: 'App Installer'"
    Warn "Continuing with manual checks..."
} else {
    Ok "winget available"
}

# ── 2. Python ─────────────────────────────────────────────────────────────────
Info "Checking Python..."
if (-not (Has "python")) {
    Warn "Python not found -- installing via winget..."
    WinGet-Install "Python.Python.3.11" "Python 3.11"
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}
$pyVer = python --version 2>&1
Ok "Python: $pyVer"

# ── 3. Node.js ────────────────────────────────────────────────────────────────
Info "Checking Node.js..."
if (-not (Has "node")) {
    Warn "Node.js not found -- installing via winget..."
    WinGet-Install "OpenJS.NodeJS.LTS" "Node.js LTS"
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}
if (Has "node") {
    $nodeVer = node --version 2>&1
    Ok "Node.js: $nodeVer"
} else {
    Fail "Node.js installation failed. Install from https://nodejs.org and re-run."
}

# ── 4. Ollama ─────────────────────────────────────────────────────────────────
Info "Checking Ollama..."
if (-not (Has "ollama")) {
    Warn "Ollama not found -- installing via winget..."
    WinGet-Install "Ollama.Ollama" "Ollama"
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}
if (-not (Has "ollama")) {
    Warn "Ollama not found. Download from https://ollama.ai/download and re-run."
} else {
    Ok "Ollama found"
}

# ── 5. Start Ollama ───────────────────────────────────────────────────────────
Info "Starting Ollama service..."
$ollamaRunning = $false
try {
    $resp = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    $ollamaRunning = $true
    Ok "Ollama already running"
} catch {
    if (Has "ollama") {
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
        Start-Sleep -Seconds 4
        try {
            Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop | Out-Null
            $ollamaRunning = $true
            Ok "Ollama started"
        } catch {
            Warn "Ollama didn't start in time. Make sure it's running before using Phantom."
        }
    }
}

# ── 6. Pull LLM model ─────────────────────────────────────────────────────────
if ($ollamaRunning) {
    Info "Checking installed models..."
    $tagsJson = (Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing).Content | ConvertFrom-Json
    $models = $tagsJson.models | ForEach-Object { $_.name }
    $preferred = @("qwen2.5-coder:7b","llama3.1","mistral","llama3")
    $activeModel = ""
    foreach ($m in $preferred) {
        foreach ($inst in $models) {
            if ($inst -like "$($m.Split(':')[0])*") { $activeModel = $inst; break }
        }
        if ($activeModel) { break }
    }
    if (-not $activeModel) {
        Warn "No model found. Pulling qwen2.5-coder:7b (~4.7 GB)..."
        ollama pull qwen2.5-coder:7b
        $activeModel = "qwen2.5-coder:7b"
    }
    Ok "Active model: $activeModel"
}

# ── 7. Python dependencies ────────────────────────────────────────────────────
Info "Installing Python dependencies..."
if (Test-Path "$ROOT\backend\requirements.txt") {
    python -m pip install -r "$ROOT\backend\requirements.txt" --quiet 2>&1 | Out-Null
    Ok "Python packages installed"
} else {
    python -m pip install fastapi uvicorn httpx websockets playwright --quiet 2>&1 | Out-Null
    Ok "Core Python packages installed"
}

# ── 8. Playwright browser ─────────────────────────────────────────────────────
Info "Installing Playwright Chromium..."
python -m playwright install chromium 2>&1 | Out-Null
Ok "Playwright Chromium ready"

# ── 9. Security tools (Windows) ───────────────────────────────────────────────
Info "Checking security tools..."

# nmap
if (-not (Has "nmap")) {
    Warn "nmap not found -- installing..."
    WinGet-Install "Insecure.Nmap" "nmap"
} else { Ok "nmap: $(nmap --version 2>&1 | Select-Object -First 1)" }

# sqlmap (Python-based, works on Windows)
if (-not (Has "sqlmap")) {
    Warn "sqlmap not found -- installing via pip..."
    python -m pip install sqlmap --quiet 2>&1 | Out-Null
    Ok "sqlmap installed via pip"
} else { Ok "sqlmap found" }

# nuclei (Go binary)
if (-not (Has "nuclei")) {
    Warn "nuclei not found. Install from https://github.com/projectdiscovery/nuclei/releases"
    Warn "Download nuclei_windows_amd64.zip, extract to C:\Windows\System32 or add to PATH"
} else { Ok "nuclei: $(nuclei -version 2>&1 | Select-Object -First 1)" }

# ffuf
if (-not (Has "ffuf")) {
    Warn "ffuf not found. Install from https://github.com/ffuf/ffuf/releases"
    Warn "Download ffuf_windows_amd64.zip and add to PATH"
} else { Ok "ffuf found" }

# nikto (Perl-based -- harder on Windows, skip gracefully)
if (-not (Has "nikto")) {
    Warn "nikto not available on Windows -- HTTP scanning will use built-in fallback"
} else { Ok "nikto found" }

# ── 10. Node.js dependencies ──────────────────────────────────────────────────
Info "Installing Node.js dependencies..."
if (-not (Test-Path "$ROOT\node_modules")) {
    Set-Location $ROOT
    npm install --legacy-peer-deps --silent
    Ok "Node packages installed"
} else {
    Ok "Node packages already installed"
}

# ── 11. Start Backend ─────────────────────────────────────────────────────────
Info "Starting Phantom backend on :8000..."
$backendRunning = $false
try {
    Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop | Out-Null
    $backendRunning = $true
    Ok "Backend already running on :8000"
} catch {
    $backendJob = Start-Process -FilePath "python" `
        -ArgumentList "-m uvicorn main:app --host 0.0.0.0 --port 8000" `
        -WorkingDirectory "$ROOT\backend" `
        -RedirectStandardOutput "$env:TEMP\phantom_backend.log" `
        -RedirectStandardError  "$env:TEMP\phantom_backend_err.log" `
        -WindowStyle Hidden `
        -PassThru

    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 1
        try {
            Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop | Out-Null
            $backendRunning = $true
            Ok "Backend started (PID $($backendJob.Id))"
            break
        } catch {}
    }
    if (-not $backendRunning) {
        Warn "Backend didn't start in time. Check $env:TEMP\phantom_backend_err.log"
    }
}

# ── 12. Launch Phantom UI ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ==========================================" -ForegroundColor Green
Write-Host "   All systems go!  Launching Phantom AI   " -ForegroundColor Green
Write-Host "  ==========================================" -ForegroundColor Green
Write-Host "   API:   http://localhost:8000             " -ForegroundColor Cyan
Write-Host "   Press Ctrl+C in this window to stop      " -ForegroundColor Yellow
Write-Host ""

Set-Location $ROOT
npm start
