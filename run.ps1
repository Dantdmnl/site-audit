$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message, [ValidateSet("INFO", "WARN", "ERROR")]$Level = "INFO")
    $colors = @{"INFO" = "Cyan"; "WARN" = "Yellow"; "ERROR" = "Red"}
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [$Level]" -ForegroundColor $colors[$Level] -NoNewline
    Write-Host " $Message"
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = "$root\.venv"
$venvPython = "$venv\Scripts\python.exe"
$reqFile = "$root\requirements.txt"
$dependencyStamp = "$venv\.site-audit-dependencies.json"
$pythonCommand = if (Test-Path $venvPython) { $venvPython } else { "python" }

# 1. Check Python availability
Write-Status "Verifying Python 3.10+..." INFO
try {
    $pyVersion = & $pythonCommand --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found in PATH"
    }
    Write-Status "Found: $pyVersion" INFO
    
    # validate Python 3.10+
    if ($pyVersion -match '(\d+\.\d+)') {
        $major, $minor = $matches[1].Split('.')
        if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 10)) {
            throw "Python 3.10+ required (found $($matches[1]))"
        }
    }
} catch {
    Write-Status "ERROR: $_" ERROR
    Write-Status "Install Python 3.10+ from https://python.org" WARN
    exit 1
}

# 2. Create/validate venv
if (-not (Test-Path $venvPython)) {
    Write-Status "Creating virtual environment in .venv..." INFO
    & $pythonCommand -m venv $venv
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Failed to create venv" ERROR
        exit 1
    }
}

# 3. Install dependencies
if (Test-Path $reqFile) {
    Write-Status "Checking dependencies..." INFO
    
    # Test if core modules load so we only run pip if necessary (much faster startup)
    $depsOk = $true
    $requirementsHash = (Get-FileHash -LiteralPath $reqFile -Algorithm SHA256).Hash
    try {
        $stamp = Get-Content -LiteralPath $dependencyStamp -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($stamp.requirementsHash -ne $requirementsHash) { $depsOk = $false }
    } catch {
        $depsOk = $false
    }
    try {
        $null = & $venvPython -c "import requests, bs4, prompt_toolkit, pypac, tldextract, defusedxml; from urllib3.response import HTTPResponse; assert hasattr(HTTPResponse, 'read1')" 2>&1
        if ($LASTEXITCODE -ne 0) { $depsOk = $false }
    } catch {
        $depsOk = $false
    }
    
    if (-not $depsOk) {
        Write-Status "Installing or updating required dependencies..." INFO
        & $venvPython -m pip install --quiet -r $reqFile
        if ($LASTEXITCODE -ne 0) {
            Write-Status "Dependency installation failed! Check pip output." ERROR
            exit 1
        }
        @{ requirementsHash = $requirementsHash } | ConvertTo-Json | Set-Content -LiteralPath $dependencyStamp -Encoding UTF8
    }
    Write-Status "Environment ready" INFO
}

# 4. Run site_audit.py with all remaining arguments
& $venvPython "$root\site_audit.py" @args
exit $LASTEXITCODE
