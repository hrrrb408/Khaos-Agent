[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Workspace,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $CaPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Directory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $LogPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ErrorLogPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $PidPath,

    [ValidateRange(1, 65535)]
    [int] $Port = 8443
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workspaceRoot = (Resolve-Path -LiteralPath $Workspace -ErrorAction Stop).Path
$pythonPath = Join-Path $workspaceRoot '.venv\Scripts\python.exe'
$receiverScript = Join-Path $workspaceRoot 'scripts\run_worm_audit_receiver.py'

foreach ($requiredPath in @($pythonPath, $receiverScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "WORM receiver dependency is missing: $requiredPath"
    }
}

if (Test-Path -LiteralPath $PidPath -PathType Leaf) {
    throw "WORM receiver pid file already exists: $PidPath"
}

foreach ($parent in @(
    (Split-Path -Parent $CaPath),
    (Split-Path -Parent $Directory),
    (Split-Path -Parent $LogPath),
    (Split-Path -Parent $ErrorLogPath),
    (Split-Path -Parent $PidPath)
)) {
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

$env:PYTHONPATH = Join-Path $workspaceRoot 'python'
$argumentLine = '"{0}" --port {1} --directory "{2}" --emit-ca "{3}"' -f `
    $receiverScript, $Port, $Directory, $CaPath

$process = Start-Process `
    -FilePath $pythonPath `
    -ArgumentList $argumentLine `
    -WorkingDirectory $workspaceRoot `
    -RedirectStandardOutput $LogPath `
    -RedirectStandardError $ErrorLogPath `
    -PassThru

[System.IO.File]::WriteAllText(
    $PidPath,
    "$($process.Id)`n",
    [System.Text.UTF8Encoding]::new($false)
)

Start-Sleep -Milliseconds 250
$process.Refresh()
if ($process.HasExited) {
    $stdout = if (Test-Path -LiteralPath $LogPath) {
        Get-Content -LiteralPath $LogPath -Raw
    } else {
        ''
    }
    $stderr = if (Test-Path -LiteralPath $ErrorLogPath) {
        Get-Content -LiteralPath $ErrorLogPath -Raw
    } else {
        ''
    }
    throw "WORM receiver exited during startup (pid=$($process.Id)); stdout=$stdout; stderr=$stderr"
}

"WORM receiver started as an owned process (pid=$($process.Id))"
