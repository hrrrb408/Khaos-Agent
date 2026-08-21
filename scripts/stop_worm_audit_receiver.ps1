[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $PidPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $PidPath -PathType Leaf)) {
    return
}

try {
    $rawPid = (Get-Content -LiteralPath $PidPath -Raw).Trim()
    $receiverPid = 0
    if (-not [int]::TryParse($rawPid, [ref]$receiverPid) -or $receiverPid -le 0) {
        throw "WORM receiver pid file is malformed: $PidPath"
    }

    $process = Get-Process -Id $receiverPid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return
    }

    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $receiverPid"
    if ($null -eq $processInfo -or $processInfo.CommandLine -notmatch 'run_worm_audit_receiver\.py') {
        throw "refusing to stop an unrelated process recorded in $PidPath (pid=$receiverPid)"
    }

    Stop-Process -Id $receiverPid -Force
    if (-not $process.WaitForExit(10000)) {
        throw "WORM receiver did not exit after termination (pid=$receiverPid)"
    }
}
finally {
    Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
}
