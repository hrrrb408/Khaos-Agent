# Run from an elevated PowerShell prompt.  This installer intentionally uses
# the SCM's Service SID and never installs the authority as LocalSystem with a
# caller-controlled account or as a same-user Python process.
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$InstallRoot = 'C:\Program Files\Khaos',
    [string]$AgentSid,
    [string]$ProtectedKeyPath = 'C:\ProgramData\Khaos\authority-key.dpapi',
    [string]$NamedPipe = '\\.\pipe\KhaosAuthorityD',
    [string]$BackendPipe = '\\.\pipe\KhaosAuthorityDBackend'
)
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Khaos authority installation requires an elevated administrator shell'
}
if (-not [IO.Path]::IsPathRooted($Binary) -or -not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw 'authority binary must be an existing absolute path'
}
if ($NamedPipe -notlike '\\.\pipe\*') {
    throw 'authority Named Pipe must be local and named-pipe based'
}
if ($BackendPipe -notlike '\\.\pipe\*' -or $BackendPipe -eq $NamedPipe) {
    throw 'authority backend pipe must be a distinct local Named Pipe'
}
if ([string]::IsNullOrWhiteSpace($AgentSid)) {
    throw 'Agent SID is required'
}
if (-not (Test-Path -LiteralPath $ProtectedKeyPath -PathType Leaf)) {
    throw 'pre-provisioned DPAPI key marker is required; the installer will not create authority key material'
}

New-Item -ItemType Directory -Force -Path $InstallRoot, (Split-Path -Parent $ProtectedKeyPath) | Out-Null
Copy-Item -LiteralPath $Binary -Destination (Join-Path $InstallRoot 'khaos-authorityd-windows.exe') -Force
$installed = Join-Path $InstallRoot 'khaos-authorityd-windows.exe'

$service = Get-Service -Name 'KhaosAuthorityD' -ErrorAction SilentlyContinue
if ($null -eq $service) {
    New-Service -Name 'KhaosAuthorityD' -DisplayName 'Khaos Authority Daemon' `
        -BinaryPathName "`"$installed`"" -StartupType Automatic | Out-Null
}
# SCM computes and attaches the dedicated S-1-5-80-* Service SID to the
# service token.  Refuse the restricted/default modes.
& "$env:SystemRoot\System32\sc.exe" sidtype KhaosAuthorityD unrestricted | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'failed to enable the KhaosAuthorityD Service SID' }
$authoritySid = (New-Object System.Security.Principal.NTAccount('NT SERVICE\KhaosAuthorityD')).Translate([System.Security.Principal.SecurityIdentifier]).Value

$envFile = Join-Path $InstallRoot 'native-authority.env'
@(
    "KHAOS_AUTHORITYD_NAMED_PIPE=$NamedPipe"
    "KHAOS_AUTHORITYD_BACKEND_PIPE=$BackendPipe"
    "KHAOS_AGENT_SID=$AgentSid"
    "KHAOS_AUTHORITYD_SERVICE_SID=$authoritySid"
    "KHAOS_AUTHORITYD_DPAPI_KEY_PATH=$ProtectedKeyPath"
    'KHAOS_AUTHORITYD_PROTECTED_KEY_REF=khaos-authority-signing-key'
) | Set-Content -LiteralPath $envFile -Encoding ascii

& "$env:SystemRoot\System32\sc.exe" config KhaosAuthorityD binPath= "`"$installed`" --config `"$envFile`"" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'failed to bind the service to its authority-owned configuration' }

# The config and DPAPI marker are authority-owned; the Agent only gets the
# pipe name.  A missing or weak ACL is a deployment failure.
$authorityAce = "${authoritySid}:(R)"
& "$env:SystemRoot\System32\icacls.exe" $envFile /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" $authorityAce | Out-Null
& "$env:SystemRoot\System32\icacls.exe" $ProtectedKeyPath /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" $authorityAce | Out-Null

Start-Service -Name 'KhaosAuthorityD'
Get-Service -Name 'KhaosAuthorityD' | Where-Object Status -eq 'Running' | Out-Null
