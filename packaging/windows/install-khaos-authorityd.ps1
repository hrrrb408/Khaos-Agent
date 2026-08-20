# Run from an elevated PowerShell prompt.  This installer intentionally uses
# the SCM's Service SID and never installs the authority as LocalSystem with a
# caller-controlled account or as a same-user Python process.
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$InstallRoot = 'C:\Program Files\Khaos',
    [string]$AgentSid,
    [string]$ProtectedKeyPath = 'C:\ProgramData\Khaos\authority-key.dpapi',
    [string]$NamedPipe = '\\.\pipe\KhaosAuthorityD',
    [string]$BackendPipe = '\\.\pipe\KhaosAuthorityDBackend',
    # CI provisioning only: create the DPAPI marker under the SYSTEM
    # identity (the account the service runs as) through a one-shot
    # scheduled task.  Production must pre-provision the marker out of
    # band; the installer never creates key material under the caller's
    # own identity.
    [switch]$ProvisionDpapiKey
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'service-sid.ps1')

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
    if ($ProvisionDpapiKey) {
        $markerDir = Split-Path -Parent $ProtectedKeyPath
        New-Item -ItemType Directory -Force -Path $markerDir | Out-Null
        # Provision DPAPI-protected material under the SYSTEM identity via
        # a one-shot scheduled task: CryptProtectData scope must match the
        # service's own security context, never the caller's.
        # The entropy literal below must stay byte-identical to the Rust
        # CryptUnprotectData entropy in
        # rust/khaos-core/src/bin/khaos-authorityd-windows.rs: DPAPI refuses
        # to decrypt when the optional entropy does not match.
        $provisionScript = Join-Path $env:TEMP 'khaos-provision-dpapi.ps1'
        @(
            '$ErrorActionPreference = "Stop"'
            'Add-Type -AssemblyName System.Security'
            '$entropy = [System.Text.Encoding]::UTF8.GetBytes("khaos-authorityd-key-marker")'
            '$plain = [System.Text.Encoding]::UTF8.GetBytes("khaos-authority-protected-key-marker")'
            '$protected = [System.Security.Cryptography.ProtectedData]::Protect($plain, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)'
            "[System.IO.File]::WriteAllBytes('$ProtectedKeyPath', [byte[]]`$protected)"
        ) | Set-Content -LiteralPath $provisionScript -Encoding ascii
        $action = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$provisionScript`""
        & "$env:SystemRoot\System32\schtasks.exe" /Create /TN KhaosAuthorityDKeyProvision /RU SYSTEM /RL HIGHEST /SC ONCE /ST 00:00 /F /TR $action | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to create the SYSTEM key-provisioning task' }
        try {
            & "$env:SystemRoot\System32\schtasks.exe" /Run /TN KhaosAuthorityDKeyProvision | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'failed to run the SYSTEM key-provisioning task' }
            $deadline = (Get-Date).AddSeconds(60)
            while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $ProtectedKeyPath -PathType Leaf)) {
                Start-Sleep -Milliseconds 500
            }
            if (-not (Test-Path -LiteralPath $ProtectedKeyPath -PathType Leaf)) {
                throw 'SYSTEM key provisioning did not produce the DPAPI marker'
            }
        }
        finally {
            & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN KhaosAuthorityDKeyProvision /F | Out-Null
            Remove-Item -LiteralPath $provisionScript -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        throw 'pre-provisioned DPAPI key marker is required; pass -ProvisionDpapiKey only in CI provisioning'
    }
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
$authoritySid = Get-KhaosServiceSid -ServiceName 'KhaosAuthorityD'

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
