# Resolve a Windows Service SID through the Service Control Manager.
#
# NT SERVICE\<name> is a virtual account.  Account-name translation can race
# the SCM after sidtype is enabled, so callers must use the SCM's showsid
# query and fail closed if it does not return exactly one valid Service SID.
function Get-KhaosServiceSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName
    )

    $scPath = Join-Path $env:SystemRoot 'System32\sc.exe'
    $output = @(& $scPath showsid $ServiceName 2>&1)
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "SCM showsid failed for '$ServiceName': $text"
    }

    $matches = [regex]::Matches(
        $text,
        'S-1-5-80(?:-\d+){5}(?!\d)'
    )
    if ($matches.Count -ne 1) {
        throw "SCM returned an invalid Service SID for '$ServiceName'"
    }

    $sid = $matches[0].Value
    try {
        $parsedSid = [System.Security.Principal.SecurityIdentifier]::new($sid)
    }
    catch {
        throw "SCM returned a malformed Service SID for '$ServiceName'"
    }
    if ($parsedSid.Value -ne $sid) {
        throw "SCM returned a non-canonical Service SID for '$ServiceName'"
    }

    return $sid
}
