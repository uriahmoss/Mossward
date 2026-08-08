[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Configuration,
    [string]$InstallDirectory = "$env:ProgramFiles\Mossward Agent",
    [string]$DataDirectory = "$env:ProgramData\Mossward\Agent"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'MosswardAgent'
$binaryPath = Join-Path $InstallDirectory 'mossward-agent.exe'
$configurationPath = Join-Path $DataDirectory 'agent.json'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session.'
}
if ((Get-AuthenticodeSignature -LiteralPath $Binary).Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw 'The Mossward endpoint-agent Authenticode signature is not valid.'
}
if (-not (Test-Path -LiteralPath $Configuration -PathType Leaf)) { throw "Configuration not found: $Configuration" }

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
Copy-Item -LiteralPath $Binary -Destination $binaryPath -Force
Copy-Item -LiteralPath $Configuration -Destination $configurationPath -Force
& icacls.exe $InstallDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent installation directory.' }
& icacls.exe $DataDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent data directory.' }

& $binaryPath service install --config $configurationPath
if ($LASTEXITCODE -ne 0) { throw 'Could not register the Mossward Agent Windows service.' }
try {
    & icacls.exe $InstallDirectory /grant:r "NT SERVICE\${serviceName}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant the service access to its executable.' }
    & icacls.exe $DataDirectory /grant:r "NT SERVICE\${serviceName}:(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant the service access to agent state.' }
} catch {
    & $binaryPath service uninstall | Out-Null
    throw
}

Write-Host 'Signed Mossward endpoint agent installed but not started.'
Write-Host "Enroll it using --token-stdin, then run: $binaryPath service start"
