param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$EnvironmentFile,
    [string]$InstallDirectory = "$env:ProgramFiles\Mossward",
    [string]$DataDirectory = "$env:ProgramData\Mossward"
)

$ErrorActionPreference = "Stop"
$serviceName = "Mossward"
$binaryPath = Join-Path $InstallDirectory "mossward.exe"
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell session."
}
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "Mossward binary not found: $Binary" }
if (-not (Test-Path -LiteralPath $EnvironmentFile -PathType Leaf)) { throw "Environment file not found: $EnvironmentFile" }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw "The Mossward service is already installed." }

$environment = Get-Content -LiteralPath $EnvironmentFile | ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") }
foreach ($entry in $environment) {
    if ($entry -notmatch '^MOSSWARD_[A-Z0-9_]+=') { throw "Invalid environment entry: $entry" }
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
Copy-Item -LiteralPath $Binary -Destination $binaryPath -Force
& $binaryPath service install
if ($LASTEXITCODE -ne 0) { throw "Mossward service installation failed." }
try {
    & icacls.exe $DataDirectory /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "NT SERVICE\Mossward:(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not secure the Mossward data directory." }
    New-ItemProperty -Path $serviceRegistryPath -Name Environment -PropertyType MultiString -Value $environment -Force | Out-Null
    Start-Service -Name $serviceName
} catch {
    & $binaryPath service uninstall | Out-Null
    throw
}
Write-Host "Mossward is installed and running as NT SERVICE\Mossward."
