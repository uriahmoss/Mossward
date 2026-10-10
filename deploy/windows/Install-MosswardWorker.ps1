[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Configuration,
    [Parameter(Mandatory = $true)][string]$Certificate,
    [Parameter(Mandatory = $true)][string]$PrivateKey,
    [Parameter(Mandatory = $true)][string]$CA
)
$ErrorActionPreference = 'Stop'
$serviceName = 'MosswardWorker'
$installDirectory = Join-Path $env:ProgramFiles 'Mossward Worker'
$dataDirectory = Join-Path $env:ProgramData 'Mossward\Worker'
$identityDirectory = Join-Path $dataDirectory 'identity'
$stateDirectory = Join-Path $dataDirectory 'state'
$binaryPath = Join-Path $installDirectory 'mossward-worker.exe'
$configPath = Join-Path $identityDirectory 'worker.json'

function Invoke-ACL([string[]]$Arguments) {
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Worker ACL configuration failed.' }
}
function Assert-RegularFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Worker input must be a regular file, not a reparse point.'
    }
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell session.'
}
foreach ($path in @($Binary, $Configuration, $Certificate, $PrivateKey, $CA)) { Assert-RegularFile $path }
if ((Get-AuthenticodeSignature -LiteralPath $Binary).Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw 'Worker executable must have a valid Authenticode signature from your approved publisher.'
}
if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installDirectory) -or (Test-Path -LiteralPath $dataDirectory)) {
    throw 'Existing worker service or directories found; refusing to overwrite.'
}
foreach ($parent in @($env:ProgramFiles, $env:ProgramData, (Join-Path $env:ProgramData 'Mossward'))) {
    if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Managed installation parent must not be a reparse point.'
    }
}
$config = Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$expected = @{
    certificate_file = (Join-Path $identityDirectory 'worker.crt')
    private_key_file = (Join-Path $identityDirectory 'worker.key')
    ca_file = (Join-Path $identityDirectory 'ca.crt')
    state_directory = $stateDirectory
}
foreach ($property in $expected.Keys) {
    if ($config.$property -ne $expected[$property]) { throw "Configuration must use the managed path for $property." }
}
foreach ($directory in @($installDirectory, $dataDirectory, $identityDirectory, $stateDirectory)) {
    New-Item -ItemType Directory -Path $directory | Out-Null
    Invoke-ACL @($directory, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
}
Copy-Item -LiteralPath $Binary -Destination $binaryPath
Copy-Item -LiteralPath $Configuration -Destination $configPath
Copy-Item -LiteralPath $Certificate -Destination $expected.certificate_file
Copy-Item -LiteralPath $PrivateKey -Destination $expected.private_key_file
Copy-Item -LiteralPath $CA -Destination $expected.ca_file
& $binaryPath --config $configPath --check-config
if ($LASTEXITCODE -ne 0) { throw 'Worker configuration/identity check failed; secured files retained for inspection.' }
& $binaryPath service install --config $configPath
if ($LASTEXITCODE -ne 0) { throw 'Worker service installation failed; secured files retained.' }
try {
    Invoke-ACL @($installDirectory, '/grant:r', "NT SERVICE\${serviceName}:(OI)(CI)RX")
    Invoke-ACL @($dataDirectory, '/grant:r', "NT SERVICE\${serviceName}:RX")
    Invoke-ACL @($identityDirectory, '/grant:r', "NT SERVICE\${serviceName}:(OI)(CI)RX")
    Invoke-ACL @($stateDirectory, '/grant:r', "NT SERVICE\${serviceName}:(OI)(CI)M")
} catch {
    & $binaryPath service uninstall | Out-Null
    throw
}
Write-Host 'Worker installed but not started. Configuration/identity are read-only; state is writable.'
Write-Host "Start with: & '$binaryPath' service start"
