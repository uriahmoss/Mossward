param(
    [Parameter(Mandatory = $true)][string]$ToolsDirectory,
    [int]$ExpectedMajor = 0
)
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    & go run ./scripts/postgresverify --tools-dir $ToolsDirectory --expected-major $ExpectedMajor
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL verification failed.' }
} finally {
    Pop-Location
}
