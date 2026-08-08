[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.-]{0,63}$')][string]$Version,
    [ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64',
    [Parameter(Mandatory = $true)][string]$SignTool,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$TimestampUrl,
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'
$artifactName = "mossward-agent_${Version}_windows_${Architecture}"
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$artifactDirectory = Join-Path $staging 'mossward-agent'
$binary = Join-Path $artifactDirectory 'mossward-agent.exe'
$updater = Join-Path $artifactDirectory 'mossward-agent-updater.exe'
$archive = Join-Path $OutputDirectory "$artifactName.zip"

try {
    if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) { throw "SignTool not found: $SignTool" }
    New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = $Architecture
    $linkerFlags = "-s -w -buildid= -X mossward/internal/agentapp.Version=$Version"
    & go build -trimpath -ldflags $linkerFlags -o $binary ./cmd/mossward-agent
    if ($LASTEXITCODE -ne 0) { throw 'Windows endpoint-agent build failed.' }
    & go build -trimpath -ldflags '-s -w -buildid=' -o $updater ./cmd/mossward-agent-updater
    if ($LASTEXITCODE -ne 0) { throw 'Windows endpoint-agent updater build failed.' }

    & $SignTool sign /fd SHA256 /sha1 $CertificateThumbprint /tr $TimestampUrl /td SHA256 $binary
    if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed.' }
    & $SignTool sign /fd SHA256 /sha1 $CertificateThumbprint /tr $TimestampUrl /td SHA256 $updater
    if ($LASTEXITCODE -ne 0) { throw 'Updater Authenticode signing failed.' }
    & $SignTool verify /pa /v $binary
    if ($LASTEXITCODE -ne 0) { throw 'Authenticode verification failed.' }
    & $SignTool verify /pa /v $updater
    if ($LASTEXITCODE -ne 0) { throw 'Updater Authenticode verification failed.' }

    Copy-Item deploy/windows/Install-MosswardAgent.ps1 $artifactDirectory
    Copy-Item config/mossward-agent.json.example (Join-Path $artifactDirectory 'agent.json.example')
    Copy-Item docs/ENDPOINT_AGENT.md (Join-Path $artifactDirectory 'README.md')
    Compress-Archive -Path $artifactDirectory -DestinationPath $archive -CompressionLevel Optimal -Force
    Get-FileHash -Algorithm SHA256 -LiteralPath $archive | Format-List
    Write-Host "Created signed Windows release: $archive"
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}
