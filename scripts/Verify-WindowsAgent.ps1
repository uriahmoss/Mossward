[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$ExpectedThumbprint
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "Agent binary not found: $Binary" }
$signature = Get-AuthenticodeSignature -LiteralPath $Binary
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode signature is not valid: $($signature.StatusMessage)"
}
if ($ExpectedThumbprint -and $signature.SignerCertificate.Thumbprint -ne $ExpectedThumbprint.ToUpperInvariant()) {
    throw "Unexpected signing certificate: $($signature.SignerCertificate.Thumbprint)"
}
$signature | Select-Object Status, StatusMessage, @{Name='Subject';Expression={$_.SignerCertificate.Subject}},
    @{Name='Thumbprint';Expression={$_.SignerCertificate.Thumbprint}}, TimeStamperCertificate
