[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Configuration,
    [Parameter(Mandatory = $true)][string]$Certificate,
    [Parameter(Mandatory = $true)][string]$PrivateKey,
    [Parameter(Mandatory = $true)][string]$CA
)
$ErrorActionPreference = 'Stop'
if ($env:MOSSWARD_TEST_WORKER_WINDOWS_SERVICE -ne '1' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Test signing requires explicit opt-in on a disposable GitHub-hosted runner.'
}
$signer = $null
$trustPath = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString() + '.cer')
try {
    $signer = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Mossward disposable CI test signer' -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddDays(1) -KeyExportPolicy NonExportable
    Export-Certificate -Cert $signer -FilePath $trustPath | Out-Null
    Import-Certificate -FilePath $trustPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $trustPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
    $signature = Set-AuthenticodeSignature -LiteralPath $Binary -Certificate $signer -HashAlgorithm SHA256
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw 'Temporary CI executable signature validation failed.'
    }
    & (Join-Path $PSScriptRoot '../deploy/windows/Install-MosswardWorker.ps1') -Binary $Binary -Configuration $Configuration -Certificate $Certificate -PrivateKey $PrivateKey -CA $CA
} finally {
    if ($signer) {
        foreach ($store in @('Root', 'TrustedPublisher', 'My')) {
            $path = "Cert:\LocalMachine\$store\$($signer.Thumbprint)"
            if (-not (Test-Path -LiteralPath $path)) { continue }
            if ($store -eq 'My') {
                Remove-Item -LiteralPath $path -Force -DeleteKey
            } else {
                Remove-Item -LiteralPath $path -Force
            }
        }
    }
    if (Test-Path -LiteralPath $trustPath) { Remove-Item -LiteralPath $trustPath -Force }
}
