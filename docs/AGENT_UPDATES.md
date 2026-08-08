# Endpoint-agent updates

Endpoint-agent updates are explicit, signed, bounded operations rather than a
general remote-execution channel. The first update slice defines and validates
the signed release contract before any installer is allowed to replace a
running executable.

Every update envelope contains the exact base64-encoded manifest bytes, a
trusted key identifier, and an Ed25519 signature binding the key identifier to
those exact bytes. The signed
manifest fixes:

- Schema and semantic release version
- Linux or Windows target and `amd64` or `arm64` architecture
- HTTPS artifact location
- Exact SHA-256 digest and bounded artifact size
- Short issuance and expiration window
- Bounded post-update health-confirmation timeout

Unknown fields, untrusted keys, invalid signatures, unsupported platforms,
insecure URLs, invalid digests, oversized artifacts, and expired or excessively
long validity windows are rejected before download or installation.

The release-signing key is separate from endpoint identity certificates,
server TLS certificates, Authenticode certificates, and Sigstore identities.
Only its public key belongs in agent configuration. Production signing should
use an offline or hardware-backed release authority with a narrowly scoped
online signing key and documented rotation and revocation procedures.

The remaining implementation will download to a private staging directory,
stream and verify the declared size and digest, preserve exactly one known-good
binary, perform an atomic platform-specific replacement, require a successful
health confirmation, and roll back automatically on startup or health failure.
It will not accept scripts, command lines, additional payloads, or peer-provided
updates.
