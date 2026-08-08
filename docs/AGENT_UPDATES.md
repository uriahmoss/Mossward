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

Artifact staging downloads without redirects or transparent content encoding,
uses a private directory and temporary file, streams and verifies the declared
size and SHA-256 digest, flushes the candidate before an atomic rename, and
removes partial files on every failure. The target operating system and
architecture must exactly match the running agent.

Before activation, the agent copies the currently running executable into its
private update state, verifies the complete copy, and records its version,
SHA-256 digest, exact size, and safe basename. A strict, owner-only transaction
journal records the target digest, lifecycle state, and health deadline before
replacement begins. An interrupted agent can therefore distinguish a prepared
update from one awaiting health confirmation or requiring rollback.

On Linux and other Unix service hosts, activation copies and re-verifies the
candidate into a temporary file beside the installed executable, preserves its
executable mode, persists the awaiting-health transaction first, then uses a
same-filesystem atomic rename and directory synchronization. The running
process continues on its original inode and exits with a restart-required
result so the service manager can launch the replacement.

Windows activation intentionally refuses in-process replacement and will use a
separate stopped-service update helper. The remaining implementation will add
that helper, require successful health confirmation, and roll back
automatically on startup or health failure.

After activation, the replacement must complete an authenticated server
check-in before its signed health deadline. A matching embedded release version
then commits the transaction. On Unix, startup after a missed deadline restores
and reverifies the known-good executable through the same atomic replacement
path, marks the rollback complete, and requests one final service restart.
It will not accept scripts, command lines, additional payloads, or peer-provided
updates.
