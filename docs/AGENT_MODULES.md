# Endpoint module framework

Mossward endpoint modules extend detection and inventory without granting a
server the ability to send arbitrary code or commands to agents. The framework
is being delivered in independently verified layers; package trust, execution,
permissions, assignment, and rollout are not implied by the manifest contract.

## Versioned manifest contract

Every module declares manifest schema version `1` and module API version `1`.
The manifest uses a stable lowercase dotted identifier, semantic module and
minimum-agent versions, supported operating systems and architectures, and one
or more typed capabilities.

The initial capability vocabulary is deliberately detection-only:

- `inventory`
- `configuration_check`
- `file_metadata`
- `network_metadata`
- `process_metadata`

Unknown, empty, or duplicate platform and capability declarations are rejected.
Mossward does not use Go's dynamic plugin facility.

## Trust, assignment, and rollout

Module envelopes carry the canonical manifest, package, SHA-256 digest, and an
Ed25519 publisher signature. Server and endpoint independently verify all four.
Publisher keys are explicitly registered and may be disabled. Immutable
releases use audited staged, approved, and revoked states.

Approved releases can target one endpoint or an asset group. Direct endpoint
assignments take precedence. Stable percentage rings support staged rollout.
Compatibility checks cover module API, agent version, OS, and architecture.
The global emergency control disables all modules on the next check-in.

## Permissions and execution

Permissions use a closed vocabulary for OS information, packages, processes,
connection metadata, and file metadata. Declarative inventory and configuration
checks can only use signed, declared permissions and bounded comparison
operators.

Native detectors are single-entrypoint packages using a versioned JSON protocol
through the separate `mossward-module-host`. Production installations run that
host as a dedicated low-privilege account. It receives a minimal environment
without Mossward identity-key, certificate, configuration, or state paths. The
host constrains traversal, runtime, result size, permission declarations, and
result schema. Signed memory limits range from 16 to 512 MiB; the Linux or
Windows service sandbox applies that declared OS-level limit.

Agents retain the preceding package and roll back after repeated failures.
Health, version, crash count, and bounded errors return over authenticated
check-in. Packages cannot declare shell commands, extra files, undeclared
downloads, permission expansion, self-propagation, or identity-key access.

## Developer tools

Use `mossward-module-sdk validate --manifest manifest.json --package package.bin`
for local validation. The `sign` command additionally accepts `--private-key`
and `--output`. Signing keys remain outside Mossward.
