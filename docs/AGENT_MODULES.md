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
These capabilities describe the kind of result a module may produce; they do
not grant filesystem, network, process, or identity access. Explicit permissions
and isolation are separate roadmap controls. Mossward does not use Go's dynamic
plugin facility and this slice does not load or execute module packages.
