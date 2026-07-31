# Architecture and security boundaries

## First milestone

The browser UI calls a small Go HTTP API. The API resolves and validates every
requested target and port against centrally configured policy before queueing
work. Approved IP addresses are pinned in the persisted job. A single bounded
scheduler and worker pool perform TCP connection checks, and the file-backed
repository persists scans and findings.

```text
Browser -> API -> scope validation -> bounded scan workers -> authorized targets
                  |                         |
                  +---- file repository <---+
```

## Trust boundaries

- A scan request is untrusted even when it comes from the local UI.
- DNS is resolved once before authorization. Every returned address must fall
  inside an allowed CIDR, and workers connect only to those pinned addresses.
- CIDR blocks and explicit IP ranges are expanded before queueing. Expansion is
  bounded by the same target limit, deduplicated, and authorization-checked
  address by address.
- Ports must be centrally allowed; the request cannot expand policy.
- The global queue bounds pending scans, while one worker pool bounds network
  concurrency across the process.
- The server listens only on loopback by default.
- Results may contain sensitive infrastructure metadata and are stored with owner-only permissions.
- Startup marks scans interrupted by a previous process exit as failed instead
  of leaving them permanently queued or running.

## Evolution

For multi-user deployment, separate the control plane from scanner workers. The control plane owns authentication, authorization, inventory, scheduling, and findings. Workers receive short-lived, signed jobs limited to an organization and approved scope. PostgreSQL becomes the source of truth, and an append-only audit log records policy and scan lifecycle events.
