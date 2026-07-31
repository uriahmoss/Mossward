# Architecture and security boundaries

## First milestone

The browser UI calls a small Go HTTP API. The API resolves and validates every
requested target and port against centrally configured policy before queueing
work. Approved IP addresses are pinned in the persisted job. A single bounded
scheduler and worker pool perform TCP connection checks, and the file-backed
SQLite repository persists scans and findings.

Workers emit one result for every attempted target-and-port pair, including
closed ports. The scheduler periodically persists completed and total check
counters, allowing the scan detail view to report real progress while bounding
file writes to roughly one hundred updates per scan.

Reachable endpoints pass through a protocol inspector. The inspector separates
normalized service observations from actionable security findings:

- HTTP requests use a custom transport that connects to the pinned approved IP,
  preserves the intended Host header, limits response bodies, and never follows
  redirects.
- TLS handshakes collect certificate and negotiated-protocol evidence with
  verification reported as explicit findings.
- SSH and generic banners are read passively with strict byte and time limits.
- Declarative check identifiers keep findings stable as presentation and
  remediation text evolve.

```text
Browser -> API -> scope validation -> bounded scan workers -> authorized targets
                  |                         |
                  +---- SQLite database <----+
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
- SQLite uses foreign keys, transactional scan snapshots, WAL journaling, a
  busy timeout, and one application connection to serialize local writes.
- Indexed product/version observations and check/severity findings provide the
  query foundation for CVE correlation and reporting.
- Schema versions are recorded transactionally so future releases can migrate
  existing databases safely.
- Legacy JSON scan history is imported once and archived recoverably.
- Startup marks scans interrupted by a previous process exit as failed instead
  of leaving them permanently queued or running.

## Evolution

For multi-user deployment, separate the control plane from scanner workers. The control plane owns authentication, authorization, inventory, scheduling, and findings. Workers receive short-lived, signed jobs limited to an organization and approved scope. PostgreSQL can replace SQLite as the source of truth, and an append-only audit log records policy and scan lifecycle events.
