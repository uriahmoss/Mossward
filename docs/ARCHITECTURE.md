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

## Future endpoint agent

A hosted Mossward deployment may optionally enroll a small endpoint agent for
deeper local assessment than network probes can provide. The agent should
collect narrowly defined defensive evidence such as:

- Operating-system edition, build, and patch level
- Installed packages, applications, and exact versions
- Listening services and their owning processes
- Local users, security policy summaries, and relevant configuration posture
- Disk encryption, host firewall, endpoint protection, and update status
- Package- and platform-specific evidence for higher-confidence CVE matching
- Outbound network-flow metadata and the local process responsible for each
  connection

The agent is not a general remote shell. Its security model must include:

- Explicit administrator enrollment and revocation
- A unique device identity backed by mutually authenticated TLS
- Outbound-only connections from endpoints to the control plane
- Short-lived, signed, schema-validated assessment jobs
- A fixed allowlist of read-only collectors instead of arbitrary commands
- Least-privilege execution, with privileged collectors isolated and minimized
- Signed, rollback-capable agent updates
- Local and server-side audit logs for jobs, configuration, and updates
- Bounded collection, redaction, retention, and tenant isolation
- Offline queue limits and replay protection

### Endpoint network telemetry

The agent may observe outbound network activity so the Mossward server can
correlate destinations with current threat intelligence. This capability
should collect metadata by default, not packet payloads:

- Destination IP address, port, transport protocol, and connection outcome
- First seen, last seen, connection count, and approximate byte totals
- Executable path, process identity, and verified signer or file hash when
  available
- DNS query and response context observed on the endpoint
- TLS server name when the operating system exposes it without interception
- Device, user-session, and network-interface context needed for investigation

Mossward can compare this evidence with versioned indicators for malware
command-and-control systems, botnets, phishing infrastructure, malicious
domains, suspicious hosting, and other known threats. A match should retain the
indicator source, confidence, category, feed timestamp, expiration, and exact
evidence that produced the alert.

Destination reputation alone is not proof of compromise. Shared hosting,
content-delivery networks, recycled IP addresses, VPNs, and stale indicators
can create false positives. Prioritization should correlate destination
reputation with the initiating process, domain, certificate context, frequency,
and other endpoint or scan findings.

Privacy and safety boundaries:

- No full packet capture or application payload collection by default
- No TLS interception, certificate injection, or credential collection
- Local aggregation and deduplication before upload
- Configurable exclusions for applications, destinations, and sensitive
  networks
- Explicit retention limits and role-based access to endpoint telemetry
- Encryption in transit and at rest, with audit logs for searches and exports
- Bounded event queues so loss of server connectivity cannot exhaust endpoint
  storage
- Clear administrator disclosure and policy controls before telemetry is
  enabled

### Endpoint coverage detection

An optional server policy may detect systems that appear on an authorized
network but do not have an enrolled Mossward endpoint agent. This is a
detection and coverage-control feature; it does not install the agent or modify
the discovered device.

The Mossward server should correlate:

- Assets and addresses observed by authorized network scans
- Active endpoint-agent identities and their latest check-in
- Hostnames, IP addresses, hardware addresses, and stable device identifiers
  when available
- Passive neighbor-table evidence reported by enrolled endpoints
- Administrator classifications for agent-eligible computers, infrastructure,
  printers, mobile devices, and intentionally unmanaged equipment

Coverage results should distinguish:

- Enrolled and recently active
- Enrolled but stale or offline
- Discovered and likely agent-eligible, but not enrolled
- Discovered but classified as agent-ineligible
- Ambiguous identity requiring administrator review

Active subnet discovery should normally originate from the Mossward server or
from one explicitly designated discovery sensor per isolated network segment.
Running duplicate discovery scans from every endpoint would create unnecessary
traffic, inconsistent evidence, and a larger security boundary.

When coverage detection is enabled, it must remain constrained by:

- Explicitly authorized CIDRs and server-side enablement
- Per-segment schedules, concurrency limits, and rate limits
- Device and network exclusions
- No stealth, exploitation, credential attempts, or automatic agent deployment
- Clear evidence and confidence for every missing-agent alert
- Deduplication and aging so transient addresses do not remain permanent gaps
- Audit logging for policy changes and discovery activity

### Agent integrity and tamper alerts

The endpoint agent should monitor its own security-relevant state and report
possible tampering to the Mossward server. This remains a detection capability;
the agent does not retaliate, remove software, or take autonomous remediation
actions.

Locally observable integrity events may include:

- Agent service stop, disablement, uninstall, or unexpected termination
  attempts when the operating system exposes the event
- Changes to the agent executable, libraries, configuration, permissions, or
  protected installation paths
- Failure to validate a signed update, policy, collector, or server command
- Replacement, deletion, or unexpected use of the device identity and private
  key
- Disabled collectors, blocked server communication, or persistent local queue
  failures
- Unexpected rollback of the agent version, policy version, or security state
- Loss of access to required operating-system audit or telemetry facilities

An agent cannot reliably report after it has been terminated, isolated, or
fully compromised. The control plane must independently evaluate:

- Expected heartbeat interval and last successful check-in
- Agent version, policy version, and collector-health attestations
- Monotonic event sequence numbers and replay protection
- Gaps between network asset observations and agent presence
- Repeated enrollment, identity changes, or duplicate device identities

Tamper events should be authenticated with the enrolled device identity,
sequence-numbered, timestamped, acknowledged by the server, and retained in an
append-only audit history. The server should distinguish an explicit local
tamper event from an inferred condition such as a missed heartbeat, because
power loss, network outages, reimaging, and legitimate administration can
produce similar symptoms.

Administrative boundaries:

- Authorized maintenance windows and uninstall workflows suppress expected
  alerts without deleting their audit record
- Server-side policy controls alert thresholds and escalation
- Local event queues are encrypted, bounded, and resistant to simple deletion
  where the operating system permits
- Integrity monitoring uses documented operating-system facilities and signed
  artifacts, not invasive kernel hooks or adversarial self-defense behavior
- Administrator-level compromise may defeat local observation; Mossward must
  report confidence and limitations rather than claiming guaranteed tamper
  prevention

### Optional endpoint relay

An enrolled endpoint may be explicitly promoted to a relay for agents in a
segmented or highly restricted network that cannot connect directly to the
Mossward server. This is an optional transport role, not a general-purpose
proxy, scanner, remote-access bridge, or trust authority.

The preferred communication path is:

```text
Segmented endpoint agents -> designated relay -> Mossward server
```

Endpoint evidence, heartbeats, policies, jobs, acknowledgements, and updates
should remain signed and encrypted end-to-end between each originating agent
and the Mossward server. The relay authenticates separately to the server and
forwards opaque, bounded messages without gaining authority to impersonate
downstream agents or modify their content.

Relay requirements:

- Explicit promotion, server approval, certificate role, and revocation
- An allowlist of enrolled downstream agent identities and permitted network
  interfaces
- Outbound-only server connectivity from the relay when the network design
  permits it
- A dedicated Mossward protocol and server destination allowlist rather than
  arbitrary TCP, UDP, HTTP, or SOCKS forwarding
- End-to-end message signatures, sequence numbers, acknowledgements, and replay
  protection
- Encrypted, size-bounded store-and-forward queues for temporary server outages
- Per-agent and aggregate bandwidth, connection, storage, and message limits
- Health, capacity, backlog, version, certificate, and tamper telemetry
- Audit records for role changes, downstream enrollment, routing, drops, and
  delivery outcomes
- Configurable high availability with deterministic failover to an approved
  secondary relay or direct server path

The server should visibly distinguish direct and relayed agents, including the
relay path and last successful end-to-end acknowledgement. A compromised relay
may delay or drop traffic, but end-to-end authentication should prevent it from
silently forging endpoint evidence or trusted server policy.

Relay discovery must not be automatic. Administrators select the relay,
authorized network segment, listening interface, downstream identities, and
fallback behavior. Removing the role should close the relay listener and
invalidate relay-specific credentials without unenrolling the endpoint's own
agent identity.

Network observations and agent evidence should converge on the same asset
record while retaining their distinct provenance. Findings should report
whether their confidence comes from unauthenticated network evidence,
credentialed remote evidence, or a locally enrolled agent.
