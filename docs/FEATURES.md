# Mossward feature tracker

This is the authoritative implementation tracker for Mossward. Update this file
whenever a feature moves between states. A checked item means the behavior is
implemented and verified; an unchecked item is not yet complete.

## Completed

### Project foundation

- [x] Isolated Go module under the `Mossward` project directory
- [x] Embedded browser interface
- [x] Pastel-green visual theme and feature landing page
- [x] Environment-based configuration
- [x] Container build
- [x] Linux and Windows cross-build verification
- [x] Structured info, warning, and error logging for major application flows
- [x] Graceful HTTP server, scanner, and database shutdown

### Authorized network scanning

- [x] Individual IPv4 and IPv6 targets
- [x] Fully qualified domain-name targets with pinned address resolution
- [x] CIDR expansion
- [x] Inclusive IP-address ranges
- [x] Configurable authorized-network allowlist
- [x] Configurable port allowlist
- [x] Bounded target expansion
- [x] Bounded global scan queue
- [x] Bounded connection concurrency
- [x] Live scan progress and persistent scan history
- [x] Dedicated scan-detail view

### Service inspection and findings

- [x] TCP reachability observations
- [x] HTTP status, title, and selected response metadata
- [x] TLS certificate and negotiated-protocol metadata
- [x] SSH and passive generic banner inspection
- [x] Product and version extraction when explicitly disclosed
- [x] Observation confidence levels
- [x] Cleartext HTTP finding
- [x] Missing HTTP security-header finding
- [x] Service-version disclosure finding
- [x] TLS expiration and near-expiration findings
- [x] TLS hostname-mismatch finding
- [x] Legacy TLS protocol finding
- [x] Reachable administrative and database service findings

### Persistence

- [x] SQLite as the authoritative local data store
- [x] Numbered, forward-only schema migrations
- [x] Foreign-key enforcement and WAL journaling
- [x] Owner-only database permissions
- [x] Recoverable migration from legacy JSON scan history
- [x] Interrupted-scan reconciliation
- [x] Normalized observations, findings, CVEs, and identity records

### Vulnerability intelligence

- [x] Manual NVD CVE synchronization
- [x] Configurable NVD API key
- [x] Normalized CVE, CPE range, reference, and feed-status storage
- [x] Narrow product normalization mappings
- [x] Version-range comparison and matching
- [x] No CVE match without product and version evidence
- [x] CISA Known Exploited status retained from NVD data
- [x] CVE matches shown on scan details
- [x] Critical-CVE homepage feed
- [x] Environment matches prioritized above general critical CVEs
- [x] Feed freshness and local record count

### Local authentication and MFA

- [x] Localhost-only first-time setup
- [x] First identity is always a local Administrator
- [x] One-time bootstrap lockout after initialization
- [x] Argon2id password hashing
- [x] Password timing equalization for nonexistent accounts
- [x] Mandatory Administrator TOTP enrollment during bootstrap
- [x] AES-256-GCM encryption for stored identity secrets
- [x] Owner-only server identity-key file
- [x] Ten hashed, single-use recovery codes
- [x] Recovery-code authentication and audit warning
- [x] TOTP replay protection
- [x] Generic authentication failure messages

### Sessions and account protection

- [x] Cryptographically random server-side sessions
- [x] Only session-token hashes persisted
- [x] HttpOnly and SameSite=Strict cookies
- [x] Secure cookies when served over TLS
- [x] Twelve-hour absolute session lifetime
- [x] Protected application pages and APIs
- [x] CSRF header enforcement for authenticated state changes
- [x] Progressive account-and-source login throttling
- [x] No permanent automatic account lockout
- [x] Failed-login audit events without submitted credentials
- [x] Active-session inventory
- [x] Current-session identification
- [x] Individual session revocation
- [x] Revoke all other sessions
- [x] Logout with immediate server-side invalidation
- [x] Account Security page

### WebAuthn and FIDO2

- [x] WebAuthn relying-party dependency selected and integrated
- [x] Configurable relying-party ID
- [x] Explicit allowed-origin configuration
- [x] HTTPS required outside localhost and loopback
- [x] Cross-origin ceremonies disabled
- [x] User verification required
- [x] Privacy-preserving no-attestation default
- [x] Startup configuration validation
- [x] Encrypted WebAuthn credential persistence
- [x] Persistent, expiring, single-use registration ceremonies
- [x] Persistent, expiring, single-use authentication ceremonies
- [x] Registration requires recently verified MFA
- [x] Multiple named credentials per user
- [x] Security-key, Windows Hello, Touch ID, and passkey enrollment
- [x] WebAuthn login and second-factor verification
- [x] Sign-counter and backup-state updates after successful authentication
- [x] Credential removal safeguards
- [x] WebAuthn browser interface
- [x] WebAuthn security, replay, and origin-validation tests

### Users, invitations, and authorization

- [x] Administrator user-management interface
- [x] Local-user invitations
- [x] SSO-user invitations
- [x] Random, single-use, hashed invitation tokens
- [x] Invitation expiration and acceptance flow
- [x] Administrator role enforcement
- [x] Analyst role enforcement
- [x] Viewer role enforcement
- [x] Disable and reactivate users
- [x] Revoke sessions after role or account-status changes
- [x] Prevent disabling or demoting the final active local Administrator
- [x] Require recent MFA for sensitive identity changes

### Entra ID and AD FS federation

- [x] Administrator-managed OIDC provider configuration
- [x] Entra ID authorization-code flow with PKCE
- [x] AD FS authorization-code flow with PKCE
- [x] OIDC discovery and signed ID-token validation
- [x] Exact issuer, audience, nonce, state, redirect, and tenant validation
- [x] Encrypted OIDC client-secret storage
- [x] Provider test-login workflow before activation
- [x] Explicit provider enable and disable controls
- [x] SSO logout behavior

### SSO provisioning

- [x] Invite-only provisioning as the default
- [x] Immutable provider-and-subject identity links
- [x] Optional Entra just-in-time provisioning
- [x] Approved-tenant restriction
- [x] Approved email-domain restriction
- [x] Approved group restriction
- [x] Group-to-role mappings
- [x] Viewer as the default JIT role
- [x] Explicit warning and confirmation for JIT Administrator mappings
- [x] Re-evaluate group-derived access during subsequent logins

### Audit and policy administration

- [x] Searchable audit-event interface
- [x] Audit-event retention policy
- [x] Database-managed authorized CIDR policies
- [x] Database-managed allowed-port policies
- [x] Per-policy target and concurrency limits
- [x] Authentication policy settings
- [x] MFA requirements by role
- [x] Configurable session duration
- [x] Trusted reverse-proxy configuration

### Server deployment hardening

- [x] Explicit local, direct-TLS, ACME, and reverse-proxy transport modes
- [x] Direct TLS configuration with TLS 1.2 minimum
- [x] Certificate validity, hostname, expiration, and private-key permission validation
- [x] Trusted reverse-proxy HTTPS and client-address handling
- [x] Hosted request-host validation
- [x] Secure proxy-aware cookies, HSTS, and sensitive-response cache controls
- [x] Reverse-proxy deployment guidance
- [x] Hardened Linux systemd service definition and installation guidance
- [x] Native Windows Service installation, lifecycle, recovery, and event logging
- [x] Identity-key backup and restore procedure
- [x] Versioned identity-key keyring with legacy raw-key compatibility
- [x] Crash-safe identity-key rotation and transactional ciphertext migration
- [x] Mandatory pre-rotation backup and retained recovery key
- [x] Consistent SQLite backup and integrity-checked restore workflow
- [x] Versioned server backup manifest with per-file SHA-256 checks
- [x] Optional ACME and endpoint-PKI continuity in server backups
- [x] Staged restore with recoverable pre-restore copies
- [x] Authentication-aware readiness endpoint
- [x] Secure startup validation for hosted deployments

## Approved and queued

### Certificate automation and endpoint identity

- [x] ACME account registration and persistent certificate lifecycle
- [x] Explicit certificate-authority terms acceptance
- [x] Exact-host ACME issuance policy
- [x] ACME HTTP-01 validation
- [x] ACME TLS-ALPN-01 validation
- [x] ACME staging and custom standards-compliant directory support
- [x] Owner-only ACME account and certificate cache
- [x] Automatic certificate renewal and graceful in-memory replacement
- [x] Renewal status, expiration warnings, failure visibility, and audit events
- [x] Mossward private root and online agent-issuing intermediate CA
- [x] Dedicated TLS 1.3 endpoint API listener and private-PKI server identity
- [x] Hashed, expiring, single-use endpoint enrollment tokens
- [x] Endpoint-generated private keys and constrained CSR signing
- [x] Immutable per-endpoint SPIFFE-style certificate identity
- [x] Per-endpoint mutually authenticated TLS identity and check-in
- [x] Endpoint certificate renewal, revocation, inventory, and alerts

## Ordered implementation roadmap

Work through this sequence unless a review explicitly changes product priority.
Items within a slice are ordered by dependency. Completed prerequisites remain
checked so the next unfinished dependency is unambiguous.

### 1. Distributed scanner-worker MVP — complete

- [x] Explicit worker enrollment, revocation, and mutually authenticated identity
- [x] Worker health, version, certificate, capacity, and capability heartbeats
- [x] Administrator-assigned network, port, concurrency, rate, and site scopes
- [x] Signed, expiring, declarative jobs with worker-side scope validation
- [x] Outbound-only mTLS polling with worker-bound atomic leases
- [x] Persistent replay protection, completion receipts, and duplicate rejection
- [x] Signed evidence batches and persistent target-and-port checkpoints
- [x] Encrypted bounded outbox, backpressure, retry jitter, and load-aware dispatch
- [x] Safe checkpoint-based failover after explicit lease expiration
- [x] Per-worker and global job-dispatch kill switches
- [x] Constrained worker scan runtime using only declared targets, ports, and checks
- [x] Explicit local-or-remote policy execution with no automatic fallback
- [x] Authenticated active-job lease renewal bounded by the signed job expiration
- [x] Manual and scheduled remote policies create signed worker-bound jobs
- [x] Exact-retry idempotency with altered-payload replay rejection
- [x] Worker poll, execute, lease-renew, encrypted-outbox, and upload loop
- [x] Project accepted remote observations, findings, checkpoints, CVEs, and worker provenance into scans and assets
- [x] Deployable scanner-worker command with strict mTLS, trust-key, scope, and encrypted-state configuration
- [x] End-to-end policy launch, remote execution, evidence ingestion, and resume
- [x] Dead-letter quarantine for repeatedly failing jobs
- [x] Fleet health visibility for offline, outdated, revoked, and overloaded workers

Do failover before enabling execution so interrupted work cannot silently duplicate
checks. Add kill switches before the runtime so administrators can stop dispatch
without disabling identity or evidence delivery. Dead-letter handling and fleet
visibility follow the working end-to-end path because they depend on real runtime
failure and health states.

## Delivered foundations referenced by the roadmap

### Asset inventory

- [x] Durable asset records independent of individual scans
- [x] Asset identity and address correlation
- [x] Ownership, environment, and classification fields
- [x] Custom asset groups with multi-group membership
- [x] Explicit Administrator acknowledgement for overlapping memberships
- [x] Reverse visibility from groups to referencing scan policies
- [x] Service and exposure history
- [x] Evidence provenance across scanner and endpoint source types
- [x] Audited manual asset retirement and restoration
- [x] Configurable asset aging behavior with a 30-day default
- [x] Administrator-reviewed asset merge behavior with field-level and Apply all choices

### Scan policies and scheduling

- [x] Reusable scan profiles
- [x] Group-targeted scan policies with address deduplication
- [x] Per-target group provenance retained on policy-launched scans
- [x] Scheduled scans
- [x] Scan cancellation with partial evidence retention and audit logging
- [x] Smooth per-policy check-rate limits with friendly presets and advanced control
- [x] Maintenance windows
- [x] Per-policy IANA timezone and daylight-saving-aware execution
- [x] Friendly one-time, daily, and weekly schedules with advanced cron
- [x] Configurable missed-run behavior and overlapping-run skips
- [x] Persistent target-and-port checkpoints across maintenance windows
- [x] Configurable cumulative active-runtime email alerts
- [x] Administrator-managed TLS SMTP settings with encrypted credentials
- [x] Launch remote scan policies into signed distributed-worker jobs
- [x] Signed and scope-limited worker jobs

## Remaining ordered roadmap

### 2. Scan interface and results UX

- [x] Split the scan experience into focused linked pages or sections instead
      of one oversized page
- [x] Add scan-result sorting and configurable filters
- [x] Redesign the overall scan-results presentation for clearer hierarchy,
      readability, and responsive use
- [x] Add findings-specific sorting and filtering controls

### 3. Declarative checks

- [x] Signed declarative check format
- [x] HTTP configuration checks
- [x] TLS configuration checks
- [x] SSH configuration checks
- [x] Check-version lifecycle and trust policy
- [x] Separate policy for any future intrusive checks

### 4. Reporting and evidence lifecycle

- [x] Finding status and assignment
- [x] Exceptions and accepted-risk records
- [x] Evidence retention and aging
- [x] Trend reporting
- [x] Executive summaries
- [x] CSV and structured-data exports
- [x] Printable reports

### 5. Endpoint-agent core

- [x] Explicit enrollment and revocation
- [x] Mutually authenticated device identity
- [x] Outbound-only agent communication
- [x] Read-only collector allowlist
- [x] Signed Linux endpoint agent
- [x] Signed Windows endpoint agent
- [x] Signed, rollback-capable updates

### 6. Endpoint extension framework

- [x] Versioned module interface and capability declarations
- [x] Signed manifests, package checksums, and trusted-publisher policy
- [x] Declarative inventory and configuration-check modules
- [x] Isolated low-privilege native-module host for OS-integrated detectors
- [x] Explicit filesystem, network, resource, and data-access permissions
- [x] Prevent modules from accessing endpoint identity private keys
- [x] Server-side module catalog and per-group or per-endpoint assignments
- [x] Compatibility checks across module, agent, and operating-system versions
- [x] Staged deployment rings, module health reporting, and rollback
- [x] Per-module resource limits, crash isolation, and emergency disable controls
- [x] Versioned developer SDK, validation tools, and testing harness
- [x] Prohibit arbitrary web-uploaded scripts, undeclared downloads, permission
      expansion, self-propagation, and unreviewed shell execution

### 7. Endpoint inventory and CVE evidence

- [x] Operating-system and patch inventory
- [x] Installed package and application inventory
- [x] Listening service and owning-process inventory
- [x] Local security-posture evidence
- [x] Endpoint-backed CVE correlation

### 8. Endpoint network telemetry

- [x] Optional privacy-bounded outbound connection metadata
- [x] Process-to-destination correlation
- [x] DNS and available TLS server-name context
- [x] Threat-intelligence indicator correlation (exact IP and hostname matching; detection only)
- [x] Indicator source, confidence, timestamp, and expiration
- [x] Configurable application and destination exclusions
- [x] No payload capture or TLS interception (immutable metadata-only contract)

### 9. Endpoint coverage and integrity

- [x] Opt-in missing-agent coverage detection
- [x] Authorized-segment discovery policies
- [x] Agent-eligible and agent-ineligible classifications
- [x] Stale-agent and missed-heartbeat alerts
- [x] Agent executable, configuration, and identity integrity events
- [x] Signed and sequence-numbered tamper events
- [x] Maintenance-window suppression with retained audit history

### 10. Optional endpoint relay

- [x] Explicit relay promotion and revocation
- [x] Approved downstream agent allowlist
- [x] Dedicated Mossward transport only
- [x] End-to-end signed and encrypted messages
- [x] Bounded encrypted store-and-forward queue
- [x] Relay health, capacity, and tamper telemetry
- [x] Approved failover behavior
- [x] Direct-versus-relayed path visibility

### 11. Relay communication windows and delayed telemetry

- [x] Administrator-defined relay upload windows with per-policy timezone
- [x] Outbound relay-to-server connections only during approved windows
- [x] Per-node and per-group `allow delayed heartbeats` policy
- [x] Explicit node settings overriding inherited group heartbeat policy
- [x] Preserve both generated-at and server-received-at heartbeat timestamps
- [x] Window-aware stale-node alerts with configurable post-window grace period
- [x] Encrypted, bounded queue for delayed heartbeats and Mossward agent logs
- [x] Signed, sequenced, compressed agent-log batches with source provenance
- [x] Priority queueing for integrity and tamper alerts during closed windows
- [x] Acknowledge-before-delete delivery with duplicate rejection and resume
- [x] Queue age, capacity, dropped-record, and last-upload visibility
- [ ] Clock-drift detection so incorrect endpoint time cannot silently bypass windows
- [ ] Exclude Windows Event Logs, syslog, and general application-log collection
      unless Mossward's product scope is explicitly expanded later

### 12. Later platform scale and worker operations

- [ ] Organization and tenant boundaries
- [ ] Per-organization scope policies
- [ ] PostgreSQL storage option
- [ ] Independently deployable control plane and scanner-worker runtime
- [ ] Signed staged worker updates with deployment rings and rollback
- [ ] Prohibit arbitrary payload execution, self-propagation, covert persistence,
      peer-to-peer control, and automatic scope expansion
- [ ] Append-only administrative audit stream
- [ ] High-availability deployment guidance

## Product boundaries

- Mossward is detection and assessment software, not an exploitation platform.
- Network and endpoint checks remain non-destructive and authorization-scoped.
- Endpoint telemetry is metadata-oriented; payload capture and TLS interception
  are excluded by default.
- Mossward reports evidence and confidence rather than claiming proof when data
  is ambiguous.
- Automatic remediation, arbitrary remote commands, stealth, credential attacks,
  and adversarial self-defense are outside the current product scope.
