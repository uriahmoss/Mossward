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

## Roadmap — not yet started

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
- [ ] Distributed scanner workers
- [ ] Signed and scope-limited worker jobs

### Declarative checks

- [ ] Signed declarative check format
- [ ] HTTP configuration checks
- [ ] TLS configuration checks
- [ ] SSH configuration checks
- [ ] Check-version lifecycle and trust policy
- [ ] Separate policy for any future intrusive checks

### Reporting and evidence lifecycle

- [ ] Finding status and assignment
- [ ] Exceptions and accepted-risk records
- [ ] Evidence retention and aging
- [ ] Trend reporting
- [ ] Executive summaries
- [ ] CSV and structured-data exports
- [ ] Printable reports

### Endpoint agent

- [ ] Signed Linux endpoint agent
- [ ] Signed Windows endpoint agent
- [ ] Explicit enrollment and revocation
- [ ] Mutually authenticated device identity
- [ ] Outbound-only agent communication
- [ ] Read-only collector allowlist
- [ ] Operating-system and patch inventory
- [ ] Installed package and application inventory
- [ ] Listening service and owning-process inventory
- [ ] Local security-posture evidence
- [ ] Endpoint-backed CVE correlation
- [ ] Signed, rollback-capable updates

### Endpoint extension framework

- [ ] Versioned module interface and capability declarations
- [ ] Signed manifests, package checksums, and trusted-publisher policy
- [ ] Declarative inventory and configuration-check modules
- [ ] Isolated low-privilege native-module host for OS-integrated detectors
- [ ] Explicit filesystem, network, resource, and data-access permissions
- [ ] Prevent modules from accessing endpoint identity private keys
- [ ] Server-side module catalog and per-group or per-endpoint assignments
- [ ] Compatibility checks across module, agent, and operating-system versions
- [ ] Staged deployment rings, module health reporting, and rollback
- [ ] Per-module resource limits, crash isolation, and emergency disable controls
- [ ] Versioned developer SDK, validation tools, and testing harness
- [ ] Prohibit arbitrary web-uploaded scripts, undeclared downloads, permission
      expansion, self-propagation, and unreviewed shell execution

### Endpoint network telemetry

- [ ] Optional privacy-bounded outbound connection metadata
- [ ] Process-to-destination correlation
- [ ] DNS and available TLS server-name context
- [ ] Threat-intelligence indicator correlation
- [ ] Indicator source, confidence, timestamp, and expiration
- [ ] Configurable application and destination exclusions
- [ ] No payload capture or TLS interception by default

### Endpoint coverage and integrity

- [ ] Opt-in missing-agent coverage detection
- [ ] Authorized-segment discovery policies
- [ ] Agent-eligible and agent-ineligible classifications
- [ ] Stale-agent and missed-heartbeat alerts
- [ ] Agent executable, configuration, and identity integrity events
- [ ] Signed and sequence-numbered tamper events
- [ ] Maintenance-window suppression with retained audit history

### Optional endpoint relay

- [ ] Explicit relay promotion and revocation
- [ ] Approved downstream agent allowlist
- [ ] Dedicated Mossward transport only
- [ ] End-to-end signed and encrypted messages
- [ ] Bounded encrypted store-and-forward queue
- [ ] Relay health, capacity, and tamper telemetry
- [ ] Approved failover behavior
- [ ] Direct-versus-relayed path visibility

### Multi-user and distributed scale

- [ ] Organization and tenant boundaries
- [ ] Per-organization scope policies
- [ ] PostgreSQL storage option
- [ ] Separate control plane and scanner workers
- [x] Explicit worker enrollment, revocation, and mutually authenticated identity
- [ ] Outbound-only worker polling with no required inbound listener
- [x] Server-side mTLS job polling with worker-bound atomic leases
- [x] Hashed one-time lease credentials and safe expired-lease reclamation
- [x] Worker health, version, certificate, capacity, and capability heartbeats
- [x] Administrator-assigned network, port, concurrency, and rate scopes
- [x] Signed, expiring, declarative jobs with unique identifiers
- [x] Worker-job scope validation and server-side job-identifier replay prevention
- [x] Worker-side persistent replay ledger before job execution
- [x] Lease-authenticated completion receipts and duplicate-result rejection
- [ ] Signed, sequenced evidence batches with collector provenance
- [ ] Persistent target-and-port checkpoints for interrupted distributed jobs
- [ ] Encrypted bounded store-and-forward for temporary server outages
- [ ] Load-aware assignment, site affinity, backpressure, and polling jitter
- [ ] Safe failover and reassignment after explicit lease expiration
- [ ] Per-worker and global job-dispatch kill switches
- [ ] Dead-letter quarantine for repeatedly failing jobs
- [ ] Signed staged worker updates with deployment rings and rollback
- [ ] Fleet health visibility for offline, outdated, revoked, and overloaded workers
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
