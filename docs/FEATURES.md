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

## Approved and queued

### Server deployment hardening

- [ ] Direct TLS configuration
- [ ] Reverse-proxy deployment guidance
- [ ] Linux systemd service definition and installation guidance
- [ ] Windows Service installation and lifecycle support
- [ ] Identity-key backup and restore procedure
- [ ] Identity-key rotation procedure
- [ ] SQLite backup and restore workflow
- [ ] Authentication-aware readiness endpoint
- [ ] Secure startup validation for hosted deployments

## Roadmap — not yet started

### Asset inventory

- [ ] Durable asset records independent of individual scans
- [ ] Asset identity and address correlation
- [ ] Ownership, environment, and classification fields
- [ ] Service and exposure history
- [ ] Evidence provenance across scanner and endpoint sources
- [ ] Asset aging, merge, and retirement behavior

### Scan policies and scheduling

- [ ] Reusable scan profiles
- [ ] Scheduled scans
- [ ] Scan cancellation
- [ ] Per-policy rate limits
- [ ] Maintenance windows
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
