# Mossward transport deployment

Mossward has three explicit transport modes. Complete the localhost-only first
administrator setup before moving an installation into a hosted mode. A hosted
installation that is not initialized remains live but reports `setup_required`
and HTTP 503 from `/api/ready`.

## Local mode

Local mode is the default and permits HTTP only on a loopback listener.

```text
MOSSWARD_TRANSPORT_MODE=local
MOSSWARD_LISTEN=127.0.0.1:8080
MOSSWARD_PUBLIC_ORIGIN=http://localhost:8080
```

## Direct TLS mode

Direct TLS uses an administrator-provided certificate. The certificate must be
current and cover the public-origin hostname. On Unix systems, the private key
must not grant group or other permissions.

```text
MOSSWARD_TRANSPORT_MODE=tls
MOSSWARD_LISTEN=0.0.0.0:8443
MOSSWARD_PUBLIC_ORIGIN=https://mossward.example.com:8443
MOSSWARD_TLS_CERT_FILE=/etc/mossward/tls/fullchain.pem
MOSSWARD_TLS_KEY_FILE=/etc/mossward/tls/private-key.pem
MOSSWARD_WEBAUTHN_RP_ID=mossward.example.com
MOSSWARD_WEBAUTHN_ORIGINS=https://mossward.example.com:8443
```

Mossward permits TLS 1.2 and TLS 1.3. It refuses expired, not-yet-valid, or
hostname-mismatched certificates and warns 30 days before expiration.

## Automatic TLS with ACME

ACME mode obtains and renews a certificate for the exact public-origin
hostname. The hostname must be public DNS, and the administrator must explicitly
accept the selected certificate authority's terms. Mossward never accepts terms
implicitly.

```text
MOSSWARD_TRANSPORT_MODE=acme
MOSSWARD_LISTEN=:443
MOSSWARD_PUBLIC_ORIGIN=https://mossward.example.com
MOSSWARD_WEBAUTHN_RP_ID=mossward.example.com
MOSSWARD_WEBAUTHN_ORIGINS=https://mossward.example.com
MOSSWARD_ACME_EMAIL=admin@example.com
MOSSWARD_ACME_ACCEPT_TOS=true
MOSSWARD_ACME_CACHE_DIR=data/acme
MOSSWARD_ACME_HTTP_LISTEN=:80
```

The default directory is Let's Encrypt production. Test initial routing with
the staging directory before switching to production:

```text
MOSSWARD_ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory
```

HTTP-01 requires inbound TCP 80 to reach `MOSSWARD_ACME_HTTP_LISTEN`.
TLS-ALPN-01 uses the primary TLS listener, normally TCP 443. Mossward supports
both challenge types and the ACME server selects an available method. The ACME
cache contains the account key and certificates; it is created with owner-only
directory and file permissions and must be included in protected server backups.

The Users administration page reports whether the certificate is pending,
active, due for renewal, or in error. Mossward logs issuance, renewal, request
failures, and certificates approaching expiration. Issuance and renewal are
also appended to the administrative audit stream.

ACME cannot generally issue certificates for IP addresses, localhost, or
private-only DNS names. In reverse-proxy mode, let the proxy manage ACME instead.

## Reverse-proxy mode

Keep the backend listener private. List only the immediate proxy addresses or
networks in `MOSSWARD_TRUSTED_PROXY_CIDRS`; never use a broad client network.

```text
MOSSWARD_TRANSPORT_MODE=proxy
MOSSWARD_LISTEN=127.0.0.1:8080
MOSSWARD_PUBLIC_ORIGIN=https://mossward.example.com
MOSSWARD_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
MOSSWARD_WEBAUTHN_RP_ID=mossward.example.com
MOSSWARD_WEBAUTHN_ORIGINS=https://mossward.example.com
```

Nginx location configuration:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Caddy configuration:

```caddyfile
mossward.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy supplies the preserved host, forwarded scheme, and client-address chain.
Mossward ignores these headers unless the direct peer is trusted. Proxy-mode
requests without a trusted HTTPS indication are rejected.

## Health checks

- `GET /api/health` is a process liveness check.
- `GET /api/ready` checks the scanner, database-backed identity state, and
  initialization state without returning internal error details.
- `GET /api/admin/certificate-status` reports certificate state to authenticated
  administrators.

Use readiness, not liveness, to decide whether a load balancer should send
production traffic to Mossward.

## PostgreSQL foundation

SQLite remains the production storage backend. PostgreSQL support is being
introduced in verified slices and is not yet selectable for a production
Mossward server. The foundation uses pgx, requires PostgreSQL 14 or newer,
serializes schema changes with an advisory transaction lock, and creates the
same immutable one-organization installation identity.

Future PostgreSQL deployments will use `MOSSWARD_DATABASE_BACKEND=postgresql`
and `MOSSWARD_DATABASE_URL`. The URL must identify a host and database and use
`sslmode=verify-full`; Mossward does not silently downgrade transport or fall
back to SQLite. Keep the URL in a service secret rather than a checked-in file
or command-line argument. Fresh installations will be supported first. Existing
SQLite databases will require the later offline migration utility and will
never be converted automatically at server startup.

The parity layer now includes PostgreSQL-native installation organization and
scope-policy tables using `TIMESTAMPTZ`, `JSONB`, relational ownership, and
database constraints. A tested SQL binder converts Mossward placeholders for
PostgreSQL while preserving quoted literal and identifier text. PostgreSQL
server startup remains blocked until every repository and audit dependency has
equivalent behavior.

PostgreSQL migration version 3 adds the foundational user table and an
append-only audit stream protected from update or deletion by a database
trigger. Organization scope-policy creation, updates, reads, and lists now have
PostgreSQL implementations; changes and their audit event commit in the same
transaction, matching the SQLite security boundary.

PostgreSQL migration version 4 provides the current fresh-install schema for
invitations, sessions, login throttling, TOTP, recovery codes, encrypted
WebAuthn credentials, one-time authentication ceremonies, OIDC providers,
external identities, and application metadata. It uses native `BYTEA`,
`BOOLEAN`, `JSONB`, and `TIMESTAMPTZ` types plus normalized-email indexes and
the same role and identity-kind constraints. Repository method parity remains
required before PostgreSQL can serve authentication traffic.

The PostgreSQL repository now supports listing users, role and status changes,
session revocation after access changes, invitations, token lookup, and atomic
local invitation acceptance with encrypted TOTP material and recovery-code
hashes. Final-local-administrator protection locks the relevant PostgreSQL rows
before counting, preventing concurrent changes from bypassing the safeguard.

First-time PostgreSQL setup now has repository parity for initialization checks,
administrator creation, encrypted TOTP material, recovery-code hashes, and
normalized local identity lookup. Bootstrap takes a transaction-scoped advisory
lock before checking for existing users, so concurrent setup requests cannot
both create the first administrator. The account and audit event commit
together.

PostgreSQL session parity now covers creation, active-user resolution, bounded
activity timestamp updates, logout, session listing, current-session marking,
single and bulk revocation, and recent-MFA timestamps. Session changes that are
security events share a transaction with the append-only audit record.

PostgreSQL authentication-state parity now includes progressive bounded login
throttling, atomic TOTP counter advancement, and single-use recovery codes with
audit events. Failed-login updates take a transaction advisory lock derived
from the already-hashed throttle key, preventing concurrent attempts from
losing increments without storing or exposing the original login identifier.

PostgreSQL WebAuthn parity now includes encrypted credential creation, listing,
state updates, and deletion. WebAuthn and OIDC ceremonies are consumed through
one atomic `DELETE ... RETURNING` statement, so simultaneous callbacks cannot
both obtain the same encrypted challenge state and kind substitution remains
rejected.

PostgreSQL OIDC parity now covers encrypted provider configuration, JSONB
tenant/domain/group/role policy, mandatory provider testing before enablement,
invite-only provisioning, JIT provisioning, external identity linking, and
group-derived role updates. Resolution locks each provider/subject pair and
relevant identity rows so concurrent callbacks cannot duplicate or cross-link
accounts; identity changes and audit records commit atomically.

PostgreSQL migration version 5 and its repository methods add authentication
policy storage, MFA-role policy reads, filtered audit queries, and controlled
retention. Ordinary audit updates and deletes remain blocked by the append-only
trigger. Retention deletion is available only through the dedicated database
routine invoked in the same transaction that stores the new policy and appends
its audit event.

PostgreSQL identity-key maintenance can now re-encrypt TOTP secrets, WebAuthn
credentials, active ceremony state, and OIDC client secrets in one transaction.
Any decrypt, encrypt, update, or audit failure rolls the entire rotation back.
PostgreSQL migration version 6 adds encrypted SMTP settings, administrator
recipient references, and per-scan long-running alert deduplication. SMTP
updates and recipient replacement are audited atomically. SMTP password
ciphertexts are now included in PostgreSQL identity-key rotation, completing
rotation parity for every encrypted identity and notification column currently
available in that backend.

PostgreSQL migration version 7 establishes the core scan data model: scans,
targets, ports, service observations and metadata, findings, and resumable scan
checkpoints. Repository query parity remains gated until the transactional scan
save and load methods are complete.

PostgreSQL migration version 8 adds the CVE catalog, affected-product ranges,
references, scan-linked CVE matches, and feed synchronization state. Endpoint
software relevance remains dependent on the later endpoint-inventory parity
slice.

PostgreSQL migration version 9 establishes asset identities and aliases,
lifecycle and aging state, service history, and evidence provenance. Scan-save
projection into these tables remains gated until its transactional repository
helpers are complete.

PostgreSQL migration version 10 adds asset groups, audited membership
relationships, reusable scan policies, ordered group targeting, scheduling
windows, missed-run behavior, rate limits, and local or remote execution mode.

PostgreSQL migration version 11 adds finding workflow indexes, administrator-
approved finding exceptions and reminder state, plus a default 365-day evidence
retention policy with configurable 30-to-3650-day bounds.

PostgreSQL migration version 12 establishes endpoint enrollment tokens,
certificate identities and lifecycle state, heartbeat timestamps, collector and
network-exclusion policy, platform version fields, and optional asset linkage.

PostgreSQL migration version 13 adds endpoint OS and patch inventory, ordered
installed-software snapshots, and endpoint-to-CVE matches with collection and
receipt timestamps kept separately.

PostgreSQL migration version 14 adds listening-service snapshots with process
ownership and executable evidence, plus pass/fail/unknown security-posture
evidence. Collection and server receipt times remain distinct.

PostgreSQL migration version 15 adds endpoint connection snapshots, process and
hostname context, expiring IP/hostname threat indicators, and referentially
bound indicator matches that are removed with their source connection.

PostgreSQL migration version 16 adds signed integrity snapshots, monotonic
sequence state, and append-only component-change events for executable,
configuration, and endpoint identity hashes.

PostgreSQL migration version 17 adds signed endpoint-agent update releases,
separate approval and revocation actors, platform-specific uniqueness, and one
active assignment state per endpoint through assigned, offered, and installed.

PostgreSQL migration version 18 adds scanner-worker enrollment and certificate
identity, health and dispatch controls, signed jobs and leases, evidence and
checkpoints, reassignment history, and dead-letter quarantine storage. The
matching worker repository operations preserve replay, lease, completion, and
quarantine controls.

PostgreSQL migration version 19 adds endpoint extension-module publisher trust,
signed staged releases, endpoint and group assignments, deterministic rollout
rings, module health state, and endpoint-to-asset links. The matching repository
operations preserve approval gates, compatibility checks, rollout selection,
audit records, and the global emergency-disable control.

## Endpoint identity and mTLS listener

Endpoint identity is optional and disabled until `MOSSWARD_AGENT_LISTEN` is
set. It uses a dedicated listener so reverse-proxy behavior cannot weaken client
certificate validation.

```text
MOSSWARD_AGENT_LISTEN=:9443
MOSSWARD_AGENT_SERVER_NAMES=mossward.example.com,10.0.0.10
MOSSWARD_AGENT_PKI_DIR=data/agent-pki
```

On first activation Mossward creates a ten-year private endpoint root CA, a
two-year online issuing intermediate CA, and a 90-day server certificate for
the configured agent server names. The listener requires TLS 1.3 and a valid,
active Mossward endpoint certificate. Browser sessions, bearer tokens, and
forwarded client-certificate headers cannot authenticate to it.

Root, intermediate, and server private keys are owner-only files. Include the
entire PKI directory in protected backups; losing it breaks established agent
trust after server recovery. A future key-lifecycle slice will cover offline
root handling and controlled rotation.

An administrator creates a 15-minute, single-use enrollment token from the
Users page. Only its SHA-256 hash is stored. The endpoint generates its own
ECDSA P-256/P-384 or RSA-2048-or-stronger key and sends a signed PEM CSR with the
token to `POST /api/agent/enroll` over the normal server HTTPS connection.
Mossward ignores requested subject names and SANs, assigning an immutable
`spiffe://mossward/endpoint/<id>` identity. The response contains the 90-day
client certificate and CA chain; the endpoint private key never leaves it.

This slice provides enrollment and authenticated `POST /api/agent/v1/check-in`
transport. Signed Linux and Windows agents, certificate renewal and revocation,
inventory collection, and relay behavior remain separate roadmap slices.
