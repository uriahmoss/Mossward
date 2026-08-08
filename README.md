# Mossward

Mossward is an original, defensive vulnerability-management project for assets you own or are explicitly authorized to assess. It provides scoped TCP visibility, safe service identification, and initial HTTP, TLS, SSH, and exposure checks.

It does not exploit services, guess credentials, evade monitoring, or scan public addresses by default.

Implementation status and the maintained roadmap are tracked in
[`docs/FEATURES.md`](docs/FEATURES.md).
Hosted transport configuration and reverse-proxy examples are documented in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).
Linux and Windows Server installation is covered in
[`docs/SERVICE_INSTALLATION.md`](docs/SERVICE_INSTALLATION.md).
Server-state protection and disaster recovery are documented in
[`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md).

Administrators can manage database-backed scan scope policies from the Users
page. Every scan selects an enabled policy, and Mossward enforces that policy's
authorized CIDRs, allowed ports, target limit, and concurrency limit before and
during execution. Environment limits remain server-wide safety caps.

Current service inspection includes:

- HTTP status, page title, and selected non-secret response headers
- HTTPS and generic TLS certificate and protocol metadata
- SSH and passive generic banner evidence
- Product/version identification when explicitly disclosed
- Confidence levels for service observations

Current non-destructive checks include:

- Cleartext HTTP
- Missing HTTP security headers
- Disclosed service versions
- Expired or soon-to-expire TLS certificates
- TLS hostname mismatches
- TLS 1.0 or TLS 1.1 support
- Reachable SSH, SMB, RDP, PostgreSQL, and Redis services
- Version-qualified CVE correlation against a locally synchronized NVD dataset

The homepage includes a critical-CVE watch feed. CVEs matched to product and
version evidence from completed scans are prioritized and labeled as environment
matches. When Mossward has no qualified local matches, the panel falls back to
recent critical records. CISA Known Exploited Vulnerability status is retained
when NVD supplies it.

Mossward sends a bounded HTTP `GET /`, TLS ClientHello, or passive banner read
only when applicable. It does not follow HTTP redirects, and every connection
uses the pinned IP address approved during scope validation.

## Run locally

Requirements: Go 1.26 or newer.

```sh
cd Mossward
go run ./cmd/mossward
```

Open <http://127.0.0.1:8080> for the Mossward feature homepage. Choose
**Network scan** to configure and review scans. Results are stored in
`data/mossward.db`.

On first launch, Mossward redirects to a localhost-only setup page. The first
identity is always a local Administrator and setup is not complete until a TOTP
authenticator code has been verified. Save the displayed single-use recovery
codes before continuing. Subsequent local sign-ins require the password plus
an authenticator or unused recovery code.

Repeated login failures are tracked by both normalized account and source
address. Mossward applies progressively longer temporary blocks without
permanently locking the account, and records failed attempts without retaining
submitted credentials. The Account page lists active sessions and supports
individual revocation, revoking every other session, and logout.

When upgrading from a JSON-backed Mossward version, existing
`data/scans.json` history is imported automatically on first startup and
preserved as `data/scans.json.imported`.

Recent scans link to a dedicated detail view with live check progress, approved
scope, timing, reachable services, evidence, and remediation guidance.

Scan targets may be individual IP addresses, fully qualified domain names,
CIDR blocks such as `192.168.1.0/24`, or inclusive ranges such as
`192.168.2.10-192.168.2.25`. IPv4 network and broadcast addresses are omitted
for CIDRs of `/30` or larger networks. Expanded addresses must remain within
the configured target limit and authorization allowlist.

For the standard development workflow:

```sh
make run
make verify
make build
```

Synchronize the latest CVE intelligence manually before scanning:

```sh
go run ./cmd/mossward cve sync
```

Create and validate a protected server backup:

```sh
mossward backup create --output /secure/backups/mossward.tar.gz
mossward backup inspect --input /secure/backups/mossward.tar.gz
```

Rotate the identity encryption key while the service is stopped:

```sh
mossward identity-key rotate --backup /secure/backups/pre-rotation.tar.gz --confirm-rotation
```

The initial implementation imports CVEs published during the last 120 days,
which is the maximum date window accepted by one NVD API request. Use
`--days 30` for a smaller refresh. Set `MOSSWARD_NVD_API_KEY` to an NVD API key
to use the authenticated request cadence. Feed failures do not prevent network
scans, and the homepage always displays the last successful refresh state.

`make build` writes the executable to `bin/mossward`. All generated files stay
inside this project directory.

## Project layout

```text
Mossward/
├── cmd/mossward/       Application entry point
├── config/             Example runtime configuration
├── data/               Local scan data (ignored by Git)
├── deploy/             Linux systemd and Windows Service assets
├── docs/               Architecture and design documentation
├── internal/
│   ├── api/            HTTP routes and transport concerns
│   ├── agentidentity/  Private PKI, enrollment, and endpoint mTLS identity
│   ├── config/         Configuration parsing
│   ├── intelligence/   NVD ingestion, normalization, and version comparison
│   ├── model/          Core domain types
│   ├── probe/          Safe protocol identification and checks
│   ├── scanner/        Scope validation and scan execution
│   └── store/          SQLite schema, migrations, and queries
├── web/                Embedded browser interface
├── Dockerfile          Reproducible container build
├── Makefile            Development commands
└── go.mod              Isolated Go module
```

Mossward is intentionally a self-contained module. It does not import or depend
on scripts elsewhere in the parent repository.

## Run in a container

Build the image with `docker build -t mossward .`. A container must use direct
TLS or reverse-proxy mode because its listener cannot remain host-loopback-only.
Mount persistent data and any manual TLS material rather than storing it in the
container layer. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) before publishing
the service.

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MOSSWARD_LISTEN` | `127.0.0.1:8080` | Server listen address |
| `MOSSWARD_TRANSPORT_MODE` | `local` | `local`, manual `tls`, automatic `acme`, or trusted `proxy` transport |
| `MOSSWARD_PUBLIC_ORIGIN` | `http://localhost:8080` | Exact externally visible origin and permitted hosted request authority |
| `MOSSWARD_TLS_CERT_FILE` | Empty | Certificate chain used in direct TLS mode |
| `MOSSWARD_TLS_KEY_FILE` | Empty | Owner-only private key used in direct TLS mode |
| `MOSSWARD_ACME_EMAIL` | Empty | ACME account contact, required in ACME mode |
| `MOSSWARD_ACME_ACCEPT_TOS` | `false` | Explicit acceptance of the configured ACME provider's terms |
| `MOSSWARD_ACME_CACHE_DIR` | `data/acme` | Owner-only ACME account and certificate cache |
| `MOSSWARD_ACME_DIRECTORY_URL` | Let's Encrypt production | Standards-compliant ACME directory endpoint |
| `MOSSWARD_ACME_HTTP_LISTEN` | `:80` | HTTP-01 challenge listener |
| `MOSSWARD_TRUSTED_PROXY_CIDRS` | Empty | Immediate proxies allowed to supply forwarded client and HTTPS information |
| `MOSSWARD_AGENT_LISTEN` | Empty | Dedicated TLS 1.3 mTLS endpoint API listener |
| `MOSSWARD_AGENT_SERVER_NAMES` | Empty | Names permitted on the endpoint API server certificate |
| `MOSSWARD_AGENT_PKI_DIR` | `data/agent-pki` | Owner-only private endpoint PKI directory |
| `MOSSWARD_DATABASE_FILE` | `data/mossward.db` | SQLite database path |
| `MOSSWARD_DATA_FILE` | `data/scans.json` | Legacy JSON path used only for one-time import |
| `MOSSWARD_IDENTITY_KEY_FILE` | `data/identity.key` | Owner-only AES-256 key used to encrypt identity-provider and MFA secrets |
| `MOSSWARD_ALLOWED_CIDRS` | Loopback and RFC1918/ULA networks | Networks the scanner may assess |
| `MOSSWARD_ALLOWED_PORTS` | Common administrative and web ports | Ports users may request |
| `MOSSWARD_MAX_TARGETS` | `256` | Maximum requested target names per scan |
| `MOSSWARD_MAX_CONCURRENT` | `32` | Maximum simultaneous connections |
| `MOSSWARD_QUEUE_SIZE` | `16` | Maximum pending scans |
| `MOSSWARD_CONNECT_TIMEOUT_MS` | `800` | Per-connection timeout in milliseconds |

Treat changes to the CIDR allowlist as security-policy changes. Only add networks for which you have documented authorization.

Hostnames are resolved during request validation, and the approved addresses
are stored in the scan job. Connections use those pinned addresses rather than
performing a second DNS lookup.

An annotated starting configuration is available at
`config/mossward.env.example`. Copy it to `.env` if needed; `.env` is ignored
so machine-specific policy does not enter source control.

## Current API

- `GET /api/health`
- `GET /api/ready`
- `GET /api/admin/certificate-status`
- `GET /api/admin/endpoints`
- `GET /api/admin/agent-enrollment-tokens`
- `POST /api/admin/agent-enrollment-tokens`
- `POST /api/admin/endpoints/{id}/revoke`
- `POST /api/agent/enroll`
- `GET /api/config`
- `GET /api/scans`
- `POST /api/scans`
- `GET /api/scans/{id}`
- `GET /api/assets`
- `GET /api/assets/{id}`
- `PATCH /api/assets/{id}`
- `GET /api/asset-groups`
- `POST /api/admin/asset-groups`
- `POST /api/admin/asset-groups/{id}/members/{asset}`
- `GET /api/scan-policies`
- `POST /api/admin/scan-policies`
- `POST /api/scan-policies/{id}/run`
- `GET /api/admin/smtp`
- `PUT /api/admin/smtp`
- `GET /api/intelligence/news`
- `GET /api/intelligence/status`

The separate mTLS endpoint API exposes `POST /api/agent/v1/check-in` and
`POST /api/agent/v1/certificate/renew`. Renewal authenticates the current
endpoint certificate and accepts a newly generated public-key CSR during the
certificate's final 30 days.

Reusable scan policies support manual, one-time, daily, weekly, and standard
five-field cron schedules. Each policy selects an IANA timezone and may define
a maintenance window. At the window boundary Mossward stops dispatching new
checks, persists completed address-and-port checkpoints, and resumes remaining
work in the next window. Missed occurrences default to being skipped. SMTP
long-running alerts measure cumulative active scan time and exclude paused time.
Queued, running, and maintenance-paused scans can be canceled by analysts or
administrators while retaining completed checks and collected evidence.
Reusable policies can also pace check dispatch smoothly from 1 to 1,000 checks
per second, or use an unlimited rate, independently of concurrency controls.

The distributed-scanner foundation supports short-lived, single-use worker
enrollment, worker-generated private keys, SPIFFE-style mutually authenticated
identity, explicit network and resource scopes, check-in inventory, and audited
revocation. Distributed scan-job execution is not enabled yet.
Versioned worker heartbeats report a constrained capability allowlist, software
and platform versions, available concurrency, and healthy or degraded state.
Workers that do not check in for five minutes are flagged as offline.
Distributed jobs use a versioned declarative envelope signed by a dedicated
Ed25519 key that is separate from the certificate authority. Job validation
enforces the enrolled worker's networks, ports, capabilities, concurrency, and
rate limits, while persistent unique job identifiers provide replay tracking.
Job polling and execution remain disabled until the next transport slices.

Durable asset evidence records retain the source type, source identity,
originating record, collection time, address, and source scan when applicable.
The same constrained provenance model accepts authenticated endpoint evidence
when endpoint collectors are implemented; Mossward does not currently claim
that an endpoint collector is available.

Scanner workers can now poll the control plane over their existing outbound
mTLS connection. The server leases only jobs explicitly assigned to the
authenticated worker, stores only a hash of the short-lived lease credential,
and safely makes abandoned jobs available again after lease expiration.

The control plane also accepts bounded completion receipts for actively leased
jobs. Each receipt is bound to the authenticated worker and one-time lease,
records a unique result identifier and outcome, and atomically consumes the
lease so duplicate submissions cannot change completed job state.

The scanner-worker runtime has an owner-only persistent replay ledger. A worker
must verify a job's Ed25519 signature, identity,
validity window, assigned networks, ports, resource limits, and capabilities
before atomically recording the job ID. Previously recorded IDs remain blocked
after process restarts, and the ledger is claimed before the executor acts.

The constrained executor runs only the target, port, concurrency, rate, and
inspection capabilities declared by the verified job. It skips signed resume
checkpoints, stops at job expiration or cancellation, and emits bounded,
sequential evidence with a checkpoint for every attempted target-and-port pair.
Packaging this executor into an independently deployed worker process and wiring
the complete poll-to-upload loop remain part of the next integration slice.

Scanner-worker evidence can be transferred in bounded, certificate-signed
batches over the authenticated worker channel. Each batch carries immutable
worker, job, scan, certificate, and sequence provenance; observations and
findings are restricted to the job's exact targets and ports. The control plane
rejects tampering, duplicate IDs, sequence gaps, expired leases, and data after
a final batch. A successful completion receipt requires final evidence, while
failed or canceled jobs may close without observations.

Distributed jobs persist signed completion checkpoints for every finished
target-and-port pair, including checks that produce no positive observation.
Checkpoint writes are idempotent across evidence batches and survive lease or
process interruption. A worker job cannot report successful completion until
the server has the complete expected checkpoint matrix. After an explicit lease
expiration, the dispatcher can re-sign the same job for a different eligible
worker with a signed resume manifest containing completed checkpoints and the
next evidence sequence. The reassignment is atomic, retains assignment history,
and rejects late evidence from the previous worker.

The scanner-worker client foundation includes a bounded FIFO outbox for signed
evidence and completion messages when the control plane is temporarily
unavailable. Payloads are protected at rest with AES-256-GCM and a dedicated
owner-only local key. The queue never evicts older evidence to admit new data,
detects duplicate IDs and ciphertext tampering, and removes a message only
after its delivery callback succeeds. Live worker-runtime integration remains
separate scheduling work.

Worker scheduling now has configurable exponential retry and outbox-pressure
foundations. Positive cryptographic jitter spreads reconnect attempts without
shortening a server-provided `Retry-After`, while bounded delays prevent
uncontrolled wait growth. Workers can pause new-job polling at a configured
queue threshold and continue forwarding already collected evidence.

The control-plane dispatcher can now select a fresh, healthy worker whose
assigned networks, ports, capabilities, rate limit, and available concurrency
fit a job. Pending and leased jobs reserve capacity, selection and persistence
are serialized to avoid local over-assignment, and deterministic load balancing
prefers fewer active jobs before remaining capacity and heartbeat freshness.
Administrators can assign an optional normalized site identifier when creating
a worker enrollment token. Jobs without a site use normal load-aware selection;
jobs with a site are dispatched only to workers carrying that exact identifier,
with no implicit cross-site fallback.

Administrators can pause all new scanner-worker dispatch or pause an individual
worker without revoking its identity. These audited controls block both new job
assignment and pending-job leases while allowing heartbeats, active-job evidence,
and completion delivery to continue.

Reusable scan policies explicitly select local server execution or remote worker
execution; existing and newly created policies default to local. Remote policies
may require a worker site and never fall back to local execution. Once assigned,
a job remains bound to that worker unless the server issues a signed reassignment
after its lease has expired.

An active worker can renew its authenticated lease before expiration using the
same one-time lease credential and mTLS identity. Renewals never move the job,
never revive an expired lease, never shorten an existing lease, and cannot extend
past the expiration carried in the signed job.

Manual and scheduled reusable policies share one execution launcher. Local
policies enter the server scanner queue, while remote policies persist the scan
and create a signed worker-bound job through the load-aware dispatcher. Dispatch
failure is recorded on the scan and never triggers local fallback. Remote jobs
are valid for at most 24 hours, use a 12-hour default, honor shorter maintenance
windows, and are assigned only when the worker certificate covers the job.

The worker client runtime drains its encrypted outbox before polling, pauses new
work when configured queue pressure is reached, verifies and claims each signed
job, executes it, renews its active lease, and queues evidence before completion.
Messages retain insertion order and are deleted only after a successful server
response. Exact evidence and completion retries are acknowledged idempotently,
while an accepted identifier reused with changed content remains a replay error.
Accepted remote evidence is projected into the originating scan using the same
observations, findings, CVE matching, checkpoints, and asset history as local
execution. Asset evidence retains the scanner-worker identity as its source.
Jobs that exhaust three lease attempts enter durable dead-letter quarantine.
They cannot be leased or reassigned again, their scans visibly fail, and their
failure count, reason, worker, and quarantine time remain available for review.
The administrator worker inventory derives a fleet state for healthy, degraded,
offline, outdated, overloaded, and revoked workers and shows active workload and
reserved concurrency alongside heartbeat and certificate alerts.
The deployable `mossward-worker` command and its strict configuration are
documented in [`docs/SCANNER_WORKER.md`](docs/SCANNER_WORKER.md).

Asset lifecycle management marks systems stale after a configurable interval
(30 days by default), supports audited retirement and restoration, and provides
an administrator-reviewed merge workflow that preserves identity, group,
service, and evidence history.

Example:

```sh
curl -X POST http://127.0.0.1:8080/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"name":"Local host","targets":["127.0.0.1"],"ports":[80,443]}'
```

## Roadmap

1. Add authenticated users, roles, audit logs, and per-organization scope policies.
2. Introduce a signed declarative check format with HTTP/TLS/SSH configuration checks.
3. Add scheduling, cancellation, rate limits, and distributed workers.
4. Add PostgreSQL support when multi-user or distributed deployment requires it.
5. Add an optional endpoint agent for authenticated local inventory and
   vulnerability assessment on enrolled Linux and Windows systems, including
   privacy-bounded outbound network telemetry and threat-intelligence
   correlation. Add opt-in endpoint coverage detection that identifies
   agent-eligible devices without a current enrollment, plus agent-integrity
   and missed-heartbeat alerts for possible tampering. Optionally allow an
   explicitly designated endpoint to relay end-to-end protected agent traffic
   from an isolated network segment.
6. Extend CVE ingestion with incremental modified-date synchronization, broader
   product mappings, vendor-advisory enrichment, and endpoint inventory evidence.
7. Add evidence lifecycle, remediation workflow, exceptions, exports, and reporting.

The scanner should remain non-destructive by default. Intrusive checks, if ever introduced, must require an explicit policy, authorization record, and separate execution profile.
