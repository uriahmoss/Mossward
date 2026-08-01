# Mossward

Mossward is an original, defensive vulnerability-management project for assets you own or are explicitly authorized to assess. It provides scoped TCP visibility, safe service identification, and initial HTTP, TLS, SSH, and exposure checks.

It does not exploit services, guess credentials, evade monitoring, or scan public addresses by default.

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
├── docs/               Architecture and design documentation
├── internal/
│   ├── api/            HTTP routes and transport concerns
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

The container retains Mossward's loopback-only default. To make it reachable
from the host, explicitly opt in to the container listener while binding the
published port to the host's loopback interface:

```sh
docker build -t mossward .
docker run --rm \
  -e MOSSWARD_LISTEN=0.0.0.0:8080 \
  -p 127.0.0.1:8080:8080 \
  -v mossward-data:/app/data \
  mossward
```

Do not publish Mossward on an external interface. Authentication and
multi-user authorization are not implemented yet.

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MOSSWARD_LISTEN` | `127.0.0.1:8080` | HTTP listen address |
| `MOSSWARD_DATABASE_FILE` | `data/mossward.db` | SQLite database path |
| `MOSSWARD_DATA_FILE` | `data/scans.json` | Legacy JSON path used only for one-time import |
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
- `GET /api/config`
- `GET /api/scans`
- `POST /api/scans`
- `GET /api/scans/{id}`
- `GET /api/intelligence/news`
- `GET /api/intelligence/status`

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
