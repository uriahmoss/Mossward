# PostgreSQL runtime verification

Run from a clone with Go (version in `go.mod`), a native PostgreSQL installation,
and a C compiler for Go race tests. Do not run as root: PostgreSQL refuses it.

Linux/macOS:

```sh
bash scripts/verify-postgres.sh --tools-dir /usr/lib/postgresql/16/bin --expected-major 16
```

Windows PowerShell:

```powershell
./scripts/Verify-PostgreSQL.ps1 -ToolsDirectory 'C:\Program Files\PostgreSQL\17\bin' -ExpectedMajor 17
```

On Homebrew/macOS, use `/opt/homebrew/opt/postgresql@16/bin` instead.
The expected-major argument detects tool-version drift; omitting it accepts
installed PostgreSQL 14 or newer. This is not a claim of verified support for
every accepted version.

## Isolation and checks

The shared Go verifier creates its own temporary cluster on a random loopback
TCP port, with SCRAM authentication and random administrator/test passwords.
It never accepts a DSN or modifies an existing PostgreSQL service. It removes
inherited PostgreSQL and Mossward environment settings before invoking tools
and injects only its own four dedicated test-database connections.

The test role cannot create roles/databases and is not a superuser. The suite
runs every test with race detection and without cached results, including live
repository parity, SQLite migration, native backup/recovery and key rotation.
It then runs Go vet and builds the server and endpoint agent.

The cluster uses non-TLS localhost connections solely for disposable synthetic
test data; production TLS requirements remain unchanged. Passwords, database
files, logs and backup artifacts are never uploaded by the workflow. Native
tool diagnostics are withheld to avoid credential exposure. On a tool failure,
inspect locally before cleanup if needed; do not publish unredacted logs.

Cleanup stops the owned cluster before deleting its temporary directory. If
shutdown cannot be confirmed, verification fails and retains the directory,
reporting its path for manual inspection. Interrupts and a 20-minute verification
deadline trigger cleanup; forced process termination may require manual cleanup.

## Hosted verification status

The shared shell entry point passed the full live suite on macOS with PostgreSQL
16.15, including clean shutdown/removal. Workflow linting and PowerShell syntax
validation passed. These checks do not substitute for hosted runtime results.

`.github/workflows/postgresql.yml` runs on pushes to main, pull requests and
manual dispatch. It uses read-only repository permissions, pinned checkout/Go
setup actions, no production secrets, and preinstalled native PostgreSQL tools:

| Runner | PostgreSQL major | Status |
| --- | --- | --- |
| Ubuntu 24.04 | 16 | Awaiting hosted execution |
| Windows Server 2022 | 14 | Awaiting hosted execution |
| Windows Server 2025 | 17 | Awaiting hosted execution |

Runner images can change. A missing installation or unexpected major fails the
job rather than silently skipping live tests. Inspect all three job results
after pushing; keep the roadmap runtime milestone open until they pass.
GitHub Actions must be enabled for the repository; private-repository usage may
consume the account's Actions allowance. No additional database setup is needed.
