# Independent server and scanner-worker deployment

The existing `mossward` server is the control plane and may still run local scans.
`mossward-worker` is an independently built, outbound-only scanner. Neither
installation requires the endpoint agent. Workers never connect to the server
database, accept arbitrary commands, or expand their approved scan scopes.

Build all three binaries with `make build`, or build just a worker:

```sh
go build -trimpath -o mossward-worker ./cmd/mossward-worker
```

Use `docs/DEPLOYMENT.md` for the server's existing Linux/Windows service,
HTTPS setup and database configuration. Complete first-time local administrator
and MFA setup before hosting it. Enable the dedicated endpoint/worker mTLS
listener. Keep PostgreSQL reachable only from the server, never from workers.
This slice does not introduce a separate scheduler or disable local scans.

## Enrollment and network access

An administrator issues a scoped, single-use scanner-worker enrollment token.
On the worker host generate its private key and signed CSR. Submit the token/CSR
to `POST /api/scanner-workers/enroll` over verified HTTPS using the existing
enrollment API. Do not send private keys to the server. Store the returned worker
ID, certificate chain, CA and job-signing public key in the configuration described
in `SCANNER_WORKER.md`. An automated enrollment CLI is not supplied in this slice.

Allow worker outbound connections to the configured server listener and approved
scan destinations/ports; permit DNS only if needed. No inbound worker listener is
required. Select explicit remote execution and its worker site in scan policies.
Local execution remains available; unavailable remote workers do not cause local
fallback. Never reuse one worker identity on multiple machines.

## Read-only preflight

```sh
mossward-worker --config /absolute/path/worker.json --check-config
```

Preflight checks configuration, supported capabilities/scope, key/certificate
matching, validity, immutable worker identity and trusted client-authentication
certificate chain. It performs no network requests and creates no state files.
It does not prove server reachability, revocation status or filesystem write
access. Run it as the eventual service identity where possible. Relative config
paths and trailing CLI arguments are rejected; existing `--config` startup works.

## Linux systemd

Verify your build or approved publisher's signature/checksum before installation.
Use the example in `SCANNER_WORKER.md` with these absolute paths:

- Configuration: `/etc/mossward-worker/worker.json`
- Certificate, private key, CA: `/etc/mossward-worker/worker.crt`, `worker.key`, `ca.crt`
- State: `/var/lib/mossward-worker`

```sh
sudo sh deploy/linux/install-mossward-worker.sh ./mossward-worker ./worker.json
sudo install -o root -g mossward-worker -m 0640 ./worker.crt /etc/mossward-worker/worker.crt
sudo install -o mossward-worker -g mossward-worker -m 0400 ./worker.key /etc/mossward-worker/worker.key
sudo install -o root -g mossward-worker -m 0640 ./ca.crt /etc/mossward-worker/ca.crt
sudo runuser -u mossward-worker -- /usr/local/bin/mossward-worker --config /etc/mossward-worker/worker.json --check-config
sudo systemctl enable --now mossward-worker.service
sudo journalctl -u mossward-worker.service
```

The installer refuses to overwrite existing binary/config/service files and does
not start the service. The system account has no shell or capabilities, a private
temporary directory, read-only system/configuration access and writable worker
state only. The unit runs preflight before startup. SIGTERM cancels work and closes
the encrypted outbox/replay ledger; lease expiry controls later resume/reassignment.
Stop with `systemctl stop mossward-worker.service`. Do not delete state on stop.

## Windows Service

Build/sign the native executable with your approved Authenticode publisher.
The installer requires a valid signature; verify its publisher against your
organization's release policy before running it. A valid signature alone is not
a publisher allowlist. Use an elevated PowerShell session.

Set JSON paths (escaping backslashes) to:

- Certificate: `C:\ProgramData\Mossward\Worker\identity\worker.crt`
- Key: `C:\ProgramData\Mossward\Worker\identity\worker.key`
- CA: `C:\ProgramData\Mossward\Worker\identity\ca.crt`
- State: `C:\ProgramData\Mossward\Worker\state`

```powershell
./deploy/windows/Install-MosswardWorker.ps1 -Binary ./mossward-worker.exe -Configuration ./worker.json -Certificate ./worker.crt -PrivateKey ./worker.key -CA ./ca.crt
& "$env:ProgramFiles\Mossward Worker\mossward-worker.exe" service start
& "$env:ProgramFiles\Mossward Worker\mossward-worker.exe" service status
& "$env:ProgramFiles\Mossward Worker\mossward-worker.exe" service stop
```

`NT SERVICE\MosswardWorker` has executable/configuration/identity read access and
state-directory modification rights, not LocalSystem privileges. The installer
disables inherited ACLs, refuses existing installations, checks configuration
and does not start the service. Failed installs retain secured files for manual
inspection; they do not silently overwrite/retry. Event Viewer → Windows Logs →
Application, source `MosswardWorker`, receives operational info/warnings/errors.
Restart recovery is bounded to two retries. Uninstall requires a stopped service
and retains all configuration, identity and state files.

## Manual updates and recovery

Automatic signed staged worker updates/rings/rollback remain queued separately.
For manual upgrades: stop the service, back up configuration/identity and the
complete state directory (including encrypted-outbox key), verify the replacement
build, replace only the executable, preflight, and restart. Keep the prior verified
binary for rollback. Do not replace state or private keys during an upgrade.
Copying only outbox.db without its key makes retained evidence unreadable.
Treat backups as credentials and encrypt/access-control them accordingly.

After a failure check service logs, certificate expiration and chain, filesystem
permissions, DNS, outbound firewall rules, server fleet health and dispatch
switches. Do not delete replay state or re-enable revoked identities to bypass a
failure. Re-enroll explicitly after identity compromise. No installers open
firewalls, modify server scopes or install/start services automatically during
tests.

## Verification boundary

The application runtime rehearsal uses real TLS 1.3 client/server identities,
a signed site-scoped job and an owned loopback TCP scan listener. It verifies
signed evidence, retained evidence/completion after failed delivery and restart,
delivery ordering, persistent replay rejection, mismatched-site rejection and
clean cancellation. It runs in the ordinary test suite without touching host
services. This tests the application runtime against a minimal test controller,
not the full control plane or native service manager.

Unit tests, full project verification, PowerShell/shell syntax and native-target
cross-builds cover this slice locally. Installing/starting these new services on
real Linux/Windows hosts remains an operator acceptance check; cross-compilation
is not service-runtime verification. Container orchestration and HA deployment
remain separate work. Validate graceful stop, queue preservation, low-privilege
file access, restart recovery and a scoped remote scan before production use.

The hosted `worker-systemd` job now explicitly opts into
`TestNativeSystemdWorkerAcceptance` on a disposable Ubuntu runner. It builds the
real worker, installs the production unit, provisions a synthetic identity,
preflights as the service account, and starts/stops/restarts through systemd.
The scan targets only the test's owned loopback listener, against the minimal
mTLS test controller—not a full production control plane. Existing installation
paths or accounts cause rejection. Cleanup stops the service and removes only
the exact installed files; protected diagnostic state and the account remain
until the disposable host is discarded. Never enable
`MOSSWARD_TEST_WORKER_SYSTEMD=1` on a production or shared host. Successful hosted
execution and native Windows service acceptance remain pending.
