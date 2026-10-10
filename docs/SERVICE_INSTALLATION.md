# Mossward service installation

Complete first-time setup locally and review `DEPLOYMENT.md` before exposing a
service installation. Keep the database, identity key, ACME cache, and endpoint
PKI on persistent storage with access limited to the Mossward service account.

## Linux with systemd

Build Mossward on the target system, then install the binary, account,
configuration, and unit from an administrative shell:

```sh
sudo sh deploy/linux/manage-mossward-server.sh install bin/mossward deploy/linux/mossward.local.env.example
sudo systemctl enable --now mossward.service
```

Edit `/etc/mossward/mossward.env` before starting the service. The supplied
local example binds only loopback; the separate `mossward.env.example` uses
reverse-proxy mode. Both store writable state under
`/var/lib/mossward`. The unit runs as the dedicated `mossward` account, grants
only the low-port bind capability needed for direct ACME, and applies systemd
filesystem, device, privilege, kernel, and address-family restrictions.

Lifecycle and logs:

```sh
sudo systemctl status mossward.service
sudo systemctl restart mossward.service
sudo systemctl stop mossward.service
sudo journalctl -u mossward.service
```

The lifecycle script requires root, real root-owned non-writable managed parents,
and a dedicated non-root account. It serializes operations, refuses overwriting
an existing executable/unit, and does not start a new installation automatically.
It never changes firewall rules, proxies, other services, or an external database.
Verify the source revision/build before supplying an executable. Legacy manual
installations have no managed receipt and must be reviewed before adoption.

### Uninstall and reinstall

```sh
sudo sh deploy/linux/manage-mossward-server.sh uninstall
sudo sh deploy/linux/manage-mossward-server.sh install bin/mossward
sudo systemctl enable --now mossward.service
```

Uninstall stops/disables only Mossward and removes its unit/executable. It retains
`/etc/mossward`, `/var/lib/mossward`, the account, databases, keys and certificates.
Reinstall without an environment-file argument reuses retained configuration.
There is deliberately no purge/reset option. An uninstall/reinstall does not undo
database migrations or reset first-time setup.

### Verified offline update

Stop the service and create a **current backup of this installation** with the
old executable using its actual service environment. Do not source the environment
file as shell code or put its secrets into command-line arguments. For SQLite:

```sh
sudo systemctl stop mossward.service
sudo install -d -o mossward -g mossward -m 0700 /var/lib/mossward/backups
sudo systemd-run --wait --pipe --collect --uid=mossward --gid=mossward \
  -p EnvironmentFile=/etc/mossward/mossward.env \
  -p WorkingDirectory=/var/lib/mossward \
  /usr/local/bin/mossward backup create --output /var/lib/mossward/backups/pre-update.tar.gz
sudo sh deploy/linux/manage-mossward-server.sh update bin/mossward \
  --backup /var/lib/mossward/backups/pre-update.tar.gz --confirm-current-offline-backup
```

Choose a new archive filename for every update. PostgreSQL requires its native
offline backup flags/client tools; follow `POSTGRESQL_RECOVERY.md` instead of the
SQLite backup command above. Back up the environment file and externally managed
TLS certificates separately in private storage. Copy recovery material off-host.
The confirmation attests freshness and installation identity: archive inspection
verifies integrity, not that the operator chose the correct/latest installation.

Update requires a stopped service and valid archive; it retains the previous
executable at `/etc/mossward/mossward.previous`, atomically replaces only the
binary, starts Mossward and checks readiness. Default readiness is loopback port
8080; for another listener set `MOSSWARD_READINESS_URL` explicitly through `sudo
env` to the correct `/api/ready` URL (loopback HTTP or certificate-verified HTTPS).
It never bypasses TLS validation. The installation must already be initialized.

On failed readiness the service is stopped; neither database nor executable is
automatically rolled back. Review logs and restore the verified offline backup
with the compatible previous executable if necessary. Archive the previous binary
in private recovery storage before the next update; the script refuses to overwrite
it. Binary-only downgrade after a schema migration is not a supported rollback.
Orchestration fixture tests use redirected paths/mocked host commands; real Linux
installation and lifecycle acceptance remains required on the lab host.

## Windows Server

Build or copy `mossward.exe` and edit
`deploy\windows\mossward.env.example`. From an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\Install-MosswardService.ps1 `
  -Binary .\mossward.exe `
  -EnvironmentFile .\deploy\windows\mossward.env.example
```

The installer copies the binary under `C:\Program Files\Mossward`, creates
`C:\ProgramData\Mossward`, applies an ACL for Administrators, SYSTEM, and the
`NT SERVICE\Mossward` virtual account, installs an automatic native Windows
Service, configures controlled restart recovery, stores service-specific
environment values, and starts Mossward. Application flow, warnings, and errors
are written to the Windows Application event log with source `Mossward`.

Native lifecycle commands are also available from an elevated terminal:

```powershell
& 'C:\Program Files\Mossward\mossward.exe' service status
& 'C:\Program Files\Mossward\mossward.exe' service stop
& 'C:\Program Files\Mossward\mossward.exe' service start
& 'C:\Program Files\Mossward\mossward.exe' service uninstall
```

Stop Mossward before replacing its executable or uninstalling it. Uninstallation
removes the service and event-log registration but intentionally preserves the
binary, configuration, database, keys, certificates, and other server data.

The service environment is stored at
`HKLM\SYSTEM\CurrentControlSet\Services\Mossward\Environment` and is protected
by the service registry key's Windows ACL. Restart the service after changing
those values. Never place passwords, tokens, or private-key contents directly
in command-line arguments.
