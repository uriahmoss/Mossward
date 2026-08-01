# Mossward service installation

Complete first-time setup locally and review `DEPLOYMENT.md` before exposing a
service installation. Keep the database, identity key, ACME cache, and endpoint
PKI on persistent storage with access limited to the Mossward service account.

## Linux with systemd

Build Mossward on the target system, then install the binary, account,
configuration, and unit from an administrative shell:

```sh
sudo useradd --system --home-dir /var/lib/mossward --shell /usr/sbin/nologin mossward
sudo install -d -o mossward -g mossward -m 0700 /var/lib/mossward
sudo install -d -o root -g mossward -m 0750 /etc/mossward
sudo install -o root -g root -m 0755 bin/mossward /usr/local/bin/mossward
sudo install -o root -g mossward -m 0640 deploy/linux/mossward.env.example /etc/mossward/mossward.env
sudo install -o root -g root -m 0644 deploy/linux/mossward.service /etc/systemd/system/mossward.service
sudo systemctl daemon-reload
sudo systemctl enable --now mossward.service
```

Edit `/etc/mossward/mossward.env` before starting the service. The supplied
example uses reverse-proxy mode and stores writable state under
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

For an upgrade, stop the service, replace only `/usr/local/bin/mossward`, and
start it again. Do not replace the data directory or secret files. Removing the
unit does not remove Mossward data.

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
