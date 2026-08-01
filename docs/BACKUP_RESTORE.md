# Mossward backup and restore

Mossward backup archives contain security-sensitive server state. Every archive
is created with owner-only permissions and includes:

- A transactionally consistent SQLite snapshot, including its schema version.
- The matching identity encryption key required to decrypt MFA and OIDC data.
- ACME account and certificate state when present.
- Endpoint CA and server identity state when present.
- A versioned manifest with file sizes and SHA-256 integrity checks.

The archive is compressed but not encrypted. Store it in encrypted storage with
access at least as restrictive as the running Mossward server. SHA-256 checks
detect corruption; they do not make a compromised archive trustworthy.

## Create a backup

Backup creation may run while Mossward is serving requests. SQLite creates a
consistent snapshot without copying live WAL or shared-memory files.

```sh
mossward backup create --output /secure/backups/mossward-2026-08-01.tar.gz
```

The command refuses to overwrite an existing archive. Use a new filename for
every backup so previous recovery points remain available. Copy the completed
archive to protected storage outside the server and periodically test it with:

```sh
mossward backup inspect --input /secure/backups/mossward-2026-08-01.tar.gz
```

Inspection verifies every manifest hash, the identity-key format, SQLite
integrity, and schema compatibility without changing server state.

## Rotate the identity encryption key

Identity-key rotation re-encrypts TOTP secrets, WebAuthn credential records,
active authentication ceremonies, and OIDC client secrets. Stop Mossward first
and choose a new path for the mandatory pre-rotation backup:

```sh
mossward identity-key rotate \
  --backup /secure/backups/mossward-before-key-rotation.tar.gz \
  --confirm-rotation
```

The key file is upgraded from the legacy raw-key format to a versioned keyring.
Mossward writes the new key alongside the old key before beginning the SQLite
transaction, allowing either generation of ciphertext to be decrypted if the
process is interrupted. After every encrypted database value commits under the
new key, the active keyring is pruned to the new key.

The original key file remains beside the configured identity key as
`identity.key.pre-rotation-<new-key-id>`. Keep it and the mandatory archive until
MFA, WebAuthn, and configured SSO providers have been tested. Both contain
sensitive recovery material and must retain owner-only access. Removing these
recovery copies is always a separate administrator decision.

## Restore

Stop every Mossward process that uses the target database before restoring.
Restoring while a server or maintenance command is running is unsupported.

Linux:

```sh
sudo systemctl stop mossward.service
sudo -u mossward /usr/local/bin/mossward backup restore \
  --input /secure/backups/mossward-2026-08-01.tar.gz \
  --confirm-restore
sudo systemctl start mossward.service
```

Windows Server, from an elevated PowerShell session:

```powershell
& 'C:\Program Files\Mossward\mossward.exe' service stop
& 'C:\Program Files\Mossward\mossward.exe' backup restore `
  --input C:\SecureBackups\mossward-2026-08-01.tar.gz `
  --confirm-restore
& 'C:\Program Files\Mossward\mossward.exe' service start
```

Restore extracts into a temporary staging directory and validates the complete
archive before changing the configured destinations. Existing database, WAL,
shared-memory, identity-key, ACME, and endpoint-PKI paths are renamed with a
`.pre-restore-<timestamp>` suffix. If installation of a staged file fails,
Mossward attempts to roll all renamed paths back automatically.

After starting Mossward, check `/api/ready`, confirm local and SSO sign-in,
review the certificate status, and verify endpoint check-ins. Retain the
pre-restore files until those checks pass; deleting old recovery copies remains
an explicit administrator action.
