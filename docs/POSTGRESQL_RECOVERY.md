# PostgreSQL backup, recovery, and key rotation

These offline commands use PostgreSQL's native `pg_dump` and `pg_restore`.
Install trusted client tools compatible with the server version, then put them
on `PATH` or pass `--pg-tools-dir /path/to/postgresql/bin`. On Windows, use the
directory containing `pg_dump.exe` and `pg_restore.exe`.

Use a dedicated Mossward database with the application in its default `public`
schema. Custom application schemas are not supported by this maintenance path.
The commands use `MOSSWARD_DATABASE_BACKEND=postgresql` and
`MOSSWARD_DATABASE_URL`; production configuration continues to require
`sslmode=verify-full`. Include the intended database, user, and TLS settings
explicitly in the URL. Supply secrets through your protected configuration,
not a shell history entry. Credentials are passed to native tools through a
temporary owner-only service file, not command arguments or diagnostics.

Native tools provide consistent database dumps, but the application keyring and
PKI are separate files. Stop Mossward before creating a complete backup or
rotating keys so these components remain aligned. Confirmation flags acknowledge
this requirement; they do not automatically stop the service.

## Create and inspect a complete backup

```sh
./bin/mossward backup create --output /secure/backups/mossward.tar.gz --confirm-offline
./bin/mossward backup inspect --input /secure/backups/mossward.tar.gz
```

The archive includes a custom-format database dump, the identity keyring, agent
PKI, and ACME files when present. Its versioned manifest records installation
identity, schema version, sizes, and SHA-256 digests. Creation and inspection
verify integrity, and creation refuses to overwrite an existing archive.
SQLite version-1 backups remain supported; PostgreSQL uses version 2 and cannot
be restored as a SQLite database.

Archives contain private keys and credentials. They are **not encrypted** by
Mossward. Store them in encrypted, access-controlled backup storage; protect
Windows files with appropriate ACLs. The existing total expansion limit is
1 GiB and 10,000 files, including the manifest. Database files are streamed
rather than buffered into memory; identity keyrings are limited to 1 MiB.

Only restore archives from a trusted source. Checksums detect damage, not
malicious modifications or authenticity. Native database restores execute SQL,
including function definitions. This is not an arbitrary remote-command feature;
it is a local, explicitly authorized administrator recovery operation.

## Recover without replacing the current installation

1. Keep the original database and application files intact. Stop all services
   that could connect to the recovery destination.
2. Have a PostgreSQL administrator create a new empty dedicated database owned
   by a non-superuser Mossward login. For example, using an existing login:

   ```sql
   CREATE DATABASE mossward_recovery OWNER mossward;
   ```

3. Set `MOSSWARD_DATABASE_URL` to this new database. Set
   `MOSSWARD_IDENTITY_KEY_FILE`, `MOSSWARD_AGENT_PKI_DIR`, and
   `MOSSWARD_ACME_CACHE_DIR` to new, non-overlapping paths. They must not already
   exist. Provide destinations for every component included in the archive.
4. Run:

   ```sh
   ./bin/mossward backup restore --input /secure/backups/mossward.tar.gz --confirm-offline --confirm-restore
   ```

5. Start Mossward against the recovered configuration. Verify local/MFA login,
   SSO if enabled, assets, findings, scans, endpoint certificate trust, and audit
   writes before switching users or agents to it. Never run the original and
   recovered servers concurrently against the same agents without a planned
   cutover. Preserve the original installation until validation is complete.

Restore rejects occupied destinations, additional user schemas, and superuser
connections. It uses an advisory guard shared with application schema startup,
and `pg_restore --single-transaction --exit-on-error --no-owner --no-acl`.
It never issues `--clean`, disables constraints/triggers, or drops a destination.
Objects are owned by the recovery role; PostgreSQL roles, grants, database-level
settings, and cluster-level configuration are **not** provisioned automatically.

After the native restore, Mossward verifies schema version and installation
identity before publishing staged application files. Database restoration and
filesystem publication cannot be one atomic transaction. If the native process
is interrupted, validation fails, or file publication fails, do not start
Mossward. The error identifies owner-only `.mossward-recovery-*` staging with
the matching keyring/PKI. Inspect the destination state and complete a controlled
recovery or choose another empty database and fresh file paths. An interrupted
connection can leave an uncertain commit outcome; never assume that the database
is empty or automatically delete it. Keep the original archive and retained
staging until recovery is verified.

## Rotate the identity encryption key

```sh
./bin/mossward identity-key rotate --backup /secure/backups/pre-rotation.tar.gz --confirm-rotation
```

Rotation creates and verifies a mandatory new complete PostgreSQL backup before
changing the keyring. It retains old and new keys while transactionally rotating
TOTP, WebAuthn credential/ceremony state, OIDC client secrets, and SMTP passwords.
The database transaction records the rotation audit event. Only after commit
does the command prune inactive keys.

If backup fails, the keyring and ciphertexts are unchanged. If database rotation
fails, keep the pending multi-key keyring and backup; the transaction rolls back.
If final keyring publication fails after the database commit, retain the pending
keyring and retry offline rotation using a new backup path. Do not manually remove
keys or restore only the database: historical backups must always be paired with
their historical keyring. The operation does not rotate endpoint CA certificates.

Both maintenance commands accept `--timeout` (default `1h`), and
`--pg-tools-dir`. Native tool diagnostics are withheld because they may contain
SQL, sensitive row values, or connection details. For detailed investigation,
use trusted PostgreSQL tools directly in a protected administrator session.

## Live verification

Use separate, dedicated **empty** databases owned by a non-superuser login:

- `MOSSWARD_TEST_POSTGRES_BACKUP_DSN`
- `MOSSWARD_TEST_POSTGRES_RESTORE_DSN`
- `MOSSWARD_TEST_POSTGRES_ROTATION_DSN`

These must be PostgreSQL URLs whose database names start with `mossward_test_`.
The tests create and clean only their generated `public` application schemas.
Do not use production databases. Set `MOSSWARD_TEST_POSTGRES_TOOLS_DIR` when the
client tools are not on `PATH`, then run:

```sh
make test-postgres-recovery
make verify
```

The explicit recovery target fails if its DSNs are missing. The normal test
suite skips these integration tests when the dedicated databases are absent.
The live tests cover backup inspection, no-overwrite behavior, malformed-dump
failure, native restoration, installation identity, encrypted MFA/keyring pairing,
PKI, audit sequences, occupied-target rejection, successful CLI key rotation,
and mandatory-backup failure without key changes. They have been exercised with
PostgreSQL 16.15 on macOS; Linux/Windows runtime rehearsals and other PostgreSQL
versions remain on the roadmap.

Native-tool references: [pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html),
[pg_restore](https://www.postgresql.org/docs/16/app-pgrestore.html),
[connection service files](https://www.postgresql.org/docs/16/libpq-pgservice.html).
