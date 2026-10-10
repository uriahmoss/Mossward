# Linux lab installation acceptance

For the authorized lab agent, using the exact product commit pinned in the
`server-lab` mailbox request. This is a fresh Mossward installation on an existing
Ubuntu host, not permission to reset the host or disturb its AI services.

1. Preserve unrelated work. Build/test the pinned revision in a separate clone
   or worktree. Run `make verify`; do not enable disposable worker service tests
   on this shared host. Do not assume PostgreSQL or Windows verification passed.
2. Inventory existing listeners and Mossward paths/accounts/services read-only.
   If Mossward already exists, stop and report the conflict instead of overwriting
   it. Preserve existing AI services, firewall, proxy, certificates and databases.
3. Follow `SERVICE_INSTALLATION.md`, using the local environment example and
   SQLite. Select an unused loopback port; adjust the listen/public origin and
   WebAuthn origin together in a private environment file. Never bind public HTTP
   or alter firewall/proxy rules. Install via `manage-mossward-server.sh` and start
   the low-privilege systemd service.
4. Verify service identity, localhost listener, health and logs. On a fresh
   installation `/api/ready` returning HTTP 503 with `setup_required` is expected,
   not evidence that the service is broken. Do not create an administrator,
   choose the user's password, seed MFA, or disable authentication for testing.
5. Stop the service; retain a private copy of configuration and complete state.
   Exercise the data-preserving uninstall/reinstall once. Confirm retained files
   are unchanged while stopped; restart and confirm the same installation and
   setup state. No purge, database reset, or unrelated service deletion.
6. Leave Mossward running on loopback for user setup. Provide connection/tunnel
   instructions through an appropriate private channel; public mailbox outcomes
   must omit host addresses, paths, credentials and raw logs. Report only sanitized
   status, source revision and actual checks.
7. After the user initializes admin/MFA, test authenticated results and an
   explicitly authorized loopback-only scan. Test updates using a current verified
   offline backup and the configured readiness URL; failed readiness must stop
   Mossward and retain recovery material. These checks remain pending until they
   are actually performed. Do not downgrade migrated data without verified restore.

Stop and request input for conflicting resources, elevated permissions outside
the requested Mossward install, non-localhost exposure, or access to another PC.
No production signing identities or runtime state belong in Git. Receiving this
request is not successful installation; publish actual evidence-backed outcomes.
