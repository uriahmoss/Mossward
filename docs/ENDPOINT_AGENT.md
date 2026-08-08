# Endpoint agent

The Mossward endpoint agent makes outbound HTTPS connections only. It does not
open a listening port. Enrollment uses a single-use token, while routine
check-ins and certificate renewal use TLS 1.3 with mutual authentication.

## Build and configure

Run `make build` and install `bin/mossward-agent` with permissions that prevent
untrusted users from replacing it. Copy `config/mossward-agent.json.example` to
an administrator-controlled location and adjust these fields:

- `server_url` is the Mossward web origin used for initial enrollment.
- `endpoint_url` is the dedicated endpoint mTLS origin configured by
  `MOSSWARD_AGENT_LISTEN`.
- `enrollment_ca_file` is optional when `server_url` uses a publicly trusted
  certificate. Otherwise, it must be an absolute path to the enrollment
  server's trusted CA bundle.
- `state_directory` must be an absolute, agent-private directory.
- `check_in_interval_seconds` defaults to 60 and accepts 15 through 86400.

On Windows, use absolute drive-letter paths such as
`C:\\ProgramData\\Mossward\\Agent`. Restrict the configuration and state
directory ACLs to Administrators, SYSTEM, and the dedicated service identity.

## Enroll

Create a single-use endpoint enrollment token in the Mossward administration
interface. On the endpoint, run:

```sh
mossward-agent enroll --config /etc/mossward/agent.json --token TOKEN
```

The agent generates its private key locally. Only a certificate signing request
and the enrollment token leave the endpoint. The private key, issued
certificate, private CA chain, and identity metadata are written to the state
directory with owner-only file permissions on Unix systems. Treat the token as
a secret and do not place it in the persistent configuration file.

## Run

Start the long-running process with:

```sh
mossward-agent run --config /etc/mossward/agent.json
```

The process checks in over the dedicated mTLS endpoint, retries failed outbound
connections with a bounded backoff, and renews its certificate when fewer than
30 days remain. Revoked endpoint identities are rejected by the server during
the TLS handshake.

Service-unit packaging and queued endpoint telemetry are separate roadmap
slices. Until service packages are added, use the operating system's service
manager with a dedicated, least-privileged account and an explicit absolute
configuration path.
