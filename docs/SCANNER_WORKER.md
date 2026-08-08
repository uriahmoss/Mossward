# Mossward scanner worker

`mossward-worker` is the outbound-only remote scanning process. It accepts only
HTTPS control-plane origins, authenticates with a Mossward-issued client
certificate, verifies signed jobs with the configured Ed25519 public key, signs
evidence with its device key, and keeps pending messages in an encrypted local
outbox.

## Configuration

Pass an absolute configuration path with `--config` or set
`MOSSWARD_WORKER_CONFIG`. Keep the state directory and private key accessible only
to the operating-system account running the worker.

```json
{
  "server_url": "https://mossward.example.com:8443",
  "worker_id": "replace-with-enrolled-worker-id",
  "certificate_file": "/etc/mossward-worker/worker.crt",
  "private_key_file": "/etc/mossward-worker/worker.key",
  "ca_file": "/etc/mossward-worker/mossward-agent-ca.crt",
  "job_signing_public_key": "replace-with-enrollment-response-value",
  "state_directory": "/var/lib/mossward-worker",
  "allowed_cidrs": ["192.168.10.0/24"],
  "allowed_ports": [22, 80, 443],
  "max_concurrent": 4,
  "rate_limit_per_second": 10,
  "capabilities": [
    "tcp_connect",
    "service_identification",
    "http_configuration",
    "tls_configuration",
    "ssh_configuration"
  ],
  "poll_interval_seconds": 15,
  "probe_timeout_seconds": 5,
  "outbox_maximum_items": 10000,
  "outbox_maximum_bytes": 104857600
}
```

The local scope must match the server-side enrollment scope. A signed job must
pass both sets of restrictions before execution. The worker refuses HTTP URLs,
relative security-sensitive paths, invalid network or port scopes, unsupported
capabilities, mismatched or expired certificates, invalid signing keys, and
private keys with group or world permissions on Unix systems.

## Run

```sh
mossward-worker --config /etc/mossward-worker/worker.json
```

The worker sends a heartbeat, drains retained evidence, and polls for one job per
cycle. Temporary failures use bounded exponential backoff and honor server
`Retry-After` guidance. Interrupting the process leaves queued evidence encrypted
for its next start; unfinished server work becomes eligible for checkpoint-based
reassignment only after its lease expires.
