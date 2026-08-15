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
- `collector_allowlist` is the endpoint's local ceiling for built-in read-only
  collectors. It defaults to empty, so collection remains disabled. Supported
  identifiers are `operating_system`, `installed_software`,
  `listening_services`, and `security_posture`. Unknown or duplicate values
  prevent startup; values are never interpreted as commands or paths.
- `update_enabled` defaults to false. Enabling it also requires
  `update_signing_key_id` and a base64, unpadded Ed25519 public key in
  `update_signing_public_key`. This local trust pin is required in addition to
  server authorization and cannot be enabled remotely.

On Windows, use absolute drive-letter paths such as
`C:\\ProgramData\\Mossward\\Agent`. Restrict the configuration and state
directory ACLs to Administrators, SYSTEM, and the dedicated service identity.

## Enroll

Create a single-use endpoint enrollment token in the Mossward administration
interface. On the endpoint, run:

```sh
mossward-agent enroll --config /etc/mossward/agent.json --token TOKEN
```

For service installations, avoid exposing the token in the process list. Pipe
it from a root-only file into the unprivileged agent account:

```sh
sudo cat /root/mossward-enrollment-token | sudo -u mossward-agent \
  /usr/local/bin/mossward-agent enroll \
  --config /etc/mossward-agent/agent.json --token-stdin
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

Adding a collector to the local allowlist does not by itself execute it. The
agent requires both this local permission and the endpoint-specific policy sent
by the server. Server authorization is empty by default. This intersection
prevents the server from expanding an endpoint's locally approved collection
boundary. Collector execution and evidence submission remain separate roadmap
slices.

## Logging and diagnostics

The agent writes operational flow at info level, recoverable check-in and
certificate-renewal failures at warning level, and fatal startup failures at
error level. The systemd unit sends stdout and stderr to journald without
creating a separate sensitive log file:

```sh
sudo journalctl -u mossward-agent.service --since today
```

Run a read-only diagnostic report when troubleshooting:

```sh
mossward-agent diagnose --config /etc/mossward-agent/agent.json
mossward-agent diagnose --config /etc/mossward-agent/agent.json --offline --json
```

Diagnostics check state-directory permissions, private-key protection, the
certificate/key pair, private CA trust, certificate validity, and an optional
TLS 1.3 mutual-authentication handshake. The command never prints private keys,
enrollment tokens, or certificate contents. `--offline` performs only local
checks, while `--json` produces a machine-readable support report. An unhealthy
report exits nonzero for monitoring and automation.

Queued endpoint telemetry remains a separate roadmap slice. Linux deployments
can use the signed release workflow and hardened systemd unit below.

## Signed Linux release

The Linux release workflow builds a static `amd64` or `arm64` archive and signs
the complete archive with a Sigstore bundle. The signing key is never stored in
this repository. Set `MOSSWARD_COSIGN_KEY` to an external Cosign key, hardware
token, or KMS URI and run:

```sh
scripts/package-linux-agent.sh 0.1.0 amd64 dist
scripts/verify-linux-agent.sh \
  dist/mossward-agent_0.1.0_linux_amd64.tar.gz \
  dist/mossward-agent_0.1.0_linux_amd64.tar.gz.sigstore.json \
  /trusted/mossward-release.pub
```

Verify the archive before extracting or installing it. The included installer
creates a dedicated unprivileged account, protected configuration and state
directories, and a hardened systemd unit. It deliberately leaves the service
stopped until enrollment succeeds. Release-signing automation must use a
protected CI identity, hardware-backed key, or KMS rather than a filesystem key
committed with the source.

## Signed Windows release

Windows release packaging cross-builds the endpoint executable, applies a
SHA-256 Authenticode signature, obtains an RFC 3161 SHA-256 timestamp, and
verifies the result before creating the archive. The signing certificate is
selected from the Windows certificate store by thumbprint, allowing a hardware
provider or managed signing service to protect the private key.

```powershell
.\scripts\Package-WindowsAgent.ps1 `
  -Version 0.1.0 -Architecture amd64 `
  -SignTool 'C:\Program Files (x86)\Windows Kits\10\bin\signtool.exe' `
  -CertificateThumbprint 'REPLACE_WITH_40_HEX_CHARACTERS' `
  -TimestampUrl 'https://timestamp.example.com'
```

The installer refuses unsigned or invalidly signed executables, locks the
installation and state directories to Administrators, SYSTEM, and the isolated
`NT SERVICE\MosswardAgent` virtual account, and registers a native automatic
Windows Service. It deliberately leaves the service stopped until enrollment
succeeds.

After extracting the verified release archive, install both signed executables:

```powershell
.\Install-MosswardAgent.ps1 `
  -Binary .\mossward-agent.exe `
  -Updater .\mossward-agent-updater.exe `
  -Configuration .\agent.json
```

The separately signed updater is intentionally narrow: it can stop and start
only the `MosswardAgent` service and accepts only a previously verified update
transaction. It monitors the new service through its health deadline and
restores the known-good executable if startup or authenticated check-in fails.

Service lifecycle and troubleshooting commands are built into the same signed
agent executable:

```powershell
mossward-agent.exe service start
mossward-agent.exe service stop
mossward-agent.exe service status
mossward-agent.exe diagnose --config 'C:\ProgramData\Mossward\Agent\agent.json'
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='MosswardAgent']]]"
```

Info, warning, and error records are written to the Windows Application Event
Log under the `MosswardAgent` source. Service removal preserves configuration,
certificates, private keys, and other agent state.

## Operating-system and patch inventory

When the local configuration and server collector policy both allow
`operating_system`, the agent reports a timestamped OS snapshot during its
authenticated check-in. Linux reports `/etc/os-release` identity, build data,
architecture, and the running kernel patch level. Windows reports the product,
display version, build number, and cumulative-update build revision from the
local registry. Collection is read-only and does not contact update services.

The server replaces the endpoint's prior patch snapshot transactionally and
retains separate collected-at and received-at timestamps. Administrators can
read it from `GET /api/admin/endpoints/{id}/os-inventory`. A missing snapshot is
reported as unavailable rather than inferred from network observations.

When `installed_software` is allowed locally and by server policy, Linux agents
read the installed dpkg or APK database, or use the fixed read-only RPM query
when RPM is available. Windows agents read both native and 32-bit uninstall
registry views. Names, versions, publishers when available, architectures, and
collection sources are normalized into a bounded snapshot. The server replaces
the prior snapshot transactionally and exposes it at
`GET /api/admin/endpoints/{id}/software-inventory`.

When `listening_services` is allowed, Linux agents correlate listening TCP and
bound UDP sockets from `/proc` with owning process IDs, names, and executable
paths available to the agent service identity. Windows agents use fixed
read-only `netstat.exe` and `tasklist.exe` queries to correlate listeners with
process IDs and names. The snapshot contains metadata only: it does not capture
packets, payloads, or established outbound connections. Administrators can read
the transactionally replaced snapshot from
`GET /api/admin/endpoints/{id}/listening-inventory`.

When `security_posture` is allowed, Linux agents report Secure Boot visibility,
root device-mapper encryption evidence, and active nftables configuration.
Windows agents report Secure Boot, Windows Firewall profile state, and system
volume BitLocker evidence. Every check uses `pass`, `fail`, or `unknown`;
unavailable permissions, tools, or platform evidence remain unknown rather than
being presented as a confirmed failure. The snapshot is available from
`GET /api/admin/endpoints/{id}/posture-inventory`.

The server correlates installed software with NVD affected-version ranges only
when a package has an explicit version and an exact, reviewed product alias.
Matches are labeled medium-confidence candidates because Linux distributions
may backport security fixes without making NVD's upstream version range directly
decisive. Every result retains package name, version, package source, match
evidence, CVSS, Known Exploited status, and the NVD source URL. Refreshing either
the software snapshot or CVE feed removes stale matches. Results are available
from `GET /api/admin/endpoints/{id}/cves` and environment matches also influence
the critical-CVE homepage feed.

The optional `network_telemetry` collector records a bounded point-in-time
snapshot of TCP and supported connected UDP metadata. It excludes sockets whose
local ports are listening and labels the remaining direction as
`outbound_candidate` rather than claiming certainty. Records contain local and
remote addresses and ports plus owning process metadata when available. No
payload, packet contents, DNS traffic, TLS contents, or browsing history are
captured. Administrators can read the snapshot from
`GET /api/admin/endpoints/{id}/network-inventory`.

Each connection is correlated with its OS-reported PID and process name when
available. Linux also records the executable path visible through `/proc` to the
agent service identity. Missing process identity remains empty rather than being
guessed, and Mossward does not open process memory or inspect process payloads.

Name context remains provenance-separated from connection identity. Linux uses
only non-loopback entries already present in `/etc/hosts`; Windows uses entries
already present in the DNS client cache when `ipconfig.exe /displaydns` is
available and parseable. Mossward does not perform reverse-DNS lookups merely to
enrich telemetry. A separate TLS server-name field is persisted for OS-native
sources, but remains empty when no such source exists. Cached DNS names are
never presented as observed TLS SNI, and Mossward does not inspect ClientHello
packets or intercept TLS to obtain it.

Threat indicators supplied by an administrator can be correlated with collected
remote IP addresses and hostnames. Indicators require a source, confidence,
observation time, and future expiration. Matching is exact, remains
detection-only, and does not block traffic, remediate endpoints, or send
telemetry to a third party.

Network telemetry supports audited, per-endpoint application and destination
exclusions. Application rules match an exact process name or executable path;
destination rules match an exact IP address, exact hostname, or normalized CIDR.
The agent combines locally configured privacy exclusions with server policy and
filters before upload. The server filters again before persistence. Policies do
not disable agent identity, integrity, update, or other inventory controls.

The endpoint network collector has an immutable metadata-only privacy contract.
It exposes no setting or capability for packet payload capture, DNS packet
capture, TLS interception, or certificate injection. Administrators can inspect
that contract through `GET /api/admin/network-telemetry/privacy`. A schema test
requires explicit privacy review if fields are ever added to connection
telemetry.

Missing-agent coverage detection is disabled by default. When an administrator
enables it with recent MFA, Mossward compares active, non-retired inventory
assets with active endpoint-to-asset links and reports unmatched assets as
coverage gaps. This slice does not initiate discovery scans or presume that
every network device is eligible for an endpoint agent.

Coverage discovery policies define administrator-approved CIDR segments and are
managed with recent MFA. Every segment must remain wholly inside the server's
global allowed CIDR scope. These policies establish authorization boundaries;
creating or enabling one does not itself launch a scan.

Assets have an explicit agent-eligibility state: `unknown`, `eligible`, or
`ineligible`. New assets default to `unknown`. Only explicitly eligible,
unlinked assets are counted as missing-agent coverage gaps; unknown assets are
shown separately for review, and ineligible assets require an administrator
reason and are excluded from gap counts. Changes require recent MFA and are
audited.

The agent fingerprints its executable, loaded configuration file, and local
identity bundle with SHA-256. Only fingerprints are uploaded; file contents and
private keys are never transmitted. The server records the first observation as
a baseline and retains component-specific events when a later fingerprint
changes. Integrity events are detection evidence and do not trigger automatic
file or process changes.

Each integrity snapshot is signed with the endpoint's existing ECDSA identity
key and includes a durable, monotonically increasing sequence number. The server
verifies the signature against the mutually authenticated client certificate
and rejects reused or reset sequences. Sequence gaps are allowed so a lost HTTP
response cannot permanently strand an agent. Stored change events retain their
source sequence and signature for later verification.

Administrators can create time-bounded maintenance windows for an endpoint or
asset group. Windows require recent MFA, a reason, an existing target, and a
maximum duration of 30 days. Active windows suppress only missed/stale heartbeat
notifications and replace them with a visible informational status. Certificate
and integrity signals are never suppressed. Creation and cancellation remain in
the audit log, and the underlying heartbeat timestamps and integrity evidence
are retained.

Endpoint relay capability is unauthorized by default. Administrators can create
an explicit, reasoned relay authorization for an active endpoint and revoke it
with recent MFA. Only one authorization can be active per endpoint, while prior
revoked authorizations remain available as history. Promotion in this slice
does not open a listener, approve downstream agents, or forward traffic.

Downstream relay authorization is an explicit endpoint allowlist. Both the relay
and downstream endpoint must be active, self-assignment is prohibited, and a
downstream endpoint can have only one active relay assignment. Authorization and
revocation require recent MFA and a reason. Revoking a relay also revokes its
active downstream assignments while preserving their history. Allowlisting is
still inert until the dedicated relay transport is implemented.

Relay messages use a versioned Mossward-only frame and media type with a closed
allowlist of agent check-in, server reply, agent-log batch, and tamper-alert
message kinds. The frame has no host, port, URL, command, or arbitrary protocol
fields and cannot represent SOCKS, HTTP CONNECT, TCP forwarding, or a general
proxy. Administrators can inspect the immutable contract through
`GET /api/admin/relay-transport/contract`. Forwarding remains disabled while
the remaining relay controls are implemented.

Relay frames use dedicated X25519 recipient keys, HKDF-SHA-256 key derivation,
AES-256-GCM authenticated encryption, and ECDSA-P-256 signatures from the
sender's endpoint identity. Encryption keys are deliberately separate from
certificate signing keys. The relay sees routing identifiers and bounded
ciphertext but cannot decrypt or silently modify message content. Recipient-key
binding prevents delivery to a different endpoint key. Network forwarding stays
disabled until key provisioning and the remaining relay controls are complete.

Endpoint heartbeat monitoring is enabled by default with configurable warning
and stale thresholds. A missed heartbeat produces a warning; once the longer
stale threshold is reached, a single stale-agent error supersedes that warning.
For agents that have never checked in, the enrollment time starts the grace
period. Settings changes require recent MFA and are audited.
