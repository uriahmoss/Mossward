# Declarative check format

Mossward declarative checks are data, not executable scripts. The first schema
supports `http`, `tls`, and `ssh` check kinds and intentionally provides no shell,
process, filesystem, or arbitrary network-execution primitive.

Each distributed check is carried in a signed JSON envelope:

```json
{
  "algorithm": "Ed25519",
  "key_id": "mossward.release-2026",
  "check": {
    "schema_version": 1,
    "id": "mossward.http.security-headers",
    "version": "1.0.0",
    "kind": "http",
    "title": "Required HTTP security headers",
    "description": "Reports required response headers that are absent.",
    "severity": "medium",
    "spec": {
      "required_headers": ["content-security-policy"]
    }
  },
  "signature": "base64-without-padding"
}
```

The signature covers a deterministic representation of all check fields and a
Mossward-specific signing context. Equivalent JSON-object key ordering and
whitespace produce the same payload. Consumers must validate the envelope and
verify its Ed25519 signature before interpreting `spec`.

Schema version 1 requires namespaced lowercase identifiers, semantic versions,
a supported kind and severity, a bounded title, and an object-valued spec no
larger than 64 KiB.

## HTTP specifications

HTTP checks can declare the following bounded, read-only response assertions:

- `require_https`: require the observed response to use HTTPS
- `required_headers`: header names that must have a non-empty value
- `forbidden_headers`: header names that must not have a value
- `header_contains`: required case-insensitive fragments by header name
- `allowed_status_codes`: exact acceptable response status codes
- `remediation`: guidance included with a failed check

A specification must contain at least one assertion and no more than 32 total
rules. Header names must be valid HTTP field names. Mossward evaluates these
rules against the single response already collected by its bounded HTTP probe;
the format cannot issue additional requests, follow redirects, submit data, or
execute code.

## TLS specifications

TLS checks can evaluate the negotiated protocol and cipher, whether the bounded
legacy-protocol probes succeeded, and the observed leaf certificate:

- `minimum_version`: `TLS1.0`, `TLS1.1`, `TLS1.2`, or `TLS1.3`
- `disallow_legacy_protocols`: reject observed TLS 1.0 or TLS 1.1 support
- `disallowed_cipher_suites`: exact Go/IANA-style cipher-suite names
- `require_current_certificate`: require the leaf certificate to be within its
  validity dates; this does not claim public-chain trust
- `require_hostname_match`: require the leaf certificate to match the target
- `minimum_certificate_days_left`: warn within a bounded 0–3650 day window
- `remediation`: guidance included with a failed check

The evaluator uses handshake evidence already gathered by the scanner and
cannot alter protocol negotiation outside Mossward's fixed TLS probes.

## SSH specifications

SSH checks evaluate only the server identification line collected by the
existing bounded banner probe:

- `allowed_protocol_versions`: accepted identification protocol versions
- `allowed_software`: case-insensitive software allowlist
- `disallowed_software`: case-insensitive software denylist
- `forbidden_comment_terms`: prohibited fragments in the identification comment
- `forbid_version_disclosure`: flag an explicitly disclosed software version
- `remediation`: guidance included with a failed check

An SSH definition may use an allowlist or a denylist, but not both, and may
contain at most 32 total rules. This slice does not authenticate, attempt
credentials, start a session, run commands, or claim visibility into key
exchange and authentication settings that are absent from the identification
line.

## Lifecycle and publisher trust

Mossward persists explicitly trusted Ed25519 publisher keys and immutable check
versions in SQLite. A check is imported into `staged` state only after its
signature verifies against a currently trusted publisher. Activation retires
the previously active version, maintaining at most one active version per check
identifier.

Activating a lower semantic version requires an explicit rollback approval.
Revoked publishers cannot import or activate versions. Existing version numbers
cannot be replaced with different signed content, and publisher key identifiers
cannot be rebound to different public keys. These controls preserve an auditable
line between trust establishment, review, activation, retirement, and rollback.

## Intrusive-check boundary

Schema version 1 treats a missing `execution_class` as `observational` for
compatibility. A definition may explicitly declare `intrusive`, but the current
HTTP, TLS, and SSH evaluators reject that class and Mossward ships no intrusive
executor.

Any future intrusive executor must pass a separate, SQLite-backed policy gate.
That gate defaults disabled and requires both an exact check-ID allowlist entry
and a current administrator approval bound to the exact check ID and version.
An expired, future-dated, mismatched, or anonymous approval is rejected. This
policy does not enable intrusive functionality; it establishes the mandatory
authorization boundary before such functionality could be considered later.
