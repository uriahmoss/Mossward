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

TLS- and SSH-specific spec schemas are introduced in their respective slices.
Publisher trust, version activation, rollback, and key rotation remain part of
the check lifecycle and trust-policy slice.
