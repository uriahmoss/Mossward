# Mossward Engineering Rules

## Product boundary

- Mossward is defensive detection and vulnerability-management software for
  systems the operator owns or is explicitly authorized to assess.
- Do not add exploitation, credential attacks, evasion, covert persistence,
  arbitrary payload execution, self-propagation, or automatic scope expansion.
- If a proposed feature weakens security or expands Mossward beyond detection,
  stop, explain the risk, and offer safer alternatives before implementation.
- Ask before making a major architectural or product-scope decision.

## Code

- Favor clarity, safety, and maintainability.
- Avoid deep nesting; prefer guard clauses and focused helpers.
- Keep functions, types, and modules concise and separate unrelated logic.
- Replace magic values and unnecessary hard-coding with named constants,
  configuration, or narrowly scoped enums.
- Refactor violations encountered within the current work scope only.
- Preserve the one-organization-per-install boundary and existing authorization,
  audit, cryptographic, scan-scope, and detection-only controls.

## Workflow

- Work in small, reviewable slices and track status in `docs/FEATURES.md`.
- Ask when uncertainty materially affects intent, behavior, architecture, scope,
  or safety.
- Do not overwrite, discard, or reformat unrelated user changes.
- Keep secrets, credentials, private keys, certificates, tokens, runtime data,
  databases, and machine-specific `.env` files out of Git.
- Use info logs for useful flow, warnings for degraded/recoverable conditions,
  and errors for major failures. Never log secrets or unnecessary sensitive data.

## Verification

- Update relevant tests whenever behavior changes.
- Before calling a slice complete, run:

  ```sh
  make verify
  ```

- When `make` is unavailable, run:

  ```sh
  go test ./...
  go vet ./...
  go build ./cmd/mossward ./cmd/mossward-agent
  ```

- Run `git diff --check` before committing.
- Do not mark PostgreSQL parity complete without live PostgreSQL migration and
  repository integration tests.

## Starting or resuming work

- Read `AGENTS.md`, `docs/FEATURES.md`, and relevant design/deployment docs.
- Run `git status --short --branch`, fetch the remote, and verify local `main`
  against `origin/main` before editing.
- Continue from the next incomplete roadmap slice unless the user requests a
  different task.
