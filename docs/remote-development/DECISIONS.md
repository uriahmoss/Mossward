# Durable decisions

These summarize established requirements, not new work authorizations.

- Mossward is detection and authorized assessment, not remediation or exploitation.
- One organization per installation; preserve scope, identity, audit, and access
  controls. Root AGENTS.md is the shared engineering baseline.
- Remote workers execute only explicitly assigned, constrained jobs. No automatic
  scope expansion or arbitrary remote commands.
- UI improvements from the 2026-10-10 review are queued in FEATURES.md.
  Functional correctness precedes optional homepage customization.
- Worker management should have a dedicated homepage destination, not Users.
- Findings must prominently identify the affected host and port, distinct from
  original scan scope. Drill-down must preserve results context.
- Asset metadata should support reusable choices and previewed bulk updates.
  Additional multi-value tags and preference ownership need review before design.
- Reports need portal viewing and downloads; saved-versus-on-demand behavior
  needs review before persistence changes.
- Unattended development requires explicit package approval. No main integration
  or live-server changes are authorized by a development wake.

Add dated decision records with human approval references as choices are resolved.
Do not treat speculative discussion or screenshots as authority to expand scope.
