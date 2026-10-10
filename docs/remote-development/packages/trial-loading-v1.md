# trial-loading-v1

Specification revision: 1. State: approved by Uriah on 2026-10-10.
Base: 52d3571e96a8e1093f76d5ef3cca82b93e65df03.
Branch: codex/remote-trial-loading-v1.

Goal: diagnose and fix UI-002: the scan-detail loading placeholder remains above
loaded results and reserves excessive blank space.

Read root AGENTS, remote-development contract/queue, UI-002, and scan-detail
markup/scripts/styles. Permitted changes: scan-detail HTML/JS, narrowly relevant
CSS (no global redesign), focused UI regression tests/test harness if needed,
FEATURES and package progress documentation. Do not change backend/API/auth,
scan execution, other pages, dependencies, or live services. Ask if that scope
cannot fix the confirmed cause; do not guess or merely remove error handling.

Acceptance: initial loading is visible; successful results clear the placeholder
and its reserved space; failed/empty requests have explicit appropriate states;
background refresh retains results and scroll. Reproduce locally with synthetic
data, not the live server. Add regression coverage for success, failure and refresh,
run make verify and git diff --check plus the UI tests, and inspect desktop/narrow
layouts. Report unavailable visual checks as incomplete, not passed.

Commit and push this dedicated branch only after required checks pass. Include
sanitized handoff with base/result SHAs, checks and remaining questions. No main
push/merge, deployment, live-data access or early wake. Report via existing
Mossward server-lab mailbox, preserving unrelated results. Dirty/conflicting
checkout, changed approval or failed checks requires stopping and reporting.
