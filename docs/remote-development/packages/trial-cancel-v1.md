# trial-cancel-v1

Specification revision: 1. State: approved by Uriah on 2026-10-10.
Base: 52d3571e96a8e1093f76d5ef3cca82b93e65df03.
Branch: codex/remote-trial-cancel-v1.
Dependency: trial-loading-v1 has passed required checks and been pushed; it need
not be merged. Start this independent branch from the approved base, not its code.

Goal: fix UI-003: overlapping scan status/cancel controls and cancellation shown
for completed scans.

Read root AGENTS, remote-development contract/queue, UI-003, and scan-detail
markup/scripts/styles and existing scan state definitions. Permitted changes:
scan-detail HTML/JS, narrowly relevant CSS, focused UI tests/test harness if
needed, FEATURES and package progress documentation. Do not change backend/API,
authorization, state machine, scan execution, dependencies, other pages or services.

Acceptance: cancel is offered only for existing cancellable states; completed,
failed and cancelled scans do not offer it. Existing cancellation confirmation,
permission handling and error feedback remain. Status and action controls do not
overlap on desktop, narrow screens or zoom. Use synthetic fixtures for all relevant
states and regression tests for terminal/nonterminal controls; run make verify,
git diff --check and UI tests. Inspect responsive/zoom layouts; missing checks mean
not complete. If fixes require backend changes, stop and ask.

Commit/push this dedicated branch after all checks pass, then stop: no next package
is approved. No main merge/push, deployment, live-data access or early wake.
Report sanitized commit/check outcomes and questions through server-lab and
versioned progress docs. Stop on conflicts, changed approval or failed checks.
