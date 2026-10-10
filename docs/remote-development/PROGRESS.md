# Remote development handoff

2026-10-10: Handoff documentation established. Development is disabled; there is
no approved package, active development branch, or scheduler activation.
No implementation or production changes authorized by this handoff.

For every active run, append a sanitized entry with:

- UTC timestamp, package ID/specification revision, and state
- Base SHA, branch, and checkpoint/result commit SHAs
- Work completed and remaining acceptance criteria
- Exact checks run, results, required checks skipped and why
- Blockers/questions requiring human input
- Next permitted action and whether branch push occurred

Record results after commands run, not predicted outcomes. Keep operational
server-lab results in their existing mailbox; do not copy secrets or raw logs.
