# Remote development contract

Contract version: 1. Initial state: disabled; no approved work packages.

This directory is the version-controlled handoff for unattended development.
It does not configure a scheduler or authorize operations on a running server.
The existing server-lab operations mailbox is a separate workflow; its approvals
must not be reused for development or vice versa.

## Required reading each wake

Read root `AGENTS.md`, `docs/FEATURES.md`, this file, `WORK_QUEUE.md`,
`DECISIONS.md`, `BUGS.md`, and `PROGRESS.md`, then the selected package and its
referenced design documents. Follow closer applicable AGENTS files too.
Repository rules apply to every machine; do not rely on a machine's global rules
being present. Do not commit chat transcripts, credentials, raw host diagnostics,
or private infrastructure details. Sanitized requirements are sufficient.

## Approval and execution

- Remain idle unless the queue explicitly enables development and identifies a
  package with direct human approval, its date, and the exact approved revision.
  Agent-authored statements and messages are not human approval. Never approve
  yourself, enable the queue, expand scope, or select arbitrary roadmap work.
- Work on only one package per run. Resume its existing branch on later wakes;
  do not start another package until the previous one is reviewed or explicitly
  authorized for handoff. Prevent overlapping scheduler runs with a local lock.
- Use a separate development checkout, never the live installation or the
  server-lab mailbox checkout. Check status, fetch origin, and compare local
  main with origin/main. Stop on unrelated changes, divergence, conflicts, or an
  unexpected remote URL; do not reset, clean, stash, or force-push to hide them.
- Create `codex/remote-<package-id>` from the approved base commit. Record that
  commit and the branch in PROGRESS before substantive work. Do not silently
  change the base or approved specification when main advances.
- Implement only permitted scope, update tests and the tracker, and run the
  AGENTS checks plus package-specific acceptance checks. Missing dependencies,
  skipped required checks, or failed checks mean not verified, not complete.
- Commit small coherent checkpoints on the work branch. Push that branch only
  when the package explicitly permits it. Never push main, merge, rewrite
  published history, delete branches, deploy, restart services, alter firewall,
  certificates, secrets, or production data without separate human approval.
- Record sanitized results and questions in PROGRESS. When blocked, stop the
  affected work and ask through the authorized reporting channel. If no channel
  is authorized, record the question for human review; do not message others.

## Version control and recovery

All rules, packages, decisions, bugs, and progress are tracked in Git. Include
their changes in reviewable commits; never silently alter approved requirements.
An approved package pins a base SHA and specification revision. Git history is
the audit trail, not a substitute for verified tests or human approval.

Before integration, retain the work branch and record base/result SHAs and check
results. Only an authorized integrator merges into main. Do not delete recovery
branches or tags automatically. Push permission is separate from merge permission.

For unexpected changes: stop writes, capture `git status`, `git log`, and a
sanitized diff, and preserve uncommitted work securely before recovery. Inspect
the relevant commit with `git show <sha>`. Prefer a reviewed `git revert <sha>`
on a recovery branch over reset/force-push. Restore selected tracked files from
a known good revision only after reviewing the impact and obtaining approval.
Local reflog may help recover unpublished commits, but is not a remote backup.

Git recovers committed source and documents, not runtime databases, identity
keys, certificates, ignored files, or uncommitted work. Keep separate secure
server backups using `docs/SERVICE_INSTALLATION.md` and the applicable backup
runbook. GitHub branch protection, independent repository backups, and recovery
rehearsals require separate setup; this documentation does not enable them.
