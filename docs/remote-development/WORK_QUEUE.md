# Approved remote work queue

Queue format version: 1

Development enabled: **yes, only for the two trial packages below after verified
successful installation of the remote development gate**

Approved packages (in order):

1. [trial-loading-v1](packages/trial-loading-v1.md) — approved
2. [trial-cancel-v1](packages/trial-cancel-v1.md) — approved

Direct human approval: Uriah, 2026-10-10, requested a few minor trial slices on
hourly wakes and explicitly permitted committing and pushing completed slices.
The sending coordinator records that approval here and in the scoped mailbox
request. Both package specifications are revision 1, pinned to the immutable
commit supplied by that request. Approved product base for both:
`52d3571e96a8e1093f76d5ef3cca82b93e65df03`.
Separate branches keep the trials independent. After the first passes all checks
and is pushed, the second may start on the next hourly review without awaiting
merge. No further packages are approved. Main integration and deployment remain
unauthorized. No early-wake metadata is permitted for these trials.

The UI review items in `docs/FEATURES.md` are backlog, not authorization to start.
The hourly scheduler must remain idle for development until direct human approval
is recorded here with package ID, specification revision, approval date, base
commit SHA, and permissions. Only the human or an explicitly authorized
coordinator may change approval state. Approval to write these documents does
not authorize activating the queue or editing scheduler configuration.

Use `PACKAGE_TEMPLATE.md` to propose a bounded package. Keep approved packages
under `packages/` and link them here. Amendments require renewed human approval.
States: proposed, approved, in progress, blocked, ready for review, integrated.
Ready for review does not mean permission to merge or begin another package.
