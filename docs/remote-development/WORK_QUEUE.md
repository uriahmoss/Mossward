# Approved remote work queue

Queue format version: 1

Development enabled: **no**

Approved packages: **none**

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
