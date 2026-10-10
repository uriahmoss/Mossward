# Reported UI issues

Reported during the 2026-10-10 browser review. These are user observations, not
locally reproduced root causes. All remain unverified and queued; none authorizes
implementation. Corresponding acceptance backlog is in docs/FEATURES.md.

| ID | Area | Reported reproduction / symptom | Expected behavior |
| --- | --- | --- | --- |
| UI-001 | Recent scans | Run a CIDR scan, open recent scans; expanded addresses fill the row | Compact scope/count, details on demand |
| UI-002 | Scan details | Open completed scan; loading placeholder remains above results | Loading clears; results near top |
| UI-003 | Scan overview | Completed scan shows overlapping status/cancel controls | Non-overlapping, state-appropriate controls |
| UI-004 | Findings | View range-scan findings; affected IP is hard to locate, CIDR labeled target | Prominent actual host/port, distinct scan scope |
| UI-005 | Reports | Open Reports after scan; unavailable message despite trend data | Reports render or explain specific empty/error state |

Triage reproduction and severity before implementation; no ranking assigned yet.
For each issue add sanitized reproduction, confirmed cause, package/commit link,
test coverage, and verification result. Do not attach credentials or raw private
environment screenshots to a public repository. Keep feature requests in the
roadmap rather than misclassifying them as confirmed defects.
