# Security scope

This is a synthetic local demonstration, not a deployed security service.
Do not put real credentials, account records, telemetry or private identifiers
into its fixtures. No containment executor is present. Approval means
APPROVED_SIMULATION only, with execution_status NOT_IMPLEMENTED.

The threat model is in docs/THREAT_MODEL.md. Finite tools and typed host checks
are logical application boundaries; trusted Python providers and local operators
are not sandboxed against the filesystem or database. Local reviewer names and
rubric receipts are labels/attestations, not authentication. Content hashes detect
changed inputs but do not resist an administrator who edits code and hashes.

There is no configured private disclosure channel in this unpublished checkout.
If sharing a report with a future maintainer, keep it reproducible with fictional
data and exclude secrets or personal details. Nothing in the quickstart sends
reports or messages to an external service. Hosted CI and publication remain
unexecuted.
