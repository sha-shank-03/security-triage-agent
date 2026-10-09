# Threat model and limits

Assets are immutable fictional evidence, the correctness of a committed
disposition, the exact content of a review decision, and the distinction between
raw recommendations and guarded outcomes. No real credentials, live identity
system, containment executor or account write exists.

| Input or failure | Host control | Remaining limit |
| --- | --- | --- |
| Source text requests approval or invents instructions | Source records stay tool data; finite tool dispatch and typed support validation decide authority | Prompt adherence and real-model behavior remain unmeasured |
| Provider invents citations, versions or session targets | Claims must match observed immutable records; target must be an observed success supporting escalation | Finite claim vocabulary cannot validate arbitrary prose |
| Provider requests files, SQL, external URLs, review or execution | Those tools are absent; schemas and dispatcher reject unknown tools/fields | Trusted Python provider is not an OS sandbox |
| Empty, partial or late telemetry | Explicit coverage, ingestion cutoff, bounded pages and conservative benign gate | Source coverage assertions are fictional and trusted |
| Lookalike address or unrelated travel | Exact observed-IP match and full-interval validity | No real geolocation, threat feed or identity enrichment |
| Interrupted request or lost response | Reservation commits first; explicit resume retains counts/deadline and reconstructs observations | Requires one active investigator per run |
| Cancel arrives during finalization | Database write lock and state check serialize commit/cancel; no executor | In-flight HTTP cancellation waits for its bounded timeout |
| Approval reused for changed target/snapshot/user/session | Exact payload hash, row version, monotonic snapshot registry, per-record version and expiry checks | Registry knows only snapshots explicitly registered locally |
| Duplicate review delivery | Request-ID/intent hash returns historical result without another transition | Reviewer is a local label, not authenticated identity |
| HTTP timeout, 429, 5xx, redirect, oversized or malformed response | Remaining-budget timeout, one retry for selected transient failures, fixed loopback route, byte/one-call/schema bounds | Server may proxy or execute weights remotely |
| SQLite commit failure | Atomic final/review transaction rolls back; reservation remains consumed | Abrupt OS/disk loss beyond SQLite durability is not simulated |
| Local administrator edits code, evidence or both hashes | Evidence hash/index integrity checks catch isolated edits | No tamper-proof audit, signing, remote attestation or admin defense |

The protocol harness contains only owned short-lived loopback servers and a
single explicitly launched crash-test child. They are not started on import.
No unrelated process is stopped. M2 integration execution of these harnesses is
independently accepted for M2 and repeated in final M3 acceptance. The final full suite passed 65 tests, including owned crash recovery, real
loopback continuation/failure bounds and immutable source evidence after
APPROVED_SIMULATION. See EVIDENCE.md for the initial timeout-double traceback
and its bounded correction.

Synthetic labels encode an authored world truth, not a universal security
judgment. Escalation means analyst attention and a reviewable proposal, not proven
compromise. Denial sequences and unmanaged sensitive-session activity are
deliberately simplified. No result establishes SOC performance, production
readiness, incident-response compliance, real-model quality or time saved.
