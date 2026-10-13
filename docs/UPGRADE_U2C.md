# Offline case study and reviewer package - 12 October 2026

The first U2-B offline batch reached COMPLETED on all 36 split executions.
Domain success was 12/12 for the fixed playbook on development, 12/12 for
that playbook on capability, and 7/12 for the limited Gateway double on
capability. Five accepted double completions were wrong. Workflow termination
is therefore reported separately from successful triage.

Main independently ran 11 pure methods and seven native commands, checked
448 assertions, and rejected five corruptions: false completion, missing
observation, invented cost, source substitution and raw erasure. These local
results do not establish live-model or SOC quality. The 24 tasks are fictional,
worker-exposed, correlated examples from six shared family templates. They
are separate from the original 36-case regression set. A repeated one-case
demo is excluded from both split denominators.

## Results and retained failures

The following counts use each assigned provider's 12 tasks. “Full outcome”
requires disposition, urgency and gaps; task success additionally requires
verified COMPLETED state. No score threshold or positive uplift is a CI gate.

| Split / policy | Dispatched / COMPLETED | Raw / guarded disposition | Raw / guarded urgency | Raw / guarded gaps | Raw / guarded full outcome | Task success |
| --- | --- | --- | --- | --- | --- | --- |
| Development / complete-playbook-v2 | 12 / 12 | 12 / 12 | 12 / 12 | 12 / 12 | 12 / 12 | 12 |
| Capability / complete-playbook-v2 | 12 / 12 | 12 / 12 | 12 / 12 | 12 / 12 | 12 / 12 | 12 |
| Capability / gateway-double | 12 / 12 | 7 / 7 | 10 / 10 | 12 / 12 | 7 / 7 | 7 |

Every double error remains visible in the public summary:

| Case | Required disposition / urgency | Raw and guarded disposition | Alert severity | State / task success |
| --- | --- | --- | --- | --- |
| u2b-cap-01-1 | BENIGN / LOW | INCONCLUSIVE | LOW | COMPLETED / false |
| u2b-cap-01-2 | BENIGN / LOW | INCONCLUSIVE | LOW | COMPLETED / false |
| u2b-cap-02-2 | ESCALATE / CRITICAL | INCONCLUSIVE | HIGH | COMPLETED / false |
| u2b-cap-03-2 | ESCALATE / CRITICAL | INCONCLUSIVE | MEDIUM | COMPLETED / false |
| u2b-cap-06-1 | ESCALATE / HIGH | INCONCLUSIVE | HIGH | COMPLETED / false |

The three escalation misses span two HIGH and one MEDIUM alert strata.
Two also miss required CRITICAL urgency. There were no raw or guarded false
BENIGN outcomes in this batch. Correct gap accounting and supported claims
alone did not ensure the right disposition.

The original scorer's `paired.winner` compares **guarded disposition** only.
Its capability result is five playbook wins, zero double wins and seven ties.
The public package adds a separately named `paired.full_task` comparison of
task-success booleans; this batch happens to have the same counts. A class tie
can become a full-task loss when urgency, gaps or verified completion differ.
Both-success and both-failure ties count as ties. Historical `scores.json`
files were neither edited nor re-stamped.

The original public 36-case evidence also remains unchanged: adaptive raw
32/36 and guarded 34/36, MEDIUM misses held-032/033, raw false BENIGN outcomes
held-035/036 and their host corrections. U1/U2-A source and evaluation manifest
versions, failed helper/whitespace records and earlier authoring receipts remain
attributable to their original candidates.

## Latency and cost coverage

These are nearest-rank measurements from the first reports, in seconds.
Each row has measured N=12 and assigned N=12, including the five wrong results.
There were no handoffs or interrupted/unexecuted slots in this batch. The
summary kernel retains them when present and reports missing latency separately.

| Split / policy | Execution wall P50 / P95 / max | Host elapsed P50 / P95 / max |
| --- | --- | --- |
| Development / playbook | 0.750 / 1.047 / 1.047 | 0.484 / 0.797 / 0.797 |
| Capability / playbook | 0.656 / 1.000 / 1.000 | 0.422 / 0.735 / 0.735 |
| Capability / double | 3.203 / 3.734 / 3.734 | 2.938 / 3.422 / 3.422 |

Execution wall time includes case setup/cleanup. Host elapsed is the cumulative
case runtime. The playbook runs in process; the double uses loopback HTTP and
an owned transport child. This transport difference confounds a policy-speed
comparison. No live-model latency claim follows. Approval operations and wait
were zero because no approval action was implemented.

Actual cost coverage is 0/12 per policy, 0/36 overall. Actual total cost and
cost per successful task stay **null**, in INR. No billing or complete operating
cost was measured. Zero paid model calls does not make unmeasured local compute
cost zero. Tokens, provider billing and actual external sandbox effects remain
unmeasured or unexercised.

## Redacted artifacts and provenance

[The first summary](evidence/U2B_FIRST_SUMMARY.json) contains only public
fictional case IDs, dispositions/urgencies, correctness/count fields, state,
timings and hashes. [Its anchor](evidence/U2B_FIRST_REPORT_PINS.json) binds the
exact first run manifests, score reports, packets, inputs and redacted case rows.
It includes no local paths, raw observations, claims, traces, SQLite or private
coordination records. Hashes establish reproducibility, not a signature or
protection against an administrator replacing both data and anchors.

`evaluation.upgrade_public` checks frozen executable/input bytes and the
historical actor/evaluation/source fingerprints, rejects changed or duplicate
JSON, checks report aggregates and packet-to-score bindings, then uses an
explicit field projection. It never imports actors, opens SQLite, launches a
transport or reruns a case. Public validation reproduces all summary metrics
from the pinned redacted rows. It relies on the prior independent private
state/trace verification; it cannot recreate that verification from a summary.

The historical binding remains actor `378e16b39cee9fbe17d2d8c87a022d4457b33b9ca7b181788a37f4d8ae9ba53d`,
evaluation `45030132f82bca0377035e4f0b1704f5941691f847a139dd32d8d248c1ba68f1`,
and U2-B source manifest `0023d8041a8b66230986a7eb41ca8950df812713c7e0c76f30525277e4ca55ed`.
The additive U2-C packaging source manifest is a new revision. No executable,
dataset, label, evaluator or old manifest bytes change; only README receives
an appended update. There is no new scored evaluation binding. Old source
manifests describe their dated snapshots, including their earlier README.

To validate the shipped snapshot without private artifacts:

```powershell
py -3.11 -m evaluation.upgrade_public --validate docs/evidence/U2B_FIRST_SUMMARY.json
py -3.11 -m evaluation.upgrade_ci
```

To reproduce the projection when the exact original private reports are
available, use their development and capability directories. The output must
be fresh; changed or newly rerun reports are rejected by the first-run pins:

```powershell
py -3.11 -m evaluation.upgrade_public --development-dir work/main-u2b-0909-development --capability-dir work/main-u2b-0909-capability --out work/u2c-first-summary-copy.json
```

The shipped snapshot was generated once by a source-only JSON projection with
sockets and process launch blocked. No actor was dispatched, no scores were
regenerated and no SQLite was modified. Summary generation is not a corpus run.

## Demo walkthrough and failure recovery

The commands below are prepared for a later main lease and were **not executed
in this U2-C slice**. Use a fresh output directory for each example.

```powershell
py -3.11 -m evaluation.upgrade_run --split development --providers complete-playbook-v2 --demo-case u2b-dev-03-1 --max-seconds 60 --out work/reviewer-u2c-demo
py -3.11 -m evaluation.upgrade_verify --run-dir work/reviewer-u2c-demo/u2b-dev-03-1--complete-playbook-v2 --suite provider-contract --source fixtures/upgrade/development/u2b-dev-03-1.json
```

Open the fictional input first: it contains a success after related MFA
denials plus an auth collector gap. The observed workflow reads identity,
auth/resource pages, coverage and successful-session device/network context.
The supported misuse outranks the gap: raw and guarded ESCALATE/HIGH retain
the gap, and proposal is null. The independent verifier checks the source,
native packets, raw-event ordering, read coverage, claims and committed state.
The original first demo reached this result. A future demo is a repeated known
input, never an extra independent evaluation task.

```powershell
py -3.11 -m security_triage.upgrade demo --provider gateway-double --scenario false-completion --out work/reviewer-u2c-false-completion
py -3.11 -m evaluation.upgrade_verify --run-dir work/reviewer-u2c-false-completion --suite provider-contract --source fixtures/demo/case-002.json
```

The first command deliberately exits **2**: an unsupported raw BENIGN finish
is preserved, corrections exhaust their bound, and the host records guarded
INCONCLUSIVE/HANDOFF. The verifier should exit 0 because it confirms an honest
failure contract; this does not turn that raw outcome into successful triage.
401/402/429/5xx, malformed outputs, ambiguous response loss, stalled headers/body,
cancellation and bounded cleanup are covered by the U1 contracts. U2-A covers
GET-only identity/scope/version checks, full pagination, drift, rate metadata,
HTTP failures, total deadline and cancellation; real GitHub access is pending.

Fresh output directories prevent silent resume/overwrite. Failed, interrupted,
cancelled, corrupt and pending slots retain their artifacts and denominators.
No automatic transport replay or write recovery is authorized. Reviewed write
intent/apply/reconciliation and containment remain unimplemented.

## Offline CI and later regression batch

The additive `upgrade-offline.yml` uses the existing pinned checkout/Python
action revisions, Python 3.11 and only standard-library dependencies. It checks
static data pins, the redacted first-report snapshot, and the pure provider,
deadline, redaction, spend, sandbox, scoring and corruption modules through
`evaluation.upgrade_ci`. Socket creation and subprocess launch are blocked
throughout that command. Failures, errors or skips fail CI; the 7/12 quality
score is descriptive and does not fail CI. No secrets or live jobs are configured.
The original frozen workflow remains unchanged. Hosted execution/publication
and the full current legacy regression are still pending main review.

Local U2-C validation ran `py -3.11 -m evaluation.upgrade_ci` once: **61 pure
methods passed**, with zero failures, errors or skips (51 existing methods
plus 10 new publication methods). This exercised the packaged integrity gate
with sockets and process launch blocked. It is not a hosted workflow run or
the native full suite. The standalone export/validation CLI commands above
are prepared for reviewer execution; the projection functions and validation
were exercised locally without dispatch.

The exact proposed regression commands and expected exit codes are in
[UPGRADE_U2C_BATCH.json](UPGRADE_U2C_BATCH.json). They include the current full
test discovery (with native U1/U2-A failures), a baseline demo, the expected-exit-2
false-completion demo, and the original demo/36-case regression. This slice
executes only pure checks. There is no U2-B split rerun, actor tuning, new data,
hidden-set access, inference, build, download, browser, remote write or deployment.

Actual isolated GitHub/app/installation proof, reviewed external effects,
main-owned unseen evaluation, current provider/model/pricing/reservation and
live receipts remain separate gates. Final acceptance and publication belong
to main. Fictional data and new source remain under the repository MIT license;
no new library, copied detector or third-party dataset is introduced.
