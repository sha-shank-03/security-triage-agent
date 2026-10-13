# Worker-exposed evaluation source slice - U2-B, 12 October 2026

U1 passed main independent local acceptance on12 October2026:88 tests,
13 commands,137 direct SQLite/fixture assertions and4 negative controls.
U2-A subsequently passed its local read-only contract:21 pure methods,
four native HTTP methods, a new two-page synthetic read,14 direct assertions
and4 tamper controls. These are local contracts, not genuine GitHub access,
live-model quality, billing or deployment evidence. Their original manifests,
source-module bytes, raw32/36 versus guarded34/36 v1 results, MEDIUM misses,
raw false BENIGN errors, freezes and failed-run records remain attributable
to their original candidates. No historical result is rebound to this slice.

## Authored data and exposure

Main narrowed the provisional18 development /24 capability proposal to
**12 development plus12 capability tasks**: six agreed families x2 per split.
Version `worker-exposed-u2b-v1` records this amendment. Original36 regression
tasks remain separate. There is no acceptance/unseen split interface, and no
main-held set or labels were created or inspected.

The families are legitimate login, observed misuse, positive misuse amid
gaps, unresolved telemetry, unrelated identity/session evidence, and
stale/paged/drifted evidence/review. The last family includes second-page
resource evidence and stale/late context; drift/version corruption is tested
separately. Review/write capability remains unavailable. Unrelated session/IP
facts concern the same case subject; foreign-subject ingestion stays rejected
by the original schema. Future-ingested facts remain outside actor observations.

The24 files are author-created fictional facts under MIT, with no incident
logs, copied detector rules or generated model judgments. Each input manifest
pins byte and semantic hashes, case identity, family and worker exposure.
Semantic duplicate checks remove identifiers and absolute dates while retaining
fact relationships and time offsets. The files are distinct, but share family
templates and an author: they are correlated coverage, not24 independent SOC
samples. Labels are separate sidecars, version-bound to the input manifest,
same-author and worker-exposed. Independent factual adjudication checks them;
main review remains pending. No claim of blind testing or representativeness.

`evaluation/upgrade_eval_manifest.json` retains the initial source/policy pins
and first nine-check iteration. `upgrade_eval_manifest_v2.json` retains the
demo-interface revision. `upgrade_eval_manifest_v3.json` is active after adding
a durable dispatch-start marker; data and labels did not change in either refinement.
Archived earlier source bytes are hash-checked in private worker provenance.
The final source manifest records both revisions and all original freeze pins.

## Complete-playbook-v2 and equal authority

The new baseline consumes only the same initial alert/window/cutoff and past
tool observations as the U1 Gateway route. It has no file, label, evaluator,
case-ID or family branches. It reads identity, closes auth and resource pages,
checks coverage, then requests device/network context for observed successful
sessions and travel when network corroboration is missing. Supported denial
sequences or sensitive access from an unmanaged device outrank missing telemetry.
BENIGN needs complete event reads and coverage, managed-device corroboration,
approved network/travel and consistent successful MFA without adverse facts.
Unresolved facts yield INCONCLUSIVE. All terminal claims must pass the old guard.

Both compared routes use the same U1 host, evidence store/tools, null-only
proposal authority,12 cumulative attempts including terminal decisions,
two corrections,60-second total case deadline,96-KiB request,64-KiB response,
16-KiB observation and two50-row pages. The fixed baseline can close typical
one/two-session playbooks within these bounds; additional distinct contexts
may exhaust them and produce a retained handoff. No hidden unlimited reads.
The baseline emits scripted native-format packets in process; Gateway-double
uses the accepted owned HTTP child and synthetic observation-driven imitation.
Neither is a real model. The limited double is a protocol comparator; beating
it would not establish model or SOC-quality uplift.

## Independent domain scoring and operating fields

`evaluation.upgrade_run` loads input files only and preallocates every
case/provider entry before execution, then saves STARTED before dispatch.
An interrupted started slot is INTERRUPTED_UNKNOWN, not fake completion.
A start deadline/cancellation leaves
remaining tasks PENDING; exceptions retain FAILED artifacts. One in-flight
case may add up to its60-second deadline plus cleanup after a batch start gate.
Fresh directories prevent replay/overwrite. Actual raw/guarded packets, events,
source records and SQLite state are exported through the accepted U1 path.

`evaluation.upgrade_score` imports no actor or host policy. It checks input,
label, configuration and source pins; independently replays tool queries; checks
raw-event/terminal binding; verifies reports against SQLite; and validates
claims, scope, pages, gaps, state and unchanged evidence. Fake completion,
missing observations, stale citations, altered records, changed source and
fabricated cost are corruption, not successful answers. A label agrees with
independently adjudicated source facts before its verdict is used for scoring.

Raw class/urgency accuracy and claim support remain separate from guarded class,
urgency/gaps and confirmed local task completion. A correct INCONCLUSIVE
handoff can count as a class match while task completion stays false. Reports
retain every denominator row, including NO_FINAL/NO_RESULT, FAILED, PENDING,
CANCELLED, HANDOFF, INTERRUPTED_UNKNOWN and CORRUPT. Per-class counts/confusion, false BENIGN,
misses by alert severity and required urgency, interventions, per-case attempt /
observation counts, paired wins/losses/ties and state are inspectable. There is
no required uplift or worker-defined score acceptance threshold. Always choosing
INCONCLUSIVE misses the BENIGN and ESCALATE classes; correctness and completion
are reported without turning safe abstention into successful triage.

Execution wall time includes setup/cleanup; cumulative host elapsed time is
separate. Nearest-rank P50/P95/max report their actualN and include recorded
failures/handoffs. Unexecuted rows have no measured duration. Approval wait is
zero because no approval operation exists. No billing or total operating cost
is measured: actual cost coverage is0, total cost and cost per success stay
null. A local packet is not a receipt for free live inference. Directory hashes
and local files establish attribution, not protection from a local administrator
who can forge source/state/timestamps together.

## Pure evidence and prepared commands

Eleven final pure checks passed. They use in-memory SQLite, fake clocks and tiny
contract probes with socket and subprocess creation blocked. They check authored
pins/counts, policy isolation, benign network/travel, misuse ahead of gaps,
page continuation, budget handoff, raw false completion, corruption and metrics.
These probes are not the24-task evaluation. Raw outputs preserve the earlier
nine-method and ten-method passes, followed by the final eleven-method pass.
The interruption probe mocks the actor and saves only a tiny temporary manifest.
No native/full-suite/split/demo/CI
execution occurred in this worker slice.

Every command below is authored and **UNEXECUTED**. Main must independently
review sources and grant/recheck its heavy lease before local execution:

```powershell
py -3.11 -m evaluation.upgrade_dataset --verify
py -3.11 -m evaluation.upgrade_run --split development --providers complete-playbook-v2 --demo-case u2b-dev-03-1 --max-seconds 60 --out work/upgrade-u2b/demo
py -3.11 -m evaluation.upgrade_verify --run-dir work/upgrade-u2b/demo/u2b-dev-03-1--complete-playbook-v2 --suite provider-contract --source fixtures/upgrade/development/u2b-dev-03-1.json
py -3.11 -m evaluation.upgrade_run --split development --providers complete-playbook-v2 --max-seconds 180 --out work/upgrade-u2b/development
py -3.11 -m evaluation.upgrade_score --run-dir work/upgrade-u2b/development
py -3.11 -m evaluation.upgrade_run --split capability --providers complete-playbook-v2,gateway-double --max-seconds 180 --out work/upgrade-u2b/capability
py -3.11 -m evaluation.upgrade_score --run-dir work/upgrade-u2b/capability
```

A one-case demo is rejected by the split scorer to protect its denominator.
Runner exit0 means every slot reached a terminal local state, including handoff;
exit2 preserves failed/unexecuted slots. Scorer exit0 means diagnostics were
verified, not that verdicts met a quality gate; corruption returns2. Setup or
integrity failure returns1. No low score or negative pair is discarded.

Proposed free offline CI execution is **UNEXECUTED**; the pure module command
below already passed locally. The proposed commands are the dataset verifier,
the pure module below, a baseline-only capability run and its scorer. Existing
frozen CI and all original regressions stay unchanged. Integration/full-suite
commands need main assignment/lease; no hosted CI result or workflow publication
is claimed, and no keys/network/live model/sandbox writes belong in CI:

```powershell
py -3.11 -m unittest tests.test_upgrade_evaluation -v
py -3.11 -m unittest discover -s tests -p test_*.py -v
py -3.11 -m evaluation.upgrade_run --split capability --providers complete-playbook-v2 --max-seconds 180 --out work/ci-upgrade-u2b
py -3.11 -m evaluation.upgrade_score --run-dir work/ci-upgrade-u2b
```

Main U2-B source/data/pure review and native diagnostic/regression gates remain
pending. Reviewer packaging/free-CI adoption, write intent/apply/reconciliation,
genuine sandbox identity/GET/write proof, main-owned unseen rubric and baseline
freeze, actual provider/price/reservation/live evaluation, publication and hosted
CI are later separately scoped gates. This slice grants no credentials,
containment, remote write, spend or publication authority.
