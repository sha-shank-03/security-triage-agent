# Evidence log

Date: 2026-10-08. State: M1/M2 independently accepted; M3 source/pure-component checkpoint prepared, rubric review and integration pending. Accepted M2 source is preserved at local Git commit e04254caf4e7906fe32a1b1fb5700b60349a3e13; M3 changes are uncommitted. Environment: Windows/AMD64, launcher-selected CPython 3.11.9 (64-bit), bundled SQLite 3.45.1. Only M2 owned loopback HTTP doubles were contacted. No dependency downloads, actual model calls, external network, hosted CI, real accounts, deployment, or containment execution. Historical checkpoint results are preserved separately by milestone.

Independent M1 acceptance was recorded at 2026-10-08T10:11:15.291368+00:00:
four commands, nine units, six integration tests and twelve additional direct
stored-domain checks passed. The maintainer inspected the loop, host gate,
proposal transactions and independent verifier. This accepts M1 only.

## Executed checks

| Order | Exact command | Exit | Observed result |
| --- | --- | ---: | --- |
| 1 | `py -3.11 -m unittest tests.test_unit -v` | 1 | 9 tests; 4 cleanup errors. SQLite initializer connections remained open and caused Windows WinError 32 during temporary database removal. Test assertions were not weakened. |
| 2 | `py -3.11 -m unittest tests.test_unit -v` | 0 | 9 tests passed; unittest reported 0.206 seconds. Initializer now explicitly closes SQLite connections and commits created evidence before closing. |
| 3 | `py -3.11 -m compileall -q security_triage evaluation tests` | 0 | Syntax compilation passed for the M1 application, independent verifier, and unit/integration test source. No acting loop or demo was executed. |
| 4 | `py -3.11 -m security_triage demo --out work/m1` | 0 | Three scripted cases persisted: BENIGN/LOW, ESCALATE/HIGH, INCONCLUSIVE/HIGH. Command tool reported 1.165365 seconds. |
| 5 | `py -3.11 -m evaluation.verify --run-dir work/m1 --suite demo` | 0 | 3/3 dispositions, 15 supported typed claims, 15 evidence calls, one pending proposal, zero containment/source mutations. Command tool reported 0.5398408 seconds. |
| 6 | `py -3.11 -m unittest discover -s tests -p test_slice.py -v` | 0 | All 6 integration tests passed; unittest reported 0.657 seconds, command tool 1.0894228 seconds. |

Passing lightweight assertions: duplicate JSON keys/non-finite constants rejected; exact turn envelope required; budgets cannot exceed host limits; cross-subject/version/duplicate input errors rejected; duplicate denial references do not inflate counts; real SQLite auth reads; read-only write denial; unknown tools/cross-case device/unobserved sessions rejected; unseen claims cannot finalize; empty event results do not manufacture coverage. These tests do not invoke the three-case demo or acting loop.

## Completed worker acceptance

```powershell
py -3.11 -m security_triage demo --out work/m1
py -3.11 -m evaluation.verify --run-dir work/m1 --suite demo
py -3.11 -m unittest discover -s tests -p test_slice.py -v
```

The verifier checked eight invariant categories: dispositions, urgencies, gaps, typed claims, tool traces, provider-final binding, pending proposals, and source immutability. It reads stored outcomes and original fixture data rather than trusting the actor's report.

The six passing integration tests cover:

- All three dispositions, supported facts, a pending proposal, and zero evidence mutations.
- Evidence-dependent lookup order and the newly observed unmanaged device; the gap case preserves `coverage-auth-003`.
- Completed-run reuse without duplicate proposals.
- A malformed provider claim causes three rejected raw escalation attempts followed by an inconclusive host fallback and zero proposals.
- A forged session target is rejected on all three bounded attempts and produces zero proposals.
- The independent verifier rejects each of three actual database corruptions: disposition, claim value, and proposal payload.

The only proposal is `REVOKE_SESSION` for `session-002`, backed by `login-002` version 1. State: PENDING. Payload SHA-256: `3d81383ddff2d65328a441adc2c072d19bc2bb9140f6bad91c3a709a026bf148`. The evidence snapshot digest is `aac9a4837c4b19484303ba726f7ea2458d5d7a6f59637d14e3e150017eeeb7fe`. Both benign and inconclusive cases have no proposal. Generated packets are `work/m1/results.json` and `work/m1/report.md`.

## Resource execution

The exact active worker/M1 grant was checked immediately before execution at `2026-10-08T10:00:43.328605+00:00` using Python JSON parsing and timezone-aware ISO datetime comparison. The permitted window was five cumulative active minutes, one sequential CPU worker, 256 MiB RAM, 50 MiB generated scratch, and zero downloads/network/model calls. The three commands ran sequentially and their tool-reported wall times total **2.7946286 seconds**. No M1 correction or repeat acceptance batch was needed.

After temporary integration-test cleanup, four primary demo artifacts totaled **135,248 bytes**. This is retained output size, not a sampled transient scratch peak. Peak RAM and transient scratch usage were not sampled; the granted limits must not be represented as measured peaks. No dependency/download/HTTP/model process was started. The M1 lease was subsequently released; worker consumption stopped.

## Limits at the M1 checkpoint

The M1 provider is scripted and in-process. Local tampering doubles exercised validation failures in the integration suite; they do not establish live-model quality. M1 had no model transport adapter, review/expiry or crash resume. Independent maintainer verification was later completed as recorded above; all broader integration/model/benchmark claims remain governed by their separate milestone evidence. Resource estimates and unsampled peaks remain estimates/unknowns.

All fixtures are authored and fictional; three public examples demonstrate integration only. Logical tool/evaluator separation does not sandbox hostile Python code. Typed factual claims cover a finite vocabulary. A pending proposal is an artifact, not containment.

## M2 source/component checkpoint

Implemented source: exact-content SIMULATED review; immutable payload hash plus
row version; 24-hour expiry; monotonic current-snapshot registry and
identity/session version staleness; review request idempotency; explicit resume
bound to full configuration; reserved turns and persisted correction/deadline
budgets; cooperative terminal cancellation; atomic final/review transactions;
travel and bounded window/IP/session pagination; twelve development inputs;
fixed baseline, label schema, static freeze; genuine native Ollama wire adapter;
owned local HTTP/crash harnesses; independent development diagnostic harness and
scorer; architecture/threat model.

No full M2 investigation, disk recovery, actual HTTP server/client interaction
or development scoring was executed. Component tests use in-memory SQLite,
read authored fixture inputs, and inject a transport function. Direct review
store tests prepare a component payload; they do not run an actor investigation.

| Order | Exact command | Exit | Observed result |
| --- | --- | ---: | --- |
| M2-1 | py -3.11 -m unittest tests.test_m2_components -v | 0 | Initial 21 components passed; unittest 0.033 s; tool wall 0.6694437 s. |
| M2-2 | py -3.11 -m unittest tests.test_m2_components -v | 0 | Added atomic rollback check: 22 passed; unittest 0.038 s; tool wall 0.7501449 s. |
| M2-3 | py -3.11 -m unittest tests.test_m2_components -v | 0 | Added persisted limit and strict deadline checks: 24 passed; unittest 0.051 s; tool wall 0.6460108 s. |
| M2-4 | py -3.11 -m compileall -q security_triage evaluation tests | 0 | Syntax check; tool wall 0.6377436 s. |
| M2-5 | py -3.11 -m evaluation.freeze --write | 0 | Static spec/source/schema/label/input freeze, twelve inputs; no scores. Tool wall 0.4933013 s. |
| M2-6 | py -3.11 -m evaluation.freeze | 0 | Static freeze matched; tool wall 0.4928207 s. |
| M2-7 | py -3.11 -m unittest tests.test_m2_components -v | 0 | Final 25 components passed; restored-record corruption and historical review replay checked. Unittest 0.039 s; tool wall 0.6089027 s. |
| M2-8 | py -3.11 -m compileall -q security_triage evaluation tests | 0 | Final syntax check; tool wall 0.698625 s. |
| M2-9 | py -3.11 -m evaluation.freeze | 0 | Freeze still matched; tool wall 0.4433301 s. |

Final component assertions include hash/version mismatch; success/failure review
replay and conflicting IDs; expiry and newer snapshots; individual identity and
session version linkage; rejection/approval with no source mutation; burned
interrupted turns; budget/config/request mismatch; no deadline reset; terminal
cancellation; transactional rollback; strict finite deadline values; cursor
binding/restoration/two-page cap; incomplete chain detection; exact window/IP
filters; travel support; native wire continuation/schema mapping; malformed,
multiple, unknown and oversized responses; exactly one injected retry; no retry
for 401; cancellation/expired-budget before transport; fixed baseline read order;
all twelve fictional inputs validated.

There were no failing M2 test commands. Three source-authoring tool submissions
were refused before any edit: a duplicate delete/add path in one patch, and two
JavaScript syntax errors while constructing patches. They were corrected by
sequential file replacement and simpler patch construction. No test assertion
or acceptance condition was weakened. Static inspection found no actor imports
of evaluation/labels and no absolute personal paths in shipped files.

The baseline draft was corrected from five reads to six by adding the full
resource read required for benign support. Both scripts share a recommendation
function, so their future comparison measures evidence selection. Freeze digest:
c24d2589a14b43a6ca9ae06ed7a6d5e9af955f808418c1c362cfd1e8f809d1c9.
There are four BENIGN, four ESCALATE and four INCONCLUSIVE cases, two in each of
six families. Labels/schema/spec/source were frozen before any development score.
No 36-case held-out corpus, M3 scoring/gates or probability calibration exists.

M2 lightweight command tool wall times total 5.4403228 seconds, excluding source
authoring and read-only inspection. RAM/transient scratch peaks were not sampled
and remain unknown. Downloads, actual HTTP calls, actual model inference,
containment writes and M2 integration-lease consumption are zero.

## M2 commands deferred at the source checkpoint

    py -3.11 -m evaluation.freeze
    py -3.11 -m unittest discover -s tests -p test_*.py -v
    py -3.11 -m security_triage demo --out work/m2-demo
    py -3.11 -m evaluation.verify --run-dir work/m2-demo --suite demo
    py -3.11 -m evaluation.run --split development --providers scripted,baseline --repeat 1 --out work/m2-development
    py -3.11 -m evaluation.score --run-dir work/m2-development

The discovery command includes 48 authored test methods: nine earlier units,
six earlier integration checks, twenty-five M2 components and eight new M2
integration methods. Forty-eight is a source count, not an executed M2 result.
The new harnesses exercise a real owned loopback connection, bounded HTTP
failure/timeout/redirect handling, an owned crash subprocess, disk reopen,
stale/expired review and cancellation/fault outcomes. They remain unexecuted.

Proposed integration envelope: one sequential CPU worker with at most one owned
child process and one loopback double at a time; ten cumulative active minutes;
256 MiB RAM and 50 MiB generated disk ceilings; zero downloads, external network,
real server/model calls or containment. Limits are estimates, not measurements.
Integration results and independent maintainer acceptance remain pending.

## M2 completed worker integration and development diagnostics

The exact worker-owned M2 grant was active from
2026-10-08T11:05:04.116859+00:00 to 2026-10-08T12:35:04.116859+00:00, with ten
cumulative active minutes, 256 MiB RAM, 50 MiB generated disk and no downloads.
Before every command, the runner reparsed raw resources JSON, verified the exact
lease name, worker/slug/M2 ownership and active status, used timezone-aware UTC
grant/expiry comparison, and checked cumulative execution time. Commands ran
sequentially. The guard and sampler are local ignored work utilities.

| Step / attempt | Exact command | Exit | Wall seconds | Observed result |
| --- | --- | ---: | ---: | --- |
| 1 / 1 | py -3.11 -m evaluation.freeze | 0 | 0.157 | Original development freeze matched; no change to inputs, labels or baseline. |
| 2 / 1 | py -3.11 -m unittest discover -s tests -p test_*.py -v | 0 | 4.813 | 48 passed; unittest 4.528 s. Expected timeout disconnect printed a background HTTP-double WinError 10053 traceback. Raw stderr retained. |
| 2 / 2 | py -3.11 -m unittest discover -s tests -p test_*.py -v | 0 | 4.578 | Clean repeat: 48 passed; unittest 4.278 s. |
| 3 / 1 | py -3.11 -m security_triage demo --out work/m2-demo | 0 | 0.860 | BENIGN/LOW, ESCALATE/HIGH, INCONCLUSIVE/HIGH on fresh schema 2. |
| 4 / 1 | py -3.11 -m evaluation.verify --run-dir work/m2-demo --suite demo | 0 | 0.219 | 3/3 dispositions, 15 claims, 15 reads, one pending proposal, zero source mutations; eight independent invariant categories. |
| 5 / 1 | py -3.11 -m evaluation.run --split development --providers scripted,baseline --repeat 1 --out work/m2-development | 0 | 5.031 | Two sequential actor subprocess executions, twelve cases per script, one repeat; complete manifest. |
| 6 / 1 | py -3.11 -m evaluation.score --run-dir work/m2-development | 0 | 0.219 | Independent diagnostic scoring of both scripts; no held-out gates. |

No command exited nonzero. The first test run exposed an expected closed-client
ConnectionAbortedError/WinError 10053 during the delayed double's payload write.
The double already handled broken pipe/reset; it now also handles the Windows
aborted connection in that same write-only cleanup path. The timeout assertion
and all other assertions stayed intact. The full suite was repeated once for
this bounded M2 correction, with no background traceback.

The resource sampler initially recognized python.exe/python3.exe but missed the
installed executable name python3.11.exe. Its raw process creation/parent records
and RAM/disk samples were retained; its initial child count is not reliable.
Classification was corrected before the clean suite repeat and later commands.
No baseline, input, label, disposition policy, or evaluation rule changed after
the first development freeze/score.

The final 48 passing tests comprise nine earlier units, six earlier integration
checks, twenty-five M2 components and eight M2 integration methods. They checked
actual owned child exit/recovery with burned turns and unchanged absolute
deadline; exact configuration resume; current-snapshot and expiry refusal;
review idempotency after disk reopen; unchanged evidence file SHA-256 after
APPROVED_SIMULATION; wrong hash/version and forged/corrupt content/target refusal;
provider-fault and cancellation with zero proposals; zero dispositions on
cancellation; indexed-source corruption refusal; native two-request HTTP
assistant/tool continuation; one bounded transient retry; unknown functions,
oversized responses and redirects refused; real socket timeout retaining the
case deadline; and all earlier citation/proposal/verifier corruption checks.

### Development denominators and outcomes

Twelve unique authored cases were run once per provider: four BENIGN, four
ESCALATE (three HIGH, one CRITICAL) and four INCONCLUSIVE. The 24 executions do
not represent 24 independent cases. This is the development split only.

| Metric | Adaptive scripted | Fixed six-read baseline |
| --- | ---: | ---: |
| Raw correct dispositions | 12/12 | 9/12 |
| Guarded correct dispositions | 12/12 | 9/12 |
| Urgency matches | 12/12 | 10/12 |
| Gap matches | 12/12 | 12/12 |
| False dismissals among non-benign truth | 0/8 | 0/8 |
| Missed HIGH escalations, raw and guarded | 0/3 | 1/3 |
| Missed CRITICAL escalations, raw and guarded | 0/1 | 0/1 |
| Supported committed typed claims | 62/62 | 59/59 |
| Evidence calls | 71 across 12 cases | 72 across 12 cases |
| Rejected provider turns | 0 | 0 |
| Correct targets among emitted proposals | 4/4 | 3/3 |
| Correct proposals among four required | 4/4 | 3/4 |
| Evidence/containment mutations | 0 | 0 |

Raw and guarded confusion matrices are identical for each provider in this run:

| Authored truth (four per row) | Adaptive BENIGN / ESCALATE / INCONCLUSIVE | Baseline BENIGN / ESCALATE / INCONCLUSIVE |
| --- | --- | --- |
| BENIGN | 4 / 0 / 0 | 2 / 0 / 2 |
| ESCALATE | 0 / 4 / 0 | 0 / 3 / 1 |
| INCONCLUSIVE | 0 / 0 / 4 | 0 / 0 / 4 |

Baseline errors are dev-003 (matching approved travel is not retrieved), dev-008
(the later observed managed device differs from its fixed alert-device lookup),
and dev-007 (the same limitation misses unmanaged sensitive-session escalation).
All three remain INCONCLUSIVE; dev-007 retains HIGH urgency but still fails its
expected ESCALATE label. Both scripts use the same recommendation function and
the authored examples exercise these evidence-selection choices. These
diagnostics do not establish statistical uplift, real SOC accuracy, learned
reasoning, calibration or analyst productivity. No errors were hidden or labels
revised to improve the comparison.

### Measured resources and owned cleanup

Seven command attempts consumed 15.877 seconds cumulative active wall time,
including the corrected full-suite repeat. The requested 20 ms Windows sampler
observed a maximum 75,395,072 bytes (71.90234375 MiB) aggregate working set for
the launcher, application and observed owned descendants. It excludes the
monitor process and may miss short-lived peaks. This is a sampled value, not a
guaranteed absolute peak or an estimate relabeled as a measurement.

Sampled work-directory peak was 1,358,290 bytes; largest per-command growth above
its own initial work baseline was 834,093 bytes. The retained demo/development
artifacts comprise fourteen files totaling 955,974 bytes. The file sampler may
miss transient files; retained size is separate from sampled peak. Resource
checks recorded no limit violation. After the sampler fix, at most one owned
Python application child was observed. Launcher/alias processes were included
in RAM accounting and retained in raw ownership records.

All observed owned processes exited at command completion. The HTTP-double
context managers shut down/close their servers and join their owned thread;
all cleanup assertions passed. The HTTP assertions account for eight actual
loopback requests per full-suite execution, sixteen across both executions;
this derives from observed request-count assertions, not global traffic capture.
There were no external requests, dependency downloads, real server/model
inference, credentials or containment writes. Worker consumption has stopped
and this lease is release-ready for the maintainer.

Full stdout/stderr, lease checks, process creation/parent data, samples and
artifacts were preserved in local work/ and the worker receipt. Current outputs
are work/m2-demo/results.json, work/m2-demo/report.md,
work/m2-development/manifest.json and work/m2-development/scores.json. A new
evaluation uses a fresh output directory rather than overwriting its manifest.

Independent M2 acceptance is pending. M3 held-out case authorship, adjudication,
scoring/gates and hosted CI remain unexecuted. Real Ollama/model compatibility,
model quality/safety/usage, production integrations, productivity, publication
and containment remain unexecuted. No probability calibration is claimed.

## Independent M2 acceptance

Main accepted M2 at 2026-10-08T11:20:04.799947+00:00 after six independent
commands and 48 tests, 210 direct artifact checks, 121 recomputed source claims
and 54 verified source files. It confirmed the 12/12 adaptive versus 9/12
baseline development dispositions, retained baseline HIGH miss, actual crash
recovery and HTTP bounds, and wrong-digest/exact/reopen/conflicting review with
unchanged evidence. The M2 lease was released. This acceptance does not include
M3 or real-model performance.

## M3 source and pure-component checkpoint

Authored thirty-six new fictional September snapshots and schema-v2
adjudications, a reviewed-rubric prerequisite, independent query/final/proposal
replay verifier, raw/guarded denominator metrics, both-provider three-repeat
180-second parent harness, normalized outcome/trace comparison and predeclared
gates. Added deferred actual SQLite mutation and label-access/sentinel tests,
contribution/security guidance, data attribution and pinned free-public-runner
CI. No actor policy, baseline or provider decision behavior was modified.

Accepted M2 source was saved in a local Git root commit using the already
configured author identity. There was no remote/push/publication. Development
freeze c24d2589a14b43a6ca9ae06ed7a6d5e9af955f808418c1c362cfd1e8f809d1c9 and
all prior results remain intact. LF attributes were added for portable byte
fingerprints. This source history is an actual commit, not an invented revision.

Heldout-v1 freeze:
95c943961e711d67226d1ecd49f90c33e05b94338d1c80c37f30dee9603d1859.
It binds all 36 inputs, labels/schema/rubric, baseline, actor/catalog/policy/prompt
source and independent evaluator. It was written before any heldout
investigation, scoring or provider batch. The separate unsigned review receipt
is PENDING. Both execution and scoring refuse it before actor launch or outcome
data access. Tests use only synthetic in-memory review receipts and never write
approval.

| Exact command | Exit | Observed source/component result |
| --- | ---: | --- |
| py -3.11 -m unittest tests.test_m3_components -v | 0 | Initial 14 pure methods passed, unittest 0.640 s; tool wall 1.1488615 s. Hand-built ledger mutation checks and static 36-input validation; no actor run. |
| py -3.11 -m unittest tests.test_m3_components -v | 0 | Expanded filtered-benign and hypothesis/review-shape checks: 14 passed, unittest 0.066 s; tool wall 0.6235806 s. |
| py -3.11 -m compileall -q security_triage evaluation tests | 0 | Syntax check, tool wall 0.4638452 s. |
| py -3.11 -m evaluation.heldout_freeze --write | 0 | Static 36-case/schema/strata/source freeze, zero outcomes scored; tool wall 0.4364833 s. |
| py -3.11 -m unittest tests.test_m2_components tests.test_m3_components -v | 0 | Final 40 pure methods passed (25 M2 + 15 M3), unittest 0.129 s; tool wall 0.666405 s. |
| py -3.11 -m evaluation.freeze | 0 | Accepted M2 development freeze unchanged; tool wall 0.1174005 s. |
| py -3.11 -m evaluation.heldout_freeze | 0 | Heldout-v1 fingerprint unchanged; tool wall 0.4334386 s. |
| py -3.11 -m compileall -q security_triage evaluation tests | 0 | Final syntax check, tool wall 0.4967209 s. |
| py -3.11 -m evaluation.heldout_freeze --require-review | 1, expected | Negative prerequisite check refused pending approval with independent_rubric_review_required_before_heldout_run_or_score; tool wall 0.3751204 s. No actor/outcome access. |
| git diff --check | 0 | Whitespace check passed; tool wall 0.2545767 s. |

No M3 test command failed. The expected nonzero static prerequisite result is
retained. No assertions, labels, thresholds or baseline behavior were weakened.
The fifteen new pure methods verify coherent benign/escalation ledgers; nine
mutations (verdict, reference, record version, rehashed target, rehashed snapshot
version, forged review state, source index, observation and turn count); extra
review/executor refusal; changed valid traces versus normalized timestamps;
filtered/forged benign evidence refusal; 36 valid inputs and label fact tuples;
pending/changed/incomplete receipts; parent/scorer refusal before subprocess or
data access; no actor evaluator imports/label arguments; unchanged M2 freeze;
and artificial metric vectors showing that all-inconclusive refusal cannot pass
outcome gates. Synthetic metric vectors are unit inputs, not heldout scores.

### Review questions and exact unexecuted commands

docs/HELDOUT_REVIEW.md requests independent review of every row before first
scoring. Eight MEDIUM benign/escalation references retain the plan's strata while
accepted M2 defaults remain LOW for benign and HIGH/CRITICAL for escalation.
Those upward/downward differences will be reported; no global exact-urgency
threshold is invented. Observed positive misuse amid gaps and unrelated
IP/session/earlier-success/narrow coverage cases have explicit review questions.
The worker has not approved its own labels or inferred passing outcomes.

After independent rubric approval and a newly granted M3 integration window:

    py -3.11 -m evaluation.freeze
    py -3.11 -m evaluation.heldout_freeze --require-review
    py -3.11 -m compileall -q security_triage evaluation tests
    py -3.11 -m unittest discover -s tests -p test_*.py -v
    py -3.11 -m evaluation.run --split heldout --providers scripted,baseline --repeat 3 --out work/m3-heldout
    py -3.11 -m evaluation.score --run-dir work/m3-heldout --assert-gates
    py -3.11 -m security_triage demo --out work/m3-demo
    py -3.11 -m evaluation.verify --run-dir work/m3-demo --suite demo

The full suite now has 65 authored methods, including two new disk/label-access
integration methods. Sixty-five is a static method count, not an M3 integration
result. Both providers times three repeats would create 216 executions across
36 unique cases (12 BENIGN / 16 ESCALATE / 8 INCONCLUSIVE; misuse strata 4 MEDIUM /
8 HIGH / 4 CRITICAL). Those batches, all actual M3 investigations/HTTP/recovery,
scoring/gates, hosted CI and independent final acceptance remain unexecuted.
No M3 lease was consumed, downloads/model/containment calls are zero, and no
peak resource measurement is claimed for pure checks.

Proposed new M3 envelope: ten cumulative active minutes, one sequential CPU
worker with at most one owned child and one loopback double at a time, 256 MiB
RAM, 50 MiB generated disk, zero downloads/external/live-model/containment calls.
All earlier review remains SIMULATED. Main must review ambiguity, approve the
exact frozen rubric and grant the new lease before any integrated command.
This same-author deterministic corpus does not establish independent SOC/model
quality, statistically proven uplift, calibrated probabilities or time saved.


## Independent final local acceptance — 8 October 2026

Main accepted all36 raw authored rubrics before scoring and independently accepted the final local MVP afterward. A fresh107-file source/data copy needed no installation. All eight documented commands exited0: development freeze, heldout freeze/review prerequisite, compileall,65-test full suite,216paired heldout executions, independent scorer/gates, standalone three-case demo and verifier. Main wall times were0.156,0.219,0.265,6.125,39.969,0.547,1.078 and0.141seconds. All107shipping files remained unchanged during execution.

A separate main stdlib audit imported neither actor nor evaluator. It passed5723conditions across12read-only SQLite databases and216committed outcomes; recomputed1098guarded and1173raw typed claims from original observed record fields; verified source identity/session records unchanged, report/database equality, bounded counters, pending exact-content proposals and72three-repeat outcome/trace groups. Independent counter checking includes the original rejected attempt plus at most two correction retries, verifies every rejected attempt against persisted accounting, and forbids further calls after exhaustion.

Every repeat reproduced adaptive34/36guarded versus32/36raw and baseline28/36guarded versus27/36raw. Adaptive held-032 andheld-033 remain missed MEDIUM escalations with telemetry gaps. Adaptive raw held-035/036 incorrectly recommend BENIGN; finite host guards reject those and retain INCONCLUSIVE. Both guarded policies have zero false dismissals. Adaptive escalates all12HIGH/CRITICAL examples, correctly keeps12/12benign and8/8inconclusive, and emits14/16required proposals; all14emitted targets are valid. Its guarded urgency matches30/36; raw urgency matches28/36. Baseline guarded misses one HIGH escalation and retains other errors. These figures meet the predeclared adaptive gates; there is no baseline uplift or perfect-accuracy gate.

The full suite includes owned crash recovery, real loopback doubles, approval version/hash/expiry/snapshot checks, source immutability, failure/corruption controls and synthetic completion fallbacks. Main does not infer live model quality, SOC accuracy, production authentication, containment execution or power-loss safety from these tests. Proposals and reviews remain SIMULATED/NOT_IMPLEMENTED.

Original worker instrumentation failures remain preserved: its first suite printed65passes but native exit/resources were unknown after a temporary-directory sampler race; the subsequent recovery startup stopped before launch on a Windows separator alias mismatch. Main verified all13original artifacts; the corrected ignored sampler then produced successful native exits. These ignored-helper repairs changed no shipped source, actor, labels or gates. The main audit initially treated corrections_used as retries alone; inspection showed that it includes the original rejected attempt, so main corrected its helper and added exact persisted-attempt accounting. The original failed helper receipt remains, with no application rerun or source change.

Final local acceptance passed. Only status/evidence documentation changed afterward; both freezes/review prerequisite and Git whitespace checks passed. Main peak RAM was not sampled; worker73.54MiBsampled working set is separate evidence. Hosted CI, Linux execution, real models, production accounts, containment, deployment and publication remain unexecuted. Thirty-six authored examples repeated six ways are216executions, not216independent examples.

## Public source release — 9 October 2026

All three local MVP milestones passed independent acceptance on 8 October 2026, including final documentation review. The review was executed separately from the implementation worker and included documented quickstarts, meaningful success/failure tests and direct domain-state checks. The results and limitations above remain unchanged.

This source release includes application code, authored fixtures, evaluator/tests, quickstart, architecture, license/attribution and the prepared CI workflow. Private orchestration records, machine-specific paths, runtime caches and generated local runs are excluded. Offline scripted/rule/replay outcomes and local provider doubles do not establish live model quality, employer adoption or production impact. Hosted CI results are available in this repository's Actions tab after publication; historical local reports retain their original execution dates.
