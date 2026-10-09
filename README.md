# Security triage agent

Investigate fictional suspicious logins with scoped SQLite tools and return cited `BENIGN`, `ESCALATE`, or `INCONCLUSIVE` recommendations. Supported escalation can create one exact session-revocation proposal. A separate reviewer records a **SIMULATED** approval or rejection. Containment is **NOT_IMPLEMENTED**; identity, session, and evidence records remain unchanged.

Default decisions are deterministic code (`scripted_policy_v2`), selected from actual tool observations. M1 and M2 were independently accepted. Main's M2 review ran six commands/48 tests, added 210 direct checks and recomputed 121 source claims. Final local MVP acceptance passed: main ran eight commands from a fresh 107-file source copy, all 65 tests, 216 authored case executions and the demo, then passed 5,723 additional raw-state conditions. Adaptive dispositions are 34/36 guarded and 32/36 raw per repeat; two MEDIUM escalation misses remain. There is no real-server or model evaluation. See [the evidence log](EVIDENCE.md).

## Offline quickstart

Use an existing Python 3.11 installation from the repository root. No packages, keys, Docker, server, model weights, or Java build are needed for the scripts.

```powershell
py -3.11 -m security_triage demo --out work/m2-demo
py -3.11 -m evaluation.verify --run-dir work/m2-demo --suite demo
py -3.11 -m unittest tests.test_m2_components -v
```

The three examples are approved-network context, MFA denials before a success on an unmanaged device, and missing authentication telemetry. The verifier checked all three dispositions, 15 supported claims, 15 reads, one pending proposal and zero source mutations. These public examples demonstrate integration; they are not held-out data. Linux/macOS users can use `python3.11`.

The demo writes `evidence.sqlite`, `runs.sqlite`, `results.json`, and `report.md`. Source evidence opens read-only, validates its content/index against its snapshot, and refuses conflicting inputs. Completed identical runs are reused. Workflow schema 2 intentionally requires a fresh output directory when encountering an M1 schema-1 database; no old artifacts are silently migrated or overwritten.

## Resume and cancellation

```powershell
py -3.11 -m security_triage investigate-case --fixture fixtures/demo/case-002.json --out work/case --provider scripted --request-id case-request
py -3.11 -m security_triage investigate-case --fixture fixtures/demo/case-002.json --out work/case --provider scripted --request-id case-request --resume
py -3.11 -m security_triage cancel --db work/case/runs.sqlite --run-id RUN_ID_FROM_RESULTS
```

Resume must exactly match snapshot, provider configuration, request ID, policy/prompt and budget. Each turn is reserved before the provider call; a crash burns that turn. The original UTC deadline and correction count persist. Cancellation is cooperative between operations and becomes terminal; it does not produce a disposition or proposal. Use one active worker per run. The passing integration suite exercised an owned crash subprocess, recovery with unchanged deadline/consumed turns, disk reopen, and cancellation with no disposition/proposal.

## Exact-content simulated review

Read the proposal ID, payload SHA-256, row version and expiry from the generated packet. Supply those exact values:

```powershell
py -3.11 -m security_triage review --db work/m2-demo/runs.sqlite --proposal-id PROPOSAL_ID_FROM_REPORT --expected-version 1 --expected-hash HASH_FROM_REPORT --decision approve --reviewer analyst-demo --request-id review-001
```

Placeholders are not fabricated executable IDs. Wrong hash/version, expired content or changed snapshot/identity/session version refuses approval. Reusing a review request ID with identical intent returns its historical result; conflicting intent fails. Successful approval changes only proposal state to `APPROVED_SIMULATION` and adds a review/audit row. Reviewer names are local labels, not authentication.

A trusted operator can register a newer validated snapshot from a separately created evidence database using `register-snapshot --db WORKFLOW_DB --evidence-db NEW_EVIDENCE_DB --case-id CASE_ID`. Existing evidence is retained. Staleness is relative to the latest snapshot registered locally, not to an unconnected live identity system.

## Development diagnostics

```powershell
py -3.11 -m evaluation.freeze
py -3.11 -m unittest discover -s tests -p 'test_*.py' -v
py -3.11 -m evaluation.run --split development --providers scripted,baseline --repeat 1 --out work/m2-development
py -3.11 -m evaluation.score --run-dir work/m2-development
```

The static freeze binds [the fixed six-read baseline](docs/BASELINE.md), implementation, label schema, adjudications and twelve inputs. Four cases belong to each disposition, with two examples across each of six families. Labels are separate from actor tools. The parent starts one label-free actor subprocess at a time and reads labels only while scoring. This is logical isolation; it is not an OS sandbox.

Development scoring reports separate raw/guarded confusion matrices, severity-specific missed escalations, false dismissals, citations, gaps and targets. It does not set acceptance gates, create 36 held-out cases, or report probability calibration. Use a fresh evaluation output directory for a new run; the parent refuses existing manifests.

| Development result | Adaptive script | Fixed baseline |
| --- | ---: | ---: |
| Raw / guarded correct dispositions | 12/12 / 12/12 | 9/12 / 9/12 |
| False dismissals among eight non-benign cases | 0/8 | 0/8 |
| Missed HIGH / CRITICAL escalations | 0/3 / 0/1 | 1/3 / 0/1 |
| Supported typed claims | 62/62 | 59/59 |
| Correct emitted targets / required proposals | 4/4 / 4/4 | 3/3 / 3/4 |

The baseline leaves travel case dev-003 and newly observed managed-device case dev-008 inconclusive, and misses the HIGH escalation in dev-007 because its fixed original device lookup does not retrieve the observed unmanaged device. All gaps match (12/12 for each script). Both scripts share a recommendation function; this small authored diagnostic compares evidence selection and does not establish real-world uplift or model performance.

## Reviewed heldout regression

36 heldout-v1 snapshots and separate adjudications are authored and frozen:
twelve BENIGN, sixteen ESCALATE and eight INCONCLUSIVE. They are a same-author
synthetic regression corpus. All six families are familiar from the design;
publishing it makes it a public regression set.

Read [the rubric and ambiguity questions](docs/HELDOUT_REVIEW.md) before any run.
The maintainer must approve all 36 rows under the exact freeze digest, including
the MEDIUM reference urgency/accepted-policy difference and positive findings
amid gaps. The committed receipt records main approval of all 36 rows under the frozen digest. Execution and scoring
refuse a pending, incomplete or changed-digest receipt. Tests never create one.

After review, use a fresh output directory:

    py -3.11 -m evaluation.heldout_freeze --require-review
    py -3.11 -m evaluation.run --split heldout --providers scripted,baseline --repeat 3 --out work/m3-heldout
    py -3.11 -m evaluation.score --run-dir work/m3-heldout --assert-gates

These commands passed independently on this Windows HP. Two scripts times three repeats
produce 216 case executions, still 36 unique cases. The scorer independently
replays every evidence query from original fields, binds the committed result
to the accepted provider turn and source-linked proposal, checks raw/guarded
metrics and compares normalized outcomes/observable traces across repeats.
Initial run/request IDs and wall timestamps are excluded from repeat digests.
Changed valid tool choices remain part of the trace digest.

The adaptive gates are at least 31/36 dispositions, zero misuse dismissed benign,
all twelve HIGH/CRITICAL misuse escalated, ten/twelve benign and seven/eight
inconclusive correct, full accepted citation support, valid proposals, bounded
completion and no stale approvals/containment. The baseline has no uplift gate.
Exact urgency matches and under/over errors are reported separately. A failed
gate writes its scores before returning nonzero; failures are retained.

Pure M3 checks run no actor or actual corpus scoring:

    py -3.11 -m unittest tests.test_m2_components tests.test_m3_components -v
    py -3.11 -m evaluation.freeze
    py -3.11 -m evaluation.heldout_freeze

Accepted M2 source is preserved at local Git commit
e04254caf4e7906fe32a1b1fb5700b60349a3e13, with its original freeze and results.
The new version preserves baseline/provider behavior. See [contribution
guidance](CONTRIBUTING.md) and [security scope](SECURITY.md). Free standard public
GitHub-runner CI is authored with pinned action commits, read-only permissions,
no secrets/model calls and a five-minute timeout; it has not run. Its digest-bound independent review prerequisite passed locally; hosted CI remains unexecuted.

## Optional model route

`investigate-case --provider ollama --model YOUR_ALREADY_AVAILABLE_MODEL --port 11434` opts into native `/api/chat` tool calling through `127.0.0.1`. The adapter uses the standard library, caps request/response size, follows no redirects, bounds timeouts, and retries a timeout/429/5xx once. It installs and downloads nothing. This route has not been executed against a real server/model; model compatibility, licensing, quality and usage remain unverified.

Loopback identifies the contacted server, not where its weights or upstream services execute. An independently configured server can proxy remotely. Protocol-double tests establish wire behavior only. Observable calls and counts are stored; private reasoning fields are discarded.

## Boundaries and attribution

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [data card](docs/DATA_CARD.md), and [dependency notices](THIRD_PARTY_NOTICES.md). This project's original contribution is the inspectable security disposition workflow, content-bound simulated review and authored benchmark. It does not reproduce Microsoft's risk algorithms or Sigma detection rules.

Small synthetic samples and scripted decisions do not establish SOC accuracy, analyst productivity, live-model safety, incident-response completeness, or production readiness. Host guards cover a finite typed vocabulary. A local administrator can edit code or databases; SHA-256 is content binding, not tamper-proof authentication. No real accounts, telemetry, monitoring, offensive tools, or containment executor are included. Heldout local regression passed the agreed gates with documented misses; hosted CI remains unexecuted.

Code and authored fixtures are [MIT licensed](LICENSE). No external logs, detector rules, or model weights are redistributed.

