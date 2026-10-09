# Authored fictional data

Versions: demo-v1 and development-v1. All records are fictional and authored for this repository. The code and fixtures use the repository MIT license. Documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), opaque user/device/session identifiers, and UTC timestamps avoid private account information. Network/travel approval and management status are authored facts, not online lookups.

| Case | Available evidence | Expected disposition |
| --- | --- | --- |
| demo-001 | Satisfied MFA, managed device, approved network, complete auth/resource coverage | BENIGN / LOW |
| demo-002 | Two MFA denials, subsequent success from an unmanaged device, same-session sensitive access | ESCALATE / HIGH; one pending session proposal |
| demo-003 | Explicit authentication telemetry gap despite some successful-login/context records | INCONCLUSIVE / HIGH; gap retained, no proposal |

Expected labels live under `evaluation/labels/`; acting inputs are only `fixtures/demo/` and `fixtures/development/`. These are public authored examples, not representative real security logs, independent real-world samples, or held-out evaluation results. They do not support population false-positive rates, generalization, production effectiveness, or calibrated probabilities.

## Development split

Development-v1 contains twelve unique cases: four BENIGN, four ESCALATE, and four
INCONCLUSIVE. Six paired families cover exact network matching, approved travel,
MFA sequence, observed device/resource linkage, privilege and telemetry coverage.
The adjudication schema includes allowed disposition/urgency, evidence rationale,
expected/forbidden targets, gaps and authored world truth. Actor inputs contain
no expected outcome or benchmark score.

The two travel examples distinguish matching approval from unrelated address
context. The network pair rejects a prefix lookalike as approval. The privilege
pair shows that privilege raises adverse urgency without making every login
malicious. A coverage gap includes an instruction-like sentence as untrusted
source data. Cases use related patterns and are not statistically independent.

The baseline specification, implementation, schema, adjudications and input files
are bound by evaluation/development_freeze.json before the first score. Twelve
development cases are diagnostic only. No development outcome has been scored
at the M2 source checkpoint. Later worker M2 diagnostics ran both scripts on
these twelve cases once; see EVIDENCE.md for complete denominators and baseline
errors. No heldout corpus was included in M2.

## Heldout-v1 candidate

M3 now includes thirty-six fictional inputs and separate schema-v2 adjudications,
with twelve BENIGN, sixteen ESCALATE and eight INCONCLUSIVE rows. Each of the six
families has six cases and preserves the original plan's class/urgency matrix.
New September timestamps, opaque identities and exact boundary/counterexamples
exercise selection and host validation. No detector rule, real log, external
dataset or model output was copied.

The rubric keeps independent reference urgency separate from alert priority
and accepted host defaults. Eight MEDIUM benign/escalation rows require explicit
review because the retained script/host defaults differ. Observed positive
misuse amid gaps and unrelated IP/session/earlier-success context also receive
specific ambiguity review. See docs/HELDOUT_REVIEW.md.

The heldout-v1 fingerprint binds inputs, labels, rubric, baseline, actor,
prompt/policy/catalog implementation and independent evaluator. It was written
before any heldout execution or scoring. Main approved all 36 rubrics, then independently ran 216 executions and raw-state checks. Adaptive outcomes were 34/36 guarded and 32/36 raw per repeat, with held-032 and held-033 remaining missed MEDIUM escalations. Baseline outcomes were 28/36 guarded and 27/36 raw. No labels or gates were changed after scoring. Original M2 fixtures/freeze/source/results
are retained. New versions must preserve their predecessors.

The same author knew the scripted policy when constructing this corpus. It is
held apart from development tuning, not a blind or statistically independent
test sample. Three repeated deterministic executions do not increase 36 unique
cases. On publication, these inputs become a public regression set.

Domain terminology was informed by [Microsoft sign-in risk documentation](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks) and [MITRE Valid Accounts](https://attack.mitre.org/techniques/T1078/), retrieved 2026-10-08. Fixtures do not reproduce vendor classifiers, rule text, or external datasets.
