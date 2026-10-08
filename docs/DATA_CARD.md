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
errors. No held-out corpus is included in M2.

Domain terminology was informed by [Microsoft sign-in risk documentation](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks) and [MITRE Valid Accounts](https://attack.mitre.org/techniques/T1078/), retrieved 2026-10-08. Fixtures do not reproduce vendor classifiers, rule text, or external datasets.
