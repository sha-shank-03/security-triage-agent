# Heldout-v1 rubric and ambiguity review

Status: authored and frozen before the first actor batch; independent review pending.
Same author created inputs, labels and the scripts. The name heldout denotes separation from the development split and a freeze before this batch. It does not mean blind independent adjudication, independent real telemetry or unseen algorithm families. Publishing these files makes them public regression cases.

## Frozen design

36 distinct fictional snapshots use new September timestamps and identities. There are twelve BENIGN, sixteen ESCALATE and eight INCONCLUSIVE cases. Escalations have four MEDIUM, eight HIGH and four CRITICAL references; benign references are eight LOW/four MEDIUM; inconclusive references are four MEDIUM/four HIGH. Each of six families has six cases, preserving the accepted plan's family matrix.

Labels include allowed disposition/urgency, reference urgency, positive/negative factual tuples, observed-evidence groups, coverage requirements, gaps, expected/forbidden targets and rationale. Expected labels are not available to actor tools. An observed positive adverse sequence or unmanaged sensitive session can support escalation despite missing telemetry; absence of telemetry cannot support benign dismissal.

## Questions the independent reviewer must resolve before scoring

1. The accepted M2 scripts/host use HIGH or CRITICAL for escalation and LOW for BENIGN. The plan separately requires MEDIUM strata. Cases held-002/008/010/025 have MEDIUM benign references; held-014/020/032/033 have MEDIUM escalation references. Those references are kept exactly, with strict allowed urgency, and upward/downward differences are reported. No new global urgency-match threshold has been added. Approve or revise the rationale before any score; do not change the baseline to manufacture a comparison.
2. held-032/033 label already observed positive findings as ESCALATE despite a gap. The M2 script currently short-circuits on gaps. This is a deliberate retained hard case, not hidden or automatically relaxed. They are MEDIUM reference cases, not excluded rows.
3. held-018/030 distinguish an unrelated IP/session from exact target misuse; held-035 cannot dismiss unresolved earlier success; held-036 distinguishes a complete flag from coverage of the complete case interval.
4. held-003/013/031 adjudicate only the time-visible snapshot. Later ingestion or out-of-window facts do not retroactively change the case-time triage label.

The detailed source rationale and tuples live in evaluation/labels/heldout-v1.json. Review all 36 rows, including the explicit questions above. If a correction is required, retain this candidate and its freeze and create a new version. Never replace a scored dataset or use outcome inspection to weaken gates.

## Predeclared gates

Adaptive script: at least 31/36 correct dispositions, 0/16 misuse dismissed BENIGN, all 12 HIGH/CRITICAL misuse escalated, at least 10/12 benign and 7/8 inconclusive correct. All accepted claims/references must be supported, proposed actions/targets valid, stale approvals and containment mutations zero, and every case bounded/completed. Both scripts run three times; normalized outcomes and full observable tool traces must match per unique case. The baseline has no improvement or classification-accuracy gate. Repeats create 216 executions, still 36 unique cases.

Reference urgency is separate from alert priority. Exact urgency matches plus under/over errors by reference severity are reported, including high-urgency inconclusive cases. Raw and guarded matrices, errors, gaps, targets, fallback/rejection/coverage/tool counts remain separate. Zero denominators are N/A, not invented 100%. Machine timing is not analyst time saved. There are no probabilities or calibration scores.

## Review prerequisite

evaluation/heldout_review.json initially records pending. A maintainer may approve only after reviewing the frozen inputs/adjudications/rubric. The receipt must bind the current freeze digest, identify all 36 case IDs, contain reviewer/date and substantive notes, and say approved. Both parent execution and scoring reject a missing, pending, incomplete or different-digest receipt before any heldout actor/score work. This unsigned local receipt is a process attestation, not authentication or protection from an administrator.

CI reads the committed receipt. A local reviewer can supply another receipt with --review-receipt PATH; that path is never passed to an actor. No approval is created by tests, the actor, the freeze writer, or the worker's source checkpoint.

## Case index

| Case | Family | Disposition | Reference urgency | Material feature |
| --- | --- | --- | --- | --- |
| held-001 | network | BENIGN | LOW | Exact corporate IP, managed device and satisfied MFA. |
| held-002 | network | BENIGN | MEDIUM | Privileged approved routine login; planned MEDIUM follow-up reference. |
| held-003 | network | BENIGN | LOW | MFA denials ingested after cutoff are unavailable at triage time. |
| held-004 | network | BENIGN | LOW | 51 successful same-context records require the second auth page. |
| held-005 | network | ESCALATE | HIGH | Approved network/managed device do not erase the denial sequence. |
| held-006 | network | INCONCLUSIVE | MEDIUM | Approved prefix lookalike differs from exact observed address. |
| held-007 | travel | BENIGN | LOW | Matching approved travel corroborates unapproved network context. |
| held-008 | travel | BENIGN | MEDIUM | Privileged managed approved travel; planned follow-up reference. |
| held-009 | travel | BENIGN | LOW | Success reveals a new managed device; alert names old device. |
| held-010 | travel | BENIGN | MEDIUM | Travel covers both exact interval boundaries; planned follow-up reference. |
| held-011 | travel | ESCALATE | HIGH | Travel approval does not erase adverse denials and sensitive session. |
| held-012 | travel | INCONCLUSIVE | MEDIUM | Travel expires one second before cutoff. |
| held-013 | mfa | BENIGN | LOW | Denials precede the selected case window and are excluded. |
| held-014 | mfa | ESCALATE | MEDIUM | Nonprivileged managed denial sequence; planned MEDIUM reference. |
| held-015 | mfa | ESCALATE | HIGH | Two denials then success on unmanaged unapproved context. |
| held-016 | mfa | ESCALATE | HIGH | Sequence uses observed new device, distinct attempted session IDs. |
| held-017 | mfa | ESCALATE | CRITICAL | Privileged identity and same-context denial/success sequence. |
| held-018 | mfa | INCONCLUSIVE | HIGH | Denials belong to another IP; no supported adverse target linkage. |
| held-019 | failures | BENIGN | LOW | Failures with MFA unknown do not imply compromise; success corroborated. |
| held-020 | failures | ESCALATE | MEDIUM | Unmanaged sensitive same-session positive findings; planned MEDIUM reference. |
| held-021 | failures | ESCALATE | HIGH | Initial managed device differs from observed unmanaged sensitive target. |
| held-022 | failures | ESCALATE | HIGH | Sensitive exact-session record amidst unrelated nonsensitive resource. |
| held-023 | failures | ESCALATE | CRITICAL | Privileged unmanaged successful session has sensitive activity. |
| held-024 | failures | INCONCLUSIVE | MEDIUM | Failure burst without successful auth target. |
| held-025 | resource | BENIGN | MEDIUM | Privileged approved routine nonsensitive resources; planned follow-up reference. |
| held-026 | resource | ESCALATE | CRITICAL | Privileged unmanaged exact sensitive session. |
| held-027 | resource | ESCALATE | CRITICAL | Privileged denial sequence even with approved managed context. |
| held-028 | resource | ESCALATE | HIGH | Latest unmanaged sensitive target differs from earlier successful session. |
| held-029 | resource | ESCALATE | HIGH | Supporting successful authentication has record version 2. |
| held-030 | resource | INCONCLUSIVE | HIGH | Sensitive record names a different session; privilege alone is insufficient. |
| held-031 | telemetry | BENIGN | LOW | Sensitive record was ingested after cutoff; complete available streams. |
| held-032 | telemetry | ESCALATE | MEDIUM | Observed denial/success remains positive evidence despite auth gap. |
| held-033 | telemetry | ESCALATE | MEDIUM | Observed unmanaged sensitive session remains positive evidence despite resource gap. |
| held-034 | telemetry | INCONCLUSIVE | HIGH | Auth gap prevents benign despite approved/managed satisfied success. |
| held-035 | telemetry | INCONCLUSIVE | HIGH | Earlier successful device/IP remains unresolved. |
| held-036 | telemetry | INCONCLUSIVE | MEDIUM | Resource complete flag covers a narrower interval than the case. |

Accepted M2 source is preserved at local Git commit e04254caf4e7906fe32a1b1fb5700b60349a3e13. Its development freeze and prior results remain unchanged. The M3 fingerprint also binds actor and independent-evaluator source, prompt/policy/catalog versions and this rubric. A code or data change requires a new reviewed freeze/run version with previous evidence retained.

