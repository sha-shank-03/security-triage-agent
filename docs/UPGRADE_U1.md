# U1 implementation awaiting integration verification

This additive slice uses Python 3.11 and the existing immutable evidence tools and
host claim checks. The original published 36-case evidence stays historical:
raw 32/36 versus guarded 34/36, including held-032/033 MEDIUM escalation misses
and held-035/036 raw BENIGN errors. There is no new benchmark or model-quality
result in U1. No containment or GitHub connector is implemented in this slice.

The local double speaks the native OpenAI-compatible function-call protocol.
Its limited synthetic decision logic proves a mechanism, not model quality.
The success in observed authentication selects the next device request; tool
responses retain native call IDs. The case ledger reserves attempts before
dispatch, persists the raw packet and terminal recommendation before guards,
and reports the guarded outcome separately. A raw recommendation can fail.

The adapter sends a fixed Gateway endpoint with explicit model configuration;
there is no model fallback or automatic inference transport retry. HTTP errors,
rate limiting, cancellation and uncertain response loss halt with typed status.
Unknown actual usage/cost is null and reserved funds are not silently refunded.
Bounded schema/host rejections may lead to explicit correction decisions; these
are recorded new attempts, not transport replay. Defaults are 12 attempts,
2 correction retries, 60 total seconds, 96 KiB request/history, 64 KiB response,
16 KiB observation and 2,048 completion tokens. A smaller configuration may
tighten these bounds. Provider billing bounds need main's separate preflight.

One transport child performs HTTP. The parent bounds DNS/header/body stalls and
cancellation, owns its process handle, and permits two seconds for cleanup.
The child receives a runtime key by private stdin, never command arguments,
and only live mode invokes the main-injected key loader. Local doubles do not
read keys. Free text/private reasoning/error bodies are not retained; structured
packets/events are redacted. Elapsed time and an absolute expiry survive resume;
an inflight interrupted request becomes a handoff rather than being replayed.
No human approval wait is excluded in this U1 path.

The verifier imports neither actor nor host policy. It independently replays
evidence reads from the supplied original fixture, checks typed claims against
observed records, validates native history/IDs/counters, compares reports with
committed SQLite, and confirms unchanged evidence/session records. Its source
and code hashes establish attribution, not resistance to a local administrator
who can replace source, state and verifier together. Operator configuration is
trusted; this repository does not implement a global budget broker or permits.

Run from the repository root. The pure component command uses in-memory SQLite,
fake clocks and injected responses; it opens no socket or subprocess:

```powershell
py -3.11 -m unittest tests.test_upgrade_gateway tests.test_upgrade_deadline tests.test_upgrade_events tests.test_upgrade_spend -v
```

The following are prepared, **not yet executed**. They require the current
named integration lease in the coordinated portfolio environment:

```powershell
py -3.11 -m security_triage.upgrade doctor --mode offline
py -3.11 -m evaluation.freeze
py -3.11 -m evaluation.heldout_freeze --require-review
py -3.11 -m unittest tests.test_upgrade_transport -v
py -3.11 -m security_triage.upgrade demo --provider gateway-double --scenario branch-after-observation --out work/upgrade-u1/demo
py -3.11 -m evaluation.upgrade_verify --run-dir work/upgrade-u1/demo --suite provider-contract --source fixtures/demo/case-002.json
py -3.11 -m security_triage.upgrade demo --provider gateway-double --scenario false-completion --out work/upgrade-u1/false-completion
py -3.11 -m evaluation.upgrade_verify --run-dir work/upgrade-u1/false-completion --suite provider-contract --source fixtures/demo/case-002.json
py -3.11 -m unittest discover -s tests -p test_*.py -v
```

Successful branch demo should exit 0; false-completion demo should exit 2 with
raw BENIGN, guarded INCONCLUSIVE and HANDOFF. Both independent verifier commands
should exit 0, meaning the reported state is consistent, not that the rejected
raw recommendation was correct. Generated packet.json/events.jsonl and both
SQLite databases contain inspectable synthetic receipts. A verifier finding
corruption exits 1. Use fresh output paths; completed resume is idempotent and
active resume does not extend the original expiry or return spent attempts.

Actual Gateway execution is an unexecuted later gate. It requires a portable
nonsecret LIVE configuration with exact catalog model/provider, verified
pricing/billable caps and main-approved INR allocation/expiring dispatch, plus
main's secure loader. No key in config/flags, no credentials in this repository,
no live CI and no live allowance now. Calling the live CLI with missing or
zero authority refuses before creating output or loading a key. Actual external
sandbox integration and deployment are also unexecuted. No production readiness,
SOC accuracy, statistical uplift or analyst time-saving claim is made.
