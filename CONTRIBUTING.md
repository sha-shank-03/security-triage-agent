# Contributing

Use an existing Python 3.11 runtime. The project uses only the standard library.
Source and fixtures use the MIT license. Keep examples fictional and use only
opaque identifiers and documentation IP ranges.

Pure checks:

    python -m unittest tests.test_m2_components tests.test_m3_components -v
    python -m compileall -q security_triage evaluation tests
    python -m evaluation.freeze
    python -m evaluation.heldout_freeze

The full tests include owned loopback servers and an owned crash subprocess.
The benchmark runs six sequential actor subprocesses. Use a fresh work/ output
directory and complete the separate rubric review before running it. The review
guard is a procedural attestation, not an authenticated security principal.
See docs/HELDOUT_REVIEW.md for the frozen rubric and review questions.

Do not edit frozen labels or the baseline after seeing scores. Preserve the
previous dataset, freeze, source revision and results; create a new version and
review it before scoring. Report regressions and failed gates instead of
lowering thresholds or excluding hard cases. Repeat counts do not increase the
number of independent cases. Baseline parity or better performance is valid.

Keep evaluator imports and labels out of actor tools and configuration. Preserve
raw recommendations separately from host-guarded outcomes. New factual claims
need a typed source check and independent verifier support. Add mutation tests
that can detect corrupt stored domain state rather than tests that merely echo
an implementation. No review decision may execute containment.

The GitHub Actions workflow pins checkout and setup-python commit IDs, grants
read-only contents permission, persists no checkout credentials, uses no
secrets/model calls/caches/uploads and has a five-minute limit. It is authored,
not executed or claimed green. Its benchmark step remains blocked while the
committed independent review receipt is pending.
