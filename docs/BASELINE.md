# Frozen baseline specification v1

The fixed_six_reads_v1 baseline makes six predetermined evidence reads, then one
finalization attempt. This specification and its implementation are frozen with
the development adjudications before the first score. Development scores are
diagnostic; there is no held-out acceptance or probability calibration in M2.

1. Identity context.
2. Unfiltered authentication events, first page only.
3. Telemetry coverage for both streams.
4. Device context for the alert's original device.
5. Network context for the alert's exact original IP.
6. Unfiltered resource events, first page only.

It does not adapt targets, request travel, or follow pagination. It uses the same
12-turn, two-correction, 60-second maximum and the same host support gate as the
adaptive script. The resource read is necessary to support benign dismissal;
the planning draft's five-read description has been corrected before scoring.

After the six reads, the deterministic recommendation function takes the latest
observed successful authentication. It escalates on two distinct MFA denials
within one hour before that success at the same IP/device, or on unmanaged
device plus sensitive activity in its exact session. Privileged identity raises
escalation urgency to CRITICAL; other escalation urgency is HIGH. It proposes
only that observed successful session.

With complete coverage, satisfied MFA, managed device, exact approved context,
and no adverse evidence, it requests BENIGN/LOW. Otherwise it requests
INCONCLUSIVE at the alert floor and proposes nothing. The host can reject its
request when reads or corroboration are insufficient. A partial first page does
not establish complete evidence, even when coverage says the stream is complete.

Both scripts share the deterministic recommendation function. The comparison
therefore isolates evidence selection, target adaptation, and travel retrieval;
it does not compare independent detection algorithms or learned reasoning.
Expected baseline failures must remain visible in raw and guarded diagnostics.
