# Admission: scripted-02-race-double-pay

**Class: partially-validated.** outcomes matched, race ordering not shown: vault-a: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); guard:vulnerable_fixture: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); mutant:M5: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown)

Property: A guard pays each approved invoice at most once, whatever the timing of the pay calls.

Failure mode: The guard checks 'not yet paid' and starts the transfer but records nothing until the callback, so a second pay in that gap passes the same check.

Gate tools/admission/admit.py v1 (sha256 a7c55a433038b7b2...), git cbca416f9c12a81e2460e29f306bd8b0c6e0fc98 (tree clean), harness sha256 71fed1a26ecf3186..., 20261111T203359Z.
Runs counted 0 of 9 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| guard:vulnerable_fixture | known-bad | broke 100 | 1 | no | unproven |  |
| guard:vulnerable_fixture | known-bad | broke 100 | 2 | no | unproven |  |
| guard:vulnerable_fixture | known-bad | broke 100 | 3 | no | unproven |  |
| mutant:M5 | known-bad | broke 100 | 1 | no | unproven |  |
| mutant:M5 | known-bad | broke 100 | 2 | no | unproven |  |
| mutant:M5 | known-bad | broke 100 | 3 | no | unproven |  |
| vault-a | known-good | held | 1 | no | unproven |  |
| vault-a | known-good | held | 2 | no | unproven |  |
| vault-a | known-good | held | 3 | no | unproven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
