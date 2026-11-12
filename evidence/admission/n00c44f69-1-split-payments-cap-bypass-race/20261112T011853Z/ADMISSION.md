# Admission: n00c44f69-1-split-payments-cap-bypass-race

**Class: partially-validated.** outcomes matched, race ordering not shown: vault-a: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); mutant:M3: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown)

Property: A guard never spends more than the daily cap (500) in one day, even when the pays arrive together.

Failure mode: Cap checked per payment: four raced pays of 100, 50, 200 and 300 are each under 500, so all are paid (650 in a day).

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git 56872c9fff7e36891928c6baa486160b45ca24c0 (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T011853Z.
Runs counted 0 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M3 | known-bad | broke 150 | 1 | no | unproven |  |
| mutant:M3 | known-bad | broke 150 | 2 | no | unproven |  |
| mutant:M3 | known-bad | broke 150 | 3 | no | unproven |  |
| vault-a | known-good | held | 1 | no | unproven |  |
| vault-a | known-good | held | 2 | no | unproven |  |
| vault-a | known-good | held | 3 | no | unproven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
