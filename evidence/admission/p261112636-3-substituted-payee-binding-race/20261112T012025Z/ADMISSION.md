# Admission: p261112636-3-substituted-payee-binding-race

**Class: partially-validated.** outcomes matched, race ordering not shown: vault-a: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); mutant:M1: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown)

Property: A guard never pays a removed payee, even when that pay is raced with a valid one.

Failure mode: No payee check: the removed payee's invoice is paid (lin 400) next to the valid inv-pay. The race is not what breaks it; the missing check is.

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git 56872c9fff7e36891928c6baa486160b45ca24c0 (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T012025Z.
Runs counted 0 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M1 | known-bad | broke 400 | 1 | no | unproven |  |
| mutant:M1 | known-bad | broke 400 | 2 | no | unproven |  |
| mutant:M1 | known-bad | broke 400 | 3 | no | unproven |  |
| vault-a | known-good | held | 1 | no | unproven |  |
| vault-a | known-good | held | 2 | no | unproven |  |
| vault-a | known-good | held | 3 | no | unproven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
