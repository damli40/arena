# Admission: c261110-1-race-valid-double-plus-forbidd

**Class: partially-validated.** outcomes matched, race ordering not shown: vault-a: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); guard:fixed: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); guard:vulnerable_fixture: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown); mutant:M5: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown)

Property: A guard pays each approved invoice at most once, whatever the timing, and the forbidden invoices raced alongside stay refused.

Failure mode: No reservation before the transfer: the two raced pays of inv-pay both transfer (sam 200). The cancelled, removed-payee and outsider pays are refused on every reference.

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git 56872c9fff7e36891928c6baa486160b45ca24c0 (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T011747Z.
Runs counted 0 of 12 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| guard:fixed | known-good | held | 1 | no | unproven |  |
| guard:fixed | known-good | held | 2 | no | unproven |  |
| guard:fixed | known-good | held | 3 | no | unproven |  |
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
