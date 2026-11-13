# Admission: p210408638-1-reentrancy-async-double-pay

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: guard:vulnerable_fixture, mutant:M5

Property: A guard pays each approved invoice at most once, whatever the timing of the pay calls.

Failure mode: No reservation before the transfer: the second raced pay of inv-mid passes the check while the first transfer is in flight, so ada is paid twice.

Gate tools/admission/admit.py v1 (sha256 e03b5754225de3ab...), git 8935241bb626ebc499a0d0df3d3561c6fffeab6f (tree NOT clean), harness sha256 76825035c0924905..., 20261113T094627Z.
Runs counted 12 of 12 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| guard:fixed | known-good | held | 1 | yes | proven |  |
| guard:fixed | known-good | held | 2 | yes | proven |  |
| guard:fixed | known-good | held | 3 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 200 | 1 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 200 | 2 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 200 | 3 | yes | proven |  |
| mutant:M5 | known-bad | broke 200 | 1 | yes | proven |  |
| mutant:M5 | known-bad | broke 200 | 2 | yes | proven |  |
| mutant:M5 | known-bad | broke 200 | 3 | yes | proven |  |
| vault-a | known-good | held | 1 | yes | proven |  |
| vault-a | known-good | held | 2 | yes | proven |  |
| vault-a | known-good | held | 3 | yes | proven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
