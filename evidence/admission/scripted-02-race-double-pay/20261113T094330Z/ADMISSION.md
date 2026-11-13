# Admission: scripted-02-race-double-pay

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M5

Property: A guard pays each approved invoice at most once, whatever the timing of the pay calls.

Failure mode: The guard checks 'not yet paid' and starts the transfer but records nothing until the callback, so a second pay in that gap passes the same check.

Gate tools/admission/admit.py v1 (sha256 e03b5754225de3ab...), git 8935241bb626ebc499a0d0df3d3561c6fffeab6f (tree clean), harness sha256 76825035c0924905..., 20261113T094330Z.
Runs counted 9 of 9 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| guard:vulnerable_fixture | known-bad | broke 100 | 1 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 100 | 2 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 100 | 3 | yes | proven |  |
| mutant:M5 | known-bad | broke 100 | 1 | yes | proven |  |
| mutant:M5 | known-bad | broke 100 | 2 | yes | proven |  |
| mutant:M5 | known-bad | broke 100 | 3 | yes | proven |  |
| vault-a | known-good | held | 1 | yes | proven |  |
| vault-a | known-good | held | 2 | yes | proven |  |
| vault-a | known-good | held | 3 | yes | proven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
