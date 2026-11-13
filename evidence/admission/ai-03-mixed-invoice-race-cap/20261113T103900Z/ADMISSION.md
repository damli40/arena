# Admission: ai-03-mixed-invoice-race-cap

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: guard:vulnerable_fixture

Property: A guard pays each approved invoice at most once, whatever the timing of the pay calls.

Failure mode: The guard checks 'not yet paid' and starts the transfer but records nothing until the callback, so the second pay for inv-mid, sent together with the first, passes the same check.

Gate tools/admission/admit.py v1 (sha256 e03b5754225de3ab...), git 86805682518300630e344652a38216b3e81a8e04 (tree clean), harness sha256 76825035c0924905..., 20261113T103900Z.
Runs counted 9 of 9 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| guard:fixed | known-good | held | 1 | yes | proven |  |
| guard:fixed | known-good | held | 2 | yes | proven |  |
| guard:fixed | known-good | held | 3 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 200 | 1 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 200 | 2 | yes | proven |  |
| guard:vulnerable_fixture | known-bad | broke 200 | 3 | yes | proven |  |
| vault-a | known-good | held | 1 | yes | proven |  |
| vault-a | known-good | held | 2 | yes | proven |  |
| vault-a | known-good | held | 3 | yes | proven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
