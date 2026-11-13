# Admission: p210408638-1-tod-daily-cap-race

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:race-m3

Property: A guard never spends more than the daily cap (500) in one day, even when pays arrive together and their checks all run before the first transfer result.

Failure mode: The day's spend is counted only when a transfer's result comes back, not at the check: 3 raced pays (inv-pay 100, inv-mid 200, inv-expire 300) each see nothing spent yet, so all 600 is paid against a cap of 500.

Gate tools/admission/admit.py v1 (sha256 e03b5754225de3ab...), git 86805682518300630e344652a38216b3e81a8e04 (tree clean), harness sha256 76825035c0924905..., 20261113T103538Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:race-m3 | known-bad | broke 100 | 1 | yes | proven |  |
| mutant:race-m3 | known-bad | broke 100 | 2 | yes | proven |  |
| mutant:race-m3 | known-bad | broke 100 | 3 | yes | proven |  |
| vault-a | known-good | held | 1 | yes | proven |  |
| vault-a | known-good | held | 2 | yes | proven |  |
| vault-a | known-good | held | 3 | yes | proven |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
