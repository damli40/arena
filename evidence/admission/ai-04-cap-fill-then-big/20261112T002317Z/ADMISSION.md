# Admission: ai-04-cap-fill-then-big

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M2

Property: A guard never spends more than the owner's daily cap (500) in one day, however the spending is split.

Failure mode: No daily-cap check: after three honest invoices (350) the 600 invoice is paid too, 950 in one day. A cap checked per payment (M3) still refuses 600 on its own, so that is not this attack's flaw.

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git fd6564e6057c7ae55df8e8bd60bfdddeca72f65b (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T002317Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M2 | known-bad | broke 450 | 1 | yes | not-required |  |
| mutant:M2 | known-bad | broke 450 | 2 | yes | not-required |  |
| mutant:M2 | known-bad | broke 450 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
