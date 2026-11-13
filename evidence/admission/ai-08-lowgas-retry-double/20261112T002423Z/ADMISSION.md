# Admission: ai-08-lowgas-retry-double

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M4

Property: A guard pays each approved invoice at most once, whatever gas the first pay attached.

Failure mode: No already-paid check: the 50 TGas pay is enough on vault-a (its gas pre-check passes) and pays inv-pay, so the full-gas retry pays it again. No half-paid state is reached.

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git fd6564e6057c7ae55df8e8bd60bfdddeca72f65b (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T002423Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M4 | known-bad | broke 100 | 1 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 2 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
