# Admission: intents-01-agent-names-outsider-beneficiary

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: intents-planted

Property: A guard that pays into NEAR Intents credits only the invoice's own receiver inside Intents.

Failure mode: The guard lets the caller pass the beneficiary of the Intents deposit, so the agent names the outsider and the outsider is credited.

Gate tools/admission/admit.py v1 (sha256 a7c55a433038b7b2...), git cbca416f9c12a81e2460e29f306bd8b0c6e0fc98 (tree clean), harness sha256 71fed1a26ecf3186..., 20261111T203848Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| intents-honest | known-good | held | 1 | yes | not-required |  |
| intents-honest | known-good | held | 2 | yes | not-required |  |
| intents-honest | known-good | held | 3 | yes | not-required |  |
| intents-planted | known-bad | broke 200 | 1 | yes | not-required |  |
| intents-planted | known-bad | broke 200 | 2 | yes | not-required |  |
| intents-planted | known-bad | broke 200 | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
