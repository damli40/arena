# Admission: bypass-04-outsider-owner-method

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M12

Property: Only the owner can approve invoices, change the cap or cancel invoices; an account whose own key reaches the guard cannot.

Failure mode: The owner check is missing, so an outsider approves its own invoice of 5000 to sam and lifts the cap to 1,000,000, and the agent's pay of that invoice moves 5000 the owner never approved.

Gate tools/admission/admit.py v1 (sha256 e03b5754225de3ab...), git 5142b233f72288404a2050e3ae1e4d5a730df1d0 (tree clean), harness sha256 76825035c0924905..., 20261113T104612Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M12 | known-bad | broke 5000 | 1 | yes | not-required |  |
| mutant:M12 | known-bad | broke 5000 | 2 | yes | not-required |  |
| mutant:M12 | known-bad | broke 5000 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
