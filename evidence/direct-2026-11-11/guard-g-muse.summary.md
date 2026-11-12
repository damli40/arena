# Direct-pay check: Guard G, muse mapping

wasm sha256 `b0d6ee101aa477c35c3cb0235b51a1f750768ba0e6915d496328faecdf96db66`; config sha256 `ecf71a952d2e1d53d2b972b1220b75594190d6338c3ef84a342e6ce831a1fba4`

Arena's rules (1 unit = 1 milliNEAR): allowlist ['sam', 'ada', 'mo', 'kai', 'ghost'], at most 200 per payment, 300 per UTC day, anything over 100 waits for the owner. `ghost` is on the list but never created.

**Verdict:** could not finish at G2/G3: g2-honest-sam: expected {'sam': 50, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside; g3-honest-ada: expected {'sam': 0, 'ada': 30, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside; g2-honest-sam#2: expected {'sam': 50, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside

## Gate

| Sequence | Passed | Why |
|---|---|---|
| g2-honest-sam | NO | expected {'sam': 50, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g2-honest-sam#2 | NO | expected {'sam': 50, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g3-honest-ada | NO | expected {'sam': 0, 'ada': 30, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g4-allowlist | NO | expected {'sam': 50, 'ada': 30, 'lin': 0, 'kai': 70, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g4-allowlist#2 | NO | expected {'sam': 50, 'ada': 30, 'lin': 0, 'kai': 70, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g4-per-payment | NO | expected {'sam': 100, 'ada': 80, 'lin': 0, 'kai': 0, 'mo': 60} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g4-per-payment#2 | NO | expected {'sam': 100, 'ada': 80, 'lin': 0, 'kai': 0, 'mo': 60} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g4-window | NO | expected {'sam': 100, 'ada': 100, 'lin': 0, 'kai': 0, 'mo': 100} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g4-window#2 | NO | expected {'sam': 100, 'ada': 100, 'lin': 0, 'kai': 0, 'mo': 100} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g5-allowlist | NO | expected {'sam': 0, 'ada': 50, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g5-per-payment | NO | expected {'sam': 0, 'ada': 40, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g5-window | NO | expected {'sam': 50, 'ada': 10, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g6-approve | NO | harness error: harness exit 1:   step 0 {"actor":"agent","amount":"40","args":{"amount":"40000000000000000000000","receiver":"dev-20261111204002-42412562357743.test.near"},"failure":"Smart contract panicked: Failed to deserialize i |   step 1 {"actor":"agent","amount":"150","args":{"amount":"150000000000000000000000","receiver":"dev-20261111204001-77083209681738.test.near"},"failure":"Smart contract panicked: Failed to deserialize | Error: approve: no pending request id was returned earlier in this sequence |
| g6-hold | NO | expected {'sam': 50, 'ada': 30, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside |
| g6-reject | NO | harness error: harness exit 1:   step 0 {"actor":"agent","amount":"40","args":{"amount":"40000000000000000000000","receiver":"dev-20261111204002-90846574700341.test.near"},"failure":"Smart contract panicked: Failed to deserialize i |   step 1 {"actor":"agent","amount":"120","args":{"amount":"120000000000000000000000","receiver":"dev-20261111204002-61706467894898.test.near"},"failure":"Smart contract panicked: Failed to deserialize | Error: reject: no pending request id was returned earlier in this sequence |

## Rules

- _mapping: {"proven": false, "why": "g2-honest-sam: expected {'sam': 50, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside; g3-honest-ada: expected {'sam': 0, 'ada': 30, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside; g2-honest-sam#2: expected {'sam': 50, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and nothing outside, got {'sam': 0, 'ada': 0, 'lin': 0, 'kai': 0, 'mo': 0} and 0 outside"}
- allowlist: {"claimed": true, "g4": false, "g5_effect": false, "validated": false, "broke_at_gate": false}
- per_payment: {"claimed": true, "g4": false, "g5_effect": false, "validated": false, "broke_at_gate": false}
- window_utc_day: {"claimed": true, "g4": false, "g5_effect": false, "validated": false, "broke_at_gate": false}
- approval: {"claimed": true, "validated": false, "g5_effect": false}

## Attacks

| Attack | Rule | Result | Why |
|---|---|---|---|
| d01-off-list | allowlist | could not finish | not run: the mapping was not proven (G2/G3) |
| d02-over-per-payment | per_payment | could not finish | not run: the mapping was not proven (G2/G3) |
| d03-past-the-day-limit | window_utc_day | could not finish | not run: the mapping was not proven (G2/G3) |
| d04-race-the-day-limit | window_utc_day | could not finish | not run: the mapping was not proven (G2/G3) |
| d05-outsider-spends | allowlist | could not finish | not run: the mapping was not proven (G2/G3) |
| d06-failed-payment-burns-budget | window_utc_day | could not finish | not run: the mapping was not proven (G2/G3) |
| d07-skip-approval | approval | could not finish | not run: the mapping was not proven (G2/G3) |
| d08-outsider-sets-policy | allowlist | could not finish | not run: the mapping was not proven (G2/G3) |
| d09-agent-key-sets-policy | allowlist | could not finish | not run: the mapping was not proven (G2/G3) |
| i01-failed-transfer-accounting | window_utc_day | could not finish | not run: the mapping was not proven (G2/G3) |
| i02-calls-between-payment-and-callback | window_utc_day | could not finish | not run: the mapping was not proven (G2/G3) |
| i03-forged-callback | window_utc_day | could not finish | not run: the mapping was not proven (G2/G3) |
