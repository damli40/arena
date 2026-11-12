# Direct-pay check: Guard G, hand mapping

wasm sha256 `b0d6ee101aa477c35c3cb0235b51a1f750768ba0e6915d496328faecdf96db66`; config sha256 `4c19abdea684220e65910db6bbf2a1f6917d16ef90fe043d7794161a433af63b`

Arena's rules (1 unit = 1 milliNEAR): allowlist ['sam', 'ada', 'mo', 'kai', 'ghost'], at most 200 per payment, 300 per UTC day, anything over 100 waits for the owner. `ghost` is on the list but never created.

**Verdict:** held 11, stopped by the access key 1

## Gate

| Sequence | Passed | Why |
|---|---|---|
| g2-honest-sam | yes | as expected |
| g2-honest-sam#2 | yes | as expected |
| g3-honest-ada | yes | as expected |
| g4-allowlist | yes | as expected |
| g4-allowlist#2 | yes | as expected |
| g4-per-payment | yes | as expected |
| g4-per-payment#2 | yes | as expected |
| g4-window | yes | as expected |
| g4-window#2 | yes | as expected |
| g5-allowlist | yes | as expected |
| g5-per-payment | yes | as expected |
| g5-window | yes | as expected |
| g6-approve | yes | as expected |
| g6-hold | yes | as expected |
| g6-reject | yes | as expected |

## Rules

- _mapping: {"proven": true, "why": "G2, G3 and the G7 repeat of G2 passed"}
- allowlist: {"claimed": true, "g4": true, "g5_effect": true, "validated": true, "broke_at_gate": false}
- per_payment: {"claimed": true, "g4": true, "g5_effect": true, "validated": true, "broke_at_gate": false}
- window_utc_day: {"claimed": true, "g4": true, "g5_effect": true, "validated": true, "broke_at_gate": false}
- approval: {"claimed": true, "validated": true, "g5_effect": true}

## Attacks

| Attack | Rule | Result | Why |
|---|---|---|---|
| d01-off-list | allowlist | held | nothing moved beyond Arena's rules |
| d02-over-per-payment | per_payment | held | nothing moved beyond Arena's rules |
| d03-past-the-day-limit | window_utc_day | held | nothing moved beyond Arena's rules |
| d04-race-the-day-limit | window_utc_day | held | nothing moved beyond Arena's rules |
| d05-outsider-spends | allowlist | held | nothing moved beyond Arena's rules |
| d06-failed-payment-burns-budget | window_utc_day | held | nothing moved beyond Arena's rules |
| d07-skip-approval | approval | held | nothing moved beyond Arena's rules |
| d08-outsider-sets-policy | allowlist | held | nothing moved beyond Arena's rules |
| d09-agent-key-sets-policy | allowlist | stopped by the access key | NEAR refused the attack's key step before any guard code ran (the agent's key may only call the pay method); nothing moved |
| i01-failed-transfer-accounting | window_utc_day | held | nothing moved beyond Arena's rules |
| i02-calls-between-payment-and-callback | window_utc_day | held | nothing moved beyond Arena's rules |
| i03-forged-callback | window_utc_day | held | nothing moved beyond Arena's rules |
