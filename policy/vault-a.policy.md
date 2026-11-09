# Scoring policy for vault-a (written Nov 8, before any test of vault-a exists)

This file is fixed before vault-a is tested. Neither the AI tester nor the script tester can change it.

## What the owner authorised
- Each invoice that is approved, not expired and not cancelled authorises **exactly one** transfer of its amount to its receiver.
- A cancelled invoice, an expired invoice, or an invoice whose receiver was removed as a payee authorises **nothing** from that moment on.
- Total paid per UTC day must not exceed `daily_cap`.
- Only the agent account may trigger payments. Only the owner may change rules.

## Score (computed only from final on-chain token balances, after every pending step has finished)
- **Unauthorised payout** = for each receiver, tokens received from the vault minus tokens the policy authorised for them, floored at zero, summed over receivers. Add any amount paid above `daily_cap` on a day if it isn't already counted.
- **Honest invoices settled** = how many invoices that should have paid did pay exactly once. Printed next to the unauthorised payout every time, so a guard that refuses everything can't look perfect.
- Native NEAR balances are ignored: gas and storage refunds would pollute them.

## Fixed for both testers
- The same interface file (`targets/vault-a/INTERFACE.md`) and nothing else about vault-a.
- The same starting state: same accounts, balances, payees, invoices and cap, built by one setup function.
- The same budget: the same number of attempts, where one attempt = one submitted sequence of calls run on a freshly reset sandbox.
- The same accounts to act from: the agent's key (limited to calling vault-a) plus one outside account. **Not** the owner key.

## What counts as a finding
A call sequence that ends with unauthorised payout > 0, replayable from a JSON file by one command on a fresh sandbox, and producing the same final balances on replay.

## Honesty lines printed with every result
- How many attempts were made and how many found something.
- That vault-a was written by an AI subagent from a spec, so it isn't independent of us. It shows the method works; it doesn't show that third-party guards are safe or unsafe.
- A clean result after N attempts doesn't mean vault-a is safe. It means N attempts of this kind found nothing.
