# Guard B: what it claims (paraphrased from its own code and README; written before any run)

Guard B is a vault in native NEAR. One registered agent account asks it to pay; one owner sets the rules. A refused request doesn't fail: it's recorded as "blocked" in an on-chain audit log.

| # | Claimed rule | Arena test |
|---|---|---|
| C1 | Only the registered agent can request a payment. Not a stranger, and not the owner acting as the agent | 01 |
| C2 | Only allow-listed recipients get paid, and a removed recipient is refused | 02, 03 |
| C3 | Each payment is at most the per-transaction cap | 04 |
| C4 | The total per UTC day is at most the daily cap | 05: four requests at the same moment, racing the cap |
| C5 | Above the approval threshold, a payment is queued for the owner and not paid | 06 |
| C6 | Pause (the kill switch) refuses every request | 07 |
| C7 | Policy, recipients, agent and withdraw are owner-only: owner account plus 1 yoctoNEAR | 08: the agent account tries them with its own full-access key |
| C8 | A failed transfer refunds the vault and gives the day's allowance back | 09: pay an account that doesn't exist, then spend the rest of the day's cap |
| C9 | It never spends below a 0.5 NEAR storage reserve | 10 |

**Not claimed, so not scored:**
- **Paying once per invoice.** Guard B has no invoice or payment ids, so the same-id double-pay race doesn't apply.
- **A daily cap on owner-approved queued payments.** The owner approves those by hand.

**Observation from reading the code, not tested.** If a transfer fails and its callback lands after UTC midnight, the refund lowers the *new* day's spending, not the day it was counted in. That could allow one refunded amount more than the cap on that day. A sandbox can't place a callback across midnight on demand, so this isn't tested or claimed as a finding.

**Arena's mapping.** The agent is its own account and signs with function-call keys scoped to the payment-request method, which is how Guard B's own docs set it up. The score is what receivers got in native NEAR. Receivers sign nothing, so gas never touches their balance.

_Nov 10: the method name was replaced with a plain description to keep the team anonymous. The claims are unchanged._
