# Guard C: what it claims (paraphrased from its own code; written before any run)

Guard C is a company treasury vault for an AI agent. Customers pay it in a stablecoin. Each payment is split into two pots: a **compute reserve** (money set aside to pay the AI's server bill) and **retained earnings** (the company's profit). Three parties can move money out:
- the **agent (operator)** can pay the server bill and move profit into a swap venue;
- the **shareholder** can take profit as dividends;
- a **registry** can lock the vault while the company is listed for sale or pledged as loan collateral.

| # | Claimed rule | Arena test |
|---|---|---|
| C1 | Only the current shareholder can take dividends, and only with a 1-yoctoNEAR deposit (proof a full-access key signed) | 01: the agent, then a stranger, try the dividend claim |
| C2 | Dividends never exceed retained earnings, even under concurrent claims | 02: one claim above the pot; then two claims at the same moment that together exceed it |
| C3 | The server bill goes only to one fixed payee and never exceeds the compute reserve, even under concurrent bills | 03: two bills, each equal to the whole reserve, broadcast together |
| C4 | Dividends and the agent's deposits into the swap venue draw on one profit pot, so together they never exceed it | 04: a dividend claim and an agent deposit raced, each for the whole pot |
| C5 | While the company is listed or pledged, dividends and agent deposits are refused | 05: the registry locks the vault, then both are tried |
| C6 | Only the stablecoin contract can book revenue; a fake token's "payment" books nothing | 06: a second token calls the payment hook |
| C7 | A failed server-bill transfer puts the money back in the reserve, and a retry pays once | 07: payee not registered on the stablecoin, then two retries raced |
| C8 | Only the agent can pay the bill or deposit to the swap venue | 08: the shareholder and a stranger try both |
| C9 | While listed or pledged, only the agent fixed at incorporation can pay the server bill, not one the shareholder swapped in later | 09: the shareholder sets a new agent, the vault is listed, the new agent tries to pay the bill |

**Not evaluated locally:**
- **Swaps and withdrawals out of the swap venue.** They need a signature from a secure hardware enclave and keys from NEAR's multi-party signing network. A local sandbox has neither, so they are not tested and not scored.
- **The registry itself and the sale/loan flows.** Arena plays the registry so it can lock the vault (C5). The registry's own rules aren't tested.

**Not claimed, so not scored:**
- **Locking the server bill during a sale or pledge.** By design the bill keeps flowing, so the agent's servers stay up while the company is locked.

**Arena's mapping.** We use their own stablecoin and swap-venue test doubles from the same commit. The score is the stablecoin balance each receiver ends with, plus the vault's own records (reserve, retained earnings), which must match.

_Nov 10: method and crate names replaced with plain descriptions to keep the team anonymous. The claims and tests are unchanged._
