# vault-a design notes

## What it does, in one paragraph
The vault holds one NEP-141 token. The owner writes a list of trusted payees and approves
invoices (who gets paid, how much, until when). The agent can only say "pay invoice X". The
vault then checks every rule, marks the invoice as "in flight", sends the tokens with
`ft_transfer`, and a callback records whether the transfer worked.

## Invoice state machine
```
            approve_invoice
                  |
                  v
   cancel    +----------+   pay (all checks pass)   +---------+  callback: success  +------+
 <---------- | Approved | ------------------------> | Pending | ------------------> | Paid |
 Cancelled   +----------+ <------------------------ +---------+                     +------+
                           callback: transfer failed
```
- `Paid` and `Cancelled` are final. An invoice id can never be reused, even after it is final.
- "Expired" and "PayeeRemoved" are not stored states. The invoice stays `Approved` in storage,
  but `pay` refuses it and `get_invoice` reports it as `Expired` / `PayeeRemoved`.
- Expiry: payable only while `block_timestamp < expires_at_ns`. At or after the expiry it is dead.

## How the async callback is handled
NEAR cross-contract calls finish in a later block, so another `pay` can arrive in between.
- `pay` flips the invoice to `Pending` and counts the amount against today's cap **before**
  the transfer is sent. A second `pay` on the same invoice is refused while it is `Pending`.
  This is what makes "exactly one transfer per invoice" hold.
- Callback, success: `Pending -> Paid`. The amount stays counted for the day.
- Callback, failure (token panicked: receiver not registered, vault balance too low, etc.):
  `Pending -> Approved` and the day's counter is reduced by the amount, but only if the
  counter still refers to the day the amount was counted against. If midnight passed in
  between, the old day is gone and nothing is subtracted from the new day.
- Success is judged by the receipt outcome only. NEP-141 `ft_transfer` returns nothing and
  panics on any failure, so "receipt succeeded" means "tokens moved".
- The callback is `#[private]` (only the vault can call it) and written not to panic.
- `pay` refuses to start unless at least 45 TGas remain (20 for `ft_transfer`, 15 for the
  callback, 10 for itself). If the callback ever ran out of gas, the invoice would be stuck
  `Pending` forever, which is why this check comes before any state change.

## Daily cap
- The day is the UTC day: `block_timestamp / 86_400_000_000_000`.
- "Spent today" = settled payments + payments in flight. In-flight money counts, so two
  quick `pay` calls cannot both slip under the cap.
- `set_daily_cap` takes effect immediately. Lowering it below today's spend blocks further
  payments today; it does not undo anything.

## Other decisions the spec left open
- **Removing a payee kills its existing invoices for good.** Each payee gets a generation
  number when added. Invoices remember it. Remove and re-add gives a new number, so old
  invoices stay unpayable. Reason: "removed payees authorise nothing" should not quietly
  come back to life on re-add.
- **Payee status is checked at pay time**, not only at approval.
- **Owner and agent must be different accounts**, at init and on `set_agent`.
- **Owner methods that widen what can be paid need exactly 1 yoctoNEAR attached**
  (`add_payee`, `approve_invoice`, `set_agent`, `set_daily_cap`). That forces a full-access
  key, so a leaked function-call key cannot add payees or raise the cap. The protective
  methods (`cancel_invoice`, `remove_payee`) need no deposit, so they are easy in an emergency.
- **`cancel_invoice` on a `Pending` invoice is refused.** The transfer already left and
  cannot be recalled. If it fails, the invoice returns to `Approved` and can be cancelled then.
- **`pay` takes no deposit.** The vault pays the 1 yoctoNEAR for `ft_transfer` from its own
  NEAR balance. The agent can use a function-call key.
- **Init is `#[private]`**: only the vault account itself can initialise it, so nobody can
  initialise a freshly deployed vault with themselves as owner.
- **No `ft_on_transfer`.** Funding is a plain `ft_transfer` from the owner, as the spec says.
- **No withdraw, upgrade or owner-transfer method.** The spec did not ask for them and each
  is a new way to move money. See risks.

## Risks I know of
1. **Funds can only leave through invoices.** There is no owner withdraw. To recover tokens,
   the owner must add themselves as a payee and approve an invoice, and the agent must pay it,
   inside the daily cap. If the agent key is lost, `set_agent` fixes it; if the owner key is
   lost, nothing can change rules ever again.
2. **The token contract is trusted.** A malicious or buggy token could report success without
   moving funds, or move funds and then fail. The vault believes the receipt outcome.
3. **An agent can retry a failing invoice endlessly** (e.g. receiver not registered with the
   token). Each failed try costs the agent gas and releases its cap reservation; no money moves.
4. **The vault must keep NEAR** for storage (each invoice is stored forever) and the
   1 yoctoNEAR per payment. If it runs out of NEAR, new invoices and payments fail.
5. **The vault must be registered with the token** (`storage_deposit`), and so must each
   receiver, or transfers fail. Failures are recoverable (invoice goes back to `Approved`).
6. **Callback starvation** is guarded by the gas check, but the reserved numbers (20/15 TGas)
   are my estimates, not measurements against a specific token.
7. **Agent compromise** still lets an attacker pay any currently valid invoice early, up to
   the daily cap, to the receiver the owner chose. It cannot redirect money.
8. **Cross-midnight failures**: an amount counted on day D that fails after midnight is not
   credited back to day D (day D is over) and is not subtracted from day D+1. That is safe
   (it never lets more than the cap through) but slightly conservative.
9. **Wasm feature set**: built with Rust 1.86 and no `target-cpu=mvp`. If the target NEAR
   runtime rejects newer wasm features, rebuild with `-C target-cpu=mvp`. I did not deploy it.
