# vault-a interface

An invoice vault for an AI agent on NEAR. It holds one NEP-141 token and pays invoices on
behalf of an owner. An AI agent triggers payments.

## Policy (what the owner means)
- Each approved, unexpired, uncancelled invoice authorises **exactly one** transfer of its
  amount to its receiver.
- Cancelled or expired invoices, and invoices whose receiver was removed as a payee,
  authorise nothing.
- Total paid per UTC day is at most `daily_cap`.
- Only the agent can trigger payments. Only the owner can change rules.
- A transfer that genuinely fails leaves the invoice payable again.

Funding: the owner sends tokens to the vault with a plain `ft_transfer` on the token contract.
The vault (and each receiver) must be registered with the token (`storage_deposit`).

## Conventions
- Token amounts are JSON strings of u128, e.g. `"1000000"`.
- `expires_at_ns` is a JSON number: Unix time in nanoseconds (compared with block timestamp).
  An invoice is payable only while block time `<` `expires_at_ns`.
- "1 yocto" means the call must attach exactly 1 yoctoNEAR (`--depositYocto 1`).
- A UTC day is `floor(block_timestamp_ns / 86_400_000_000_000)`.

## Init
| Method | Args | Caller | Returns |
|---|---|---|---|
| `new` | `{"owner": "owner.near", "agent": "agent.near", "token": "token.near", "daily_cap": "1000"}` | the vault account itself only (deploy + init) | — |

`owner` and `agent` must differ.

## Owner methods
| Method | Args | Deposit | Returns |
|---|---|---|---|
| `add_payee` | `{"account": "bob.near"}` | 1 yocto | — |
| `remove_payee` | `{"account": "bob.near"}` | none | — |
| `approve_invoice` | `{"id": "inv-1", "receiver": "bob.near", "amount": "100", "expires_at_ns": 1767225600000000000}` | 1 yocto | — |
| `cancel_invoice` | `{"id": "inv-1"}` | none | — |
| `set_agent` | `{"account": "agent2.near"}` | 1 yocto | — |
| `set_daily_cap` | `{"daily_cap": "5000"}` | 1 yocto | — |

Notes:
- `approve_invoice`: `receiver` must currently be a payee; `id` is 1–64 bytes and can never be
  reused; `amount` > 0; `expires_at_ns` must be in the future.
- `remove_payee`: invoices already approved for that payee become permanently unpayable,
  even if the payee is added again later.
- `cancel_invoice`: fails if the invoice is paid, already cancelled, or has a payment in flight.
- `set_agent`: new agent must differ from the owner.
- `set_daily_cap`: applies immediately, including to the current day.

## Agent method
| Method | Args | Deposit | Gas | Returns |
|---|---|---|---|---|
| `pay` | `{"id": "inv-1"}` | none | at least 50 TGas, 100 TGas recommended | `true` if the transfer succeeded and the invoice is now paid, `false` if the transfer failed and the invoice is payable again |

`pay` fails immediately (no transfer) if: caller is not the agent; invoice unknown, paid,
cancelled, expired, or already being paid; receiver no longer a payee; today's total plus this
amount would exceed `daily_cap`; not enough gas attached.

## Views
| Method | Args | Returns |
|---|---|---|
| `get_invoice` | `{"id": "inv-1"}` | `null` or `{"id", "receiver", "amount": "100", "expires_at_ns": <number>, "status", "payable_now": bool}` |
| `get_config` | `{}` | `{"owner", "agent", "token", "daily_cap": "1000"}` |
| `paid_today` | `{}` | `"150"`: amount paid plus amount in flight during the current UTC day |
| `is_payee` | `{"account": "bob.near"}` | `bool` |

`status` is one of `Approved`, `Pending` (payment in flight), `Paid`, `Cancelled`,
`Expired`, `PayeeRemoved`.

## Events
Each state change logs a line `EVENT_JSON:{"standard":"vault-a","version":"1.0.0","event":...,"data":[...]}`
with event names `payee_added`, `payee_removed`, `invoice_approved`, `invoice_cancelled`,
`agent_set`, `daily_cap_set`, `payment_started`, `payment_succeeded`, `payment_failed`.
