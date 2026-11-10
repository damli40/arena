## Arena check: **arena: not run**

- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

**Could not finish:**

```
Preflight (one honest payment) could not run. Setup failed at approve_invoice: the owner's `approve_invoice` call for inv-pay failed (receiver is not a payee). Check that your init args put Arena's owner in the owner role ($owner), and the deposits in your mapping. Full log: evidence/check-fixes-2026-11-11/noop-add_payee/runs/scripted-01-control-pay-valid__vault_a.log
```

Guard wasm sha256 `52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1` · Arena commit `b8d6f5889959` (with local changes) · 11.2 s · 2026-11-10T20:55:40Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
