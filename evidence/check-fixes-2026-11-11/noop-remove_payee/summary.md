## Arena check: **arena: not run**

- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

**Could not finish:**

```
Preflight: an owner method had no visible effect:
  - remove_payee: the owner removed lin, but `is_payee` still says lin is a payee. Either your mapping points remove_payee at a method that does not do that job, or your guard's remove_payee does not work. Arena does not score a guard whose owner methods it cannot set up.
```

Guard wasm sha256 `52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1` · Arena commit `b8d6f5889959` (with local changes) · 15.3 s · 2026-11-10T20:55:40Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
