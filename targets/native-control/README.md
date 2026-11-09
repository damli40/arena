# native-control: TEST FIXTURE, deliberately vulnerable. DO NOT DEPLOY.

This contract exists so the arena's **native-NEAR scorer** has a known positive.
If a native-mode run against it reports 0 overpaid on the double-request sequence,
the native scorer is blind; that says nothing about whether this contract is safe
(it is not).

It is `../leaky-control-v2` with one change: `pay` sends the invoice amount as a
native NEAR transfer (`Promise::new(receiver).transfer(...)`) instead of a token
`ft_transfer`. Invoice amounts and `daily_cap` are in yoctoNEAR. Method names,
arguments, deposits and views match `../vault-a/INTERFACE.md`; `new` still takes a
`token` argument, which is stored and shown by `get_config` but never used.

**The flaw (kept on purpose, same as leaky-control-v2):** `pay` checks "is it paid?"
and starts the transfer, but the invoice is marked `Paid` only in the callback that
runs blocks later. A second `pay` for the same invoice that lands before the
callback still sees `Approved`, so it pays again.

`../native-fixed` is the same contract with the fix (reserve before the transfer);
`../native-fixed/CHANGES.diff` is the whole difference.

Run: `./run-arena.sh native-control` (scripted sequences, native scoring).
Frozen: see `FROZEN.txt`, checked by `../../run-arena.sh` before and after every run.
