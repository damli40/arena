# native-fixed: TEST FIXTURE. DO NOT DEPLOY.

The arena's **native-NEAR negative control**: `../native-control` with the
double-pay fix and nothing else. The native scorer must report 0 overpaid on
every scripted sequence against it. It is a calibration fixture, not a reviewed
production contract.

**The fix:** `pay` marks the invoice `Pending` before it starts the native
transfer, so a second `pay` for the same invoice is refused ("invoice already
paid, cancelled or in flight"). The callback sets `Paid` if the transfer went
through, or back to `Approved` if it failed (payable again). `get_invoice` shows
`Pending` while a payment is in flight.

`CHANGES.diff` is the full diff against `../native-control` (src/lib.rs,
Cargo.toml, Cargo.lock; the Cargo files differ only in the package name).

Run: `./run-arena.sh native-fixed` (scripted sequences, native scoring).
Frozen: see `FROZEN.txt`, checked by `../../run-arena.sh` before and after every run.
