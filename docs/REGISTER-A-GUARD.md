# Register a guard

Put your guard on the board: every attack in the library, and every new attack the paper hunter
finds, runs against it on a local NEAR sandbox. Nothing touches testnet or mainnet, and nothing
runs against a guard whose owner did not opt in.

**Guard already deployed on NEAR testnet?** You can opt in on chain instead of adding a line to
`guards/registry.json`: sign `opt_in` on the Arena contract with your guard account or its parent.
Anyone can then check your consent. See `docs/ON-CHAIN.md`. The rules below about the interface
still apply.

## What your guard must do

It must speak `targets/vault-a/INTERFACE.md`: the same method names, arguments, deposits and
views (`new`, `add_payee`, `remove_payee`, `approve_invoice`, `cancel_invoice`, `set_daily_cap`,
`pay`, `get_invoice`, ...). The harness sets up the same starting state for every guard with those
methods, so results compare like with like.

If your guard pays in native NEAR instead of tokens, it is scored from receivers' native balances
(add `--native`, see below).

If your method names or arguments differ, write a thin adapter contract that speaks
`INTERFACE.md` and calls your guard. The registry has a `methods` field for a name mapping, but the
harness does not apply renames yet, so any mapping other than the identity is refused.

## The 5 steps

1. **Build your wasm** and put it in the repo, e.g. `guards/yourteam/guard.wasm`.
   (Never under `targets/entrant-*`: the hunter refuses those paths.)

2. **Check it runs** against the hand-written attacks:

   ```
   ./run-arena.sh any guards/yourteam/guard.wasm yourteam            # token guard
   ./run-arena.sh any-native guards/yourteam/guard.wasm yourteam     # native-NEAR guard
   ```

   If setup fails here, the hunter cannot attack it either. Fix the interface first.

3. **Add an entry to `guards/registry.json`:**

   ```json
   {
     "id": "yourteam",
     "name": "YourTeam guard v1",
     "role": "subject",
     "owner": "YourTeam (contact)",
     "opt_in": "We, YourTeam, opt in to the Arena bench attacking this guard and publishing the results. - Name, 2026-11-10",
     "policy": "What your guard promises, in one plain sentence.",
     "interface": "vault-a",
     "scoring": "token",
     "wasm": "guards/yourteam/guard.wasm",
     "fingerprint": {"kind": "frozen-wasm", "wasm_sha256": "<shasum -a 256 guards/yourteam/guard.wasm>"},
     "harness_flags": ["--wasm", "guards/yourteam/guard.wasm", "--wasm-label", "yourteam"],
     "methods": {"pay": "pay", "get_invoice": "get_invoice"},
     "runnable": true
   }
   ```

   For a native-NEAR guard: `"scoring": "native"` and add `"--native"` at the end of `harness_flags`.
   The `opt_in` line is required. It is your consent to be attacked and listed, in your own words.

4. **Check the entry:**

   ```
   python3 -I tools/hunter/registry.py
   ```

   It prints every guard with `fingerprint ok` or the reason it is refused. If the wasm bytes ever
   change, the hunter skips your guard until the sha256 in the registry is updated, so a result
   always names the exact bytes it tested.

5. **Run the library against it:**

   ```
   ./run-arena.sh hunt --library --guards yourteam
   ```

   The evidence lands in `evidence/hunts/<date>-library-<id>.md` and the board
   (`site/board-data.json`, `site/board.html`) gains a column for your guard. From then on the
   daily paper hunt includes it automatically.

## How to read your column

- **broke +N**: a receiver got N tokens beyond what your guard's policy allows. Replay it with the
  command in the evidence file, on a fresh sandbox.
- **held**: those attempts found nothing. It does not prove your guard safe.
- Each hunt also runs a canary (the known double-pay race) on every guard. The leaky-on-purpose
  controls must break on it; if they do not, the hunt is marked untrusted and stays off the board.

To leave the board, remove your entry (or set `"runnable": false` with a `not_runnable_reason`).
