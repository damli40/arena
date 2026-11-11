# Arena on NEAR: opt in, and ask before you pay

Two things live on the Arena contract on NEAR testnet,
`receipts.dev-20261109195231-98743803426969.testnet` (the same contract that holds the receipts):

1. **Opt-in.** A guard owner signs one transaction that says "Arena may attack this guard, with
   this exact code". Anyone can read it. Arena's hunter only attacks an outside guard that has one.
2. **Results other contracts can read.** An agent's wallet, or any contract, can ask "was the guard
   with this code hash tested, and what did it show?" before it pays.

"Held" in a result means one thing: **the attacks Arena ran found no way past the guard.** It is not
a promise about attacks Arena did not run. The contract never says "safe".

Testnet only. Live record of what is on chain: `evidence/onchain-2026-11-11.md` (opt-ins) and `evidence/results-testnet-2026-11-11.md` (results, for Arena's own guards only).

## 1. Opt in your guard

Who may sign: **the guard account itself, or its direct parent** (`guard.team.testnet` may be opted
in by `guard.team.testnet` or by `team.testnet`, nobody else). The contract checks this on chain.
You must attach a little NEAR for storage (about 0.005; the rest comes back), which also means a
full-access key signed, not a limited app key.

Get your guard's code hash as 64 hex characters (NEAR shows it as base58):

```
node tools/lookup/cli.mjs <your-guard-account>        # prints "code: sha256 <hex>"
```

Then sign, for example with near-cli-rs (this exact command was not run here; Arena signed its own
opt-ins with `receipts-cli opt-in`, see the evidence file):

```
near contract call-function as-transaction receipts.dev-20261109195231-98743803426969.testnet opt_in \
  json-args '{"guard":"<your-guard-account>","code_hash":"<hex>","contact":"you@example.org","expires_at":null,"pays_in":"token"}' \
  prepaid-gas '30 Tgas' attached-deposit '0.02 NEAR' sign-as <your-guard-account-or-its-parent> network-config testnet sign-with-keychain send
```

| Field | Meaning |
|---|---|
| `guard` | the guard account |
| `code_hash` | sha256 of the wasm you consent to, 64 lowercase hex. New code needs a new opt-in |
| `contact` | optional, up to 128 bytes |
| `expires_at` | optional, nanoseconds since 1970. After it, the opt-in no longer counts |
| `pays_in` | `"token"` or `"native"`. If you leave it out, Arena lists your guard but does not run it, because it would score the wrong balance |

Opt out: `opt_out({"guard": ...})` with 1 yoctoNEAR attached, by the same signers. If the guard
account opts out itself, its parent cannot opt it back in; only the guard can.

Views: `opt_in_of({"guard"})`, `opt_ins({"from_index", "limit"})` (100 per page), `opt_in_count()`.
Each record says who signed (`signed_by`) and whether that was the guard or its parent (`signer_role`).

**What Arena checks at test time** (`tools/hunter/registry.py`, `hunt --outside`): the opt-in is
active, the signer is the guard or its parent, the guard's code on chain right now has the opted-in
hash, and the downloaded wasm hashes to it too. If the code changed, the hunter prints
`outside guard <id> refused: its code changed since it opted in ...` and does not attack it. If the
chain cannot be read, no outside guard is added at all. Your guard must speak
`targets/vault-a/INTERFACE.md` (see `docs/REGISTER-A-GUARD.md`).

## 2. Ask before you pay

```
arena_result(guard_code_hash: String, suite: Option<String>, arena_commit: Option<String>) -> ArenaAnswer
```

- `suite` given: the newest result in that suite. Omitted: the newest result of every suite, and the
  **worst** one is returned (broke, then incomplete, then held), so one good suite never hides a bad one.
- `arena_commit` given: only results made by that exact Arena git commit count.
- Never null. An unknown hash, suite or commit gives `status: "not_tested"`.

The answer: `status` (`held` / `broke` / `incomplete` / `not_tested`), `status_means` (one plain
sentence), `guard_code_hash` (echoed back), `suite`, `suite_version`, `attacks_ran`,
`not_applicable`, `beyond_policy`, `against_intent`, `setup`, `arena_commit`, `evidence_sha256`,
`evidence_path`, `attestation_sha256`, `published_at`, `suites_considered`.

Why an old result cannot pass for new code: results are stored under the code hash, so new code has
a new hash and gets `not_tested`. Each result also names a clean 40-hex Arena commit (the contract
refuses `-dirty`), and you can pin to one.

`setup` matters. One wasm can run in different modes. `"mode=fixed"` means the result only counts
for a guard whose `get_mode()` says `fixed`. Text that says "not readable on chain" means no contract
can check it, so do not treat that result as held for you.

**If one wasm has results under more than one mode, name the suite.** With no suite, the contract
returns the worst result across every mode. So a guard running in `fixed` mode gets `broke` back if
the same wasm broke in another mode. That errs toward not paying, but it is the wrong answer for
that guard. Pass the suite for the mode you care about (for example `race-double-pay:mode=fixed`),
or read every result with `arena_results_for({"guard_code_hash"})` (oldest first) and keep only the
ones whose `setup` matches the guard. The lookup tool (`tools/lookup/`) does the second: it reads the
guard's `get_mode()` and counts only results with that `setup`, or with no `setup` at all. Results
for other modes are listed next to the answer and never counted. If it cannot read the mode, it
answers `unclear_setting`, never `held`.

`attestation_sha256` is the fingerprint of a hardware attestation report for the run. Nothing fills
it yet; it is empty on every result today.

### Example: a wallet contract asks first (near-sdk 5)

Full contract and its sandbox test: `receipts/example-caller/src/lib.rs`,
`receipts/host/tests/onchain.rs` (`a_contract_asks_before_paying`).

```rust
use near_sdk::{env, ext_contract, near, AccountId, Gas, Promise, PromiseError};

#[near(serializers = [json])]
pub struct Answer { pub guard_code_hash: String, pub status: String, pub setup: Option<String>, pub arena_commit: Option<String> }

#[ext_contract(arena)]
trait Arena {
    fn arena_result(&self, guard_code_hash: String, suite: Option<String>, arena_commit: Option<String>) -> Answer;
}

// inside #[near] impl Wallet { ... }
pub fn ask(&self, arena: AccountId, guard_code_hash: String, suite: Option<String>,
           arena_commit: Option<String>, expected_setup: Option<String>) -> Promise {
    arena::ext(arena).with_static_gas(Gas::from_tgas(10))
        .arena_result(guard_code_hash.clone(), suite, arena_commit)
        .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(10))
              .on_answer(guard_code_hash, expected_setup))
}

#[private]
pub fn on_answer(&self, guard_code_hash: String, expected_setup: Option<String>,
                 #[callback_result] answer: Result<Answer, PromiseError>) -> bool {
    let Ok(a) = answer else { return false };                      // call failed: do not pay
    a.guard_code_hash == guard_code_hash                           // answer is about this exact code
        && a.status == "held"                                      // the attacks Arena ran found nothing
        && (a.setup.is_none() || a.setup == expected_setup)        // and it was tested set up like yours
}
```

Your contract still has to know the guard's code hash: a contract cannot read another account's
code hash on chain. Get it off chain (`view_account`), or have the guard's owner hand it over, and
check it again before large payments, because a guard with a full-access key can change its code.

## What this does not prove

- An opt-in proves that **the guard account or its parent signed**. A parent creates an account, but
  does not control it afterwards: if the guard's keys were handed to someone else, its parent can
  still opt it in. `signer_role` says which one signed.
- The contract does **not** check that `code_hash` is the code the guard runs. It cannot: NEAR gives
  contracts no way to read another account's code. Arena checks it off chain, at test time.
- A result proves who published it (the contract's owner key) and when. It does not prove the bench
  ran unmodified, or that the attacks were good. "Held" is never "safe".
- One key decides: the contract's own key publishes results and can replace the contract's code.
