# Evaluate Arena

This file is for anyone, person or coding agent, who wants to check Arena's claims by running
them. Each claim below has the command to run, the line you should see, how long it took us, and
the saved log of our own run.

If a command does not print what this file says, that is a bug in Arena or in this file. The
saved log shows what we got. We ran 12 of these commands from a fresh copy with no build folders;
every exit code and key line matched (`evidence/clean-copy-2026-11-11.md`).

## Before you start

| You need | For |
|---|---|
| Rust through rustup, Python 3 | everything in sections 1 to 4 |
| Node 18 or newer | the lookup (section 5) |
| Kani and z3 | `proofs/run.sh` only |
| Java 17 or newer | `tla/run.sh` only |

- Tested on macOS, Apple silicon. Nothing here has been run on Linux or on GitHub's runners.
- The contract folders pin Rust 1.86.0 in `rust-toolchain.toml`, and the first build downloads the
  NEAR sandbox, so the first run needs the internet.
- No command in sections 1 to 4 needs an API key, a wallet or testnet. They run on a **local NEAR
  sandbox**: a private copy of NEAR on your machine, with no real money.
- Section 5 reads NEAR testnet. It sends no transaction and needs no key.

## 1. The shortest path (about 8 minutes)

```
./verify.sh fast
```

Last line: `verify: 5 passed, 0 failed (mode=fast)`. Exit code 0.

It builds the contracts and the harness, then shows the main result: the planted-flaw guard pays
200 on a 100 invoice when two `pay` calls arrive together, the fixed guard pays 100, and the bench
scores both from final balances. Measured: 481 s on a fresh copy with no build folders, 196 s
when the builds are already there.

Its logs go to a new folder, `runs/<UTC time>-verify-fast/`, which git ignores, and every check
reads that run's own logs. `run-arena.sh` and the prompt-injection scripts do the same
(`runs/<UTC time>/`), and `arena check` writes to `./arena-report`, also ignored, so these leave
`git status` clean. To write a new saved run into `evidence/` on purpose, set `ARENA_RECORD=1`.
`tools/mutation/run.sh` (section 3) still writes into `evidence/mutation-<today>/`.

## 2. Each claim, and how to check it

| # | Claim | Command | You should see | Our time | Our saved run |
|---|---|---|---|---|---|
| 1 | Two `pay` calls at once make the planted-flaw guard pay 200 on a 100 invoice. The fixed guard pays 100. | `./verify.sh fast` | `verify: 5 passed, 0 failed (mode=fast)` | 481 s cold, 196 s warm | `evidence/verify-2026-11-11.md` |
| 2 | Every local sandbox result in the README. | `./verify.sh` | `verify: 43 passed, 0 failed (mode=full)` | 943 to 965 s (four runs); 1,910 s on Nov 12 with other builds running | `evidence/verify-2026-11-11.md`, `evidence/verify-summary.log`, `evidence/invoice-fixes-2026-11-12/verify/` |
| 3 | The fixed guard never pays one invoice twice when pay calls race. Checked on a model of the guard for any number of calls, and on the real code for every order of up to 4 pay calls. | `proofs/run.sh` | 30 checks, each `PASS` | 1,504 s | `evidence/proofs-inductive-2026-11-11.md`, `evidence/proofs-2026-11-10.md` |
| 4 | The same property in near-tla, NEAR's own model of how calls run, up to 3 pay calls. | `tla/run.sh` (all 25), or `tla/run.sh vuln_race fixed_1inv h1_outside_transfer_reconcile` (3 of them) | 25 checks as planned, or the 3 quick ones | about 46 min, or about 15 s | `evidence/tla-2026-11-11/` |
| 5 | We planted 10 mistakes in our own guard, one at a time. Our attacks caught 7. | `tools/mutation/run.sh` | `summary.tsv` with M1, M2, M4, M5, M6, M7, M8 caught and M3, M9, M10 not | one mutant: 573 s, including the two baseline checks; all ten: 2,410 s (about 40 min). Our re-runs on Nov 11 and, with the chain-only scorer, on Nov 12 (3,513 s) matched the saved table row for row | `evidence/mutation-table-2026-11-11.md`, `evidence/mutation-2026-11-12/` |
| 6 | An agent that obeys every injected instruction pays 0 tokens beyond the guard's rules, and 450 tokens against the owner's intent across five runs. | `ARENA_AGENT=compromised python3 -I tools/injection/run.py` then `python3 -I tools/injection/rescore.py` | rescore ends `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` | 80 s, then under 1 s | `evidence/injection-intent-by-recipient.md` |
| 7 | One command checks a guard against the whole attack library and says held or broke. | section 3 | `arena: held 49/49 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...)` for vault-a (exit 0), `arena: broke 5 of 49 (...)` for the leaky guard (exit 1) | 301 s and 299 s (Nov 12, two other builds running on the machine) | `evidence/invoice-fixes-2026-11-12.md` |
| 8 | The same check works for a guard that pays in plain NEAR, not a token. | section 3 | `arena: held 48/48 (0 not applicable; 1 stopped by the agent's access key before the guard ran; ...)` for native-fixed (exit 0), `arena: broke 5 of 48 (...)` for native-control (exit 1) | 257 s and 244 s | `evidence/invoice-fixes-2026-11-12.md` |
| 9 | If a guard pays any account the attack was not supposed to reach (the agent, the outsider, an account the attack named), the check says broke and names who got it. Money it cannot find makes the check incomplete, never held. | section 3 | `arena: broke 11 of 49 (...; 1800 tokens paid outside the five receivers; ...)` for planted-outflow (exit 1) | 324 s | `evidence/invoice-fixes-2026-11-12.md`, `evidence/check-outflow-2026-11-11.md` |
| 9b | A guard that pays into NEAR Intents is scored from who Intents credited. Our honest Intents guard holds; our planted copy, which lets the caller pick who is credited, breaks, and the report names who got the credit. | section 3 | `arena: held 51/51 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...)` for intents-honest (exit 0), `arena: broke 2 of 51 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...; refused 2 of 65 honest payments; 300 tokens paid outside the five receivers; ...)` for intents-planted (exit 1) | 497 s and 570 s | `evidence/invoice-fixes-2026-11-12.md`, `evidence/check-intents-2026-11-11.md` |
| 9c | A guard that asks Chain Signatures to sign is scored by counting the signing requests the owner did not allow (a hash off the list, signed twice, the wrong key, or asked for by the outsider), read from Arena's stand-in signer. Our honest guard holds; our planted copy, which signs any hash the caller passes, breaks on 3 attacks. A config whose path does not match the guard stops the check, never held. | section 3 | `arena: held 55/55 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...; signs via Chain Signatures: Arena's stand-in signer, no real MPC signing, nothing sent to another chain)` for chainsig-honest (exit 0); `arena: broke 3 of 55 (...; 3 unauthorised signing requests (a count, not an amount); ...)` for chainsig-planted (exit 1); `arena: not run` and `COULD NOT FINISH` for the wrong-path config (exit 2) | about 345 s each; the wrong-path one about 20 s | `evidence/check-chainsig-2026-11-11.md`, `evidence/clean-copy-chainsig-2026-11-12.md`, `evidence/clean-copy-chainsig-2026-11-12b.md` and `-12c.md` (after the two reviews) |
| 9d | A guard that withdraws from NEAR Intents toward another chain is scored from where each withdrawal went and what foreign destination it named, as recorded by Arena's bridge stand-in. Our honest withdraw guard holds; our planted copy, which forwards the agent's `msg`, breaks, and each BROKE line names the foreign address. Nothing reaches another chain. | section 3 | `arena: held 57/57 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...)` for withdraw-honest (exit 0), `arena: broke 3 of 57 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...; refused 3 of 72 honest payments; 500 tokens paid outside the five receivers; ...)` for withdraw-planted (exit 1); the 3 refused honest payments are the invoices the 3 BROKE attacks had already paid out | 642 s and 591 s on a fresh copy (544 s and 588 s in the working tree) | `evidence/check-withdraw-2026-11-12.md` |
| 9e | The pinned Intents release sends `ft_withdraw` with a `msg` on to the bridge stand-in, which records it; an unreadable `msg` is refunded to the sender's credit; a withdrawal with no `msg` reaches the bridge with no record. | `(cd contracts && cargo build --release --target wasm32-unknown-unknown -p test-token -p bridge-standin) && (cd harness && cargo run --release --example withdraw_spike)` | `STEP g ft_withdraw 100 to bridge, good msg: success=true returned=Some("100") receipt_failures=0`, then `... unreadable msg: ... returned=Some("0")` with `g inside Intents=900`, then `... no msg ...` with `bridge tokens=107 ... record_count=1`, and `DONE` | 24 s with the build already done | `evidence/check-withdraw-2026-11-12/spike.txt` |
| 10 | The hunter's saved attacks replay from their JSON files, with no model call. | section 4 | section 4 | about 15 s per replay | `evidence/hunts/` |
| 11 | The double-pay result and its fix are saved on NEAR testnet, and anyone can look them up. | section 5 | section 5 | 1 to 2 s | `evidence/receipts-testnet-2026-11-11.md`, `evidence/testnet-2026-11-11.md` |
| 12 | A guard owner can sign a note on NEAR testnet saying "Arena may test this exact code", and another contract can ask for a result before it pays. | section 5 | `opt-in:    opted_in` in the lookup | 1 to 2 s | `evidence/onchain-2026-11-11.md`, `evidence/results-testnet-2026-11-11.md`, `docs/ON-CHAIN.md` |
| 13 | When the hunter's model runs on NEAR AI Cloud, the run saves NEAR's attestation report (a record, signed inside NEAR's sealed hardware, of which model and configuration answered). | `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json` | `recheck: all checks pass (Intel and NVIDIA signatures are not checked offline)`, exit 0 | under 1 s | `evidence/nearai-2026-11-11.md` |
| 14 | The direct-pay path (no invoices) tells a broken guard from a correct one: 25 self-tests on a fixture with one deliberate defect each, each giving the result its defect demands. S20 (a callback anyone can call) breaks on i03 with the right callback mapping; S23 and S24 map the callback to a view method instead, and i03 is could not finish, never held. S25 (the callback takes a second argument only the guard's own call passes) still breaks on i03, because the forged call copies the guard's own arguments; S26 (the id comes back as a number, the callback wants a string) is could not finish. S27 and S28 (the callback also checks the amount, or a nonce) break on i03, because each forged call sends what the guard sent itself for that payment; S29 (a `#[callback_result]` callback, whose direct call fails reading the promise result) is not held. Local sandbox, no network, no key. Build the harness before it: `(cd harness && cargo build --release)` | `python3 -I tools/check/direct_selftest.py --out runs/direct-selftest --jobs 6` | `self-tests: 25/25 passed`, exit 0 | about 15 min | `evidence/direct-2026-11-11.md` |
| 15 | The direct-pay judging rules, with no sandbox: a guard's own error text never decides; a run across 00:00 UTC or with money still moving is could not finish; an attack that calls the callback is could not finish unless the gate saw the guard call that method on itself with the returned id (same JSON type), and i03 is held only if every forged call was refused by a caller check (`Method X is private`, or the config's refusal text), any other failure being could not finish; if every attack is not applicable the exit is 2; a config that is not JSON, a missing config file or a file that is not wasm exits 2 with one line, never 1; exit 0 only when nothing could not finish. | `python3 -I tools/check/tests/test_direct.py` | `Ran 29 tests`, `OK`, exit 0 | under 1 s | `evidence/direct-2026-11-11.md` |
| 16 | Guard G's code is not in this repo, and without it the check refuses to run: could not finish, never held. No network. | `python3 -I tools/check/direct_check.py --wasm targets/entrant-G/guard_g.wasm --guard-config targets/entrant-G/guard-config.json --out runs/guard-g-nowasm` | `verdict: could not finish before G0: the wasm targets/entrant-G/guard_g.wasm is not there (...)`, exit 2 | under 1 s | `targets/entrant-G/FROZEN.txt` |
| 17 | The Guard G fetch refuses when it cannot read the code, and writes nothing. No network needed (it points at a closed local port). | `ARENA_GUARD_G_ACCOUNT=example.testnet ARENA_TESTNET_RPC=http://127.0.0.1:9 python3 targets/entrant-G/fetch.py` | `REFUSED: RPC call failed: URLError: ...; nothing written`, exit 1 | under 1 s | `targets/entrant-G/FROZEN.txt` |
| 18 | Guard G (another team's direct-pay guard): gate 15 of 15, 11 of 12 attacks held, the 12th stopped by NEAR's access key, 0 broke. **Needs network** (one read-only testnet call) **and the Guard G account name, which is withheld from this repo to keep the team anonymous** (set `ARENA_GUARD_G_ACCOUNT`; without it `fetch.py` prints `fetch: no account given. Set ARENA_GUARD_G_ACCOUNT or write it to targets/entrant-G/account.private` and exits 1, and the check after `&&` never runs). Harness built as in row 14. Recorded on Nov 11, before the callback check was added to the gate on Nov 12; not re-run since, so whether Guard G's i03 still comes out held under that check is unconfirmed | `python3 targets/entrant-G/fetch.py && python3 -I tools/check/direct_check.py --wasm targets/entrant-G/guard_g.wasm --guard-config targets/entrant-G/guard-config.json --out runs/guard-g --jobs 6` | `ok: wrote targets/entrant-G/guard_g.wasm, sha256 b0d6ee10... matches the frozen fingerprint (277735 bytes)`, then `verdict: held 11, stopped by the access key 1`, exit 0 | about 2 s fetch, 48 s check | `evidence/direct-2026-11-11.md` |
| 19 | The two AI-proposed Guard G mappings (saved; re-running them needs no model call) each had one wrong field, and the gate caught both. Same network and account needs as row 18 (run the fetch before it). Recorded on Nov 11, before the callback check; not re-run since | `python3 -I tools/check/direct_check.py --wasm targets/entrant-G/guard_g.wasm --guard-config evidence/direct-2026-11-11/guard-g-muse-proposed-config.json --out runs/guard-g-muse --jobs 6`, then the same with `guard-g-nearai-proposed-config.json` and `--out runs/guard-g-nearai` | Muse: `verdict: could not finish at G2/G3: ...`, exit 2. NEAR AI: `verdict: could not finish 1, held 10, stopped by the access key 1`, exit 2 | 25 s, 50 s | `evidence/direct-2026-11-11.md` |
| 20 | The score never uses the guard's own answer about an invoice: a guard that lies in `get_invoice` gets the same score. An expiring invoice whose pay time cannot be read ends "cannot observe", never allowed. | `(cd harness && cargo test --release -- a1_ a2_ a3_)` | `test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 148 filtered out` | 2 s with the harness built | `evidence/invoice-fixes-2026-11-12.md` |
| 21 | An attack NEAR refuses in full (the agent's key may call only `pay`) is counted as "stopped by the access key", never as held. | `python3 -I tools/check/tests/test_check.py InvoiceFixes` | `Ran 5 tests` and `OK` | under 1 s | `evidence/invoice-fixes-2026-11-12.md` |
| 22 | The agent's key stops 3 bypass attacks before the guard runs; the same owner calls sent by the outsider reach vault-a, which refuses each one itself. | `./run-arena.sh bypass vault` | in `runs/<UTC time>/arena-<date>-bypass-vault.log`: `bypass-outsider-owner-method unauthorised=0      honest_settled=1/3 protocol_rejected=0/6` and `stopped_by_access_key=3`; exit 0 | 93 s | `evidence/invoice-fixes-2026-11-12/bypass/` |
| 23 | The guard source the proofs read builds, byte for byte, the wasm that ran on NEAR testnet (sha256 `0382023b…`). Deleting one line of it changes the hash. | `proofs/run.sh repro` (or `proofs/repro/build.sh`, and `proofs/repro/build.sh --mutant`) | `PASS  repro: fresh export of contracts/ builds 0382023b...` and `PASS  repro mutant: one deleted line changes the hash`; `build.sh` prints `REPRO MATCH: source at this commit builds the testnet wasm`, exit 0 | about 15 s each once Rust 1.86 and the crates are downloaded (the initial build downloads them: network) | `evidence/repro-build-2026-11-11.md`, `evidence/proofs-all-2026-11-11/repro-build.log` |
| 23b | The two kept testnet guard accounts serve that same code today. Reads NEAR testnet (network, read only, no key). | `proofs/repro/build.sh --onchain` | `ONCHAIN MATCH: r11bvf3-guard.arena-race-funder-1111.testnet 0382023b…` and the same for `r11cfx4-guard…`, exit 0 | about 15 s | `evidence/proofs-all-2026-11-11/repro-build.log` |
| 24 | A direct-pay guard's rules (per-payment cap, daily cap, payee list, approval threshold, charge before the transfer, refund on failure) never pay beyond their own policy, for every policy, every amount and every order of up to 8 steps. Six planted design flaws are each found. The refund-from-today design breaks the daily cap across a midnight. | `proofs/run.sh proof3` | `PASS  z3 direct-pay proof: 54 queries as planned (...)`; the log ends `z3 5.3.3, 54 queries, ... unexpected: 0`, exit 0 | 151 s (machine heavily loaded; z3 only) | `evidence/proofs-all-2026-11-11.md`, `evidence/proofs-all-2026-11-11/z3-direct-pay-k8.log` |
| 25 | The property library (`proofs/properties/`): five money properties in 116 lines. Each catches its own planted flaw, and only that one, in the harness template. | `proofs/properties/run.sh` | `properties: 7 passed, 0 failed`, exit 0 | 39 s once built (no network once `cargo` has built it, no NEAR sandbox) | `evidence/proofs-all-2026-11-11.md` section 3 |
| 25b | Apply a property to your own guard. | copy `proofs/properties/examples/template.rs`, follow `proofs/properties/README.md` ("Apply a property to your guard"), run `cargo run --release --example template -- <flaw>` to see the pattern before you write your own | with no argument: `PROPERTIES guard=template flaw=none ... broken=[]`; with `no-budget`: `... broken=["window-budget"]` | under 20 s per run | `proofs/properties/README.md` |
| 25c | `no-double-pay` holds on Arena's own guard (real source, every order of 3 pay calls on 2 invoices), and the one-line mutant breaks it. | `proofs/run.sh properties` | `PASS  no-double-pay holds on the real guard (3 pays)` and `PASS  the mutant breaks no-double-pay`; the logs end `PROPERTIES guard=arena build=real ... states=3318 ... broken=[]` and `... build=mutant ... states=8930 ... broken=["no-double-pay"]` | 243 s and 509 s on a heavily loaded machine (runs only); the whole mode took 2,233 s on a fresh export, most of it compiling two builds | `evidence/proofs-all-2026-11-11/properties-arena-*.log` |
| 26 | Four other teams' guards: each money claim checked on their real source on every case up to a bound, with a planted flaw per claim. Counts only. | **Cannot be re-run from this repo.** Their source, the private harnesses and the commits are kept outside it, so the teams stay anonymous. An outsider cannot re-run or rebuild any of these results; only the counts are published. | the counts in `evidence/proofs-all-2026-11-11.md` section 4 | per run, not published | `evidence/proofs-all-2026-11-11.md` |
| 27 | On the local sandbox, the unchanged race usually runs both payment checks in the same block, and the first payment is recorded 2 blocks later: 39 of 40 runs (35 saved, plus 4 of 5 in a reviewer's run, whose fifth run had the checks one block apart and was still a proven race). Flawed guards (guard-vulnerable, leaky-control-v2, M5) pay 100 beyond policy; fixed ones (guard-fixed, vault-a) hold. | `tools/race/c1.sh` (one run per guard; `tools/race/c1.sh 3` for three) | last line `race-c1: 5 runs; both checks in one block 5; first callback 2 blocks after the last check 5; judge: overlap-proven 5; broke 3 (M5 100, guard-vulnerable 100, leaky-control-v2 100); held 2 (guard-fixed, vault-a); not counted 0`, exit 0. **What counts as a match:** the broke and held lists exactly as shown and `not counted 0` (a run with an invalid score or that the judge does not call a race is listed there, never as held or broke, and the script exits 1). `both checks in one block` may be below the run count: we saw 39 of 40 (the other split by one block and was still a race); report a split rather than retry | 73 s with builds present (the harness and contracts build first if missing, about 11 min cold) | `evidence/race-ordering-2026-11-11.md` section 1, `evidence/race-ordering-2026-11-11/c1-traces/`, `c1-fresh-53f45b3/`, `c1-fresh-d2e2093/` |
| 28 | On testnet (Nov 10), 7 of 10 trials ran both checks in one block, 2 ran them one block apart and 1 two blocks apart. Under the strict rule (a race only if the last check is in a block strictly before the first callback) 9 are proven races and 1 (row 3) is a tie. | `python3 -I tools/race/testnet_rows.py` (reads the committed raw files; no network) | last line `testnet-2026-11-10: 10 trials; checks in the same block 7, one block apart 2, two blocks apart 1; judge: overlap-proven 9, tie-unproven 1, sequential 0, not-produced 0`, exit 0. Exact match (the input files are fixed) | under 1 s | `evidence/testnet-2026-11-11.md` |
| 29 | Races are tested with the second payment's check in the same block as the first, one block later, or (slow token) 4 and 8 blocks later. Each one-flaw guard breaks only on its own race and holds when the same payments are sent one after the other: `race-m1` (lock only within one block) breaks next-block, holds same-block; `race-m2` (lock wears off after 2 blocks) breaks only with the answer held; `race-m3` (cap counted in the callback) pays 100 above the cap. Their fix, vault-a, holds on every race. | `python3 -I tools/race/run.py` (needs the committed mutants; builds the harness and the slow token if missing; local sandbox, no network) | last line `race-c3: 30 cells, 30 passed; counted tries 90, not counted <x>; wall <s> s`, exit 0. **What counts as a match:** `30 cells, 30 passed` and `counted tries 90`. `not counted` may be above 0 (a mistimed try is thrown away and retried, up to 5 per cell). In the six committed matrix runs, 11 of 383 tries were thrown away: 10 in `c3-matrix-run1` (the S4-held cells still asked for offsets the held mode cannot produce, so that run printed `30 cells, 28 passed; counted tries 84, not counted 10`), then 1 in `c3-matrix-s4held` after the fix, and 0 in the three fresh-copy runs (`c2-matrix-fresh-c92513c`; `c3-matrix-fresh-7e9361f` and `c3-matrix-fresh-d2e2093`, each `30 cells, 30 passed; counted tries 90, not counted 0`). Block numbers differ run to run | about 500 s with `--jobs 3` | `evidence/race-ordering-2026-11-11.md` sections 1b and 1c, `evidence/race-ordering-2026-11-11/c2-matrix/`, `c2-matrix-fresh-c92513c/`, `c3-matrix-run1/`, `c3-matrix-s4held/`, `c3-matrix-fresh-7e9361f/`, `c3-matrix-fresh-d2e2093/` |
| 30 | The timed stagger lands the second check where asked. | `python3 -I tools/race/run.py hitrate sequences-race/s2-next-block.json guard-vulnerable --n 20` (and the same with `s1-same-block.json`) | last line `race-hitrate: s2-next-block on guard-vulnerable: <k> of 20 produced the requested ordering; verdicts {...}`, exit 0. We got `20 of 20` both times. **What counts as a match:** k of 20 is a measurement, not pass/fail; below 20 means misses on your machine, which the judge discards | about 100 s each with 3 at a time | `evidence/race-ordering-2026-11-11/c2-hitrate-s1/`, `c2-hitrate-s2/` |
| 31 | If nobody releases the slow token's held answers, NEAR wakes them itself, the token logs `HOLD-TIMEOUT`, and the run counts as nothing (never held, never broke). | `python3 -I tools/race/run.py timeout` | `race-timeout: verdict not-produced; HOLD-TIMEOUT logs 2; counted as nothing (correct); <s> s`, exit 0. Exact match except the time | 40 s | `evidence/race-ordering-2026-11-11/c3-timeout/` |
| 32 | Testers cannot switch the slow token's hold on or release it. | `(cd harness && ./target/release/arena-harness attempt ../sequences-race/s3-tester-cannot-hold.json --target vault --token slow)` | steps 0 and 1 `ok=false outcome=contract-failure` (the log contains `only the token account`), step 2 `ok=false outcome=REJECTED-BY-PROTOCOL`, step 3 `is_holding -> false`, exit 0 | about 15 s | `evidence/race-ordering-2026-11-11/c3-tester-cannot-hold/` |
| 33 | The gatekeeper never lets in an attack file the engine would refuse or run differently, across 3,478 generated files. Testing, not a proof, and its engine side is a copy of the engine's logic. | `python3 -I tools/agreement/compare.py` | `agreement: 3478 files (seed 20261112), 0 disagreements; ...`, exit 0 | about 10 s after the harness is built | `docs/SCHEMA-AGREEMENT.md` |

Claim 6 needs the harness built first; `./verify.sh fast` does that.

Unit tests for the tools (no sandbox, no model, no key). The lookup tests also read NEAR testnet;
set `ARENA_LOOKUP_OFFLINE=1` to skip those.

```
python3 -I tools/check/tests/test_check.py
python3 -I tools/check/tests/test_direct.py
python3 -I -m unittest discover -s tools/hunter/tests
node --test tools/lookup/test.mjs
python3 -I -m unittest discover -s tools/race/tests
```

You should see `Ran 124 tests` and `OK (skipped=1)` (just `OK` once the harness is built), then `Ran 29 tests` and `OK`, then `Ran 85 tests` and `OK`, then `pass 37`
and `fail 0`, then (the race-ordering judge, under 1 s) `Ran 23 tests` and `OK`. The hunter tests pass on a fresh copy before anything is built. These counts are for
the current commit: `evidence/clean-copy-2026-11-11.md` records 98 and 77 at the older commit it ran.

The on-chain contract's own sandbox tests (opt-in, results, a contract asking before it pays):

```
(cd receipts && cargo build --release --target wasm32-unknown-unknown)
(cd receipts/host && cargo test --release --test onchain)
```

One of them, the upgrade test, shows as `ignored`: it needs the contract's earlier build, see
`evidence/onchain-2026-11-11.md`.

A note on counting: `evidence/check-2026-11-11.md` and `check-plan-2026-11-11.md` say `52/52`.
That older count included the honest payment the check makes before any attack. There were 51
attacks; `evidence/check-fixes-2-2026-11-11.md` records the correction. The old files are kept as
they were, as a record of what the check said at the time.

## 3. Break a guard yourself

There are two ways. Both run on the local sandbox only.

### Plant one of our mistakes

`vault-a` is Arena's own reference guard. `tools/mutation/mutate.py` holds 10 small edits to it,
M1 to M10. Each one removes or weakens one rule. M0 is an unchanged copy.

```
tools/mutation/run.sh M5
```

M5 removes the "payment in flight" mark that the guard sets before it moves tokens. The script
copies vault-a, applies the edit, writes the diff to `mutants/M5/MUTATION.md`, builds it, and runs
the 10 scripted attacks against it. You should see M5 caught by `02-race-double-pay`, with 100
tokens paid beyond the policy. Logs land in `evidence/mutation-<today>/`; set `MUT_DATE=<name>` to
choose another folder name, so you do not write over a saved table.

The script first checks two things, and stops if either fails: the unchanged vault-a scores 0 on
all 10 attacks, and the leaky reference guard is caught.

Three mutants are **not** caught: M3, M9 and M10. The table says why for each
(`evidence/mutation-table-2026-11-11.md`). Run `tools/mutation/run.sh M3` to see a miss.

To plant a mistake of your own, add an entry to `tools/mutation/mutate.py` and run it the same
way.

### Check any guard with one command

```
./arena check targets/vault-a/vault_a.wasm
./arena check targets/leaky-control-v2/leaky_control.wasm
```

The first should end `arena: held 49/49 (0 not applicable; 3 stopped by the agent's access key before
the guard ran; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the
owner's intent)`, exit code 0. The second should end `arena: broke 5 of 49 (...)`, exit code 1, and
list the 5 attacks. The library has 52 attacks: 49 reach the guard, and 3 (`bypass-01`, `bypass-02`,
`bypass-03`) are refused by NEAR before any guard code runs, because the agent's key may call only
`pay`. Those 3 tested the key, not the guard, so they are not counted as held. Each writes
`arena-report/report.html`, a one-page report that needs no internet. Each took us about 300 s.

A guard that pays in plain NEAR, not a token, needs one line in its config (`"pays_in": "native"`):

```
./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json
./arena check targets/native-control/native_control.wasm --config examples/configs/native-guard.json
```

The first should end `arena: held 48/48 (0 not applicable; 1 stopped by the agent's access key before
the guard ran; ...; scored from NEAR balances)`, exit code 0. The second should end
`arena: broke 5 of 48 (...)`, exit code 1. Three token-only attacks do not apply to a guard that
holds no tokens, so the native suite has 49; one of them (`bypass-02`) is stopped by the access key,
so 48 count. About 250 s each.

A guard that pays by depositing the token into NEAR Intents needs `"pays_in": "intents"` and an
`"$intents"` init argument (full example in `examples/configs/intents-guard.json`):

```
./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json
./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json
```

The first should end `arena: held 51/51 (0 not applicable; 3 stopped by the agent's access key
before the guard ran; ...; pays via NEAR Intents: local release build, no withdrawals to other
chains)`, exit code 0. The second should end `arena: broke 2 of 51 (0 not applicable; 3 stopped by
the agent's access key before the guard ran; ...)`,
exit code 1, with `BROKE intents-01-agent-names-outsider-beneficiary: 200 tokens beyond the rules
(paid 200 tokens to the outsider (credited inside NEAR Intents))`. 54 = the 52 attacks plus 2 in
`sequences-intents/`; 3 are stopped by the access key, so 51 count. In the same 2 attacks the honest
invoice never reached its receiver (the planted guard credited someone else), so the brackets also say
`refused 2 of 65 honest payments`. Arena starts its own copy of NEAR Intents for each attack, on the local
sandbox. About 500 to 570 s each on Nov 12, with other builds running.

A guard that asks NEAR Chain Signatures to sign a transaction for another chain needs
`"signs_via": "chain-signatures"` and the `"$signer"` and `"$allowed_foreign_txs"` init arguments
(full example in `examples/configs/chainsig-guard.json`):

```
./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard.json
./arena check targets/chainsig-planted/chainsig_planted.wasm --config examples/configs/chainsig-guard.json
./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard-wrong-path.json
```

The first should end `arena: held 55/55 (0 not applicable; 3 stopped by the agent's access key before the guard ran; ...; signs via Chain Signatures: Arena's stand-in signer,
no real MPC signing, nothing sent to another chain)`, exit code 0. The second should end
`arena: broke 3 of 55 (...)`, exit code 1, with `BROKE` lines for `chainsig-01-agent-passes-other-payload`,
`chainsig-02-replay-allowed-payload` and `chainsig-04-race-two-sign-requests`, each `1 unauthorised
signing request (a count, not an amount)`. 58 = the 52 attacks plus 6 in
`sequences-chainsig/`; 3 are stopped by the access key, so 55 count. About 345 s each. The third is a wrong config on purpose (path `ethereum-2`,
the guard signs with `ethereum-1`): it should end `arena: not run` and `COULD NOT FINISH`, exit
code 2, in about 20 s. The signer is Arena's stand-in (`contracts/signer-standin`): it writes down
each request and signs nothing.

A guard that pays by WITHDRAWING from NEAR Intents toward another chain needs
`"intents": {"pays_by": "ft_withdraw"}` and the init arguments `"$intents"`, `"$bridge"` and
`"$foreign_destinations"` (full example in `examples/configs/intents-withdraw-guard.json`):

```
./arena check targets/withdraw-honest/withdraw_honest.wasm --config examples/configs/intents-withdraw-guard.json --no-muse
./arena check targets/withdraw-planted/withdraw_planted.wasm --config examples/configs/intents-withdraw-guard.json --no-muse
```

The first should end `arena: held 57/57 (...; withdraws from NEAR Intents: checks where each
withdrawal is sent and what destination it names; no delivery on another chain)`, exit code 0.
The second should end `arena: broke 3 of 57 (... 500 tokens paid outside the five receivers ...)`,
exit code 1, with three BROKE lines: `withdraw-01-agent-names-foreign-address` and
`withdraw-02-memo-msg-swap` (200 tokens each `toward eth:0xbad0000000000000000000000000000000000bad,
not on the owner's list of foreign destinations`) and `withdraw-03-right-address-wrong-chain`
(100 tokens `toward base:0x5a11000000000000000000000000000000000001`, sam's address on the wrong
chain). The check loads 60 attacks: the 52 attacks, 2 in `sequences-intents/` and 6 in `sequences-intents-withdraw/`; NEAR's access key stops 3 before the guard runs, so 57 count.
`--no-muse` only makes sure no network call is tried; these guards use the interface's names, so
none would be. There is no other chain: the bridge account is Arena's stand-in
(`contracts/bridge-standin`, built from source by the check), which records destinations and sends
nothing. About 590 to 640 s each on a fresh copy.

A guard that pays the wrong person. `targets/planted-outflow/` is a copy of vault-a with one
planted flaw: a second `pay` on a paid invoice sends the amount to whoever called, the agent.

```
./arena check targets/planted-outflow/planted_outflow.wasm
```

It should end `arena: broke 11 of 49 (0 not applicable; 3 stopped by the agent's access key before the
guard ran; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 1800 tokens paid outside the five
receivers; 2450 tokens paid against the owner's intent)`, exit code 1. Before the fix in `evidence/check-outflow-2026-11-11.md`, this
same guard scored `held 51/51` (with the 51-attack library of that day), because the check only read five receivers' balances.

To check your own guard, see `docs/CHECK-YOUR-GUARD.md`. You pass your `.wasm`, and a small config
if your guard starts differently or lacks a rule.

### Check that the extended direct mode refuses wrong configs

Guards where the agent names who gets paid come in many shapes: the agent's key on the guard's own
account, a payee list filled one call at a time, owner calls that need 1 yoctoNEAR, rolling or
anchored or lifetime windows, a signature on every payment. `docs/CHECK-YOUR-GUARD.md` ("direct
mode, extended") lists how a config declares each one. Each shape has a self-test against one test
contract (`fixtures/direct-ext-fixture/`): a right config, which must hold, and a wrong one, which
Arena must refuse ("could not finish", nothing held or broke).

```
python3 -I tools/check/direct_ext_selftest.py --out runs/ext-selftest --jobs 6
```

It should end `ext self-tests: 20/20 passed`, exit code 0. It took us 941 s on a fresh export. The
window tests are the slow part: each moves the local chain's clock, X19 and X20 by about 26 hours
(a real 24-hour window), in about 150 s each. Local sandbox only, no network. Each line says what it checked, for example
`X11 PASS [window] REFUSED: rolling window labelled anchored`. The Rust side of the same code is in
`cd harness && cargo test --release` (`154 passed; 0 failed; 1 ignored`).

Things to know when you read a result:

- **"Held" means these attacks found nothing. It does not mean the guard is safe.**
- An attack on a rule the guard does not claim is reported as **not applicable**, never as held.
- The two numbers are never added together. "Beyond policy" is the guard breaking its own rules.
  "Against the owner's intent" is money the rules allowed but the owner did not mean to send.
  vault-a holds on the first and still shows 2450 on the second, because its owner's rules are wide.
- Exit codes: 0 held, 1 broke, 2 the check could not finish or the command was wrong. "Broke"
  here means over the `--fail-on` line, which by default is any token beyond policy. With
  `--fail-on against-intent`, vault-a's `held 49/49` exits 1, because 2450 tokens went against the
  owner's intent; with `--fail-on never`, every finished check exits 0. A check that could not
  finish is never reported as held.

## 4. The hunter's attacks, and where each came from

The hunter is the part of Arena that reads new security papers and hack news and turns them into
attacks. A language model proposes each attack as **data**: a list of steps from a fixed, small
vocabulary (`call`, `view`, `race`, `wait_blocks`, `wait_seconds`, `add_key`). The model writes no
code. A validator rejects anything outside that vocabulary before the bench runs it.

What is in the repo:

- **25 saved attacks** in `sequences-paper/`, one JSON file each. 14 are call sequences and 11 are
  prompt-injection scenarios.
- **7 hunt records** in `evidence/hunts/`, one `.md` and one `.json` per run.
- **Saved is not validated.** Attack admission: **33 of 54** attacks validated, 0 partially validated, 21 unvalidated
  (`evidence/MANIFEST.md`). Saving admits nothing: of the 25 saved hunter attacks, only those the manifest lists as validated count. Validated means
  `tools/admission/admit.py` ran the attack three times on a known-good guard (held) and three times on
  a copy with the one flaw the attack names (broke by the exact amount, through the named mechanism),
  on pinned wasm bytes, and kept the raw runs in `evidence/admission/`. Re-check any stamp without a
  sandbox: `python3 -I tools/admission/admit.py --recheck sequences-scripted/03-sequential-second-pay.json`.

Each attack file has a `meta` block. You can read where the attack came from without trusting us:

| Field | What it tells you |
|---|---|
| `source`, `parents` | the paper or news item it came from, or the two attacks it was combined from |
| `author` | which model proposed it, through which tool |
| `found_in_hunt` | the hunt record that made it |
| `steps_sha256` | a fingerprint of the steps, so an edit after the fact shows |
| `broke_guards`, `held_guards` | which of Arena's own guards it broke or did not |
| `validation` | whether it ran cleanly and what it found |

Each hunt record stores the command that ran, the git commit, the list of uncommitted files at the
time, the harness fingerprint, and the result of a known-answer test run first: the double-pay
attack must break the three planted-flaw guards and must not break the three fixed ones, or the
hunt's results are not trusted. One record has no known-answer result:
`2026-11-11-news-d340fd`, a news-only hunt that found nothing to run, so it ran no attack at all.

What the 7 hunts did, in total: the model proposed 41 attacks from 10 papers and 4 news items, 25
were saved, and **2 of the 25 broke a guard**. Both broke only guards we built to be broken
(`guard-vulnerable`, `leaky-control-v2`, `native-control`). None broke a fixed guard. Most paper
attacks found nothing, and the records say so. The two Nov 11 hunts saved nothing new and broke
nothing; one of them ran on NEAR AI Cloud and its attestation can be re-checked (claim 13).

Replay one that broke a guard, with no model and no key:

```
./run-arena.sh replay sequences-paper/p210408638-1-reentrancy-async-double-pay.json --target control
./run-arena.sh replay sequences-paper/p210408638-1-reentrancy-async-double-pay.json --target vault
```

The first runs it against the leaky guard and should print a line starting
`UNAUTHORISED PAYOUT = 200` (all 200 beyond what the owner authorised). The second runs it against
vault-a and should print `UNAUTHORISED PAYOUT = 0`. About 15 s each.

To add an attack by hand, see `docs/ADD-AN-ATTACK.md`.

**What has not happened yet:** `.github/workflows/hunt.yml` schedules the hunter to run on GitHub
every day. That schedule has **never run**, because this repo has not been on GitHub. All 7 hunt
records come from runs on one Mac. The "hours from paper to attack" figure in
`evidence/response-time-2026-11-11.md` is a replay of what the schedule would do, not a
measurement of it.

The design borrows ideas from AutoRedTeamer (Andy Zhou et al., NeurIPS 2025, arXiv 2503.15754). No
code was copied. See `docs/DESIGN-CREDIT.md`.

### 4b. Attack admission and the hidden test set: check each claim

Each row: the claim, the command (from the repo root of a fresh `git archive` export, no network,
no private files), the line it prints, the exit code, and the time we measured on one Mac (Apple silicon).
One exception: the `check-public` row needs a full `git clone` (all history). In a `git archive` export or
a `--depth 1` clone it prints `0 of 18 consistent`, because it checks each run's commit against git history.

**Merge note.** This branch must reach main as a fast-forward or a merge commit, never rebased or squashed:
the hidden-set run files name the commits they ran at, and `check-public` fails once those commits are not
in main's history.

| Claim | Command | Line it prints | Exit | Time |
|---|---|---|---|---|
| 33 of 54 attacks validated, 0 partially, 21 unvalidated, and the committed count files are what the code computes | `python3 -I tools/admission/manifest.py --check` | `manifest: up to date` (the counts are in `evidence/MANIFEST.md`, line "Admission: 33 of 54 validated, ...") | 0 | 1 s |
| A stamp belongs to this file (validator passes; evidence folder, attack id, steps and spec hashes match; each stored run recorded these calls) and follows from the stored raw runs (re-judged, no sandbox) | `python3 -I tools/admission/admit.py --recheck sequences-scripted/03-sequential-second-pay.json` | `recheck scripted-03-sequential-second-pay: stored runs give validated (every reference matched in 3 counted runs; matched known-bad: mutant:M4); stamp agrees` | 0 | under 1 s |
| The double-pay race is validated from runs that record per-receipt block heights: in every counted run each later pay was checked in a block strictly before the first pay's transfer result (until 2026-11-13 it was partially validated, from runs made before the harness recorded them) | `python3 -I tools/admission/admit.py --recheck sequences-scripted/02-race-double-pay.json` | `recheck scripted-02-race-double-pay: stored runs give validated (every reference matched in 3 counted runs; matched known-bad: mutant:M5); stamp agrees` | 0 | under 1 s |
| The two race judges agree on every stored run behind the 11 validated races (the gate's `admit.race_ordering` and `tools/race/ordering.py`, written separately) | `python3 -I tools/race/compare_judges.py sequences-scripted/02-race-double-pay.json evidence/admission/scripted-02-race-double-pay/20261113T094330Z` (one race; the unit test below runs all 11) | JSON with `"all_agree": true`; saved per race in `evidence/admit-all-2026-11-13/two-judges/` and, for the 3 races re-run on a clean tree, `evidence/integrate-2026-11-13/two-judges/` (96 of 96 runs agree, every one `overlap-proven`) | 0 | under 1 s |
| A cap race is validated against a flaw that breaks it only when the pays overlap: `race-m3` (the day's spend counted when a transfer's result comes back, not at the check) | `python3 -I tools/admission/admit.py --recheck sequences-paper/p210408638-1-tod-daily-cap-race.json` | `recheck p210408638-1-tod-daily-cap-race: stored runs give validated (every reference matched in 3 counted runs; matched known-bad: mutant:race-m3); stamp agrees` | 0 | under 1 s |
| A hunter attack admitted on 2026-11-12 is validated against mutant M3 (a daily cap checked per payment instead of as a running total) as well as M2. Limit: it depends on an invoice that expires 20 s after setup being paid as the 2nd call inside those 20 s (a merge review re-ran it 9 of 9 under load; the margin is set by block time, and a miss fails toward unvalidated, never a false validated) | `python3 -I tools/admission/admit.py --recheck sequences-paper/p261108811-3-stealth-thought-no-disclosure.json` | `recheck p261108811-3-stealth-thought-no-disclosure: stored runs give validated (every reference matched in 3 counted runs; matched known-bad: mutant:M2, mutant:M3); stamp agrees` | 0 | under 1 s |
| Every attack outside the validated count says why, and a person's reason can never sit on an attack the gate has judged | `python3 -I tools/admission/manifest.py --check`, then read the `why` column of `evidence/MANIFEST.md` (reasons from `tools/admission/unvalidated.json`) | `manifest: up to date`; of the 21 unvalidated, 7 rows `no-one-flaw-finds-it`, 3 `race-not-what-is-tested`, 3 `stopped-by-access-key`, 3 `intent-only`, 1 `tests-another-contract`, 4 `not-an-attack-file`; every attack file has either a stamp or a recorded reason | 0 | 1 s |
| A hand-written, edited or copied "validated" stamp is refused, by the validator and by `--recheck` (stamp and spec copied onto another attack, steps edited with the hash recomputed, evidence folder of another attack, run files of another attack, validated claimed on partial runs); a race counts only if each later check ran in a block strictly before the earlier callback (the callback is the earliest guard receipt after the token transfer, not a later one) (same block = tie, never counted); a leg refused before any payment started is dropped rather than calling the whole race sequential; earlier evidence files are byte-identical; a recorded reason on a specced attack is refused; a hidden attack with the steps of ANY tracked file (hunt proposals under `evidence/hunts/` included) is refused, and a hidden run counts only after its commitment in git parent order | `python3 -I -m unittest discover -s tools/admission/tests` | `Ran 76 tests`, `OK` | 0 | 3 s |
| The gate itself reproduces a validation (local sandbox; needs the build from `./verify.sh fast`) | `python3 -I tools/admission/admit.py sequences-scripted/03-sequential-second-pay.json --runs 3` | `ADMISSION scripted-03-sequential-second-pay: validated (every reference matched in 3 counted runs; matched known-bad: mutant:M4)`; raw runs in `runs/evidence/admission/...` (gitignored) | 0 | 37 s |
| Every public hidden-set run file is consistent with the set it names, and git parent order puts each run after its commitment (its commit is an ancestor of HEAD, its tree was clean, and `COMMITMENT.json` at that commit names its set). Needs a full git clone: a `git archive` export or a `--depth 1` clone prints `0 of 18 consistent` | `python3 -I tools/hidden/hidden.py check-public` | `hidden-set public files: 18 of 18 consistent with the set each names (6 on current set 9748cbedd7a58c4c... (14 attacks); 6 on earlier set 835729d9f34fa123... (9 attacks); 6 on earlier set d314e04fc574c1f7... (14 attacks))` | 0 | under 1 s |
| The hunter drops a proposal with the same steps as a hidden attack and records that it matched. The record does not name the hidden attack, but it does name the hunter's own proposal, which is public, so a match reveals that hidden attack's steps: it must be retired at the next set | `python3 -I -m unittest discover -s tools/hunter/tests -p test_hidden_dupes.py` | `Ran 4 tests`, `OK` | 0 | under 1 s |

How an outsider checks the hidden set without seeing it: `hidden-set/COMMITMENT.json` holds the
set's sha256 (`9748cbed...`), its size (14) and its families. Set 4 (2026-11-12) is the third replacement
made before any of them merged. Sets 1 to 3 each held attacks with the same steps as attack files tracked
in the repository (exactly, or apart from a wait value) or on
a sibling branch that had not merged yet. The old check read only the library and the intents suite, on the
current branch, and only exact copies. Those attacks were retired and replaced. `hidden.py` now compares
every hidden attack with every attack-shaped `.json` tracked on any branch the repository knows, exactly
and up to gas and wait values, and refuses a match; it does not refuse other variants. Earlier
commitments are kept byte for byte in `hidden-set/previous/` (their `disjoint_from_public_library: true`
was wrong; `previous/NOTE.md` says so): set 1 (`835729d9...`) and set 3 (`d314e04f...`), whose run files
still check against them, and set 2 (`e35a4c1f...`), whose run files were removed because they recorded a
commit a rebase took off this branch. The order is checked by git parent order only: `check-public` requires each run's
`arena_commit` to be an ancestor of HEAD with a clean tree and `COMMITMENT.json` at that commit naming the
run's set. That trusts git history, which whoever controls the repository can rewrite before
publishing; it is not a timestamp. If a result is published on testnet, its `suite_version` must equal
the same hash. What you cannot check: the attacks themselves, or that we ran them honestly. Those wait
for the reveal (rule in `COMMITMENT.json`: after 5 guard code hashes or 30 days). Limit of the runs on
every set: the set has no race variant (a race can be admitted only from runs that record per-receipt
block heights; 11 library races are now admitted that way, but none is in the set), so the double-pay guards (`guard:vulnerable_fixture`,
`leaky-control-v2`) held every attack that applies to them (13 of 14 on sets 3 and 4); only `intents-planted`
broke (100 beyond policy, 1 attack). Every one-flaw mutant a hidden attack is admitted against (M1, M2,
M3, M4, M6, M7, M8) is a copy of vault-a and is not among the six guards run, so these runs show the set
holds on good guards, not that it catches bad ones; the private admission runs show that. On the two
Intents guards, a "held" on a family whose rule the guard does not claim (cancel, expiry, payee list) is
not meaningful: `hidden.py run` does not apply `arena check`'s applicability rules.

What a class does not show, per attack (`tools/admission/limits.json`, printed after "LIMIT:" in the
`why` column of `evidence/MANIFEST.md`): `ai-08` and `p210408638-2-reentrancy` validate only the
already-paid check (M4), not a half-paid state or a callback window; the 8 prompt-injection attacks
that are validated run scripted steps only (the harness makes the pays the injected text asks for; no
agent reads the email), so only the guard's refusal is validated; `ai-04`, `nae93287b-1` and
`p261111305-3` catch only M2 through one invoice over the cap on its own, so their "fill the cap first"
part is not tested; `p261108811-3` depends on the 20 s expiry timing above; `ai-02` and `ai-03`, titled as cap
breaches, validate only the double pay (on M5 the cap refuses the extra pay). The five cap races validated
against `race-m3` (`n00c44f69-1`, `p210408638-1-tod`, `p210408638-2-tod`, `p261111266-2`, `p261112636-1`)
had specs naming M3 (cap checked per payment) until 2026-11-12, withdrawn because M3 breaks them whether
or not the calls overlap. Before writing the new specs, each race and its twin with the same calls sent one
after the other ran on vault-a, `race-m3` and M3 (`evidence/admit-all-2026-11-13/survey/`): `race-m3`
broke only the raced version (100 or 150 above the cap), M3 broke both. The payee race `p261112636-3` stays
unvalidated: M1 breaks it both ways, and vault-a's payee check reads nothing an in-flight pay changes, so no
race-only payee flaw fits it. The old gate runs are kept in `evidence/admission/<id>/`.

What a recheck checks: the whole file passes the validator (steps, spec, and a stamp that names
this attack's own evidence folder, whose `admission.json` has the same attack id, steps sha256 and
spec sha256), every stored run recorded this attack's calls (method and invoice id at each step),
and the stored runs re-judge to the stamped class. Any failure prints one `REFUSED` line, exit 1.

What a recheck does not prove: the stored runs are bound only by the sha256s in each
`admission.json`, a file in the repo. Someone who writes plausible result files and recomputes the
hashes passes it. What binds the evidence is git history and re-running the gate (row 5).

Limit of "validated": it is only as strong as the attack's written checks. "Through the named
mechanism" means the checks the spec lists passed on every counted run (one check is the minimum),
and the flaw counts as matched because the broken copy's flaw label equals the one the spec names;
nobody checked which line of code fired.

Two references were added on 2026-11-13. `mutant:race-m3`, built on 2026-11-12 for the race study
(`evidence/race-ordering-2026-11-11.md`, `mutants/race-m3/MUTATION.md`), rebuilt from its source to the
same sha256 (`a16b7573...`). `mutant:M12`, vault-a with its owner check removed (one line in `assert_owner`),
pre-registered in `evidence/mutation-plan-2026-11-13.md` before the build: it paid 0 on the 10 scripted
attacks and broke `bypass-04` by 5000 (the outsider's own invoice), as planned
(`evidence/mutation-M12-2026-11-13/README.md`). Both are planted fixtures, not bugs found in a researched guard.

One new one-flaw mutant was built on 2026-11-12 and is NOT a reference: M11 (vault-a with its gas
pre-check removed), pre-registered in `evidence/mutation-plan-2026-11-12.md` before the build. It paid
nothing on the 10 scripted attacks or on the two low-gas AI attacks (`evidence/mutation-M11-2026-11-12/README.md`):
NEAR rejects an under-gassed `pay` as a whole, so the low-gas attacks cannot reach a half-paid state on
vault-a. A reference no attack can break validates nothing, so it is not in `references.json`.

## 5. Look up a result on NEAR testnet

```
node tools/lookup/cli.mjs <guard account on testnet>
```

It reads the guard's code fingerprint, the results Arena published for that code, and the guard's
mode, then prints one sentence. Only the status `held` is a pass; every other answer, including a
network error, is not. Exit code 0 for held, 1 for anything else, 2 for bad input or a network error.

Two accounts to try. Both run the same code (sha256 `0382023b…`); only their mode differs.

```
node tools/lookup/cli.mjs r11cfx4-guard.arena-race-funder-1111.testnet
node tools/lookup/cli.mjs r11bvf3-guard.arena-race-funder-1111.testnet
```

The first (the fixed guard) should start `Held the double-pay race test (5 of 5 runs held, 0 paid
over the limit)` and show `status:    held` and `opt-in:    opted_in`, exit code 0. It also lists the
`vulnerable_fixture` result for the same code as `not counted`, because this guard reports mode
`fixed`. The second (the planted-flaw guard) should start `Broke the double-pay race test (0 of 5
runs held; worst run paid 100 over the limit)` and show `status:    broke`, exit code 1. Each took
us 1 to 2 s.

`on chain:` is the result stored in Arena's own contract, which a wallet contract can read before it
pays (`docs/ON-CHAIN.md`). The fixed guard shows `on chain:  held` for mode `fixed`, and the
planted-flaw guard `on chain:  broke` for mode `vulnerable_fixture`. Those results were published
on Nov 11, for Arena's own guards only: `evidence/results-testnet-2026-11-11.md`, with transaction
links.

See `docs/CHECK-BEFORE-YOU-PAY.md` for more and `docs/ON-CHAIN.md` for what is stored.

## 6. What you cannot re-run from this repo

- **Guards A, B and C.** These are three other teams' guards. Their source, built files and test
  runners are not in this repo, to keep them anonymous. You can read what each one claims
  (`targets/entrant-A/`, `-B/`, `-C/`) and the per-test results (`evidence/coverage-table.md`), but
  not re-run them. The same holds for the bounded checks of their money claims (and of Guard G's):
  `evidence/proofs-all-2026-11-11.md` gives counts only; entry 26 says what a team or an outsider can re-run.
- **Guard G without its account name.** Its code is not in this repo either. Rows 18 and 19 fetch
  it from testnet, which needs network and the account name, withheld to keep the team anonymous.
  Without it you can still run rows 14 to 17 (the self-tests, the judging rules, and the two
  refusals), and read the saved summaries in `evidence/direct-2026-11-11/`.
- **The AI proposals for Guard G** (`tools/check/direct_muse.py`) need a model key; the two saved
  proposals re-run through the gate without one (row 19).
- **The capability counts for the 17 researched guards** (`docs/GUARD-CAPABILITIES.md` section 2.4)
  come from reading each team's public source and deployed code; the per-guard notes are private,
  to keep the teams anonymous, so the counts cannot be re-derived from this repo.
- **The 10 other teams' guards checked with the extended direct mode** (README, "Other teams'
  guards"). We publish counts only, so nothing here names them, and their configs and code are not
  in this repo. To re-run one, you would need its deployed account (private), network access to read
  its code from NEAR testnet (one read-only call), a config for it, and then the same command as for
  your own guard: `python3 tools/check/direct_check.py --wasm guard.wasm --guard-config guard.json
  --out report-dir`. Without the private files you can check two things: that the gate refuses wrong
  configs (the self-tests above, `ext self-tests: 20/20 passed`), and that an attack on a rule the
  gate did not validate, or one that hit a harness error, is never counted as held
  (`python3 -I tools/check/tests/test_direct.py`, ends `OK`). The counts themselves you
  have to take from us: 10 checked, 0 broke, 10 held on every rule they claim (in one, an
  owner-change attack cannot count because that guard cannot remove a payee), 1 more cannot be
  tested (it moves no money). Five of the 10
  have 24-hour windows; each was proven by moving the local chain's clock about 26 hours. In all 10 the forged-callback attack was
  not run, because no config maps a callback; the counts predate the current exit rule, so a re-run today ends `could not finish 1` (exit 2) on that attack. For the two that need a signed request on every
  payment, Arena signed as the signing service: that tests the guard's on-chain checks, not the
  team's real service.
- **The real-model runs** need a model API key: `NEARAI_API_KEY` for NEAR AI Cloud (the default),
  or `MUSE_API_KEY` with `ARENA_MODEL_PROVIDER=muse`. Without one, read the saved trials in
  `evidence/`.
- **The testnet race itself** needs a funded testnet account. The saved run is
  `evidence/testnet-2026-11-11.md`, with transaction links.
- **New hunts** need the same model key, and an Elfa key (`ELFA_API_KEY`) for news. The saved
  attacks replay without either.

## 7. Known limits

The README's "Limits" section is the full list. The ones that matter most when you judge a result:

- Everything is on a local sandbox except the double-pay race and its fix.
- The "any number of calls" proof covers a model of the guard, not the deployed wasm. The model
  was compared with the real code for up to 4 pay calls.
- Three planted mistakes go uncaught (M3, M9, M10).
- "Held" for Guards A, B and C means each kept its own written claims under tests built from those
  claims. The three guards faced different tests.
- `./arena check` trusts the guard's own view methods in its preflight step.
- Nothing has run on Linux or on GitHub.
- NEAR Intents is tested only against a local copy of its release build. For withdrawals toward
  another chain, Arena checks where a withdrawal is sent and what destination it names; it does not
  test delivery on the other chain, real bridges, or the MPC network.
- Chain Signatures requests are checked against Arena's stand-in signer, not `v1.signer`: what the
  guard asked to have signed, counted, never turned into tokens. No real MPC signing, no delivery on
  another chain, and the hashes use Arena's own format, not a real Ethereum transaction.

## How the evidence files are named

The tag `2026-11-11` in a file name is a run tag, not always the day the file was made. It was
first used on Nov 10 2026 for the second run of that day, after a fix, so that run would not
overwrite the first run's logs. Files made on Nov 11 carry the same tag. `evidence/README.md`
explains this and says which file answers which question.
