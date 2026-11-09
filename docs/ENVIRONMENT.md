# Environment: what a fresh machine needs

Facts come from the scripts and toolchain files in this folder. Anything marked GUESS was inferred and not tested. Nothing here was run while writing it.

## Tested on
- macOS on Apple silicon (Darwin 25.x). This is the only tested platform (`README.md`, "Try it").
- Linux: **not tested**. See "Linux notes".

## What to install
1. **rustup**, the Rust toolchain installer: `curl https://sh.rustup.rs -sSf | sh`. The scripts run `source "$HOME/.cargo/env"`, the file rustup writes, so rustup must be in its default location.
2. **Internet access** on first run (crates, Rust toolchains, and the NEAR sandbox binary; see below).
3. A C toolchain (`cc`/`clang`/`gcc`) and `bash`, `shasum`, `tee`, `grep`. macOS has these once the Xcode command line tools are installed (GUESS: some crates in the dependency tree compile C).

You do not install the wasm target or the NEAR sandbox by hand. The toolchain files and build steps below do it.

## Pinned Rust versions (read from the `rust-toolchain.toml` files)
rustup reads the file in the directory where `cargo` runs and picks that version.

| Crate | Pinned channel | Wasm target listed | Why (from the file's comment) |
|---|---|---|---|
| `contracts/` (guard, test-token) | `1.86.0`, profile minimal | `wasm32-unknown-unknown` | Newer Rust emits wasm features (bulk-memory, reference-types) the NEAR VM rejects |
| `targets/leaky-control/` (v1) | `1.86.0`, profile minimal | `wasm32-unknown-unknown` | same |
| `targets/leaky-control-v2/` | `1.86.0`, profile minimal | `wasm32-unknown-unknown` | same |
| `targets/vault-a/` | `1.86.0` (default profile) | `wasm32-unknown-unknown` | no comment in file |
| `tests/` (the 10 sandbox tests) | `stable` | none | runs on the host only, never compiled to wasm |
| `harness/` (the test bench) | `stable` | none | runs on the host only |

So a run installs two Rust versions: 1.86.0 (for contracts) and whatever `stable` is that day. The `stable` ones are not pinned, so a future stable release could behave differently (GUESS: low risk, unverified).

Library versions, per `README.md` "Built with": near-sdk 5.27, near-workspaces 0.24, near-sandbox (nearcore 2.14). The sandbox binary found in the harness build folder is `near-sandbox-2.14.0`. `Cargo.lock` files exist in each crate.

Auto-install: GUESS that rustup installs the pinned toolchain and wasm target itself the first time `cargo` runs in a folder with a toolchain file. Some rustup versions (1.28.x) changed this behaviour. If you see "toolchain ... is not installed", run `rustup toolchain install 1.86.0 --target wasm32-unknown-unknown` yourself.

## What the scripts download or build
- `./run.sh` (`run.sh`): builds `contracts/` to wasm with 1.86.0, then builds a second copy of the guard with the `fault-injection` feature into `contracts/target-fault` (so it can never overwrite the normal wasm), then runs `cargo test --release` in `tests/`. Extra arguments go to `cargo test` as a test-name filter (e.g. `./run.sh t1_`).
- `./run-arena.sh <mode>` (`run-arena.sh`): `ensure_built` builds `test_token.wasm` and the harness (`harness/target/release/arena-harness`) if missing. Then it checks the sha256 fingerprints of `vault-a`, `leaky-control` and `leaky-control-v2` against each `FROZEN.txt`, runs, and checks again. It builds nothing under `targets/`; those wasm files are committed and only hashed.
- **near-sandbox**: neither script downloads it directly. The `near-sandbox` crate's build step fetches the sandbox binary during `cargo build`/`cargo test` of `tests/` and `harness/` (GUESS on the mechanism; the evidence is that a `near-sandbox-2.14.0/near-sandbox` binary sits inside `harness/target/release/build/near-sandbox-*/out/.near/`, about 70 MB). Each of `tests/` and `harness/` gets its own copy. Requires internet on the first build.
- At run time the sandbox is a throwaway node on this machine (local only, no testnet or mainnet).

## Disk space
Measured on the author's machine after a full run (no clean-clone measurement):

| Folder | Size |
|---|---|
| `harness/target` | 1.1 GB |
| `tests/target` | 1.1 GB |
| `contracts/target` | 198 MB |
| `contracts/target-fault` | 143 MB |

About 2.6 GB for those four, plus Rust toolchains and the cargo download cache (`~/.cargo`, `~/.rustup`; size not measured). Plan for about 5 GB free (GUESS).

## Time
| Command | Time | Condition | Source |
|---|---|---|---|
| `./verify.sh` (full, 32 checks) | 14 min 01 s | fresh copy, no build folders, Apple silicon, Nov 9 | `README.md` "Check every claim at once"; `REPORT-foundation-2026-11-09.md` |
| `./verify.sh fast` (5 checks) | 3 min 16 s | **warm** build (ran after the full run in the same copy) | same |
| `./verify.sh fast`, cold | `[PENDING: cold-fast timing, not yet measured]` | | |
| `./run.sh` alone | about 3 min | README says "~3 minutes" (not stated warm or cold) | `README.md` section 1 |

The 14 min figure is agent-reported in the foundation report; the main session could not confirm the final `verify:` line from a file.

## Linux notes (all GUESS, untested)
- `shasum` is used in `run-arena.sh`. It ships with Perl on many distributions (Debian/Ubuntu: package `perl`) but is not guaranteed. If missing, install it or create a `shasum` wrapper around `sha256sum`. A missing `shasum` would show up as `command not found` and a failed frozen check.
- Paths and `date +%Y-%m-%d` are portable. `tee`, `grep -E`, `cut` are standard.
- The sandbox binary is fetched per platform; whether nearcore 2.14.0 publishes a build for your CPU is unchecked. Apple silicon and x86 Linux are the likely supported pairs.
- Windows: not supported (bash scripts).

## Common failures and fixes
| Message | Where it comes from | Fix |
|---|---|---|
| `source: .../.cargo/env: No such file or directory`, and `run.sh` stops | `run.sh` uses `set -e` and sources the file with no fallback (the other two scripts add `|| true`) | Install rustup, or open a new shell after installing |
| `cargo: command not found` | rustup not on `PATH` | `source "$HOME/.cargo/env"` |
| `FROZEN CHECK FAILED (before ... run): <target>/<file>`, then `expected <hash>` / `actual <hash>` | `run-arena.sh` `check_frozen`: a frozen guard file was edited or checked out with different line endings | Restore the file from the original copy. Do not edit `targets/vault-a`, `leaky-control` or `leaky-control-v2`. The run refuses to proceed on purpose |
| `ANY-TARGET FINGERPRINT CHANGED during the run` | `any` mode: the wasm you passed changed while the run was going | Do not rebuild the wasm while the bench runs |
| `usage: ./run-arena.sh scripted \| ai \| ...` | unknown mode | Use one of the listed modes |
| `bypass target must be vault or control` | bad second argument to `bypass` | `./run-arena.sh bypass vault` or `control` |
| `any` with no file: `usage: ... any <guard.wasm> [label]` | missing argument | Pass a wasm path |
| `FAIL  <label>   (expected in evidence/verify-<date>-run.log: "...")` | `verify.sh` could not find the expected result line in a log | Open the named log and read the real error (usually a build failure above the missing line) |
| `FAIL ... (no match in ... for /attempts_found_something=[1-9]/)` on the control check | the bench did not see the planted leak, or setup failed before any attack ran. v1 of the fixture failed this way before it was fixed | Read `evidence/arena-<date>-positive-control.log`. If the bench is blind, **no clean result on any guard means anything** |
| `verify:` line is the only place the totals appear | `verify.sh` prints its final tally to the terminal only | Run it as `./verify.sh 2>&1 \| tee verify-out.txt` |
| Rust compile errors from wasm features, or the NEAR VM rejecting the wasm at deploy | the wasm was built with a newer Rust than 1.86.0 | Build inside the folder with the toolchain file; do not override with `cargo +stable` for contracts |
| A run looks stuck for 20 s or more | some sequences wait in real time (`wait_seconds`) so expiry timestamps arrive | Wait. Raced calls have a 60 s timeout |
| Different date in log names than expected | logs are named with `date +%Y-%m-%d`; reruns on the same day overwrite each other | Copy logs you want to keep before rerunning (known limit, foundation report) |
| `sandbox`/download errors at first build (connection, 404, timeout) | the near-sandbox binary is fetched during the build | Check internet or proxy and rerun; if the nearcore release for your platform is missing, this cannot run there (GUESS) |
