# Check your guard

A **payment guard** is a NEAR contract that holds tokens and lets an AI agent pay approved
invoices for an owner, within rules (pay each invoice once, only approved payees, a daily cap...).
`arena check` runs every attack in Arena's library against your guard on a **local NEAR sandbox**
(a private copy of NEAR that runs on your machine; no testnet, no real money) and tells you which
attacks made it pay more than its own rules allow.

A full check (52 attacks) took **about 4 minutes** on a laptop (measured below). The first run also builds Arena's
harness, which takes a few more minutes once.

## Three steps

**1. Get Arena and build your guard.** You need Rust through rustup and Python 3.

```
git clone <arena repo> arena && cd arena
# build your guard however you normally do; you need its .wasm file
```

**2. Run the check.**

```
./arena check path/to/your_guard.wasm
```

If your guard's `new` takes different arguments, or it lacks a payee list, cancel, expiry or a
daily cap, add a config (step 3). If its method names differ, add a mapping (step 3).

**3. Read the report.** Open `arena-report/report.html`. It is one page, no internet needed.

### When you need a config

`guard.json` says how to start your guard and which rules it claims. Arena fills in the
placeholders `$owner`, `$agent`, `$token` (and `$daily_cap` = "500", `$daily_cap_number` = 500)
with its own sandbox accounts. Example, for a guard with no payee list, cancel, expiry or cap:

```json
{
  "arena_guard_config": 1,
  "init": {"method": "new", "args": {"mode": "fixed", "owner": "$owner", "agent": "$agent", "token": "$token"}},
  "features": {"payees": false, "cancel": false, "expiry": false, "daily_cap": false},
  "deposits": {"approve_invoice": 0}
}
```

```
./arena check your_guard.wasm --config guard.json
```

A rule your guard does not claim is not scored, and the starting invoices that need it are never
created. More examples: `examples/configs/`.

### When you need a mapping

Arena calls the methods named in `targets/vault-a/INTERFACE.md` (`pay`, `approve_invoice`,
`get_invoice`, ...). If yours are called something else, say which of your methods plays each
role:

```json
{
  "arena_mapping": 1,
  "methods": {"pay": "execute_payment", "approve_invoice": "approve_bill", "get_invoice": "bill_info"}
}
```

```
./arena check your_guard.wasm --config guard.json --mapping mapping.json
```

Besides names, a mapping can pick argument shapes, each from a closed list: invoice id field
(`id`, `invoice_id`), receiver field (`receiver`, `receiver_id`, `account_id`), payee field
(`account`, `account_id`, `payee`), expiry field (`expires_at_ns`, `expires_at`, `expiry`) and unit
(`ns`, `ms`, `s`), amount encoding (`u128_string`, `number`), daily-cap field (`daily_cap`, `cap`,
`limit`), status field (`status`, `state`) and paid value (`Paid`, `paid`, `PAID`), and the deposit
(0 or 1 yoctoNEAR) on each owner method. Worked example: `examples/renamed-guard/`.

**How the mapping is used.** It is data, read by a fixed translation layer written by hand in the
harness (`harness/src/adapter.rs`). Each call still goes straight from the agent's own key to your
guard, so your guard sees the real caller and the race timing is unchanged. Nothing in the mapping
is compiled or run.

**If you give no mapping** and your names differ, Arena can ask Muse (a language model) to
**propose** one from the list of method names your wasm exports. The proposal is checked before
use: every name must exist in your wasm, every shape must be on the closed lists, two roles may not
share a method. It is saved as `arena-report/mapping.json`; read it, then pass it with `--mapping`
next time. This needs a key in `~/.config/arena/model.env` (`MUSE_API_KEY=...`); `--no-muse` turns
it off.

## What the report says

| On the report | What it means |
|---|---|
| **Badge `arena: held N/N`** | none of the N attacks made your guard pay beyond its own rules |
| **Badge `arena: broke K of N`** | K attacks did. Each one is listed with its full step log |
| **Tokens paid beyond the guard's own rules** | tokens receivers got that your guard's rules do not allow, read from final token balances, summed over attacks (each attack runs on its own fresh sandbox). Any value above 0 is a guard failure |
| **Tokens paid against the owner's intent** | on the prompt-injection attacks, where the owner's intent is written down ("pay Sam 100, nothing else"): tokens paid beyond that intent. Your guard's rules allowed these payments. A guard cannot know intent; an owner can narrow the rules (fewer payees, a lower cap) to shrink it. Split by who wrote the attack (hand-written scenarios, from papers, from news) |
| **Honest invoices paid** | per attack, how many valid invoices still got paid. A guard that refuses everything would "hold" every attack, so the check first makes one honest payment and stops if it fails |
| **Wasm sha256** | the fingerprint of the exact bytes tested. Rebuild, and the fingerprint changes |
| **Arena commit** | the version of Arena (and of its attack library) that ran. "with local changes" means the Arena checkout had uncommitted edits |

The two numbers are never added together. Files in `arena-report/`: `report.html`, `report.json`,
`badge.svg`, `shields.json` (for a [shields.io endpoint badge](https://shields.io/badges/endpoint-badge)),
`summary.md`, `guard-config.resolved.json`, and `runs/` (every attempt's log and result).

`--fail-on` sets the exit code: `beyond-policy` (default: exit 1 if any token went beyond your
rules), `against-intent` (exit 1 if any went beyond your rules or against the owner's intent),
`never`. Exit 2 means the check could not finish (config, setup or preflight problem); the report
says what to fix.

## Errors and what to do

| The report says | Do this |
|---|---|
| `the guard has no method X` | map the role to your method name (`"methods": {...}`); the report lists every method your wasm exports |
| `init call ... failed` | fix `init.method` / `init.args` in your config |
| `requires an attached deposit` / `refuses an attached deposit` | set `"deposits": {"<role>": 1}` or `0` |
| `could not read the arguments` | pick the matching argument shapes (`"shapes"`) |
| `no ft_transfer was seen` | your pay method must send NEP-141 tokens with `ft_transfer` on the token passed at init; or `methods.pay` points at the wrong method |
| `invoice status reads ...` | set `shapes.status_field` / `shapes.paid_value` |

## Run it in GitHub Actions

Copy `examples/workflows/arena-check.yml` into your repo's `.github/workflows/`, fill in the three
marked lines, and every pull request gets a check. It uses `on: pull_request` with
`permissions: contents: read` and needs no secrets (unless you want Muse to propose a mapping).
The report is uploaded as an artifact, and the badge and numbers go to the job summary. Commenting
on the PR is an optional extra job, described at the bottom of that file.

**Status: the Action has not run on GitHub or on Linux yet.** Its script steps were run locally on
macOS (`tools/check/action-local.sh`). The third-party steps it uses are pinned to full commit SHAs,
each checked to exist with `gh api repos/<owner>/<repo>/commits/<sha>` on 2026-11-10:

| Step | Pinned commit | Tag |
|---|---|---|
| `actions/setup-python` | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | v7.1.0 |
| `actions/cache` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | v6.1.0 |
| `actions/upload-artifact` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | v7.0.2 |
| `actions/checkout` (example workflow) | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 |

## Publish a receipt

`arena-receipts` is a small NEAR contract where a score is published under the guard's wasm
sha256, so a wallet or contract can ask "does this guard pass?" before trusting it. Arena's own
receipts are published by `tools/receipts/publish.py`; see `receipts/README.md` for the contract and
`evidence/receipts-testnet-2026-11-10.md` for live examples, and `docs/CHECK-BEFORE-YOU-PAY.md` for
reading one before trusting a guard. A receipt proves who published a
score and when. It does not prove the bench ran unmodified, or that the attacks were good.

## Limits

- **Local sandbox only.** Nothing runs on testnet or mainnet. Timing on a real network can differ.
- **NEP-141 tokens only.** Your guard must pay with `ft_transfer`; Arena reads token balances.
  (Guards that pay in native NEAR can use `./run-arena.sh any-native`, outside this check.)
- **The library's attacks, not every attack.** The library grows (hand-written, from papers, from
  news), so the same guard can score differently on a later Arena commit. The report names the commit.
- **"Held" means held these attacks, not proved safe.**
- The starting state is Arena's (five receivers, seven invoices, a cap of 500). Your guard is
  tested on the rules it claims, inside that state.

## Measured

Wall-clock time of `./arena check` on our own guards, 52 attacks, 4 at a time (`--jobs 4`, the
default), on an Apple-silicon Mac with 10 cores, 2026-11-10. The harness was already built.

| Guard | Ran alongside | Time |
|---|---|---|
| contracts/guard, mode `fixed` | nothing | 227 s |
| contracts/guard, mode `vulnerable_fixture` | the renamed guard | 225 s |
| renamed guard (`examples/renamed-guard/`) | guard-vulnerable | 274 s |
| vault-a | leaky-control-v2 | 275 s |
| leaky-control-v2 | vault-a | 274 s |

So: about 4 minutes alone, a little more when two checks share the machine. Most of each attempt
is starting a fresh sandbox (about 12 to 15 s); 4 attempts run at once. Not measured: the first
run's build of the harness, and the Action on GitHub's runners (it defaults to 2 at a time, so
expect it to take longer there).

Full results: `evidence/check-2026-11-11.md`.
