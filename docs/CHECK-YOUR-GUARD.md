# Check your guard

A **payment guard** is a NEAR contract that holds tokens and lets an AI agent pay approved
invoices for an owner, within rules (pay each invoice once, only approved payees, a daily cap...).
`arena check` runs every attack in Arena's library against your guard on a **local NEAR sandbox**
(a private copy of NEAR that runs on your machine; no testnet, no real money) and tells you which
attacks made it pay more than its own rules allow.

A full check (51 attacks, plus one honest payment first) took **about 4 minutes** on a laptop (measured below). The first run also builds Arena's
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
created. Attacks on that rule then test nothing, so they are reported as **not applicable**, never
as held (see "What the report says"). More examples: `examples/configs/`.

If your guard claims a daily cap (the default), its init must take Arena's cap through
`$daily_cap` or `$daily_cap_number`. Arena scores the cap as 500, so a config that writes its own
number for the cap is refused with a message saying so.

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
| **Badge `arena: held N/N (...)`** | N attacks really ran against a rule your guard claims, and none of them made it pay beyond its own rules, on a local sandbox. It held these attacks; that is not a proof. Attacks that were not applicable are not in N |
| **Badge `arena: broke K of N (...)`** | K of those N attacks did. Each one is listed with its full step log |
| **The part in brackets** | always shown next to the count: how many attacks were **not applicable**, which of the 4 rules (payees, cancel, expiry, daily_cap) your guard claims, how many role methods your guard does not have, any owner method Arena could not confirm, `refused K of M honest payments` when your guard turned down honest invoices the attacks asked it to pay, `N against intent` when tokens were paid against the owner's intent, and `subset: K of N attacks` when only some attacks ran |
| **Badge colour** | green only when the guard held, nothing is in the brackets but `0 not applicable` and all 4 rules, and **0 tokens were paid against the owner's intent** in the attacks that ran. Otherwise yellow (held with something to read), red (broke) or grey (could not finish). Green is still not a proof |
| **Honest payment** | before any attack, Arena makes one normal payment your guard should allow. If it fails, the check stops. It is a check that your guard works, **not an attack**: it has its own line and is in no count, no badge and no total |
| **Not applicable** | the attack tested nothing your guard claims, so it is not counted as held. The exact rule is below |
| **Owner methods, as seen in preflight** | what each owner method (add_payee, remove_payee, cancel_invoice, set_daily_cap, set_agent) visibly did on a fresh sandbox: `confirmed`, `not confirmed` (no view showed it, or the call failed), `missing`, or `not claimed`. If one had no visible effect, the check stops (exit 2) |
| **Tokens paid beyond the guard's own rules** | tokens receivers got that your guard's rules do not allow, read from final token balances, summed over the attacks that ran (held or broke; each attack runs on its own fresh sandbox). Any value above 0 is a guard failure |
| **Tokens paid against the owner's intent** | on the prompt-injection attacks that ran, where the owner's intent is written down ("pay Sam 100, nothing else"): tokens paid beyond that intent. Your guard's rules allowed these payments. A guard cannot know intent; an owner can narrow the rules (fewer payees, a lower cap) to shrink it. Split by who wrote the attack (hand-written scenarios, from papers, from news). What not-applicable attacks paid is shown on its own line ("not counted") and never counts |
| **Honest payments** | how many honest invoices (valid, inside the cap) the attacks asked your guard to pay, and how many it refused for no reason Arena can see (no owner rule change in that attack, not over the cap). A guard that refuses everything would otherwise "hold" every attack, so any refusal shows in the brackets, near the top of report.html, and keeps the badge from being green |
| **Wasm sha256** | the fingerprint of the exact bytes tested. Rebuild, and the fingerprint changes |
| **Arena commit** | the version of Arena (and of its attack library) that ran. "with local changes" means the Arena checkout had uncommitted edits |

The two numbers are never added together. Files in `arena-report/`: `report.html`, `report.json`,
`badge.svg`, `shields.json` (for a [shields.io endpoint badge](https://shields.io/badges/endpoint-badge)),
`summary.md`, `guard-config.resolved.json`, `effects.json` (the owner-method preflight), and `runs/`
(every attempt's log and result). Every path in them is relative to the folder you ran from (or just
a file name). At the start of every run, Arena deletes the report files of the run before, so an
old badge can never be left behind by a run that failed.

### When an attack counts as "not applicable"

An attack that made your guard pay beyond its rules is always **broke**. Otherwise, it is **not
applicable** when at least one call it sent to your guard (views do not count):

1. uses a starting invoice that was never created on your guard (because you do not claim the rule it needs);
2. calls an owner method for a rule you do not claim (cancel, payee list, daily cap);
3. calls a role method your guard does not have, or NEAR answered "no such method" for a role method, or your
   guard could not read the arguments Arena sent to a role method ("missing field", "failed to deserialize",
   "invalid type", "Failed to parse"): the call never reached your rule, so it tested nothing;
4. calls an owner method whose effect Arena could not confirm in preflight;
5. or, if you claim no daily cap: pays different invoices that add up to more than Arena's cap of 500 (it is testing the cap).

Any other attack is **held**, even if your guard refused every call it made: refusing is what a guard
should do (an outsider's pay being refused is a real "held"). A "no such method" answer for a name
that plays no role (an attacker looking for a hidden method) does not make an attack not applicable:
your guard really has no such method, and that is what the attack checks. The code is
`tools/check/applicable.py`.

### Exit codes

`--fail-on` sets the exit code: `beyond-policy` (default: exit 1 if any token went beyond your
rules), `against-intent` (stricter: exit 1 if any went beyond your rules or against the owner's
intent), `never`. Exit 0 means the check finished under that line. Both lines count only attacks
that ran (held or broke): never a not-applicable attack, never the honest payment. A guard that
keeps all its rules but pays an approved payee the owner never meant to pay (the prompt-injection
attacks) still trips `against-intent`: that is a real finding about the owner's rules being wide,
not noise.

Exit 2 means the check could not finish, and the report and the console say why. The causes: a
wasm, config or mapping problem; Rust's `cargo` missing or a build failing; the honest payment in
preflight failing; an owner method with no visible effect, or a starting cap that is not Arena's 500;
an attack that errored or ran out of time; a file in Arena's attack library it could not load; an
`--only` naming an attack the library does not have; no attack at all testing a rule you claim; or an
unexpected error inside Arena itself. Exit 1 is never used for a crash.

## Errors and what to do

| The report says | Do this |
|---|---|
| `the guard has no method X` | map the role to your method name (`"methods": {...}`); the report lists every method your wasm exports |
| `init call ... failed` | fix `init.method` / `init.args` in your config |
| `requires an attached deposit` / `refuses an attached deposit` | set `"deposits": {"<role>": 1}` or `0` |
| `could not read the arguments` | pick the matching argument shapes (`"shapes"`) |
| `no ft_transfer was seen` | your pay method must send NEP-141 tokens with `ft_transfer` on the token passed at init; or `methods.pay` points at the wrong method |
| `invoice status reads ...` | set `shapes.status_field` / `shapes.paid_value` |
| `an owner method had no visible effect` | the role named is mapped to a method that does not do that job (or your method does not work); map it to the right method |
| `owner method not confirmed` | your guard has no view that shows that method's effect (`is_payee`, `get_invoice`, `get_config` with an `agent` and cap field), or the owner's call failed. Attacks that call it count as not applicable. Map the view, or fix the call (often its deposit) |
| `role methods not in the guard` | your guard has no method for those roles. Attacks that call them count as not applicable. If it does have one under another name, map it |
| `init.args does not pass Arena's cap` | pass `"$daily_cap"` or `"$daily_cap_number"` in `init.args`, or set `"features": {"daily_cap": false}` |

## Run it in GitHub Actions

Copy `examples/workflows/arena-check.yml` into your repo's `.github/workflows/`, fill in the lines
marked `<- your ...` (your build command and your wasm path), and every pull request gets a check.
The report is uploaded as an artifact, and the badge and numbers go to the job summary. Commenting
on the pull request is an optional extra job, described at the bottom of that file.

**Status: this has never run on GitHub or on Linux.** Arena has no public GitHub home yet, so the
example still says `ARENA_OWNER/arena@ARENA_COMMIT`; replace both with Arena's real place and a full
40-character commit SHA once it has one. Only the script step was run, locally on macOS, with
`tools/check/action-local.sh`
(output: `evidence/check-fixes-2-2026-11-11/action-local.txt`; what changed in that round:
`evidence/check-fixes-2-2026-11-11.md`).

The Action's outputs: `status` (`held`, `broke`, `incomplete`, `not-run`; `held` covers both a green
and a yellow badge), `full` (`true` only when the badge is green), `badge` (the badge text),
`beyond-policy`, `against-intent` and `exit-code`.

### How the workflow is split, and why

The workflow has two jobs, because building your guard means running the pull request's code, and
code like that can change anything on the machine it runs on (the PATH, the home folder, Arena's
own files). If Arena ran on that same machine, the pull request could decide the result.

1. **build** checks out the pull request, builds the `.wasm`, and uploads it (plus your
   `guard.json` / `mapping.json`, if you use them) as an artifact. It gets no secrets.
2. **check** starts on a fresh machine, downloads those files, and runs Arena at the commit you
   pinned. It never checks out or runs the pull request's code. It is the only job that may see the
   optional `MUSE_API_KEY`.
3. **comment** (optional, off by default) posts the numbers on the pull request. It alone may write
   to pull requests, and it runs no pull request code.

The workflow uses `on: pull_request` (never `pull_request_target`) and `permissions: contents: read`.

### What a badge from your own repo proves

A badge made by a workflow in the guard author's own repo is **the author's word, not proof**. The
author controls the workflow file, and a pull request can even change the workflow it is checked
by. The two-job split stops the guard's build from faking the result; it cannot stop the repo owner
from changing the workflow. It is useful to you and your reviewers. A result someone else can trust
is one they ran themselves (`./arena check` on the same wasm; the report prints its sha256) or one
on Arena's board.

### Exit codes

| Code | Meaning | Job |
|---|---|---|
| 0 | finished, nothing paid over the `fail-on` line | passes |
| 1 | finished, tokens were paid over the `fail-on` line | fails |
| 2 (or anything else) | could not finish | fails |

The job summary only shows a summary written by this run: old report files are deleted before the
check starts, and if no new one appears the summary says so and the job fails.

### Runners

The NEAR sandbox Arena uses exists only for Linux x86_64, Linux arm64 and macOS on Apple silicon.
On any other runner (Intel macOS, Windows) the Action stops at once with a plain message. Use
`runs-on: ubuntu-latest`. Linux arm64 is allowed because the sandbox library supports it and its
download exists, but nobody has run Arena there.

### Build cache (off by default)

The `cache` input (`'true'` to turn on) reuses Arena's Rust build between runs. It is off because
code that ran earlier in the same workflow run, such as your pull request's build job, may be able
to write that saved build, and Arena would then run it. With it off, every run builds Arena from
source, which takes a few extra minutes.

### Pinned steps

Every third-party step is pinned to a full commit SHA. Each SHA was checked on 2026-11-10 with
`gh api` to exist and to be exactly what its release tag points at, and each release is more than
two weeks old. Raw output: `evidence/check-fixes-2026-11-11/action-sha-check.txt`.

| Step | Pinned commit | Tag | Released |
|---|---|---|---|
| `actions/checkout` (build job) | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 | 2026-07-20 |
| `actions/upload-artifact` (build job, and the Action) | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | v7.0.2 | 2026-10-07 |
| `actions/download-artifact` (check job) | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | v8.0.2 | 2026-10-07 |
| `actions/setup-python` (the Action) | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | v7.1.0 | 2026-10-22 |
| `actions/cache` (the Action, only with `cache: 'true'`) | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | v6.1.0 | 2026-06-26 |

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
- **Owner methods are checked through the guard's own views.** Preflight confirms an owner method
  worked by reading the guard's views (`is_payee`, `get_invoice`, `get_config`). A guard whose views
  report a change its rules do not really make would pass that step. The attacks still test the
  rules themselves, but a lying view can make an owner method look confirmed.
- **The example workflow's split is not proof.** See "What a badge from your own repo proves".
- The starting state is Arena's (five receivers, seven invoices, a cap of 500). Your guard is
  tested on the rules it claims, inside that state.

## Measured

Wall-clock time of `./arena check` on our own guards, 51 attacks plus the honest payment (52 fresh sandboxes), 4 at a time (`--jobs 4`, the
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
