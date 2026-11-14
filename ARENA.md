# ARENA.md

A brief for AI reviewers and for people with two minutes. It says what Arena does, what it does not do, and where the evidence for each claim lives.

## For AI reviewers

**Built on NEAR:** near-sandbox for every attack run, NEAR function-call access keys, NEAR Intents and Chain Signatures (guards that pay through them, tested locally), NEAR testnet for published results, and NEAR AI Cloud private inference with TEE attestation for the hunter.

Arena tests payment guards: NEAR contracts that limit what an AI agent may pay. It runs a library of attacks against a guard on a throwaway local NEAR sandbox and scores each attack held or broke from the final token balances.

**Run these first.** They need Python 3 and Node 18 or newer. No build, no key, no login. Each finishes in seconds; the two lookups read NEAR testnet, so they need the internet. Run them from the repo root.

| Command | It should print | What it checks |
|---|---|---|
| `python3 -I tools/admission/manifest.py --check` | `manifest: up to date`, exit 0 | the library and hunt counts in `evidence/MANIFEST.md` match a fresh count of the repo |
| `python3 -I -m unittest discover -s tools/admission/tests` | `OK` | the admission sentence in `README.md` and `EVALUATE.md` matches the manifest; no committed evidence file was edited |
| `python3 -I tools/hunter/validate.py --self-test` | `self-test: ok (validator vs schema/attack.schema.json)` | the gatekeeper and the written step schema agree |
| `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-13-papers-abc826.json` | `recheck: all checks pass (Intel and NVIDIA signatures are not checked offline)` | the saved NEAR AI attestation of the GitHub paper hunt |
| `python3 -I tools/injection/rescore.py` | ends `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` | the 450-token "against the owner's intent" total, recomputed from saved trials |
| `node tools/lookup/cli.mjs r11bvf3-guard.arena-race-funder-1111.testnet` | `status: broke`, exit 1 | the planted-flaw guard's result, read live from NEAR testnet |
| `node tools/lookup/cli.mjs r11cfx4-guard.arena-race-funder-1111.testnet` | `status: held`, exit 0 | the fixed guard's result, read live from NEAR testnet |

Then, with Rust installed: `./verify.sh fast` (about 8 minutes on a cold machine) ends `verify: 5 passed, 0 failed (mode=fast)`. It shows the planted-flaw guard paying 200 on a 100 invoice (t1). It does not run the fixed guard; `./run.sh t2_` does, and prints `RESULT fixed race payouts per trial: [100, 100, 100, 100, 100]`. `EVALUATE.md` lists every claim with its command, expected line and our time.

**Where each headline number lives.** If two files disagree, `evidence/MANIFEST.md` decides the library and hunt counts, and the dated evidence file decides everything else.

| Number | File |
|---|---|
| planted-flaw guard paid 200 on one 100 invoice, 5 of 5 on testnet; the fix paid 100, 5 of 5 | `evidence/testnet-2026-11-11.md` |
| 33 of 54 attacks validated by the admission gate | `evidence/MANIFEST.md` |
| 9 hunt records: 46 attacks proposed, 26 saved, 2 broke a guard (both built to be broken) | `evidence/MANIFEST.md`, section "Hunts" |
| 7 of 10 planted mistakes caught | `evidence/mutation-table-2026-11-11.md` |
| `proofs/run.sh` 33 passed; near-tla 25 of 25 as planned | `evidence/proofs-all-2026-11-11.md`, row 5 |
| 500 tokens against the owner's intent in the worst single run, 0 beyond policy | `evidence/proofs-2026-11-10.md` |
| 450 tokens against the owner's intent across 5 runs of a fully fooled agent | `evidence/injection-intent-by-recipient.md` |
| real model fooled 0 times in 52 trials where it read the email | `evidence/injection-2026-11-09-model.md`, `evidence/injection-2026-11-09-adaptive.md` |
| Guards A, B, C: 29 of 29 tests of their own claims held | `evidence/coverage-table.md` |
| four other teams' guards: 34 of 38 money claims hold | `evidence/proofs-all-2026-11-11.md`, row 4 |

**What you cannot check from this repo, and why.**

- **Other teams' guards.** We name them by letter only, so their code, harnesses and logs stay private. You can read what Guards A, B, C and G claim (`targets/entrant-*/`) and the per-test results, but you cannot re-run them. The bounded proofs on four guards (34 of 38) and the 10 more teams' guards checked in direct mode are published as counts only (`EVALUATE.md` section 6).
- **The hidden test set.** The repo holds only its fingerprint (`hidden-set/COMMITMENT.json`). The set rests on the operator's honesty about which attacks ran. `python3 -I tools/hidden/hidden.py check-public` needs the git history, so it fails on an export without `.git`.
- **Real-model runs and new hunts** need model keys (and an Elfa key for news). The saved trials and hunt records in `evidence/` replay without them.
- **The hunter's GitHub keys.** GitHub shows secret names to the owner only. Anyone can check that the `hunt` Environment is limited to the `main` branch (answer below).
- **The Nov 14 news-model comparison** (`evidence/news-model-2026-11-14.md`): its driver and raw replies are kept outside the repo.

**Known limits that can change a verdict.** The full list is in `README.md`, section "Limits".

- **A false held is possible for a guard that pays part of an invoice.** Arena reads each payment as one whole invoice amount, so a guard that sends part of an invoice, where a whole-amount reading also fits, can score held where a part-payment reading would be broke. None of our guards does this.
- Everything ran on a local sandbox except the double-pay race and its fix, which also ran on NEAR testnet.
- The proofs hold up to stated bounds. The "any number of calls" proof covers a model of the guard; the real code matched the model for up to 4 pay calls.
- Held means the attacks Arena ran found nothing. It does not cover attacks Arena did not run.
- `./arena check`, the hunter and admission send a race's calls together, with no check of which block each landed in.

## FAQ

### The hunter only proposes attacks. How does a proposal become a real attack?

The hunter never writes code. It fills in a form.

Each attack is a list of at most 12 steps. Every step is one of six kinds, defined in `schema/attack.schema.json`:

- `call`: an account calls a guard method, for example the agent calls `pay` on one invoice;
- `view`: read a value from the chain;
- `race`: send up to 4 calls at the same moment;
- `wait_blocks` and `wait_seconds`: wait;
- `add_key`: add an access key.

Arguments can only be short strings (at most 128 characters), whole numbers, booleans and small lists, with at most 1,024 bytes per call.

`tools/hunter/validate.py` rejects any proposal that leaves this menu: an unknown step kind, an unknown field, an oversized argument, a target other than the guard or its token, or a fingerprint (`steps_sha256`) that doesn't match the steps. A rejected proposal never runs.

The Rust harness (`harness/src/seq.rs`) carries out each step on a throwaway local NEAR chain and reads the final balances. A paper or news item can change which steps the model picks. It can't change the code the machine runs.

A real example from `sequences-paper/`: the agent sends four `pay` calls in one race, then waits 3 blocks. That list of steps is the whole attack.

### Why is the step menu fixed, and how does it grow?

The menu is the wall between what the hunter reads and what the machine runs. Anyone can write a paper or a news post. If the model could write code, a crafted page could get code run on our machine. With a fixed menu, a fooled model can at worst produce a bad attack made of the six steps.

The same rules live in three places:

- `schema/attack.schema.json`: the written rules, for outside readers;
- `tools/hunter/validate.py`: the gatekeeper, which rejects anything off the menu or over a limit;
- `harness/src/seq.rs`: the engine. It knows the six actions and stops with "unknown step" on anything else, so a gatekeeper bug still can't make it do something new.

**Is it formally verified? No.** `python3 -I tools/hunter/validate.py --self-test` checks that the gatekeeper and the schema agree on every list and limit. `python3 -I tools/agreement/compare.py` checks the engine against the gatekeeper: it writes 3,478 attack files (cases at every limit, broken ones, and 3,300 random ones from a fixed seed), gives each to both, and fails if the gatekeeper lets in a file the engine would refuse or run differently. That work found 7 gaps in the gatekeeper, now fixed (`docs/SCHEMA-AGREEMENT.md`). This is testing, not a proof: it covers the files it generates and stops where the engine starts sending. Its engine side, `arena-harness check-seq`, copies the engine's step logic instead of calling it, so the two can drift apart; unit tests (one compares the engine's lines with a saved copy) reduce that risk. The planned fix is one function both share. Nothing proves the six actions harmless; that rests on reading `seq.rs`.

**How it grows.** The hunter can't add a step; a person has to. A new action means changing the schema, the gatekeeper and the engine together, then building a reference guard with the matching flaw and a fixed version, so attacks using the new step can pass the admission bar. That happened once: the NEAR Intents target, added on Nov 11. Some attacks need only a bigger limit (more than 4 calls in one race). Others need a new action, and some (a real second chain, waiting hours) may never fit a local sandbox.

### Where can I see the attacks and what the hunter did?

- `sequences-paper/`: 25 of the 26 attacks the hunter saved, each a short list of steps. The 26th, from the Nov 13 news hunt, sits in that hunt's folder (`evidence/hunts/2026-11-13-news-c87c9e/attacks/`) and has not been through the admission gate.
- `evidence/hunts/`: one record per hunt. Each shows which paper or news item it read, what the model proposed, and what the validator rejected and why.
- `evidence/nearai-2026-11-11.md`: how the model on NEAR AI Cloud was chosen and checked.
- To replay a saved attack against your own guard: `./run-arena.sh replay sequences-paper/<file>.json --wasm your_guard.wasm`.

The repo holds 9 hunt records. Together they proposed 46 attacks from papers and news; 26 were saved, and 2 broke a guard. Both of those guards were built to be broken (`evidence/MANIFEST.md`, "Hunts"). The news hunt that ran on GitHub on 2026-11-13 is included as a redacted copy (`evidence/hunts/2026-11-13-news-c87c9e.md`): it names five projects from other hackathons by number only, and its one new attack ran against Arena's own reference guards.

### Why are some results proved and others only measured?

A proof checks every order the calls can arrive in, up to a stated limit. A test checks the runs we made. Each result says which one it is.

- **Proved, for our own guard:** it never pays one invoice twice. That holds for any number of pay calls on a model of its logic, and for up to 4 pay calls on the real code. It never pays beyond the owner's rules, for up to 10 payment requests in our test setup. Details and limits are in `README.md`.
- **Measured, not proved:** what an AI agent chooses to do. A language model has no rules a proof can check, so Arena reports what the agent did, run by run. Testnet results are measurements too.
- **Proved up to small bounds, privately:** four other teams' guards. Of 38 money claims, 34 hold, 3 hold for the contract's own part, and 1 fails (one guard can pay above its daily cap when a refund lands after midnight; we do not say which). The bounds are 2 to 5 payment requests, owner actions and one midnight. You cannot re-run these proofs from this repo; we publish counts only (`evidence/proofs-all-2026-11-11.md`, row 4). Separately, Guards A, B and C passed tests written from their own claims (`evidence/coverage-table.md`).

### Where are the private tests?

Two things stay out of this repo on purpose.

- **Other teams' guards.** We name them by letter only. Their code and the map from letter to team stay private, so we name no team without its yes. Results are listed per letter in `evidence/coverage-table.md`.
- **A hidden test set.** 14 admitted attacks, kept out of the repo. The repo holds the set's fingerprint (`hidden-set/COMMITMENT.json`), so anyone can check later that the set did not change after the commit. Its runs on Arena's own guards are in `evidence/hidden-set/`. How to check it without seeing it: `EVALUATE.md` section 4b. One limit: the set rests on the operator's honesty about which attacks ran.

### Where does the hunter run, and what limits the damage?

The hunter runs as a GitHub Actions workflow (`.github/workflows/hunt.yml`), and the owner switched it on on 2026-11-13. Its schedule runs four hunts a day: papers and news at 01:17 UTC, news only at 07:17, 13:17 and 19:17. Two runs have happened so far, both started by hand on 2026-11-13: a paper hunt (https://github.com/damli40/arena/actions/runs/43466826430, record `evidence/hunts/2026-11-13-papers-abc826.md`) and a news hunt that read Elfa news summaries (https://github.com/damli40/arena/actions/runs/43522805712, redacted record `evidence/hunts/2026-11-13-news-c87c9e.md`). The first scheduled run, on 2026-11-14 at 01:17 UTC (https://github.com/damli40/arena/actions/runs/43533436641), failed its self-checks before hunting: the workflow restored the cached used-paper list before the test that checks committed evidence files are unchanged, and the news run had changed that list. The workflow now restores the list after the self-checks.

How it limits damage:

- It can only read the repo (`permissions: contents: read`). It never pushes or commits. Results leave as a downloadable file attached to the run.
- It treats everything it reads as untrusted: paper abstracts, news, and the model's own replies. It runs none of it. The validator checks it as data, as described above. The model has no tools, so a model fooled by a crafted page can at worst waste a few calls or propose a junk attack that the validator rejects.
- For papers, the model runs on NEAR AI Cloud private inference. Before its first call, the hunt fetches NEAR's attestation report (a record, signed inside NEAR's sealed hardware, of which model is answering), checks it and saves it. You can re-check a saved report offline: `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-13-papers-abc826.json`. 2 of the 8 hunt records ran this way (`2026-11-11-papers-e3db55` and `2026-11-13-papers-abc826`). The others used Muse Spark, which has no attestation.
- News goes to Muse Spark (`muse-spark-1.3`), which has no attestation. On Nov 14 we re-tested the attested model, GLM-5.3-flash on NEAR AI, on 22 more news items, 30 in all with the Nov 11 test. Muse's attacks passed the validator 12 of 12 times (100%) and GLM's 23 of 28 (82%), 18 points under, where the owner's rule allows about 10. GLM also made attacks from an item that doesn't map to a payment guard, and gave no answer on 4 of the 22 items (`evidence/news-model-2026-11-14.md`).
- When the hunter, `tools/check/check.py` or the injection runners start the harness, it gets a short list of named variables (`CHILD_ENV_ALLOW` in `tools/hunter/runner.py`), so no model or news key in a variable reaches it. `tools/hunter/tests/test_child_env.py` sets fake keys and checks that a child started this way sees none of them. Two limits: `run-arena.sh any`, `ai` and `replay`, run by hand, still pass the whole shell environment; and on a local machine the harness can still read key files under `~/.config/arena/`. On GitHub the keys exist as variables of the hunt step alone.

What this doesn't protect:

- The attestation shows which model answered. It doesn't show that an attack is good or that a result is right.
- The attestation doesn't cover a bug in the software running inside the sealed hardware. On Nov 8, someone used a flaw in SGLang, the engine that runs NEAR AI's models, to run code on one inference server. From there they could see requests in progress, including confidential ones. NEAR AI's report says confidential computing "does not protect against a vulnerability in the software running inside the environment": https://near.ai/blog/security-incident-report-sglang-vulnerability. Our NEAR AI hunts ran after that access and send only public paper text. Either way, the hunter treats the model's answer as untrusted: the validator decides what runs.
- The rest of the loop (fetching papers, validating, running the sandbox) runs on GitHub's machine, outside any sealed hardware.

### Who can access the workflow, its keys and its outputs?

- The repo is public. Anyone can read the workflow file. Any signed-in GitHub user can open its run logs and download its result files.
- The workflow reads its keys from a GitHub Environment named `hunt`, not from repository secrets. Since 2026-11-13 the Environment holds three: `NEARAI_API_KEY`, `MUSE_API_KEY` and `ELFA_API_KEY`. GitHub never shows a saved secret again, to anyone, including the owner.
- The Environment accepts runs from the `main` branch alone, so a run from any other branch gets no keys. Anyone can check this: `curl -s https://api.github.com/repos/damli40/arena/environments/hunt/deployment-branch-policies` lists one policy, named `main`.
- Only accounts with write access can start a run by hand or change the workflow. Pull requests, including ones from forks, can't trigger it: it runs on its schedule or by hand.

### If the owner's GitHub account is compromised, what can an attacker do?

They can't read the saved keys directly. They could edit the workflow on `main` so its next run sends the keys elsewhere, push code, or change the repo. Every GitHub project carries that risk.

Where each defence stands:

- **The `hunt` Environment, limited to `main`: in place** (check it with the command above). The repo has no repository secrets with the same names, so the Environment is where the keys come from.
- **Keys used for this hunt alone, each with a spending cap: not in place.** The NEAR AI key is also used outside the hunt, and no spending cap is confirmed on any of the three keys.
- **A passkey on the owner account:** this file makes no claim; the repo cannot show it.
- **Revoking a key after any doubt:** the owner's rule, not a setting.

No wallet key is involved: the hunter spends only on model and news calls.

### Can the hunter run on NEAR, in sealed hardware, instead of GitHub Actions?

Partly. The paper hunt's model calls already run inside NEAR AI Cloud's sealed hardware. We looked at moving the whole loop:

- **NEAR AI Cloud** runs private model calls. We found no way to run our own program there.
- **NEAR Shade Agents** (agents that run in sealed hardware and are registered on chain): NEAR's docs say not to use the framework, which hasn't been maintained since April 2026.
- **A Phala sealed container** could run the whole hunter and prove which exact code ran. We haven't confirmed that the local NEAR sandbox runs inside one, and it is not set up.

Everything the hunter reads is public, so a sealed machine adds little secrecy. It would add proof of which code produced each result. Until one is in place, the answer is no: the hunter's loop doesn't run on NEAR yet.

### Can the learning attacker read the guard first?

Yes, with `--know-guard` (`python3 -I tools/injection/adaptive.py 3 3 --know-guard`). A real attacker can read a guard, because the contract sits on a public chain and most teams publish its source. In this mode the attacker gets the guard's rules (approved payees, caps, when the daily window resets) and its source, capped at 40 KB, and names the payment it is aiming for. It still controls the email text alone, and Arena still scores every round from final chain balances.

- **It never sees the owner's instructions.** A check stops the run if any 6-word run of them, or the owner's intended payment, would reach the attacker. One leak is by design: a target the owner did intend is refused as "not accepted", which tells the attacker that payment was the owner's own.
- **Results, 3 rounds of 3 tries each, NEAR AI attacker, local sandbox, 2026-11-13:** on vault-a the agent was fooled 0 of 9 times. On the direct-pay test guard it was fooled 1 of 9: the agent paid kai 40, a payment inside the guard's rules that the owner never asked for. The guard never paid beyond its own rules in either run (`evidence/injection-2026-11-13-adaptive-guard-aware-vault-a.md`, `evidence/injection-2026-11-13-adaptive-guard-aware-direct-fixture.md`).
- **Limits:** two guards, 9 tries each. Guard-aware calls get a larger budget (24,000 tokens, 600 s), because with the source in front of it the model spent 8,000 tokens thinking and wrote no email.

## Roadmap

Planned, not built. An item moves into the FAQ above once it runs and has evidence in `evidence/`.

### Abliterated models that break guards, then fix them (NEAR AI)

On Oct 29 2026 NEAR AI released abliterated models for security work: versions of DeepSeek V4.1 Flash and Qwen 3.8 "modified to reduce refusals that interrupt legitimate security testing", running inside trusted execution environments ([NEAR AI blog](https://near.ai/blog/cybersecurity-models-and-near-ai-red-launch), accessed 2026-11-13). The plan is to point one of them at a guard, let it try to make that guard pay money it shouldn't, then have it try to fix what it broke.

- **Break.** The model proposes attacks in Arena's fixed step format, on the same throwaway local NEAR sandbox Arena uses today. A proposal counts after the admission gate admits it: it must hold on a guard known to be good and break a copy with one planted flaw, 3 runs each. The model can't add an attack by saying it works.
- **Fix.** When an attack breaks a guard, the model proposes a patch. Arena runs the patched guard against the attack that broke it, the full library and the honest payments. The patch counts if every one holds and every honest payment still goes through.
- **Scope.** Guards whose code the owner sent or published, on a local sandbox, never against a live deployment.
- **Record.** Each model call runs in NEAR AI Cloud's sealed hardware, so each result can name the model that produced it, as the hunter's paper calls do today. That proves which model answered, not that the software around it had no bugs (see the attestation answer above).

The owner plans to build this after the hackathon.
