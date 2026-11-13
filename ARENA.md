# ARENA.md

A short brief for AI readers and for people with two minutes. It says what Arena does, what it does not do, and where the evidence for each claim lives. The questions below are the ones people have asked so far. More will be added as the branches now in review are merged.

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

The Rust harness (`harness/src/seq.rs`) then carries out each step on a throwaway local NEAR chain and reads the final balances. Every attack runs through the same fixed harness code. A paper or news item can change which steps the model picks. It can't change what the machine runs.

A real example from `sequences-paper/`: the agent sends four `pay` calls in one race, then waits 3 blocks. That list of steps is the whole attack.

### Why is the step menu fixed, and how does it grow?

The menu is the wall between what the hunter reads and what the machine runs. The hunter reads papers and news that anyone can write. If the model could write code, a crafted page could get code run on our machine. With a fixed menu, the worst a fooled model can produce is a bad attack made of the six steps, and the fixed harness runs only those.

The same rules live in three places:

- `schema/attack.schema.json`: the written rules, for outside readers;
- `tools/hunter/validate.py`: the gatekeeper, which rejects anything off the menu or over a limit;
- `harness/src/seq.rs`: the engine. It knows only the six actions and stops with "unknown step" on anything else, so a gatekeeper bug still can't make it do something new.

**Is it formally verified? No.** `python3 -I tools/hunter/validate.py --self-test` checks that the gatekeeper and the written schema agree on every list and limit. `python3 -I tools/agreement/compare.py` checks the engine against the gatekeeper: it writes 3,478 attack files (cases at every limit, deliberately broken ones, and 3,300 random ones from a fixed seed), gives each to both, with no sandbox, and fails if the gatekeeper lets in a file the engine would refuse or run differently. It and its review found 7 gaps in the gatekeeper, now fixed (`docs/SCHEMA-AGREEMENT.md`). This is testing, not a proof: it covers the files it generates and stops where the engine starts sending. Its engine side, `arena-harness check-seq`, copies the engine's step logic rather than calling it, so the two can drift apart; unit tests (one compares the engine's lines with a saved copy) reduce that risk but cannot remove it. The real fix, one function both share, is planned after the open branches merge. Nothing proves the six actions are harmless; that rests on reading `seq.rs`.

**How it grows.** The hunter can't add a step; only a person can. A new action means changing the schema, the gatekeeper and the engine together, then building a reference guard with the matching flaw and a fixed version, so attacks using the new step can pass the admission bar. That has already happened once: the NEAR Intents target was added on Nov 11. Some attacks only need a bigger limit (for example, more than 4 calls in one race). Others need a new action, and some (a real second chain, waiting hours) may never fit a local sandbox.

### Where can I see the attacks and what the hunter did?

- `sequences-paper/`: the 25 attacks the hunter saved. Each one is a short, readable list of steps.
- `evidence/hunts/`: one file per hunt. Each shows which paper or news item it read, what the model proposed, and what the validator rejected and why.
- `evidence/nearai-2026-11-11.md`: how the model on NEAR AI Cloud was chosen and checked.
- To replay a saved attack against your own guard: `./run-arena.sh replay sequences-paper/<file>.json --wasm your_guard.wasm`.

So far, 7 hunts proposed 41 attacks from 10 papers and 4 news items. 25 were saved, and 2 broke a guard. Both of those guards were built to be broken.

### Why are some results proved and others only measured?

A proof checks every order the calls can arrive in, up to a stated limit. A test checks only the runs we made. Arena uses both, and each result says which one it is.

- **Proved, for our own guard:** it never pays one invoice twice. That holds for any number of pay calls on a model of its logic, and for up to 4 pay calls on the real code. It never pays beyond the owner's rules, for up to 10 payment requests in our test setup. Details and limits are in `README.md`.
- **Measured, not proved:** what an AI agent chooses to do. A language model isn't a program with rules a proof can check, so Arena reports what the agent did, run by run. Testnet results are also measurements: they show what happened on those runs.
- **Proved up to small bounds, privately:** four other teams' guards. Of 38 money claims, 34 hold, 3 hold for the contract's own part, and 1 fails (one guard can pay above its daily cap when a refund lands after midnight; we do not say which). The bounds are 2 to 5 payment requests, owner actions and one midnight. Their source and harnesses stay private, so you cannot re-run these proofs from this repo; we publish counts only (`evidence/proofs-all-2026-11-11.md`, row 4). Separately, three of those guards passed tests written from the claims they wrote themselves (`evidence/coverage-table.md`).

### Where are the private tests?

Two things stay out of this repo on purpose.

- **Other teams' guards.** We name them by letter only. Their code and the map from letter to team stay private, so no team is named without its yes. Results here are listed per letter in `evidence/coverage-table.md`.
- **A hidden test set.** 14 admitted attacks kept out of the repo. The repo holds only the set's fingerprint (`hidden-set/COMMITMENT.json`), so anyone can check later that the set did not change after it was committed. Its runs on Arena's own guards are in `evidence/hidden-set/`. How to check it without seeing it: `EVALUATE.md` section 4b. One limit: the set rests on the operator's honesty about which attacks ran.

### Where does the hunter run, and how secure is that?

Today the hunter is set up as a GitHub Actions workflow (`.github/workflows/hunt.yml`). **It is paused.** It has never run on GitHub, and it stays paused until its keys and its hosting are decided.

How it limits damage:

- It can only read the repo (`permissions: contents: read`). It never pushes or commits. Results leave only as a downloadable file attached to the run.
- Everything it reads is treated as untrusted: paper abstracts, news, and the model's own replies. None of it is run. The validator checks it as data, as described above. The model has no tools, so a model fooled by a crafted page can at worst waste a few calls or propose a junk attack that the validator rejects.
- For papers, the model runs on NEAR AI Cloud private inference. Before its first call, the hunt fetches NEAR's attestation report (a signed record from NEAR's secure hardware of which model is answering), checks it and saves it. You can re-check a saved report offline: `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json`. Only 1 of the 7 hunts so far ran this way. The others used Muse Spark, which has no attestation.
- When the hunter, `tools/check/check.py` or the injection runners start the harness, it gets only a short list of named variables (`CHILD_ENV_ALLOW` in `tools/hunter/runner.py`), so no model or news key in a variable reaches it. `tools/hunter/tests/test_child_env.py` sets fake keys and checks that a child started this way sees none of them. Two limits: `run-arena.sh any`, `ai` and `replay`, run by hand, still pass the whole shell environment; and on a local machine the harness can still read key files under `~/.config/arena/`. On GitHub the keys exist only as variables of the hunt step.

What this doesn't protect:

- The attestation shows which model answered. It doesn't show that an attack is good or that a result is right.
- The attestation doesn't cover a bug in the software running inside the secure hardware. On Nov 8, someone used a flaw in SGLang, the engine that runs NEAR AI's models, to run code on one inference server. From there they could see requests in progress, including confidential ones. NEAR AI's report says confidential computing "does not protect against a vulnerability in the software running inside the environment": https://near.ai/blog/security-incident-report-sglang-vulnerability. Our NEAR AI hunt ran on Nov 11, after that access, and sends only public paper text. Either way, the model's answer is treated as untrusted: the validator decides what runs.
- The rest of the loop (fetching papers, validating, running the sandbox) runs on GitHub's machine, outside any secure hardware.

### Who can access the workflow, its keys and its outputs?

- The repo is public. Anyone can read the workflow file. Any signed-in GitHub user can open its run logs and download its result files.
- The workflow reads its keys from a GitHub Environment named `hunt`, not from repository secrets. GitHub never shows a saved secret again, to anyone, including the owner. No secrets are set today.
- Only accounts with write access can start a run by hand or change the workflow. Pull requests, including ones from forks, can't trigger it: it runs only on its schedule or by hand.

### If the owner's GitHub account is compromised, what can an attacker do?

They can't read the saved keys directly. They could edit the workflow so its next run sends the keys elsewhere, push code, or change the repo. That is the real risk, and every GitHub project carries it.

The defences:

- a passkey on the owner account;
- keys used only for this hunt, each with a spending cap;
- a GitHub Environment, so only the `main` branch can use the keys;
- revoking a key after any doubt.

The workflow now reads its keys from an Environment named `hunt` (`environment: hunt` in `.github/workflows/hunt.yml`). Limiting that Environment to `main`, and setting capped keys in it, is the owner's job on GitHub, and this file doesn't claim either is done. Until then it protects nothing: GitHub creates an empty `hunt` Environment on the first run, and a repository secret with the same name would still be used. None of the other defences are set up today, because no keys are set. This answer will list each one as it is added. No wallet key is involved: the hunter only spends on model and news calls.

### Can the hunter run on NEAR, in secure hardware, instead of GitHub Actions?

Partly, today. The model calls for papers already run inside NEAR AI Cloud's secure hardware. We looked at moving the whole loop:

- **NEAR AI Cloud** runs private model calls. We found no way to run our own program there.
- **NEAR Shade Agents** (agents that run in secure hardware and are registered on chain): NEAR's docs say not to use the framework, which hasn't been maintained since April 2026.
- **A Phala secure container** could run the whole hunter and prove which exact code ran. We haven't confirmed that the local NEAR sandbox runs inside one, and it is not set up.

Everything the hunter reads is public, so a sealed machine adds little secrecy. What it would add is proof of which code produced each result. Until one is in place, the honest answer is no: the hunter's loop doesn't run on NEAR yet.

### Can the learning attacker read the guard first?

Yes, with `--know-guard` (`python3 -I tools/injection/adaptive.py 3 3 --know-guard`). A real attacker can read a guard, because the contract sits on a public chain and most teams publish its source. In this mode the attacker gets the guard's rules (approved payees, caps, when the daily window resets) and its source, capped at 40 KB, and names the payment it is aiming for. It still controls only the email text, and Arena still scores every round from final chain balances.

- **It never sees the owner's instructions.** A check stops the run if any 6-word run of them, or the owner's intended payment, would reach the attacker. One leak is by design: a target the owner did intend is refused as "not accepted", which tells the attacker that payment was the owner's own.
- **Results, 3 rounds of 3 tries each, NEAR AI attacker, local sandbox, 2026-11-13:** on vault-a the agent was fooled 0 of 9 times. On the direct-pay test guard it was fooled 1 of 9: the agent paid kai 40, a payment inside the guard's rules that the owner never asked for. The guard never paid beyond its own rules in either run (`evidence/injection-2026-11-13-adaptive-guard-aware-vault-a.md`, `evidence/injection-2026-11-13-adaptive-guard-aware-direct-fixture.md`).
- **Limits:** two guards, 9 tries each. Guard-aware calls get a larger budget (24,000 tokens, 600 s), because with the source in front of it the model spent 8,000 tokens thinking and wrote no email.

## Roadmap

Planned, not built. An item moves into the FAQ above only once it runs and has evidence in `evidence/`.

### Abliterated models that break guards, then fix them (NEAR AI)

On Oct 29 2026 NEAR AI released abliterated models for security work: versions of DeepSeek V4.1 Flash and Qwen 3.8 "modified to reduce refusals that interrupt legitimate security testing", running inside trusted execution environments ([NEAR AI blog](https://near.ai/blog/cybersecurity-models-and-near-ai-red-launch), accessed 2026-11-13). The plan is to point one of them at a guard and let it try to make that guard pay money it shouldn't, then try to fix what it broke.

- **Break.** The model proposes attacks in Arena's fixed step format, on the same throwaway local NEAR sandbox Arena uses today. A proposal counts only after the admission gate admits it: it must hold on a guard known to be good and break a copy with one planted flaw, 3 runs each. The model can't add an attack by saying it works.
- **Fix.** When an attack breaks a guard, the model proposes a patch. Arena runs the patched guard against the attack that broke it, the full library and the honest payments. The patch counts only if every one holds and every honest payment still goes through.
- **Scope.** Only guards whose code the owner sent or published, only on a local sandbox, never against a live deployment.
- **Record.** Each model call runs in NEAR AI Cloud's secure hardware, so each result can name the model that produced it, as the hunter's paper calls do today. That proves which model answered, not that the software around it had no bugs (see the attestation answer above).

The owner is building this after the hackathon.
