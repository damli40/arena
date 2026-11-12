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

**Is it formally verified? No.** `python3 -I tools/hunter/validate.py --self-test` checks that the gatekeeper and the written schema agree on every list and limit. Nothing yet checks that the engine agrees with them, and nothing proves the six actions are harmless; that rests on reading `seq.rs`. A test that feeds random attack files to both the gatekeeper and the engine, and fails if they disagree, is planned.

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
- **Not proved yet:** other teams' guards. Their results are tests against the claims they wrote themselves.

### Where are the private tests?

Two things stay out of this repo on purpose.

- **Other teams' guards.** We name them by letter only. Their code and the map from letter to team stay private, so no team is named without its yes. Results here are listed per letter in `evidence/coverage-table.md`.
- **A hidden test set.** It is in review and not part of this version yet. When it lands, the repo will hold only the set's fingerprint. Anyone can check later that the set never changed, and we can't tune our own guards to it.

### Where does the hunter run, and how secure is that?

Today the hunter is set up as a GitHub Actions workflow (`.github/workflows/hunt.yml`). **It is paused.** It has never run on GitHub, and it stays paused until its keys and its hosting are decided.

How it limits damage:

- It can only read the repo (`permissions: contents: read`). It never pushes or commits. Results leave only as a downloadable file attached to the run.
- Everything it reads is treated as untrusted: paper abstracts, news, and the model's own replies. None of it is run. The validator checks it as data, as described above. The model has no tools, so a model fooled by a crafted page can at worst waste a few calls or propose a junk attack that the validator rejects.
- For papers, the model runs on NEAR AI Cloud private inference. Before its first call, the hunt fetches NEAR's attestation report (a signed record from NEAR's secure hardware of which model is answering), checks it and saves it. You can re-check a saved report offline: `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json`. Only 1 of the 7 hunts so far ran this way. The others used Muse Spark, which has no attestation.

What this doesn't protect:

- The attestation shows which model answered. It doesn't show that an attack is good or that a result is right.
- The rest of the loop (fetching papers, validating, running the sandbox) runs on GitHub's machine, outside any secure hardware.
- Known gap: the sandbox processes the hunter starts get a copy of its environment, keys included. The fix (start them with only the variables they need) is planned before the workflow runs with any key.

### Who can access the workflow, its keys and its outputs?

- The repo is public. Anyone can read the workflow file. Any signed-in GitHub user can open its run logs and download its result files.
- The keys it needs would be stored as repository secrets. GitHub never shows a saved secret again, to anyone, including the owner. No secrets are set today.
- Only accounts with write access can start a run by hand or change the workflow. Pull requests, including ones from forks, can't trigger it: it runs only on its schedule or by hand.

### If the owner's GitHub account is compromised, what can an attacker do?

They can't read the saved keys directly. They could edit the workflow so its next run sends the keys elsewhere, push code, or change the repo. That is the real risk, and every GitHub project carries it.

The defences:

- a passkey on the owner account;
- keys used only for this hunt, each with a spending cap;
- a GitHub Environment, so only the `main` branch can use the keys;
- revoking a key after any doubt.

None of these are set up today, because no keys are set. This answer will list each one as it is added. No wallet key is involved: the hunter only spends on model and news calls.

### Can the hunter run on NEAR, in secure hardware, instead of GitHub Actions?

Partly, today. The model calls for papers already run inside NEAR AI Cloud's secure hardware. We looked at moving the whole loop:

- **NEAR AI Cloud** runs private model calls. We found no way to run our own program there.
- **NEAR Shade Agents** (agents that run in secure hardware and are registered on chain): NEAR's docs say not to use the framework, which hasn't been maintained since April 2026.
- **A Phala secure container** could run the whole hunter and prove which exact code ran. We haven't confirmed that the local NEAR sandbox runs inside one, and it is not set up.

Everything the hunter reads is public, so a sealed machine adds little secrecy. What it would add is proof of which code produced each result. Until one is in place, the honest answer is no: the hunter's loop doesn't run on NEAR yet.
