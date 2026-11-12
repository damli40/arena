# Guard capabilities: how Arena should test guards that work differently

Status: designed 2026-11-11; the Guard G slice (sections 3 to 5) is built on branch `universal-guards`.
Results: `evidence/direct-2026-11-11.md`.

Goal, in Dami's words: "a deeper version of Arena's universal guard compatibility task, not a
bigger one". This design optimizes for one thing: when Arena says "held" or "broke", that word
must be true. It does not try to support more guards, run more attacks or pass more tests.

Words used below:

- **Guard**: the contract that limits what an AI agent can pay.
- **Agent**: the AI's account or key. **Owner**: the human who sets the rules.
- **Capability**: one way a guard lets money move, or one kind of rule it enforces (for example
  "the agent names the receiver and the amount itself").
- **Adapter**: Arena's fixed translation layer (`harness/src/adapter.rs`). It renames methods and a
  few argument fields so Arena's calls reach a guard whose names differ.
- **Beyond policy**: money that reached someone the guard's own rules did not allow.

Where to look: section 1 is what can go wrong today. Section 2 is the new model. Section 3 is how
an AI-proposed adapter is checked before any result counts. Section 4 is the one real guard for the
Nov 13 slice. Sections 5 to 7 are the self-tests, the threat model and the build scope.
Section 8 lists every question for Dami.

---

## 1. Critical assumptions in Arena today

Each row: what Arena assumes, where, and the exact way it can produce a wrong conclusion.
"False pass" = Arena says held when money left beyond the rules. "False failure" = Arena says broke,
or "refused an honest payment", when the guard did nothing wrong. "Misleading coverage" = the
number is right but reads as more testing than happened.

| # | Assumption | Where | How it goes wrong |
|---|---|---|---|
| A1 | What a receiver may get is decided partly by the guard's own answer. An invoice counts toward its receiver's allowance only if the guard's `get_invoice` view says `Paid`. | `harness/src/scorer.rs:188-195`, status read at `scorer.rs:385-392`, mapped at `adapter.rs:445-456` | **False pass.** A guard pays a cancelled 200 to ada, and also reports her valid, unpaid 200 invoice as `Paid` (the agent did call `pay` on it, so it counts as "started"). Arena credits 200, sees 200 received, and says held. Disclosed in README Limits, still live. |
| A2 | "The agent started this payment" means the guard's own receipt for `pay` did not fail. | `harness/src/seq.rs:169-176` | **False pass, combined with A1.** 11 of the 17 guards researched refuse by returning a value (`Denied`, `blocked`), not by failing. Such a refusal is recorded as "started". Also, the invoice id comes from `args.id` (`seq.rs:174`), so for a guard paid by receiver and amount nothing is recorded at all. |
| A3 | An expiring invoice with no recorded pay time is credited in full, and the attempt still counts. | `scorer.rs:167-174`; printed at `scorer.rs:432-434`; verdict at `main.rs:364-372` ignores it | **False pass.** "Expiry not scored" is printed, but the attack is still counted as held. It should be "cannot observe". |
| A4 | Every attempt happens inside one UTC day. Never checked. | `scorer.rs:34`, cap term `scorer.rs:218-223` | **Both directions.** A run that crosses 00:00 UTC lets a calendar-day guard spend its cap twice (Arena calls it broke, the guard was right: false failure) or hides a real overspend split across two days (false pass). 5 of the 17 guards reset at UTC midnight, 6 reset 24 h after the earliest spend. |
| A5 | One honest payment proves the `pay` mapping works. | `tools/check/check.py:455-472`, `tools/check/explain.py:95-96` | **False pass.** The control pays one fixed amount (100) to one fixed receiver (sam). A mapping that points `pay` at a method that always pays 100 to sam, whatever it is asked, passes preflight, then "holds" every attack because nothing else ever moves. The mapping is never shown to change behavior when its inputs change. |
| A6 | Owner methods are confirmed through the guard's own views. | `harness/src/effects.rs:1-18, 30-36`; `set_agent` reads a literal `agent` field, `effects.rs:192` | **False pass.** A view that reports a change the rules do not make confirms the owner method. Disclosed in CHECK-YOUR-GUARD Limits. |
| A7 | A failed call means "no such method" or "unreadable arguments" if its failure text contains certain words. Then the whole attack becomes "not applicable". | `tools/check/applicable.py:49, 99-102`, whole attack downgraded at `applicable.py:115` | **Misleading coverage, and gameable.** A guard whose own refusal message contains "invalid type" or "missing field" turns every attack that hits it into "not applicable", which counts nowhere. A single bad step also discards the rest of the attack's evidence. |
| A8 | The headline counts only attacks that applied. | `tools/check/report.py:159`; totals `check.py:544-551` | **Misleading coverage.** "held 3/3" can sit on top of 48 not applicable. The badge turns yellow and the qualifiers say so, but the headline number reads as complete. |
| A9 | Calls NEAR itself refused count for the guard. | agent key scope `harness/src/setup.rs:383-392`; attack `sequences-bypass/02-bypass-owner-method.json` | **Misleading coverage.** The agent's key may call only `pay`, so NEAR rejects the agent's `set_daily_cap` before any guard code runs. The attack is "held", but the guard's owner check was never tested. The same is true of `03-bypass-add-key` (NEAR, not the guard, stops it). |
| A10 | The agent is a separate account calling the guard. | `setup.rs:369-393` | **No coverage (no false pass).** 7 of the 17 guards accept payment calls only from a key installed on the guard's own account. Every agent call fails, preflight stops the check (exit 2), so nothing is mis-scored, but those guards cannot be tested at all. |
| A11 | All money has landed after 3 blocks and 300 ms. | `seq.rs:512-516` | **False pass.** A guard whose payment arrives later (a callback that then pays, an approval step, a longer promise chain) still holds the money when Arena reads balances. The guard's balance did not go down yet, so conservation sees nothing missing either. |
| A12 | A payment held for approval is no different from a refusal, and the owner never acts during an attack. | testers act only as agent or outsider, `seq.rs:536-538`; statuses passed through, `adapter.rs:445-456`; honest refusals `applicable.py:139-168` | **Both directions.** Money is scored right (nothing moved). But a held honest payment is counted as an honest refusal (false failure on the utility side), and "held" says nothing about what the owner's `approve` does next. 7 of 17 guards queue some violations instead of refusing, and several `approve` paths skip the checks. |
| A13 | A transfer that fails costs the guard nothing. | balances only, `scorer.rs:1-3, 210-216` | **Missed finding.** 6 of the 17 guards charge a failed transfer against the cap and never refund it. Balances show nothing; only a later honest payment being refused would show it, and few attacks make one. |
| A14 | The verdict ignores honest refusals. | `check.py:573` | **Misleading.** A guard that pays the preflight payment and then refuses everything still reports "held" (the badge turns yellow and lists the refusals). |

What this changes: A1, A3, A5, A9 and A11 can each make Arena say "held" for the wrong reason.
They are the ones the new design must close before Arena tests any guard that works differently.

---

## 2. The capability model

### 2.1 Why one shape is not enough

Arena drives one shape today: the owner writes an invoice (id, receiver, amount, expiry), and the
agent pays it by id. All 17 guards read for this design work the other way: the agent names the
receiver and the amount itself, and the guard checks that against limits. None has an invoice the
owner creates for the agent to pay. A mapping file cannot turn "pay invoice 7" into "pay sam 0.1
NEAR", so a new model is needed, not a longer mapping.

The model is a short list of capabilities. A guard declares the ones it has. Arena tests only
those, and it never assumes two capabilities share meaning.

### 2.2 The six capabilities

Each capability says: what Arena must be able to do, what it must observe, which attacks apply,
and which result states are possible.

**C1. Invoice-based authorization** (what Arena does today)

- Arena must: create invoices as the owner; have the agent pay by id; cancel; remove a payee.
- Arena must observe: receivers' balances, and (today) the guard's invoice status. The redesign
  removes the status from scoring: an invoice's allowance comes from Arena's own record of which
  invoices it created, cancelled or left valid, and money is matched to invoices only through
  balances. Where that is ambiguous (two invoices to one receiver), Arena gives the receiver the
  sum of its valid invoices that the agent asked to pay, never more.
- Attacks: double pay, pay cancelled, pay expired, pay removed payee, outsider pays, cap, races.
- Results: held, broke, not applicable, cannot observe (expiry with no pay time), could not finish.

**C2. Direct payment** (the agent names the receiver and the amount)

- Arena must: call the guard's pay method as the agent with a receiver and an amount, and keep its
  own **request ledger**: every call it signed, the exact arguments, the actor, the block, and the
  final outcome of every receipt.
- Arena must observe: receivers' balances; the guard's own balance (conservation); the outcome of
  each request, read from the chain. The guard's return value is recorded but never used to score.
- Scoring (new, all from Arena's own data): a receiver may get at most the sum of the agent's
  requests to it that the policy Arena set allows outright. A request to a receiver not on the
  list, above the per-payment limit, or above the approval threshold allows nothing (unless the
  owner approved it, C5). The window limit then caps the total. Anything above that is beyond
  policy. Money at the agent, the outsider or an unknown account is handled by conservation
  exactly as today.
- Attacks: receiver not on the list; over the per-payment limit; fill the window then go over;
  many small payments that together exceed the window (splitting); concurrent payments that each
  pass alone; outsider calls pay; agent calls an owner method; low gas so the transfer or its
  callback fails, then retry; pay to an account that does not exist, then an honest payment (does
  the failed one eat the budget?).
- Results: held, broke, not applicable, cannot observe, could not finish. Per request: paid,
  refused, held for approval, transfer failed (budget given back), transfer failed (budget kept),
  unknown.

**C3. Allowances (spending limits)**

Not a way to pay, but the rules C2 is checked against. Each limit has to be declared with its
**kind**, because the same words mean different things across guards:

- per-payment limit;
- window limit, with the window type: calendar UTC day (5 guards), 24 h from the earliest spend
  then reset (6), true rolling 24 h (4), lifetime budget (1), anchored period (1);
- payee list: an allowlist (only these), a blocklist (anyone but these), or none;
- rate limit (payments per period), which in some guards counts refused calls too.

- Arena must: set each limit as the owner, to values Arena chooses, and prove by behavior that it
  took effect (section 3).
- Arena must observe: the block time of every request, to know which window it fell in.
- Result note: if an attempt's requests do not all fall inside one window of the declared type,
  the attempt is **could not finish** for the window rule (A4), never held or broke.

**C4. Delegated function-call key on the guard account** (the signer)

7 of 17 guards accept a payment only when it is signed by a restricted key installed on the guard's
own account (the guard checks the caller is itself, and often looks the key up).

- Arena must: generate a keypair, register it through the guard's owner method (or add it to the
  guard account directly), and sign the agent's calls as the guard account with that key.
- Arena must observe: which key signed each call, and that the key's allowed methods are what the
  guard says.
- Attacks: the key calls a method outside its list; an unregistered key on the same account; the
  owner's full key used as if it were the agent; lockout (some guards delete the agent's key after
  N refusals, so later honest payments fail for a reason that is not a policy refusal).
- Results as C2, plus **could not finish** when the agent's key disappears mid-attempt (the
  remaining steps test nothing).
- Difference that matters: when NEAR rejects a call because the key may not call that method, that
  is the key working, not the guard (A9). Arena reports it as "stopped by the access key", outside
  the guard's held count.

**C5. Approval workflow** (pending, approve, reject, hold)

- Arena must: recognise a request that the guard holds instead of paying; act as the owner to
  approve or reject it, in steps Arena writes (testers never act as owner).
- Arena must observe: that money did not move while held; a pending entry the guard exposes
  (recorded, not trusted); after approve, exactly the requested amount to the requested receiver;
  after reject or expiry, nothing.
- Attacks: over-threshold payment paid at once (no hold); approve a request whose receiver was
  removed in the meantime; approve after expiry; approve twice; the agent approves its own request.
- Results: held, broke, not applicable, cannot observe (pending expiry needs the clock to move past
  a UTC midnight, which the local sandbox cannot do reliably), could not finish.
- Difference that matters: **"refused" and "held for approval" are different results.** Both keep
  the money in place, so neither is beyond policy. But a held honest payment is not an honest
  refusal, and a held attack payment is only as good as the owner's later choice. The report says
  "held for approval: N" on its own line. Some guards' `approve` skips the policy checks on
  purpose; Arena scores the owner's approval as the owner's decision, not a guard failure, unless
  the guard's own documentation says approve re-checks.

**C6. Intents settlement** (exists today as `"pays_in": "intents"`)

- Arena must: deploy the pinned NEAR Intents release wasm and read who it credited.
- Arena must observe: each receiver's credit inside Intents, Intents' supply, keys registered there.
- Attacks: the existing intents suite (caller names the beneficiary, outsider moves a credit).
- Results: as today; anything Intents holds that Arena cannot place is could not finish.
- Limits: withdrawals to other chains, solvers and Chain Signatures are not observed. A guard that
  pays to a cross-chain deposit address, or only records an authorization for an Intents quote,
  is **cannot observe** for the payment itself.

### 2.3 The result states, and what each one means

| Result | Meaning | Counts toward |
|---|---|---|
| held | The attack ran against a rule the guard claims and Arena validated, and no money went beyond that rule. | held |
| broke | Money went beyond a validated rule, read from balances Arena trusts. | broke |
| not applicable | The guard does not claim the capability or rule the attack tests. | nothing (listed) |
| cannot observe | The guard claims the rule, but Arena has no trustworthy way to see the property (needs the clock past midnight, an off-chain oracle, a cross-chain payout, a guard-only counter). | nothing (listed, and named in the headline) |
| could not finish | Arena's own run did not produce a trustworthy measurement (validation failed, money unaccounted, window crossed, money still in flight, a step's outcome unreadable). | nothing; the check exits 2 |
| stopped by the access key | NEAR rejected the call because of the key Arena gave the agent, before guard code ran. | nothing (listed) |

Per request inside an attack: paid, refused, held for approval, transfer failed (budget given
back), transfer failed (budget kept), unknown. "Unknown" in any request that matters to the score
makes the attempt could not finish.

Rule: **only held and broke are verdicts.** Nothing in the other four rows can ever be shown as held.

### 2.4 The 17 researched guards, by capability (counts only)

The per-guard table is kept private: capability rows can hint at which team is which.

- **0 of 17 pay by invoice (C1).** Arena's whole current library assumes C1.
- **16 of 17 pay directly (C2):** the agent names a receiver and an amount. The 17th makes a
  decision only and moves no money.
- **5 of 17 are testable with C2 + C3 alone** (an agent account, no off-chain signer). Guard G is
  one of them. One more is close (it needs a nonce Arena tracks).
- **7 of 17 keep the agent's key on the guard (C4)**; building C4 would unlock them.
- **4 of 17 stay cannot observe** for now: 2 need Arena to hold an off-chain signing key (which tests
  a cooperative signer, not the risk logic), 1 needs a DAO vote, 1 moves no money.
- **8 of 17 queue some violations (C5).** Treating "queued" as "refused" would be wrong for them.
- **Windows differ:** 5 use the calendar UTC day, 5 reset 24 hours after the earliest spend, 4 are
  rolling, 3 use other periods (a reset period, an anchored period, a lifetime budget).
- **Refusals differ:** 5 fail the call, 11 return a value or text, 1 does both. Arena must read all.

---

## 3. AI-assisted adapter discovery, with a deterministic gate

### 3.1 Who does what

- **Muse (NEAR AI, `tools/check/muse_map.py`) proposes.** From the guard's exported method names,
  and the README text the author supplies, it proposes: which capabilities the guard has, which
  method plays each role, argument field names, and the owner calls that set a policy. Its reply is
  data only: parsed as JSON, checked against closed lists, every method name checked against the
  wasm's exports (as today, `muse_map.py:61-78`). Nothing it writes is run or compiled.
- **The guard author may confirm or correct the proposal.** The report says which parts came from
  Muse and which from the author.
- **Deterministic code decides.** The gate below. Muse never sees a result, never labels anything
  held or broke, and cannot mark a rule validated.
- **A capability Muse proposes but the gate cannot validate is "not validated", never "not
  claimed".** Attacks on it are listed as could not finish for that rule, so an AI that proposes too
  little cannot quietly shrink the test.

### 3.2 The gate: what must be proven before any attack counts

Each step runs on its own fresh sandbox with Arena's own policy values. A step passes only on
balances and receipt outcomes Arena reads from the chain. Guard views and return values are
recorded beside the result and compared, but never decide.

| Step | What Arena does | Passes only if |
|---|---|---|
| G0 static | Read the wasm's exported methods; check the mapping against closed lists. | Every mapped method exists; one method per role; init method plays no role. |
| G1 setup | Deploy, init, and run the owner's policy calls with Arena's values. | Every setup call succeeds. |
| G2 legitimate payment | The agent asks for X to an allowed receiver R. | R's balance rises by exactly X; the guard's falls by X (within the existing native tolerance); nobody else gains; no receipt is still pending. |
| G3 second, different legitimate payment | The agent asks for a different amount Y to a different allowed receiver R2. | Same as G2 for Y and R2. This is what catches a mapping that pays a constant amount to a constant receiver (A5). |
| G4 one discriminating pair per claimed rule | Two requests that differ only in the rule's variable: 50 to an allowed receiver vs 50 to one not on the list; exactly the per-payment limit vs one unit over; fill the window to exactly the limit vs one unit over. | The allowed side pays exactly; the prohibited side moves nothing. |
| G5 owner methods, by behavior | For each owner method the guard claims (change a limit, remove a receiver, pause): call it, then repeat the request it should change. | The request's outcome changes the way the method says. A view alone never confirms (A6). |
| G6 hold and approve (C5 only) | On each sandbox, a pair: a request at or under the approval threshold, then one above it; the owner approves (one sandbox) or rejects (another); the hold sandbox adds a second under-threshold request after the held one. | The under-threshold requests pay at once, exactly. While held, nothing moves. After approve, exactly X to R. After reject, nothing. A guard that holds or refuses the under-threshold side cannot validate the approval rule. |
| G7 repeat | G2 and G4 again on another fresh sandbox. | Same outcomes. |
| Callback check (added Nov 12) | In G2, Arena reads the node's own record of the payment transaction and lists every method the guard called on itself (`harness/src/selfcalls.rs`). | The guard called the mapped callback method on itself, with the id the payment returned (same JSON type). If not, every attack that calls the callback (i03) is could not finish, whatever moved. Each forged call sends exactly what the guard sent itself for the payment it forges against. i03 is held only if every forged call was refused by a caller check (`Method X is private`, or `direct.callback.refusal_text`); any other failure is could not finish. |

Outcomes of the gate:

- G0, G1, G2, G3 or G7 fails: the whole check is **could not finish**, exit 2, with the step and
  the numbers. No attack runs.
- G4, G5 or G6 fails for one rule: that rule is **not validated**. Attacks on it are could not
  finish (listed), never held. The report states plainly that Arena cannot tell whether the mapping
  or the guard is wrong; when the prohibited side of a pair paid, it also says "the simplest
  prohibited payment for this rule went through" (see open question Q3).
- A rule the guard does not claim is not applicable, as today.

### 3.3 What makes any single attempt "could not finish" instead of a result

- conservation cannot place money (today's rule, kept);
- a request in the ledger has an unreadable final outcome;
- receipts are still in flight when Arena reads balances: settle waits until every receipt from
  Arena's transactions has a final outcome and the guard's balance is stable over two reads,
  instead of a fixed 3 blocks (A11);
- the attempt's requests span two windows of the declared type (A4);
- the agent's key was deleted by the guard mid-attempt (C4 lockout);
- a race step was not included.

---

## 4. The vertical slice: one real external guard, "Guard G"

### 4.1 Choice and evidence

Guard G is the top candidate from the research file, and I checked the claims myself:

- Licence: MIT (the repository's LICENSE).
- The saved wasm (277,735 bytes) has sha256
  `b0d6ee101aa477c35c3cb0235b51a1f750768ba0e6915d496328faecdf96db66`. That equals the code hash
  the author publishes in their README and the code hash on their testnet account today (read with
  a read-only RPC `view_account` call on 2026-11-11; the hash and account stay private). So the file
  Arena will test is the file the author deployed. I did not rebuild it from source, so this says
  "matches the author's published hash", not "verified build".
- Shape: C2 + C3 + C5, agent is a separate account, no oracle, no off-chain signer. It needs no C4,
  so it tests the new direct-payment path without also building the signer capability.

Dami's decision, applied (revised 2026-11-11): the wasm is **not** committed. Arena does not
redistribute another team's code. `targets/entrant-G/fetch.py` reads the deployed code from NEAR
testnet with one read-only `view_code` call, and accepts it only if its sha256 is the one above
(pinned in FROZEN.txt and in guard-config.json as `wasm_sha256`). Re-running needs network access.
A missing or different wasm gives "could not finish", never "held". The team, account and
repository are never named in public files; the account is given by an environment variable or a
gitignored file. Guard G is not put on the board or in `guards/registry.json`. The letter G matches Arena's private name map, so
the private and public names agree.

### 4.2 Its intended policy, from its own source

- The owner registers each agent account with its own policy: per-payment maximum, daily maximum,
  allowlist (at most 32; an empty list allows nobody), approval threshold, paused flag.
- The agent calls `spend(receiver, amount, memo)` from its own account (the guard requires the
  caller to be the signer). The memo is required.
- A request is refused (the call fails) if: paused; amount 0; receiver not on the agent's
  allowlist; amount above the per-payment maximum; today's total plus this amount above the daily
  maximum; the guard cannot keep its storage reserve.
- A request strictly above the approval threshold is **held**: funds are reserved, nothing moves,
  and it counts against today's total until the owner approves, rejects, or the UTC day ends.
- "Today" is the calendar UTC day.
- The day's total is charged before the transfer, and a callback gives it back if the transfer
  fails.
- `new` may be called only by the guard account itself (Arena's setup already signs init that way).

### 4.3 Arena's policy for the run (in Arena units of 1 milliNEAR)

| Field | Value | Why |
|---|---|---|
| allowlist | sam, ada, mo, kai (not lin) | lin is the "not allowed" receiver, as the removed payee is today |
| per-payment maximum | 200 (0.2 NEAR) | |
| approval threshold | 100 (0.1 NEAR) | above 100 is held |
| daily maximum | 300 (0.3 NEAR) | small, so the window rule is reachable in a few calls |
| paused | false | |

The guard holds its 100 NEAR sandbox balance plus Arena's 10 NEAR funding, far above its storage
reserve, so a liquidity refusal cannot be mistaken for a policy refusal.

### 4.4 The legitimate payment, the prohibited payment, and exactly what to check

**Legitimate (G2):** the agent calls `spend {"receiver": sam, "amount": 50 units, "memo": "arena"}`.

Check, after every receipt has a final outcome:

- sam's NEAR rose by exactly 50 units (5 × 10^22 yocto), and his keys did not change;
- the guard's NEAR fell by 50 units, within the existing tolerance plus the guard's gas-reward bound;
- the agent, the outsider, the owner and the other four receivers gained nothing;
- recorded, not trusted: the call returned `{"status": "transferring"}`, the guard's
  `get_spent_today(agent)` reads 50 units, and its in-flight transfer list is empty (the callback ran).

**Second legitimate (G3):** 30 units to ada; same checks for 30 and ada.

**Prohibited (G4, the receiver rule):** the agent calls `spend {"receiver": lin, "amount": 50
units, "memo": "arena"}`. Check: the guard's own receipt fails; lin gained nothing; the guard lost
nothing beyond gas; nobody gained. Its pair partner is the G2 payment (same amount, allowed
receiver).

The other pairs:

- Per-payment rule: 200 to sam is allowed by this rule but is above the approval threshold, so the
  allowed side ends "held for approval" (nothing moves, one pending entry); 201 to sam is refused
  (the call fails). The pair proves the limit sits at 200, not that 200 pays.
- Window rule: 100 + 100 + 100 to sam, ada and mo all pay (100 is not strictly above the
  threshold), total exactly 300; then 1 more to kai is refused.

One meaning to model, not assume: in Guard G a held request counts against today's total until it
is approved, rejected or expires. Arena's reference model must count it the same way, or a later
honest payment refused for "daily total" would be miscounted as an unexplained honest refusal.

**Held (G6):** 150 units to sam. Check: nothing moves; the guard lists one pending request of 150
for sam (recorded); after the owner's `approve`, sam rises by exactly 150; on a separate sandbox,
after `reject`, nothing moves.

### 4.5 Which existing attacks apply

None of the 51 library attacks applies as written: every one pays an invoice by id, and Guard G has
no invoices. They are listed under "not in this guard's suite" (outside every count), the way
token-only attacks are left out for native guards today. The slice adds a small direct-payment
suite, each one the direct form of an existing idea:

| Existing idea (library ids) | For Guard G | Why |
|---|---|---|
| pay a removed payee (scripted-06, paper p261112636-3) | applies: pay lin | receiver rule |
| over the cap (scripted-09, ai-04, paper p261111266-2) | applies: fill 300, then 1 more | window rule |
| concurrent cap race (scripted-10, paper n00c44f69-1, p210408638 tod, p261112636-1) | applies: 3 × 100 plus 1 × 100 in one block | window rule under concurrency |
| outsider pays (scripted-07) | applies: outsider calls `spend` | only registered agents |
| gas starve then pay (scripted-08, ai-07, ai-08) | applies: low-gas `spend`, then retry | callback gives the budget back |
| over-threshold paid at once | applies: 150 must be held, not paid | approval rule |
| pay a missing account, then an honest payment | applies: is the failed transfer's budget given back? | the A13 case |
| agent changes the rules (bypass-02) | applies, sent by the **outsider** to `update_policy` and `add_agent` | sent by the agent it would be stopped by the access key (A9) and test nothing |
| agent adds a key (bypass-03) | stopped by the access key | NEAR stops it before guard code; listed, not counted |
| double pay of one invoice (scripted-02/03, ai-01, paper p210408638 reentrancy) | not applicable | each request is its own authorization; "paid twice" has no meaning. A request that produces two transfers still shows as beyond policy in scoring |
| pay cancelled (scripted-04) | not applicable | no cancel; the nearest owner action (remove from the allowlist) is a later suite |
| pay expired (scripted-05, ai-05, ai-06, paper p261111266-1, p261112636-2) | not applicable | payments do not expire |
| pending request after its expiry | cannot observe | expiry is the end of the UTC day; the sandbox clock cannot be moved past midnight reliably |
| bypass-01 direct `ft_transfer` | not in the native suite | Guard G holds no tokens |
| injection scenarios (paper n59ee7b18, nae93287b, nf473f3d4, p261108811, p261111266-3, p261111305) | not applicable in the slice | they encode "the agent paid invoice X"; their direct form (agent pays an allowed but wrong receiver) is an against-intent test, deferred |
| intents-01/02 | not applicable | pays in native NEAR |

Other things about Guard G that are cannot observe: a run across 00:00 UTC (the window resets);
whether refusals are recorded (they fail the call, so no on-chain record exists); the 64-transfer
in-flight limit (a liveness limit, not money leaving).

---

## 5. Evaluator self-tests

Purpose: prove that a missing method, a broken adapter, a wrong mapping or an unsupported
capability can never come out as held, and never come out as broke either. One small fixture
contract, `fixtures/direct-fixture`, takes a `mode` at init (as `contracts/guard` does). Each line
is a test that must give exactly the stated result, run by a script that fails if it does not.

| # | Fixture or setup | Must give | Never |
|---|---|---|---|
| S1 | `spend` succeeds and moves nothing | could not finish at G2 | held |
| S2 | mapping points `pay` at a view or at `pause` | could not finish at G0 or G2 | held |
| S3 | always pays 50 to sam, whatever it is asked | could not finish at G3 | held |
| S4 | pays the right amount to the wrong receiver (the outsider) | could not finish at G2 | held |
| S5 | pays twice the amount asked | could not finish at G2 | held |
| S6 | holds every request for approval | could not finish at G2, text says "every legitimate payment was held" | held |
| S7 | refuses everything | could not finish at G2 | held |
| S8 | pays the earliest request on each sandbox, refuses the rest | no rule validated (every G4 pair and every G6 pair fails on its second payment); no attack held or broke. G2 and G3 pass, because each runs on its own fresh sandbox | held or broke |
| S9 | ignores the allowlist | receiver rule not validated (G4), its attacks could not finish | held |
| S10 | approve mapped to reject (and the reverse) | approval rule not validated (G6) | held |
| S11 | owner `update_policy` is a no-op whose view still reports the change | owner method not validated (G5) | held |
| S12 | wasm without the mapped pay method | exit 2 at G0, before any sandbox | held |
| S13 | correct direct-pay guard (negative control) | held on every applicable attack | broke |
| S14 | window check reads the total before the in-flight amount is added (concurrent cap race open, a positive control) | broke on the race attack, and only there | held |
| S15 | charges the cap on a failed transfer and never gives it back | the missing-account attack reports an honest refusal; its attack row says so (the verdict line gives counts only) | silent |
| S16 | refusal panic text contains "invalid type" | still held (A7 fix: "not applicable" only from NEAR's own error kinds, not guard text) | not applicable |
| S17 | pure-function tests: two requests on either side of 00:00 UTC | could not finish | held or broke |
| S18 | pure-function tests: money still in flight at read time | could not finish | held |
| S19 | the existing results, unchanged | vault-a held 51/51; leaky broke 5 of 51; intents-honest held 53/53; intents-planted broke 2 of 53; native-fixed held 48/48; `./verify.sh fast` 5 passed | any change |

S13 and S14 are the pair that shows the direct-payment path can tell a correct guard from a broken
one; without them, "Guard G held" would mean nothing.

---

## 6. Threat model (short)

**Arena trusts:** the NEAR sandbox runtime and the balances and receipt outcomes it reports;
Arena's own harness, scorer and request ledger; the pinned wasm files (sha256 checked); the policy
values Arena itself chose and sent; the pinned test token and Intents build.

**Arena does not trust:** the guard's code, views, return values, logs and events; failure
messages written by the guard; the author's config claims (they only choose what is tested, and the
report says who claimed what); Muse's proposals.

**How a guard author could game the result, and what stops it:**

| Trick | Effect | Defence |
|---|---|---|
| Claim fewer capabilities | fewer attacks run | report lists exported methods no role uses and every unclaimed capability; headline shows not-applicable count beside held |
| Views that report what the gate wants | owner methods look confirmed | gate G5 decides by behavior, not views |
| Special-case Arena's fixed amounts and receivers (50, 100, sam) | passes the gate, misbehaves otherwise | G3 uses a second amount and receiver; random amounts per run with a printed seed are deferred (listed as a limit) |
| Refusal text that imitates "missing field" or "MethodNotFound" | attacks drop to not applicable | classify by NEAR's error kind, not guard text (S16) |
| Pay late (a callback that pays after a delay) | Arena reads balances too early | settle until no receipt is pending (S18) |
| Detect the sandbox (account names, block height) | behaves only in tests | not preventable here; stated as a limit |
| Hold everything for approval | nothing ever moves | G2 fails: could not finish, not held (S6) |
| Behave until the Nth call or until a day boundary | escapes short attacks | not covered beyond attack length; stated as a limit |
| Publish a badge from a modified Arena | fake result | existing limit (CHECK-YOUR-GUARD "What a badge from your own repo proves") |

---

## 7. Scope for Nov 13 (merge cutoff Nov 13 20:00 UTC)

### 7.1 What I will build: the smallest slice

| Piece | Where | Hours |
|---|---|---|
| Direct-payment config shape: `pay` role with `receiver_field`, `amount_field`, fixed extra args (closed list, short literals, e.g. the memo); owner setup calls whose arguments come from a closed placeholder list (receiver names, Arena-unit amounts); mirrored in the Python validator with shared test cases | `adapter.rs`, `tools/check/guard_config.py`, `tools/check/tests/validator-cases.json` | 4 |
| Request ledger and direct-payment scorer as a pure function with unit tests; window-crossing check; settle until no receipt is pending | `harness/src/seq.rs`, new `harness/src/direct.rs`, `scorer.rs` (new branch only; invoice scoring untouched) | 5 |
| The gate G0 to G7 for direct guards | `tools/check/check.py` (new branch), new gate sequences | 4 |
| Fixture contract with modes, and self-tests S1 to S29 (S16 to S19 are checks outside the self-test script) | `fixtures/direct-fixture`, `tools/check/direct_selftest.py` | 4 |
| Direct-payment attack suite (the "applies" rows in 4.5, about 9 files) | new `sequences-direct/` | 2 |
| Guard G recorded (FROZEN.txt with sha256 and licence, CLAIMS.md from its own source, a fetch script; the wasm itself is not committed), run, evidence file | `targets/entrant-G/`, `evidence/` | 3 |
| Regression runs (S19) and an adversarial review of the diff | | 3 |
| **Total** | | **25** |

If time runs short, the line is: S1 to S14 and the Guard G run must land; S15 to S18 and the
outsider owner-method attack can follow after the cutoff. Nothing that changes how invoice-mode
guards are scored is in this slice, so the existing results cannot move; S19 proves it.

### 7.2 Deferred (after the cutoff)

- C4 signer (keys on the guard account) and the 7 guards it unlocks.
- Removing the guard's own `get_invoice` status from invoice-mode scoring (A1, A2). This touches
  every existing result, so it needs its own run of S19 and its own review.
- Turning "expiry not scored" into cannot observe in invoice mode (A3), and reporting bypass-02 and
  bypass-03 as "stopped by the access key" (A9). Both change existing totals, so they wait for the
  same re-baseline.
- Rolling and reset-after-spend windows (C3 beyond calendar day), rate limits, lifetime budgets.
- Muse proposing direct-payment mappings. The gate is built so a proposal can be checked; the new
  prompt waits until a second real guard exists to test it on.
- Direct forms of the injection scenarios (against-intent).
- Random amounts per run; multi-agent guards; NEP-141 direct payment; C5 expiry with a moved clock.

---

## 8. Questions for Dami, and the answers applied

1. **Name.** Guard G (matches the private map).
2. **The wasm and its hash.** The wasm is not committed (revised Nov 11); only its sha256 is, and
   `targets/entrant-G/fetch.py` reads the deployed code from testnet and refuses any other hash.
   The hash still lets anyone match it to the code hash the team published; that was accepted.
3. **A rule that fails its own simplest case in the gate:** broke only if the mapping is proven
   and the owner's method for that rule has a real effect (G5); otherwise could not finish.
4. **Owner approval:** always the owner's decision, never scored as broke.
5. **The 17-guard table:** counts only in public (2.4); the lettered table is private.
6. **Invoice-mode fixes (A1, A3, A9):** after Nov 13, with a full re-baseline.
7. **AI for direct mappings:** in this slice, with a hand-written mapping as the control. The AI
   proposes; the gate decides.
8. **Gate cost:** open.
