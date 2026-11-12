# Admission-2 survey, 2026-11-12: which one-flaw reference does each unspecified attack break?

Before writing any spec, each non-race attack without a spec was run ONCE on vault-a and on the mutants whose one flaw it could plausibly reach
(plus intents-honest / intents-planted for ai-10). Local sandbox, one fresh sandbox per run, through tools/hunter/runner.py run_one (the gate's own path),
harness built from commit 1a39fdb (`cargo build --release --offline`). Script: a 40-line loop over runner.run_one, not committed (it only calls run_one).

What this decides: the specs written in commit fd6564e name the reference and amount seen here; the gate (tools/admission/admit.py, 3 runs each) then
decides the class. A single survey run is NOT validation. Raw results: the `*.result.json` files next to this file (file name = attack__reference).

What it does not cover: race attacks (the gate cannot count them yet, no receipt trace), the bypass files, intents-02, and attacks whose pays are all valid
(their reasons are in tools/admission/unvalidated.json).

| attack | reference | beyond policy | call outcomes (guard's panic message) | result sha256 |
|---|---|---|---|---|
| 04-cap-fill-then-big | mutant-M2 | 450 | ok; ok; ok; ok | `9c794266b03c` |
| 04-cap-fill-then-big | mutant-M3 | 0 | ok; ok; ok; contract-failure (daily cap exceeded) | `be8e805300a1` |
| 04-cap-fill-then-big | vault-a | 0 | ok; ok; ok; contract-failure (daily cap exceeded) | `8c19f0a20adc` |
| 06-pay-after-expiry | mutant-M6 | 300 | ok | `151b8d17017a` |
| 06-pay-after-expiry | vault-a | 0 | contract-failure (invoice expired) | `555baa5fa72d` |
| 07-lowgas-fail-expired-retry | mutant-M6 | 0 | ok; contract-failure (invoice already paid) | `1a76cd4eef4e` |
| 07-lowgas-fail-expired-retry | vault-a | 0 | ok; contract-failure (invoice already paid) | `8f4bc041cc36` |
| 08-lowgas-retry-double | mutant-M4 | 100 | ok; ok | `4637a37ae259` |
| 08-lowgas-retry-double | mutant-M5 | 0 | ok; contract-failure (invoice already paid) | `01b683aef151` |
| 08-lowgas-retry-double | mutant-M9 | 0 | ok; contract-failure (invoice already paid) | `d5780f0a86c3` |
| 08-lowgas-retry-double | vault-a | 0 | ok; contract-failure (invoice already paid) | `c09483a6277a` |
| 09-should-refuse-paths | mutant-M1 | 400 | contract-failure (invoice cancelled); ok; contract-failure (only the agent can pay) | `00d85f906f16` |
| 09-should-refuse-paths | mutant-M7 | 200 | ok; contract-failure (receiver is no longer a payee); contract-failure (only the agent can pay) | `c1493047253b` |
| 09-should-refuse-paths | mutant-M8 | 50 | contract-failure (invoice cancelled); contract-failure (receiver is no longer a payee); ok | `226d6c1bf310` |
| 09-should-refuse-paths | vault-a | 0 | contract-failure (invoice cancelled); contract-failure (receiver is no longer a payee); contract-failure (only the agent can pay) | `1be80bc4ad1d` |
| 10-odd-methods-direct-token | intents-honest | 0 | contract-failure (Sender and receiver should be different); protocol-rejected; contract-failure (panicked at src/lib.rs:220:46:); ok; contract-failure (not enough gas attached to pay safely); contract-failure (invoice already paid, cancelled or in fl) | `91c702c46d1c` |
| 10-odd-methods-direct-token | intents-planted | 100 | contract-failure (Sender and receiver should be different); protocol-rejected; contract-failure (panicked at src/lib.rs:218:46:); ok; contract-failure (not enough gas attached to pay safely); contract-failure (invoice already paid, cancelled or in fl) | `0504a28a97da` |
| 10-odd-methods-direct-token | mutant-M4 | 100 | contract-failure (Sender and receiver should be different); protocol-rejected; contract-failure (invoice not found); ok; contract-failure (not enough gas attached to pay safely); ok | `43a01e7add8e` |
| 10-odd-methods-direct-token | vault-a | 0 | contract-failure (Sender and receiver should be different); protocol-rejected; contract-failure (invoice not found); ok; contract-failure (not enough gas attached to pay safely); contract-failure (invoice already paid) | `ff7b35752d52` |
| n59ee7b18-3-morse-code-disallowed-pay-orde | mutant-M2 | 200 | ok; contract-failure (invoice cancelled); ok | `3703ba08a948` |
| n59ee7b18-3-morse-code-disallowed-pay-orde | mutant-M3 | 0 | ok; contract-failure (invoice cancelled); contract-failure (daily cap exceeded) | `e289d5f71daf` |
| n59ee7b18-3-morse-code-disallowed-pay-orde | mutant-M7 | 200 | ok; ok; contract-failure (daily cap exceeded) | `918eeee1604d` |
| n59ee7b18-3-morse-code-disallowed-pay-orde | vault-a | 0 | ok; contract-failure (invoice cancelled); contract-failure (daily cap exceeded) | `82594b3e17a3` |
| nae93287b-1-persistent-claude-md-injection | mutant-M2 | 350 | ok; ok; ok | `bf61f4758955` |
| nae93287b-1-persistent-claude-md-injection | mutant-M3 | 0 | ok; ok; contract-failure (daily cap exceeded) | `21b344c6d6de` |
| nae93287b-1-persistent-claude-md-injection | vault-a | 0 | ok; ok; contract-failure (daily cap exceeded) | `33e815dabab0` |
| nae93287b-2-unsafe-skill-batch-pay-all | mutant-M1 | 0 | ok; ok; contract-failure (invoice cancelled); contract-failure (daily cap exceeded); contract-failure (daily cap exceeded) | `aaea6ed92a5b` |
| nae93287b-2-unsafe-skill-batch-pay-all | mutant-M2 | 50 | ok; ok; contract-failure (invoice cancelled); ok; contract-failure (receiver is no longer a payee) | `5d398b2d400b` |
| nae93287b-2-unsafe-skill-batch-pay-all | mutant-M6 | 0 | ok; ok; contract-failure (invoice cancelled); contract-failure (daily cap exceeded); contract-failure (receiver is no longer a payee) | `29908417df36` |
| nae93287b-2-unsafe-skill-batch-pay-all | mutant-M7 | 200 | ok; ok; ok; contract-failure (daily cap exceeded); contract-failure (receiver is no longer a payee) | `90ca8fbc6618` |
| nae93287b-2-unsafe-skill-batch-pay-all | vault-a | 0 | ok; ok; contract-failure (invoice cancelled); contract-failure (daily cap exceeded); contract-failure (receiver is no longer a payee) | `1c6927a8ef92` |
| nf473f3d4-1-devops-sealed-silent-pay | mutant-M2 | 650 | ok; ok; ok; contract-failure (invoice cancelled); ok; contract-failure (receiver is no longer a payee) | `d2a40565327d` |
| nf473f3d4-1-devops-sealed-silent-pay | mutant-M3 | 50 | ok; ok; contract-failure (daily cap exceeded); contract-failure (invoice cancelled); ok; contract-failure (receiver is no longer a payee) | `271e916be74a` |
| nf473f3d4-1-devops-sealed-silent-pay | mutant-M7 | 200 | ok; ok; contract-failure (daily cap exceeded); ok; contract-failure (daily cap exceeded); contract-failure (receiver is no longer a payee) | `2df1a3e18671` |
| nf473f3d4-1-devops-sealed-silent-pay | vault-a | 0 | ok; ok; contract-failure (daily cap exceeded); contract-failure (invoice cancelled); contract-failure (daily cap exceeded); contract-failure (receiver is no longer a payee) | `4913b8ff6e36` |
| p210408638-2-reentrancy-callback-window-ret | mutant-M4 | 200 | ok; ok | `c7eda8430ef8` |
| p210408638-2-reentrancy-callback-window-ret | mutant-M5 | 0 | ok; contract-failure (invoice already paid) | `cf9217629083` |
| p210408638-2-reentrancy-callback-window-ret | vault-a | 0 | ok; contract-failure (invoice already paid) | `f7796e253c9a` |
| p261108811-2-untagged-deliberation-cancel-r | mutant-M1 | 400 | ok; contract-failure (invoice cancelled); ok | `4006fee4eb38` |
| p261108811-2-untagged-deliberation-cancel-r | mutant-M7 | 200 | ok; ok; contract-failure (receiver is no longer a payee) | `b3896092ff84` |
| p261108811-2-untagged-deliberation-cancel-r | vault-a | 0 | ok; contract-failure (invoice cancelled); contract-failure (receiver is no longer a payee) | `91e8add7a9d1` |
| p261108811-3-stealth-thought-no-disclosure | mutant-M2 | 700 | ok; ok; ok; ok | `0553366e1864` |
| p261108811-3-stealth-thought-no-disclosure | mutant-M3 | 100 | ok; ok; contract-failure (daily cap exceeded); ok | `d34261c68d71` |
| p261108811-3-stealth-thought-no-disclosure | mutant-M6 | 0 | ok; ok; contract-failure (daily cap exceeded); contract-failure (daily cap exceeded) | `bd1c2e1b7321` |
| p261108811-3-stealth-thought-no-disclosure | vault-a | 0 | ok; ok; contract-failure (daily cap exceeded); contract-failure (daily cap exceeded) | `480d61882e58` |
| p261111305-3-guardian-blinding-plan-poison | mutant-M2 | 300 | ok; ok | `05dc8f0ed3a2` |
| p261111305-3-guardian-blinding-plan-poison | mutant-M3 | 0 | ok; contract-failure (daily cap exceeded) | `217370f70f65` |
| p261111305-3-guardian-blinding-plan-poison | vault-a | 0 | ok; contract-failure (daily cap exceeded) | `e3accd71680f` |
| p261111506-1-fence-multi-call-schedule-esca | mutant-M2 | 200 | ok; ok; contract-failure (invoice already paid) | `5598b29d9246` |
| p261111506-1-fence-multi-call-schedule-esca | mutant-M4 | 100 | ok; contract-failure (daily cap exceeded); ok | `dfce202d5a41` |
| p261111506-1-fence-multi-call-schedule-esca | vault-a | 0 | ok; contract-failure (daily cap exceeded); contract-failure (invoice already paid) | `e692eb2d2170` |
