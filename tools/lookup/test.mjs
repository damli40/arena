// node --test tools/lookup/test.mjs
// Live tests read NEAR testnet (read-only). Set ARENA_LOOKUP_OFFLINE=1 to skip them.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { lookup, base58ToHex, STATUS, CAVEAT, DEFAULTS, OPT_IN, resolveOnchainResults } from "./arena-lookup.mjs";

const HASH = "0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e";
const HASH_B58 = "EhCoUXADTgdLnHXseYdoxREYUomy9pocMjKfHNYKGh3";
const GUARD = "some-guard.testnet";

// ---------- stubbed fetch ----------

function receipt(suite, over = {}) {
  return {
    guard_code_hash: HASH, guard_label: "x", suite, beyond_policy: "0", against_intent: null,
    tests_run: 5, tests_held: 5, harness_commit: "c".repeat(40), evidence_sha256: "e".repeat(64),
    evidence_path: "evidence/x.md", published_at: "1794327024705760594", ...over,
  };
}
const RACE_FIXED = receipt("race-double-pay:mode=fixed");
const RACE_VULN = receipt("race-double-pay:mode=vulnerable_fixture", { beyond_policy: "100", tests_held: 0 });
const PROOF = receipt("proof-pay-race-inductive", { tests_run: 30, tests_held: 30 });

const ok = (result) => ({ jsonrpc: "2.0", id: 1, result: { block_height: 1, block_hash: "B", ...result } });
const bytes = (v) => [...new TextEncoder().encode(JSON.stringify(v))];
const execError = (msg) => ok({ error: `wasm execution failed with error: ${msg}`, logs: [] });

/**
 * handlers: { account, receipts, mode, keys, optin, results } each either a value, a full RPC body (object with
 * `error` or `result`), or a function returning one; `throw` simulates a network failure.
 */
function stubFetch(h) {
  const calls = [];
  const fetch = async (url, init) => {
    const p = JSON.parse(init.body).params;
    calls.push(p);
    let key;
    if (p.request_type === "view_account") key = "account";
    else if (p.request_type === "view_access_key_list") key = "keys";
    else if (p.method_name === "receipts_for") key = "receipts";
    else if (p.method_name === "get_mode") key = "mode";
    else if (p.method_name === "opt_in_of") key = "optin";
    else if (p.method_name === "arena_results_for") key = "results";
    let v = h[key];
    if (typeof v === "function") v = v(p);
    if (v === "throw") throw new TypeError("fetch failed");
    if (v && v.httpStatus) return { ok: false, status: v.httpStatus, json: async () => { throw new SyntaxError("x"); } };
    let body;
    if (v && (v.error || v.result)) body = v;
    else if (key === "account") body = ok({ code_hash: HASH_B58, amount: "1", locked: "0", storage_usage: 1 });
    else if (key === "keys") body = ok({ keys: [] });
    else body = ok({ result: bytes(v), logs: [] });
    return { ok: true, status: 200, json: async () => body };
  };
  return { fetch, calls };
}

async function run(h, opts = {}) {
  const s = stubFetch(h);
  const a = await lookup(GUARD, { fetch: s.fetch, ...opts });
  return { a, calls: s.calls };
}

function assertEveryAnswerShape(a) {
  assert.equal(a.caveat, CAVEAT);
  assert.equal(typeof a.sentence, "string");
  for (const d of a.receipts) {
    assert.match(d.publish_tx_url, /^https:\/\/testnet\.nearblocks\.io\//);
    assert.match(d.published_date, /^\d{4}-\d{2}-\d{2}$/);
    assert.match(d.evidence_sha256, /^[0-9a-f]{64}$/);
  }
}

describe("unit (stubbed fetch)", () => {
  test("base58 code hash converts to the sha256 hex", () => {
    assert.equal(base58ToHex(HASH_B58), HASH);
    assert.equal(base58ToHex("11111111111111111111111111111111"), "00".repeat(32));
  });

  test("control: matching mode and held receipts give held", async () => {
    const { a, calls } = await run({ receipts: [RACE_VULN, RACE_FIXED, PROOF], mode: "fixed" });
    assert.equal(a.status, STATUS.HELD);
    assert.deepEqual(a.receipts.filter((d) => d.counted).map((d) => d.suite).sort(), ["proof-pay-race-inductive", "race-double-pay:mode=fixed"]);
    // every read after view_account is pinned to the same block
    for (const p of calls.slice(1)) assert.equal(p.block_id, "B");
    assertEveryAnswerShape(a);
  });

  test("mode mismatch: guard reports a mode no suite is for -> unclear, never held", async () => {
    const { a } = await run({ receipts: [RACE_VULN, RACE_FIXED, PROOF], mode: "fixed_v2" });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
    assert.match(a.sentence, /depend on a setting this lookup can't read\. Don't rely on them\./);
    assert.ok(a.receipts.every((d) => !d.counted));
    assertEveryAnswerShape(a);
  });

  test("mode mismatch: fixed guard, only the broken-mode receipt exists -> unclear, never held", async () => {
    const { a } = await run({ receipts: [RACE_VULN], mode: "fixed" });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
  });

  test("mode mismatch: broken-mode guard does not inherit the fixed and proof passes", async () => {
    const { a } = await run({ receipts: [RACE_FIXED, PROOF], mode: "vulnerable_fixture" });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
  });

  test("missing get_mode (method not found, reported inside result) -> unclear, never held", async () => {
    const { a } = await run({ receipts: [RACE_FIXED, PROOF], mode: execError("MethodResolveError(MethodNotFound)") });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
    assert.equal(a.mode_read, "no_get_mode");
    assert.match(a.sentence, /no get_mode\(\)/);
    assertEveryAnswerShape(a);
  });

  test("missing get_mode (method not found, reported as an RPC error) -> unclear, never held", async () => {
    const body = { jsonrpc: "2.0", id: 1, error: { name: "HANDLER_ERROR", cause: { name: "CONTRACT_EXECUTION_ERROR" }, data: "MethodResolveError(MethodNotFound)" } };
    const { a } = await run({ receipts: [RACE_FIXED, PROOF], mode: body });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
  });

  test("get_mode returns something that is not a mode name -> unclear", async () => {
    const { a } = await run({ receipts: [RACE_FIXED], mode: { mode: "fixed" } });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
  });

  test("get_mode panics -> unclear", async () => {
    const { a } = await run({ receipts: [RACE_FIXED], mode: execError("FunctionCallError(ExecutionError(\"not initialized\"))") });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
    assert.equal(a.mode_read, "unreadable");
  });

  test("suites whose setting can't be read are never a pass, even when they held", async () => {
    const cov = receipt("claims-coverage", { tests_run: 9, tests_held: 9 });
    const { a } = await run({ receipts: [cov], mode: execError("MethodResolveError(MethodNotFound)") });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
    const { a: b } = await run({ receipts: [cov], mode: "fixed" });
    assert.equal(b.status, STATUS.UNCLEAR_SETTING);
  });

  test("a suite this lookup does not know is never a pass", async () => {
    const { a } = await run({ receipts: [receipt("race-double-pay:mode=fixed-but-new")], mode: "fixed-but-new" });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
  });

  test("RPC error on view_account -> error, never held", async () => {
    for (const account of ["throw", { httpStatus: 503 }, { jsonrpc: "2.0", id: 1, error: { name: "INTERNAL_ERROR", cause: { name: "INTERNAL_ERROR" }, data: "boom" } }]) {
      const { a } = await run({ account, receipts: [RACE_FIXED, PROOF], mode: "fixed" });
      assert.equal(a.status, STATUS.ERROR, JSON.stringify(account));
      assert.match(a.sentence, /could not finish/);
    }
  });

  test("RPC error on receipts_for -> error, never held", async () => {
    for (const receipts of ["throw", { httpStatus: 500 }, { jsonrpc: "2.0", id: 1, error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_BLOCK" }, data: "x" } }]) {
      const { a } = await run({ receipts, mode: "fixed" });
      assert.equal(a.status, STATUS.ERROR);
    }
  });

  test("RPC (network) error on get_mode -> error, never held", async () => {
    const { a } = await run({ receipts: [RACE_FIXED, PROOF], mode: "throw" });
    assert.equal(a.status, STATUS.ERROR);
  });

  test("timeout -> error, never held", async () => {
    const fetch = (url, init) => new Promise((_, rej) => init.signal.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));
    const a = await lookup(GUARD, { fetch, timeoutMs: 20 });
    assert.equal(a.status, STATUS.ERROR);
    assert.match(a.error, /timed out/);
  });

  test("a receipt in an unexpected shape -> error, never held", async () => {
    const { a } = await run({ receipts: [{ ...RACE_FIXED, beyond_policy: "lots" }], mode: "fixed" });
    assert.equal(a.status, STATUS.ERROR);
    const { a: b } = await run({ receipts: [{ ...RACE_FIXED, guard_code_hash: "f".repeat(64) }], mode: "fixed" });
    assert.equal(b.status, STATUS.ERROR);
    const { a: c } = await run({ receipts: { not: "a list" }, mode: "fixed" });
    assert.equal(c.status, STATUS.ERROR);
  });

  test("against-intent payments count as broken", async () => {
    const r = receipt("race-double-pay:mode=fixed", { against_intent: "450" });
    const { a } = await run({ receipts: [r], mode: "fixed" });
    assert.equal(a.status, STATUS.BROKE);
  });

  test("the newest receipt per suite wins", async () => {
    const older = { ...RACE_FIXED, published_at: "1794269841987566904" };
    const newerBroken = { ...RACE_FIXED, beyond_policy: "5", tests_held: 4 };
    const { a } = await run({ receipts: [older, newerBroken], mode: "fixed" });
    assert.equal(a.status, STATUS.BROKE);
  });

  test("unknown publish tx falls back to the contract page and says so", async () => {
    const r = { ...RACE_FIXED, published_at: "1794327024705760000" };
    const { a } = await run({ receipts: [r], mode: "fixed" });
    assert.equal(a.receipts[0].publish_tx, null);
    assert.equal(a.receipts[0].publish_tx_url, `${DEFAULTS.explorer}/address/${DEFAULTS.receiptsContract}`);
    assert.ok(a.receipts[0].publish_tx_note);
  });

  const OPT = { guard: GUARD, code_hash: HASH, contact: null, expires_at: null, pays_in: "token",
    signed_by: GUARD, signer_role: "guard", opted_in_at: "1", active: true };
  const RES = (over = {}) => ({ guard_code_hash: HASH, status: "held", status_means: "held: ...", suite: "race-double-pay:mode=fixed",
    suite_version: "1", attacks_ran: 5, not_applicable: 0, beyond_policy: "0", against_intent: null, setup: "mode=fixed",
    arena_commit: "c".repeat(40), evidence_sha256: "e".repeat(64), evidence_path: "evidence/x.md", attestation_sha256: null,
    published_at: "1", ...over });

  test("opt-in: matching code -> opted_in; changed code -> code_changed; expired; none; never changes status", async () => {
    const cases = [
      [OPT, OPT_IN.OPTED_IN], [{ ...OPT, code_hash: "ab".repeat(32) }, OPT_IN.CODE_CHANGED],
      [{ ...OPT, active: false }, OPT_IN.EXPIRED], [null, OPT_IN.NOT_OPTED_IN], ["throw", OPT_IN.UNKNOWN],
      [{ ...OPT, guard: "other.testnet" }, OPT_IN.UNKNOWN],
    ];
    for (const [optin, want] of cases) {
      const { a } = await run({ receipts: [RACE_FIXED], mode: "fixed", optin, results: [RES()] });
      assert.equal(a.opt_in.status, want, JSON.stringify(optin));
      assert.equal(a.status, STATUS.HELD, "opt-in never changes the answer");
      assert.equal(typeof a.opt_in.sentence, "string");
    }
    const { a } = await run({ receipts: [RACE_FIXED], mode: "fixed", optin: { ...OPT, signer_role: "parent", signed_by: "parent.testnet" } });
    assert.match(a.opt_in.sentence, /created this guard \(parent\.testnet\)/);
  });

  test("on-chain result: shown as read, bound to this code hash, never says safe", async () => {
    for (const st of ["held", "broke", "incomplete"]) {
      const { a } = await run({ receipts: [RACE_FIXED], mode: "fixed", optin: null, results: [RES({ status: st })] });
      assert.equal(a.onchain_result.status, st);
      assert.doesNotMatch(a.onchain_result.sentence, /\bsafe\b|\bsecure\b/i);
    }
    // no result stored for this code -> not_tested
    const none = (await run({ receipts: [RACE_FIXED], mode: "fixed", results: [] })).a.onchain_result;
    assert.equal(none.status, "not_tested");
    assert.equal(none.sentence, "Arena has no result on chain for this exact code yet.");
    const held = (await run({ receipts: [RACE_FIXED], mode: "fixed", results: [RES()] })).a.onchain_result;
    assert.match(held.sentence, /found no way past it\. Attacks Arena did not run might\./);
    assert.match(held.sentence, /set up like this: mode=fixed/);
    assert.deepEqual(held.other_setups, []);
    // a result for another code hash, a status the contract never stores, a non-list, or a failed read -> unknown
    for (const results of [[RES({ guard_code_hash: "ab".repeat(32) })], [RES({ status: "safe" })], [RES({ status: "not_tested" })],
      [RES(), null], [RES({ suite: 7 })], [RES({ setup: 7 })], RES(), "throw"]) {
      const { a } = await run({ receipts: [RACE_FIXED], mode: "fixed", results });
      assert.equal(a.onchain_result.status, "unknown", JSON.stringify(results));
      assert.equal(a.status, STATUS.HELD, "the on-chain result never changes the answer");
    }
    // an old contract without the method: unknown, and the receipts answer is unchanged
    const { a } = await run({ receipts: [RACE_FIXED], mode: "fixed", results: execError("MethodNotFound") });
    assert.equal(a.onchain_result.status, "unknown");
    assert.equal(a.status, STATUS.HELD);
  });

  // The planted-flaw guard and the fixed guard run the same wasm. Each must see only its own mode's result.
  const R_VULN = RES({ status: "broke", suite: "race-double-pay:mode=vulnerable_fixture", setup: "mode=vulnerable_fixture", beyond_policy: "100" });
  const R_FIXED = RES();
  const R_PROOF = RES({ suite: "proof-pay-race-inductive", attacks_ran: 30 });

  test("on-chain result, shared wasm: the fixed guard is not told 'broke' because the planted-flaw mode broke", async () => {
    const { a } = await run({ receipts: [RACE_VULN, RACE_FIXED, PROOF], mode: "fixed", results: [R_VULN, R_FIXED, R_PROOF] });
    const r = a.onchain_result;
    assert.equal(r.status, "held");
    assert.equal(r.setup, "mode=fixed");
    assert.equal(r.suites_considered, 2);
    assert.deepEqual(r.other_setups, [{ suite: "race-double-pay:mode=vulnerable_fixture", setup: "mode=vulnerable_fixture", status: "broke" }]);
    assert.match(r.sentence, /is "held"/);
    assert.match(r.sentence, /set up another way \(mode=vulnerable_fixture: broke\)\. Those do not count for this guard/);
  });

  test("on-chain result, shared wasm: the planted-flaw guard is told 'broke', and does not inherit the fixed 'held'", async () => {
    const { a } = await run({ receipts: [RACE_VULN, RACE_FIXED, PROOF], mode: "vulnerable_fixture", results: [R_VULN, R_FIXED, R_PROOF] });
    const r = a.onchain_result;
    assert.equal(r.status, "broke");
    assert.equal(r.suite, "race-double-pay:mode=vulnerable_fixture");
    assert.equal(r.other_setups.length, 2);
    assert.ok(r.other_setups.every((o) => o.status === "held"));
  });

  test("on-chain result: only another mode's result exists -> not_tested for this guard, and the other is named", async () => {
    const { a } = await run({ receipts: [RACE_FIXED], mode: "fixed", results: [R_VULN] });
    assert.equal(a.onchain_result.status, "not_tested");
    assert.match(a.onchain_result.sentence, /no result on chain for this exact code set up the way this guard is \(mode "fixed"\)/);
    assert.match(a.onchain_result.sentence, /mode=vulnerable_fixture: broke/);
    const { a: b } = await run({ receipts: [RACE_VULN], mode: "vulnerable_fixture", results: [R_FIXED, R_PROOF] });
    assert.equal(b.onchain_result.status, "not_tested", "a held for the fixed mode is never shown as this guard's result");
  });

  test("on-chain result: the guard's mode can't be read -> unclear_setting, never held", async () => {
    for (const mode of [execError("MethodResolveError(MethodNotFound)"), execError("panic"), 7, null, "throw"]) {
      const { a } = await run({ receipts: [RACE_FIXED], mode, results: [R_FIXED, R_PROOF] });
      assert.equal(a.onchain_result.status, "unclear_setting", JSON.stringify(mode));
      assert.match(a.onchain_result.sentence, /could not read how this guard is set up/);
      assert.notEqual(a.status, STATUS.HELD);
    }
  });

  test("on-chain result: worst counted suite decides, newest per suite wins, a result with no setup always counts", async () => {
    const m = { mode_read: "ok", mode: "fixed" };
    // newest per suite: an older broke replaced by a newer held
    assert.equal(resolveOnchainResults([RES({ status: "broke" }), RES()], HASH, null, m).status, "held");
    assert.equal(resolveOnchainResults([RES(), RES({ status: "broke" })], HASH, null, m).status, "broke");
    // worst of the counted suites
    assert.equal(resolveOnchainResults([R_FIXED, RES({ suite: "proof-pay-race-inductive", status: "incomplete" })], HASH, null, m).status, "incomplete");
    assert.equal(resolveOnchainResults([R_FIXED, RES({ suite: "s2", status: "broke" }), RES({ suite: "s3", status: "incomplete" })], HASH, null, m).status, "broke");
    // a result with no setup is not tied to a mode, so it counts even when the mode can't be read
    const noSetup = RES({ suite: "whole-library", setup: null, status: "broke" });
    assert.equal(resolveOnchainResults([noSetup], HASH, null, { mode_read: "no_get_mode", mode: null }).status, "broke");
    assert.equal(resolveOnchainResults([noSetup, R_FIXED], HASH, null, m).status, "broke");
    // the suite filter narrows what is looked at
    const f = resolveOnchainResults([R_VULN, R_FIXED], HASH, "race-double-pay:mode=vulnerable_fixture", m);
    assert.equal(f.status, "not_tested");
    assert.equal(f.other_setups.length, 1);
    // a near-miss setup string never counts
    assert.equal(resolveOnchainResults([RES({ setup: "mode=fixed " })], HASH, null, m).status, "not_tested");
    assert.equal(resolveOnchainResults([RES({ setup: "mode=fixed_v2" })], HASH, null, m).status, "not_tested");
  });

  test("bad account id -> bad_input, no network call", async () => {
    const s = stubFetch({});
    const a = await lookup("Not A Valid Id", { fetch: s.fetch });
    assert.equal(a.status, STATUS.BAD_INPUT);
    assert.equal(s.calls.length, 0);
  });

  test("no failure case above ever reports held (sweep)", async () => {
    const modes = ["throw", execError("MethodResolveError(MethodNotFound)"), "other", 7, null];
    const sets = [[RACE_FIXED], [PROOF], [RACE_FIXED, PROOF], [receipt("claims-coverage")]];
    for (const mode of modes) for (const receipts of sets) {
      const { a } = await run({ receipts, mode });
      assert.notEqual(a.status, STATUS.HELD, `mode=${JSON.stringify(mode)} suites=${receipts.map((r) => r.suite)}`);
    }
  });
});

describe("demo page", () => {
  test("bundled offline example parses and matches the live shape", () => {
    const html = readFileSync(new URL("./demo.html", import.meta.url), "utf8");
    const m = html.match(/<script type="application\/json" id="bundled-example">([\s\S]*?)<\/script>/);
    assert.ok(m, "demo.html has a bundled example");
    const ex = JSON.parse(m[1]);
    assert.ok(Array.isArray(ex) && ex.length >= 2);
    for (const a of ex) {
      assert.equal(a.caveat, CAVEAT);
      assertEveryAnswerShape(a);
    }
    assert.deepEqual(ex.map((a) => a.status).sort(), ["broke", "held"]);
  });

  test("site/lookup.html is built from this demo.html (rebuild with node site/build-lookup.mjs)", () => {
    const pick = (f) => readFileSync(new URL(f, import.meta.url), "utf8").match(/<script type="application\/json" id="bundled-example">[\s\S]*<\/html>/)[0];
    assert.equal(pick("../../site/lookup.html"), pick("./demo.html"), "site/lookup.html is out of date");
    for (const m of ["arena-lookup.mjs", "suites.mjs"]) {
      const copy = readFileSync(new URL(`../../site/${m}`, import.meta.url), "utf8");
      assert.equal(copy.slice(copy.indexOf("\n") + 1), readFileSync(new URL(`./${m}`, import.meta.url), "utf8"), `site/${m} is out of date`);
    }
  });
});

const LIVE = process.env.ARENA_LOOKUP_OFFLINE ? { skip: "ARENA_LOOKUP_OFFLINE set" } : {};

describe("live, NEAR testnet (read-only)", LIVE, () => {
  test("fixed guard: held, both counted receipts are the fixed-mode ones", async () => {
    const a = await lookup("r11cfx4-guard.arena-race-funder-1111.testnet");
    assert.equal(a.status, STATUS.HELD, a.sentence);
    assert.equal(a.code_hash, HASH);
    assert.equal(a.mode, "fixed");
    const counted = a.receipts.filter((d) => d.counted).map((d) => d.suite).sort();
    assert.deepEqual(counted, ["proof-pay-race-inductive", "race-double-pay:mode=fixed"]);
    assert.ok(a.receipts.every((d) => d.publish_tx), "every receipt has a known publish tx");
    assertEveryAnswerShape(a);
  });

  test("planted-flaw guard: broke, same code hash", async () => {
    const a = await lookup("r11bvf3-guard.arena-race-funder-1111.testnet");
    assert.equal(a.status, STATUS.BROKE, a.sentence);
    assert.equal(a.code_hash, HASH);
    assert.equal(a.mode, "vulnerable_fixture");
    assert.match(a.sentence, /^Broke the double-pay race test/);
    assert.deepEqual(a.receipts.filter((d) => d.counted).map((d) => d.suite), ["race-double-pay:mode=vulnerable_fixture"]);
    assertEveryAnswerShape(a);
  });

  test("fixed guard asked about the broken-mode suite only: unclear, not held", async () => {
    const a = await lookup("r11cfx4-guard.arena-race-funder-1111.testnet", { suite: "race-double-pay:mode=vulnerable_fixture" });
    assert.equal(a.status, STATUS.UNCLEAR_SETTING);
  });

  test("a contract with no receipts: no record", async () => {
    const a = await lookup("r11cfx4-token.arena-race-funder-1111.testnet");
    assert.equal(a.status, STATUS.NO_RECORD, a.sentence);
    assert.match(a.sentence, /No Arena record/);
  });

  test("an account that does not exist", async () => {
    const a = await lookup("arena-lookup-no-such-account-7f3a9.testnet");
    assert.equal(a.status, STATUS.NO_ACCOUNT, a.sentence);
  });

  test("a plain account with no code", async () => {
    const a = await lookup("arena-race-funder-1111.testnet");
    assert.equal(a.status, STATUS.NO_CONTRACT, a.sentence);
  });

  test("an RPC that does not answer: error, not a pass", async () => {
    const a = await lookup("r11cfx4-guard.arena-race-funder-1111.testnet", { rpcUrl: "http://127.0.0.1:9/", timeoutMs: 3000 });
    assert.equal(a.status, STATUS.ERROR);
  });
});
