// node --test tools/lookup/test.mjs
// Live tests read NEAR testnet (read-only). Set ARENA_LOOKUP_OFFLINE=1 to skip them.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { lookup, base58ToHex, STATUS, CAVEAT, DEFAULTS } from "./arena-lookup.mjs";

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
 * handlers: { account, receipts, mode, keys } each either a value, a full RPC body (object with
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
