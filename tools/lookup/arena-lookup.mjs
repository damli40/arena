// arena-lookup: "check before you pay".
// Give it a guard's account id on NEAR testnet. It reads the code the account runs, looks up the
// receipts Arena published for that code, reads the guard's mode, and answers in one plain sentence.
//
// No dependencies. Uses only fetch, so it runs in Node 18+ and in the browser.
// Read-only: it sends view calls, never a transaction.
//
// The rule it never breaks: an answer can only be "held" when every result it counts was published
// for the exact setting this guard reports. Anything it can't read or match is never a pass.

import { SUITES, PUBLISH_TXS } from "./suites.mjs";

export const DEFAULTS = Object.freeze({
  network: "testnet",
  rpcUrl: "https://rpc.testnet.fastnear.com",
  receiptsContract: "receipts.dev-20261109195231-98743803426969.testnet",
  explorer: "https://testnet.nearblocks.io",
  timeoutMs: 15000,
  staleAfterDays: 30,
});

export const CAVEAT = "A record of what Arena tested, not a guarantee.";

// Every status the lookup can return. Only "held" means a published result applies and held.
export const STATUS = Object.freeze({
  HELD: "held",
  BROKE: "broke",
  UNCLEAR_SETTING: "unclear_setting",
  NO_RECORD: "no_record",
  NO_CONTRACT: "no_contract",
  NO_ACCOUNT: "no_account",
  ERROR: "error",
  BAD_INPUT: "bad_input",
});

const UNCLEAR_SENTENCE =
  "Results exist for this code, but they depend on a setting this lookup can't read. Don't rely on them.";

// ---------- small helpers ----------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Base58 (Bitcoin alphabet) to lowercase hex. NEAR's view_account.code_hash is base58 of the sha256. */
export function base58ToHex(s) {
  if (typeof s !== "string" || s.length === 0) throw new Error("empty base58 string");
  let n = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error(`not base58: ${JSON.stringify(ch)}`);
    n = n * 58n + BigInt(v);
  }
  let hex = n === 0n ? "" : n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let lead = 0; // each leading "1" is one zero byte
  while (lead < s.length && s[lead] === "1") lead++;
  return "00".repeat(lead) + hex;
}

const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
export function isValidAccountId(id) {
  return typeof id === "string" && id.length >= 2 && id.length <= 64 && ACCOUNT_RE.test(id);
}

function b64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function nsToDate(ns) {
  const ms = Number(BigInt(ns) / 1000000n);
  return new Date(ms);
}

function u128(v, field) {
  if (typeof v !== "string" || !/^\d+$/.test(v)) throw new LookupError("bad_receipt", `receipt field ${field} is not a number: ${JSON.stringify(v)}`);
  return BigInt(v);
}

class LookupError extends Error {
  constructor(kind, message, cause) {
    super(message);
    this.kind = kind; // "transport" | "rpc" | "unknown_account" | "exec" | "bad_receipt"
    this.cause = cause;
  }
}

// ---------- RPC ----------

function makeRpc(opts) {
  const doFetch = opts.fetch || globalThis.fetch;
  if (typeof doFetch !== "function") throw new Error("no fetch available");
  return async function rpc(params) {
    const ctl = typeof AbortController === "function" ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), opts.timeoutMs) : null;
    let res, body;
    try {
      res = await doFetch(opts.rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "arena-lookup", method: "query", params }),
        signal: ctl ? ctl.signal : undefined,
      });
    } catch (e) {
      throw new LookupError("transport", `could not reach ${opts.rpcUrl}: ${e && e.name === "AbortError" ? "timed out" : (e && e.message) || e}`);
    } finally {
      if (timer) clearTimeout(timer);
    }
    try {
      body = await res.json();
    } catch {
      throw new LookupError("transport", `RPC answered HTTP ${res.status} with a body that is not JSON`);
    }
    if (body && body.error) {
      const name = (body.error.cause && body.error.cause.name) || body.error.name || "";
      const data = typeof body.error.data === "string" ? body.error.data : JSON.stringify(body.error.data || "");
      if (name === "UNKNOWN_ACCOUNT" || /does not exist while viewing/.test(data)) {
        throw new LookupError("unknown_account", data || "account does not exist");
      }
      if (name === "CONTRACT_EXECUTION_ERROR" || name === "NO_CONTRACT_CODE") {
        throw new LookupError("exec", data || name);
      }
      throw new LookupError("rpc", `RPC error ${name || body.error.code}: ${data || body.error.message || ""}`.trim());
    }
    if (!res.ok) throw new LookupError("transport", `RPC answered HTTP ${res.status}`);
    if (!body || typeof body.result !== "object" || body.result === null) {
      throw new LookupError("rpc", "RPC answer has no result");
    }
    // Some nodes report a failed view call inside `result` instead of as an RPC error.
    if (typeof body.result.error === "string") throw new LookupError("exec", body.result.error);
    return body.result;
  };
}

async function viewCall(rpc, block, accountId, method, args) {
  const r = await rpc({
    request_type: "call_function",
    ...block,
    account_id: accountId,
    method_name: method,
    args_base64: b64(JSON.stringify(args)),
  });
  if (!Array.isArray(r.result)) throw new LookupError("rpc", `${method}: no result bytes`);
  const text = new TextDecoder().decode(new Uint8Array(r.result));
  try {
    return JSON.parse(text);
  } catch {
    throw new LookupError("rpc", `${method}: result is not JSON`);
  }
}

// ---------- the verdict for one receipt ----------

function judgeReceipt(r) {
  const beyond = u128(r.beyond_policy, "beyond_policy");
  const against = r.against_intent == null ? null : u128(r.against_intent, "against_intent");
  if (!Number.isInteger(r.tests_run) || !Number.isInteger(r.tests_held)) {
    throw new LookupError("bad_receipt", "receipt tests_run/tests_held are not integers");
  }
  const held = r.tests_run > 0 && r.tests_held === r.tests_run && beyond === 0n && (against === null || against === 0n);
  return { held, beyond, against };
}

function describeReceipt(r, opts) {
  const info = SUITES[r.suite];
  const when = nsToDate(r.published_at);
  const txHash = PUBLISH_TXS[`${r.guard_code_hash}|${r.suite}|${r.published_at}`] || null;
  const { held, beyond, against } = judgeReceipt(r);
  return {
    suite: r.suite,
    test: info ? info.test : `"${r.suite}" test`,
    what: info ? info.what : "a suite this lookup does not know",
    guard_label: r.guard_label,
    result: held ? "held" : "broke",
    tests_run: r.tests_run,
    tests_held: r.tests_held,
    beyond_policy: beyond.toString(),
    against_intent: against === null ? null : against.toString(),
    published_at_ns: r.published_at,
    published_at: when.toISOString(),
    published_date: when.toISOString().slice(0, 10),
    age_days: Math.floor((Date.now() - when.getTime()) / 86400000),
    publish_tx: txHash,
    publish_tx_url: txHash
      ? `${opts.explorer}/txns/${txHash}`
      : `${opts.explorer}/address/${opts.receiptsContract}`,
    publish_tx_note: txHash ? null : "This receipt's publish transaction is not in this lookup's list; the link goes to the receipts contract's history.",
    evidence_path: r.evidence_path,
    evidence_sha256: r.evidence_sha256,
    harness_commit: r.harness_commit,
    counted: false,
    not_counted_because: null,
  };
}

// ---------- sentences ----------

function receiptPhrase(d) {
  const runs = d.suite.startsWith("proof-") ? "checks" : "runs";
  if (d.result === "held") {
    const extra = d.against_intent === null ? "" : `, ${d.against_intent} paid against the user's intent`;
    return `the ${d.test} (${d.tests_held} of ${d.tests_run} ${runs} held, ${d.beyond_policy} paid over the limit${extra})`;
  }
  const parts = [`${d.tests_held} of ${d.tests_run} ${runs} held`];
  if (d.beyond_policy !== "0") parts.push(`worst run paid ${d.beyond_policy} over the limit`);
  if (d.against_intent !== null && d.against_intent !== "0") parts.push(`${d.against_intent} paid against the user's intent`);
  return `the ${d.test} (${parts.join("; ")})`;
}

function joinAnd(xs) {
  return xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
}

function datesOf(ds) {
  return joinAnd([...new Set(ds.map((d) => d.published_date))]);
}

// ---------- the lookup ----------

/**
 * Look up a guard account on NEAR testnet.
 * @param {string} accountId  the guard's account id
 * @param {object} [options]  { suite, rpcUrl, receiptsContract, explorer, timeoutMs, fetch }
 * @returns {Promise<object>} a structured answer; `answer.sentence` is the plain-words version.
 *          Only `answer.status === "held"` means a published result applies to this guard and held.
 */
export async function lookup(accountId, options = {}) {
  // An option passed as undefined keeps its default (a CLI flag that was not given must not erase the RPC URL).
  const opts = { ...DEFAULTS };
  for (const [k, v] of Object.entries(options || {})) if (v !== undefined) opts[k] = v;
  const base = {
    account: accountId,
    network: opts.network,
    status: null,
    sentence: null,
    caveat: CAVEAT,
    code_hash: null,
    mode: null,
    mode_read: null, // "ok" | "no_get_mode" | "unreadable" | null when not attempted
    block: null,
    suite_filter: opts.suite || null,
    receipts: [],
    notes: [],
    error: null,
    receipts_contract: opts.receiptsContract,
    rpc: opts.rpcUrl,
  };
  const done = (status, sentence, extra = {}) => ({ ...base, ...extra, status, sentence });

  if (!isValidAccountId(accountId)) {
    return done(STATUS.BAD_INPUT, `"${accountId}" is not a valid NEAR account id.`);
  }

  let rpc;
  try {
    rpc = makeRpc(opts);
  } catch (e) {
    return done(STATUS.ERROR, "This lookup could not run (no fetch available). It has no answer, so treat the guard as unchecked.", { error: e.message });
  }
  const failed = (e) =>
    done(STATUS.ERROR, `The lookup could not finish: ${e.message}. It has no answer, so treat the guard as unchecked.`, { error: e.message });

  // 1. The code the account runs, at one final block. Every later read uses this same block,
  //    so the code, the mode and the receipts all describe one moment.
  let acct;
  try {
    acct = await rpc({ request_type: "view_account", finality: "final", account_id: accountId });
  } catch (e) {
    if (e.kind === "unknown_account") return done(STATUS.NO_ACCOUNT, `There is no account called ${accountId} on NEAR ${opts.network}.`);
    return failed(e);
  }
  base.block = { height: acct.block_height, hash: acct.block_hash };
  const at = { block_id: acct.block_hash };

  let codeHash;
  try {
    codeHash = base58ToHex(acct.code_hash);
  } catch (e) {
    return failed(new Error(`could not read the account's code hash (${e.message})`));
  }
  if (codeHash.length !== 64) return failed(new Error(`code hash has the wrong length (${codeHash.length / 2} bytes)`));
  if (/^0+$/.test(codeHash)) {
    return done(STATUS.NO_CONTRACT, `${accountId} has no contract deployed, so there is no guard code to look up.`);
  }
  base.code_hash = codeHash;

  // 2. Every receipt Arena published for this code (oldest first), then the newest per suite,
  //    which is what the contract's own latest(hash, suite) returns.
  let all;
  try {
    all = await viewCall(rpc, at, opts.receiptsContract, "receipts_for", { guard_code_hash: codeHash });
  } catch (e) {
    return failed(new Error(`reading receipts from ${opts.receiptsContract}: ${e.message}`));
  }
  if (!Array.isArray(all)) return failed(new Error("receipts_for did not return a list"));
  for (const r of all) {
    if (!r || r.guard_code_hash !== codeHash || typeof r.suite !== "string" || typeof r.published_at !== "string") {
      return failed(new Error("receipts_for returned a receipt for a different code hash or in an unexpected shape"));
    }
  }
  const latest = new Map();
  for (const r of all) latest.set(r.suite, r); // later entries are newer
  let picked = [...latest.values()];
  if (opts.suite) picked = picked.filter((r) => r.suite === opts.suite);

  if (picked.length === 0) {
    if (opts.suite && latest.size > 0) {
      return done(STATUS.NO_RECORD, `No Arena record for this code in the suite "${opts.suite}". Arena has published other suites for it: ${[...latest.keys()].join(", ")}.`);
    }
    return done(STATUS.NO_RECORD, `No Arena record for this code (sha256 ${codeHash.slice(0, 8)}…). Arena has not published a result for it.`);
  }

  let described;
  try {
    described = picked.map((r) => describeReceipt(r, opts));
  } catch (e) {
    return failed(e);
  }
  base.receipts = described;

  // 3. The guard's mode. The broken and the fixed guard can share one wasm; only get_mode() tells them apart.
  try {
    const m = await viewCall(rpc, at, accountId, "get_mode", {});
    if (typeof m === "string" && m.length > 0) {
      base.mode = m;
      base.mode_read = "ok";
    } else {
      base.mode_read = "unreadable";
      base.notes.push(`get_mode() returned ${JSON.stringify(m)}, which is not a mode name.`);
    }
  } catch (e) {
    if (e.kind !== "exec") return failed(new Error(`reading the guard's mode: ${e.message}`));
    if (/MethodNotFound/i.test(e.message)) {
      base.mode_read = "no_get_mode";
    } else {
      base.mode_read = "unreadable";
      base.notes.push(`get_mode() failed: ${e.message}`);
    }
  }

  // 4. Count only the results whose setting this lookup can read and that match this guard.
  for (const d of described) {
    const info = SUITES[d.suite];
    if (!info) {
      d.not_counted_because = "this lookup does not know what this suite's result depends on";
    } else if (info.setting.kind !== "mode") {
      d.not_counted_because = `it depends on ${info.setting.what}, which this lookup can't read`;
    } else if (base.mode_read === "no_get_mode") {
      d.not_counted_because = `it applies only to mode "${info.setting.value}", and this guard has no get_mode() to say which mode it runs`;
    } else if (base.mode_read !== "ok") {
      d.not_counted_because = `it applies only to mode "${info.setting.value}", and this guard's mode could not be read`;
    } else if (base.mode !== info.setting.value) {
      d.not_counted_because = `it is for mode "${info.setting.value}", and this guard reports mode "${base.mode}"`;
    } else {
      d.counted = true;
    }
  }
  const counted = described.filter((d) => d.counted);

  // Notes that matter whatever the verdict.
  const stale = described.filter((d) => d.age_days > opts.staleAfterDays);
  if (stale.length) base.notes.push(`Some results are more than ${opts.staleAfterDays} days old (${stale.map((d) => d.published_date).join(", ")}).`);
  try {
    const keys = await rpc({ request_type: "view_access_key_list", ...at, account_id: accountId });
    if (Array.isArray(keys.keys) && keys.keys.some((k) => k.access_key && k.access_key.permission === "FullAccess")) {
      base.notes.push("This account still has a full-access key, so its owner can replace the code or its settings after you check. Check again right before you pay.");
    }
  } catch {
    base.notes.push("Could not read this account's keys, so this lookup can't say whether its code can still be changed.");
  }

  if (counted.length === 0) {
    const why = described.map((d) => `the ${d.test} result is not counted because ${d.not_counted_because}`);
    let reason = "";
    if (base.mode_read === "no_get_mode") reason = " This guard has no get_mode(), so the lookup can't tell which setting it runs.";
    else if (base.mode_read === "ok") reason = ` This guard reports mode "${base.mode}", and no published result${opts.suite ? " in that suite" : ""} for this code is for that mode.`;
    else if (base.mode_read === "unreadable") reason = " This guard's mode could not be read.";
    base.notes.push(...why.map((w) => w[0].toUpperCase() + w.slice(1) + "."));
    return done(STATUS.UNCLEAR_SETTING, UNCLEAR_SENTENCE + reason);
  }

  const broke = counted.filter((d) => d.result === "broke");
  const held = counted.filter((d) => d.result === "held");
  const modeWords = base.mode ? ` in mode "${base.mode}"` : "";
  if (broke.length) {
    let s = `Broke ${joinAnd(broke.map(receiptPhrase))}${modeWords}, published ${datesOf(broke)}.`;
    if (held.length) s += ` It held ${joinAnd(held.map(receiptPhrase))}.`;
    return done(STATUS.BROKE, s);
  }
  base.notes.push("Only the mode was matched. Other setup (who owns the guard, which agent and token it serves) was not checked against what Arena tested.");
  return done(STATUS.HELD, `Held ${joinAnd(held.map(receiptPhrase))}${modeWords}, published ${datesOf(held)}.`);
}

/** Plain-text rendering used by the CLI. */
export function formatAnswer(a) {
  const lines = [a.sentence, a.caveat];
  lines.push("");
  lines.push(`account:   ${a.account} (NEAR ${a.network})`);
  if (a.code_hash) lines.push(`code:      sha256 ${a.code_hash}`);
  if (a.mode_read) lines.push(`mode:      ${a.mode_read === "ok" ? a.mode : a.mode_read === "no_get_mode" ? "(no get_mode)" : "(could not read)"}`);
  if (a.block) lines.push(`read at:   block ${a.block.height}`);
  lines.push(`status:    ${a.status}`);
  for (const d of a.receipts) {
    lines.push("");
    lines.push(`- ${d.test} [${d.suite}]: ${d.result}, ${d.tests_held}/${d.tests_run}, over limit ${d.beyond_policy}${d.against_intent === null ? "" : `, against intent ${d.against_intent}`}`);
    lines.push(`  ${d.counted ? "counted" : `not counted: ${d.not_counted_because}`}`);
    lines.push(`  published ${d.published_at}  tx ${d.publish_tx_url}`);
    lines.push(`  evidence  ${d.evidence_path}  sha256 ${d.evidence_sha256}`);
  }
  if (a.notes.length) {
    lines.push("");
    for (const n of a.notes) lines.push(`note: ${n}`);
  }
  if (a.error) lines.push(`error: ${a.error}`);
  return lines.join("\n");
}
