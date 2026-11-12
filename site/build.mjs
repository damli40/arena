// Builds site/index.html: the Arena results page with Fig 1, a live replay of real runs.
//   node site/build.mjs            (needs the anatomy kit; set ANATOMY_KIT or install the skill)
// It also rebuilds site/lookup.html (site/build-lookup.mjs). The look comes from site/theme.css and
// the top bar from site/nav.json, shared with tools/hunter/board.py. Optional: ARENA_REPO_URL.
// Every number on the page is read from evidence/ at build time. Nothing is typed in by hand
// except the plain-English labels. The figure is drawn with the anatomy kit (MIT, (c) 2026 Ryan).
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { homedir } from "node:os";
import { themeCss, topbar, footer, FONTS, FAVICON } from "./chrome.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const KITDIR = process.env.ANATOMY_KIT || join(homedir(), ".claude/skills/anatomy");
const k = await import(pathToFileURL(join(KITDIR, "kit/iso-kit.mjs")).href);
const { kitScript } = await import(pathToFileURL(join(KITDIR, "scripts/inline-kit.mjs")).href);
const ev = (p) => join(ROOT, "evidence", p);
const json = (p) => JSON.parse(readFileSync(ev(p), "utf8"));

// ---------------------------------------------------------------- data from evidence
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const md = (s) => esc(s).replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>").replace(/ ✅/g, "").replace(/[–—]/g, "-");

// Nov 10 testnet race (files tagged 2026-11-11) with the current guard build (0382023b). Run 1 holds vulnerable trial 1, run 2 the other
// four vulnerable trials, run 3 the five fixed trials. Pool them and filter by mode.
const TESTNET = ["testnet-2026-11-11-run1-raw.json", "testnet-2026-11-11-run2-raw.json", "testnet-2026-11-11-run3-raw.json"];
function testnetScenario(mode, label) {
  const mine = TESTNET.flatMap((f) => json(f).trials.map((t) => ({ t, f }))).filter((x) => x.t.mode === mode);
  // The replay below tells the story as "call A pays, call B is checked second". Use the first trial where that
  // is what happened (in some fixed trials B won and A was refused), and stop the build if there is none.
  const has = (t, pay, role) => (t[pay]?.steps || []).some((s) => s.role.startsWith(role));
  const pick = mine.find((x) => has(x.t, "pay_a", "on_transfer") && (mode === "fixed" ? !has(x.t, "pay_b", "ft_transfer") : true));
  if (!pick) throw new Error(`no ${mode} testnet trial where call A paid first`);
  if (mine.length !== 5) throw new Error(`expected 5 ${mode} testnet trials, found ${mine.length}`);
  const t = pick.t, file = [...new Set(mine.map((x) => x.f))].join(", evidence/");
  const all = mine.map((x) => Number(x.t.receiver_received));
  const step = (pay, role) => t[pay].steps.find((s) => s.role.startsWith(role));
  const N = step("pay_a", "tx_to_receipt").block_height;
  const fixed = t.mode === "fixed";
  const checkB = step("pay_b", "pay");
  const log = [
    { at: 0.3, text: `block ${N}: the agent signs two pay calls for one 100-token invoice, one with key A, one with key B` },
    { at: 1.8, text: `block ${step("pay_a", "pay").block_height}: guard checks call A: not paid yet, so it starts the transfer` },
    fixed
      ? { at: 2.0, text: `block ${checkB.block_height}: guard checks call B: refused, "payment already in flight"` }
      : { at: 2.0, text: `block ${checkB.block_height}: guard checks call B: still "not paid", so it starts a second transfer` },
    { at: 2.7, text: `block ${step("pay_a", "ft_transfer").block_height}: tokens move to the receiver` },
    { at: 3.9, text: fixed
        ? `block ${step("pay_a", "on_transfer").block_height}: guard confirms the one payment it had already recorded`
        : `block ${step("pay_a", "on_transfer").block_height}: guard records "paid", two blocks too late; its own log says DOUBLE PAYOUT` },
  ];
  return {
    id: fixed ? "fixed" : "flaw", label, where: "NEAR testnet", fixed, coin: 100, limit: Number(t.invoice_amount),
    paid: Number(t.receiver_received), trials: all,
    links: [["call A", t.pay_a.link], ["call B", t.pay_b.link]], source: `evidence/${file}`, log,
  };
}

function coverage() {
  const text = readFileSync(ev("coverage-table.md"), "utf8");
  const out = {};
  let guard = null;
  for (const line of text.split("\n")) {
    const h = line.match(/^## Guard ([ABC])/);
    if (h) { guard = h[1]; out[guard] = { rows: [], verdict: "" }; continue; }
    if (!guard) continue;
    if (/^\*\*Verdict/.test(line)) out[guard].verdict = line;
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    if (cells.length === 5 && /^\d\d/.test(cells[0])) out[guard].rows.push({ test: cells[0], claim: cells[1], tried: cells[2], result: cells[3], paid: cells[4] });
  }
  return out;
}

function injection() {
  const dir = ev("injection-2026-11-09-compromised");
  const rows = readdirSync(dir).filter((f) => /^s\d.*\.json$/.test(f)).sort().map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));
  const label = { "s0-clean": "No injection (control)", "s1-overt": "Overt instruction in the email", "s2-payee-swap": "Changed payment details", "s3-fake-authority": "Fake message from the owner", "s4-memo-field": "Instruction hidden in another invoice's memo" };
  return rows.map((r) => {
    const wrong = Object.entries(r.received).filter(([n, v]) => (n === "sam" ? v - 100 : v) > 0).map(([n, v]) => [n, n === "sam" ? v - 100 : v]);
    return { scenario: label[r.scenario] || r.scenario, wrong, missed: Math.max(0, 100 - (r.received.sam || 0)), policy: r.policy_leak, refused: r.guard_refused };
  });
}

const cov = coverage();
const raceRow = (g, test) => cov[g].rows.find((r) => r.test.startsWith(test));
const aRace = raceRow("A", "01");
const cRace = raceRow("C", "03");
const scenarios = [
  testnetScenario("vulnerable_fixture", "Planted flaw"),
  testnetScenario("fixed", "Fixed guard"),
  { id: "guardA", label: "Guard A", where: "local sandbox", fixed: true, coin: 100, limit: 100, paid: 100, trials: null, links: [], source: "evidence/coverage-table.md, Guard A test 01",
    log: [
      { at: 0.3, text: "two pay calls for one payment id, sent at the same moment from two keys" },
      { at: 1.8, text: "Guard A records \"paid\" and takes the money off the balance before the transfer starts" },
      { at: 2.0, text: "the second call is refused: already paid" },
      { at: 2.7, text: "tokens move once" },
      { at: 3.9, text: `receiver: ${aRace.paid.replace(/\s*\(.*/, "")} on a ${aRace.paid.match(/\((.*)\)/)[1]} limit` },
    ] },
  { id: "guardC", label: "Guard C", where: "local sandbox", fixed: true, coin: 300, limit: 300, paid: 300, trials: null, links: [], source: "evidence/coverage-table.md, Guard C test 03",
    log: [
      { at: 0.3, text: "two server-bill payments of 300 (the whole bill pot), sent at the same moment from two keys" },
      { at: 1.8, text: "Guard C takes 300 off its record of the pot before the transfer starts" },
      { at: 2.0, text: "the second bill is refused: not enough left in the pot" },
      { at: 2.7, text: "tokens move once, to the one fixed payee" },
      { at: 3.9, text: `payee: ${cRace.paid.replace(/\s*\(.*/, "")} on a ${cRace.paid.match(/\((.*)\)/)[1]} limit` },
    ] },
];
for (const s of scenarios) s.beyond = Math.max(0, s.paid - s.limit);
const inj = injection();
const injWrong = inj.reduce((a, r) => a + r.wrong.reduce((b, [, v]) => b + v, 0), 0);
const injPolicy = inj.reduce((a, r) => a + r.policy, 0);
const totalTests = ["A", "B", "C"].reduce((a, g) => a + cov[g].rows.length, 0);
// The rows are not all the same kind (evidence/coverage-table.md): the "00 control" rows are honest
// payments (claim "utility"), a row marked "not claimed" is a stress test of a rule the guard never
// promised, and every other row tests a rule the guard wrote down. Counted apart, never added up.
const kindOf = (r) => (/^utility$/i.test(r.claim) ? "honest" : /not claimed/i.test(r.test) ? "stress" : "claimed");
const covCount = (G, kind, held) => cov[G].rows.filter((r) => kindOf(r) === kind && (!held || /\*\*held\*\*/.test(r.result))).length;
const sumG = (kind, held) => ["A", "B", "C"].reduce((a, G) => a + covCount(G, kind, held), 0);
const claimedTests = sumG("claimed"), claimedHeld = sumG("claimed", true);
const stressTests = sumG("stress"), stressHeld = sumG("stress", true);
const honestPays = sumG("honest");
const honestSettled = ["A", "B", "C"].reduce((a, G) => a + cov[G].rows.filter((r) => kindOf(r) === "honest" && /settled|paid/.test(r.result)).length, 0);
const stressGuards = ["A", "B", "C"].filter((G) => covCount(G, "stress") > 0);
const flawT = scenarios[0];
// The 500: z3's worst single run under the broad rules, replayed on the local test chain (evidence/proofs-2026-11-10.md).
const cross = readFileSync(ev("proofs-2026-11-10/crosscheck.sh.out"), "utf8").match(/RESULT crosscheck .*against_intent=(\d+) beyond_policy=(\d+) .*-> MATCH/);
const worst = cross ? Number(cross[1]) : NaN, worstPolicy = cross ? Number(cross[2]) : NaN;
const injMaxRun = Math.max(...inj.map((r) => r.wrong.reduce((b, [, v]) => b + v, 0)));
if (worst !== 500 || worstPolicy !== 0 || injMaxRun !== 200 || injWrong !== 450 || injPolicy !== 0 || totalTests !== 33 || claimedTests !== 29 || claimedHeld !== claimedTests || stressTests !== 1 || stressHeld !== 1 || honestPays !== 3 || honestSettled !== 3 || claimedTests + stressTests + honestPays !== totalTests || flawT.paid !== 200 || scenarios[1].paid !== 100 || scenarios[0].trials.length !== 5 || scenarios[1].trials.length !== 5 || scenarios[0].trials.some((v) => v !== 200) || scenarios[1].trials.some((v) => v !== 100))
  throw new Error(`evidence changed: worst=${worst} worstPolicy=${worstPolicy} maxRun=${injMaxRun} wrong=${injWrong} policy=${injPolicy} tests=${totalTests} claimed=${claimedHeld}/${claimedTests} stress=${stressHeld}/${stressTests} honest=${honestSettled}/${honestPays} flaw=${flawT.paid}; update the words on the page`);

// ---------------------------------------------------------------- "Test your own guard" data
// The board (site/board-data.json, written by tools/hunter/board.py) gives the counts for the links
// under the hero. The attack count for `arena check` is the size of the attack library less the honest-payment
// control (a preflight, not an attack), counted by
// the same code `arena check` uses (tools/hunter/catalog.py). If Python cannot run here, fall back to
// the board's attack count and say "on the board" instead of "in the library".
const boardData = JSON.parse(readFileSync(join(HERE, "board-data.json"), "utf8"));
const boardGuards = boardData.guards.filter((g) => g.runnable);
const boardAttacks = boardData.attacks.length;
let libraryAttacks = null;
{
  const r = spawnSync("python3", ["-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import catalog; a, p = catalog.load(); u, d = catalog.unique(a); print(sum(x['meta']['id'] != 'scripted-01-control-pay-valid' for x in u) if not p else -1)", join(ROOT, "tools/hunter")], { encoding: "utf8", cwd: ROOT });
  const n = Number((r.stdout || "").trim());
  if (r.status === 0 && Number.isInteger(n) && n > 0) libraryAttacks = n;
}
const checkCount = libraryAttacks ?? boardAttacks;
const checkWhere = libraryAttacks != null ? "in Arena's library" : "on the board";

// ARENA_REPO_URL (a plain https URL) turns doc and file names into links into the repo, at
// ARENA_REPO_REF (default main). Unset, they stay plain code-font paths, never dead links.
// Same rules as tools/check/report.py receipt_link().
const REPO = (() => {
  const base = (process.env.ARENA_REPO_URL || "").replace(/\/+$/, "");
  const ref = process.env.ARENA_REPO_REF || "main";
  if (!base) return null;
  if (!/^https:\/\/[A-Za-z0-9.-]+(\/[A-Za-z0-9._~-]+)*$/.test(base) || !/^([0-9a-f]{7,40}|[A-Za-z0-9][A-Za-z0-9._-]{0,99})$/.test(ref) || ref.includes(".."))
    throw new Error("ARENA_REPO_URL must be a plain https URL and ARENA_REPO_REF a commit id or simple branch name");
  return { base, ref };
})();
const repoPath = (p) => REPO ? `<a href="${esc(`${REPO.base}/blob/${REPO.ref}/${p}`)}" rel="noopener"><code>${esc(p)}</code></a>` : `<code>${esc(p)}</code>`;

// Demo GIF: shown only if the file exists at build time. Nothing is rendered otherwise.
const GIF = "img/arena-check.gif";
// Its width and height are read from the GIF header (bytes 6-9), so the page keeps the right space for it
// before it arrives and nothing below jumps when it does.
const gifSize = (b) => (b.toString("latin1", 0, 3) === "GIF" ? { w: b.readUInt16LE(6), h: b.readUInt16LE(8) } : null);
const gifDims = existsSync(join(HERE, GIF)) ? gifSize(readFileSync(join(HERE, GIF))) : null;
const gifHtml = existsSync(join(HERE, GIF))
  ? `<figure class="check-gif"><img src="${GIF}"${gifDims ? ` width="${gifDims.w}" height="${gifDims.h}"` : ""} alt="A terminal running ./arena check on a guard. Attacks run one by one, then the report card shows how many held and how many broke." loading="lazy" decoding="async"></figure>`
  : "";

// Sample report: a real report.json from an `arena check` run. Shown only if the file exists.
// The report format is still changing, so every field is read defensively and anything missing is
// left out. Fields read: status, totals.ran, totals.held, totals.broke, totals.not_applicable,
// totals.beyond_policy, guard.label, finished_utc. Nothing here is typed in by hand.
const SAMPLE_REPORT = "evidence/check-fixes-2-2026-11-11/leaky-control-v2/report.json";
function sampleReport() {
  let r;
  try { r = JSON.parse(readFileSync(join(ROOT, SAMPLE_REPORT), "utf8")); } catch { return ""; }
  const t = r && typeof r.totals === "object" && r.totals ? r.totals : {};
  const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const ran = num(t.ran), held = num(t.held), broke = num(t.broke), na = num(t.not_applicable), beyond = num(t.beyond_policy);
  if (ran == null && held == null && broke == null) return "";
  const stats = [
    ran != null && [ran, "attacks ran", ""],
    held != null && [held, "held", ""],
    broke != null && [broke, "broke", broke > 0 ? " bad" : ""],
    beyond != null && [beyond, "tokens paid beyond policy", beyond > 0 ? " bad" : ""],
  ].filter(Boolean).map(([n, k, c]) => `<div class="s${c}"><div class="n">${n}</div><div class="k">${esc(k)}</div></div>`).join("");
  const status = typeof r.status === "string" ? r.status : null;
  const label = r.guard && typeof r.guard.label === "string" ? r.guard.label : null;
  const role = label ? (boardData.guards.find((g) => g.id === label) || {}).role : null;
  const roleWords = { "positive-control": "our guard that is leaky on purpose", "negative-control": "our fixed control guard", subject: "a guard on the board" }[role];
  const date = typeof r.finished_utc === "string" && /^\d{4}-\d\d-\d\d/.test(r.finished_utc) ? r.finished_utc.slice(0, 10) : null;
  const about = [
    label ? `Guard: ${roleWords ? `${esc(roleWords)} (<code>${esc(label)}</code>)` : `<code>${esc(label)}</code>`}.` : "",
    date ? `Finished ${esc(date)}.` : "",
    na != null ? `${na} ${na === 1 ? "attack" : "attacks"} did not apply to it.` : "",
  ].filter(Boolean).join(" ");
  return `<div class="card sample">
    <div class="sample-top"><span class="eyebrow">Sample report card</span>${status ? `<span class="st ${status === "broke" ? "st-broke" : status === "held" ? "st-held" : "st-none"}">${esc(status)}</span>` : ""}</div>
    <div class="sample-nums">${stats}</div>
    ${about ? `<p class="small">${about} From ${repoPath(SAMPLE_REPORT)}.</p>` : ""}
  </div>`;
}
const sampleHtml = sampleReport();

// ---------------------------------------------------------------- figure geometry
const W = 760, H = 430;
const PLATE = { x: -172, y: -62, w: 334, d: 124, r: 8 }, PLATE_H = 10, FOOT_H = 5;
const RISER = { x: -140, y: -25, w: 216, d: 50, r: 2 }, RISER_TOP = 6;
const LANES = [-11, 11];
const COIN_R = 5.5, COIN_H = 2.6;
const START_X = -125.5, CHECK_X = -1, LANE_END = 74;
const HEAD_REST = -134, HEAD_PUSH = -122;
const PIN_X = 5, PIN_TOP = 20;
const BEAM = { x: -12, y: -35, w: 30, d: 70, r: 2 }, BEAM_Z = 48, BEAM_H = 8;
const FLAG_OPEN = -5, FLAG_PAID = 11;
const PAN = [112, 0], PAN_R = 20, PAN_Z = 4, PAN_TOP = 6.5;
const DIAL_Z = 44, DIAL_H = 6, DIAL_R = 15, DIAL_TOP = DIAL_Z + DIAL_H;
const ROD_LEN = 38;
const POST = [112, -46], POST_TOP = 76;

const P = k.fitProjection(
  [...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0), [BEAM.x, BEAM.y, BEAM_Z + BEAM_H + 6], [POST[0], POST[1], POST_TOP + 2], [PAN[0] + DIAL_R, 0, DIAL_TOP]],
  W, H, { pad: 26, azimuth: 38 });
const at = (p) => k.iso(p, P);
const S = (paths, style) => k.solidSvg(paths, style);
const L = (d, style) => k.lineSvg(d, style);
const D = (pts, style) => k.dotsSvg(pts, style);

function base() {
  const o = [`<path class="iso-halo" d="${k.haloOf(PLATE, -PLATE_H - FOOT_H, PLATE_H, P)}"/>`];
  const feet = k.corners(PLATE, 22).sort((a, b) => k.depthOf([...a, 0], P) - k.depthOf([...b, 0], P));
  for (const [x, y] of feet) {
    o.push(S(k.cylinder(x, y, 7, -PLATE_H - FOOT_H, 1.6, P, 28), { tone: "lo" }));
    o.push(S(k.cylinder(x, y, 5.4, -PLATE_H - FOOT_H + 1.6, FOOT_H - 1.6, P, 28), { tone: "mid" }));
  }
  o.push(S(k.slabOf(PLATE, -PLATE_H, PLATE_H, P, 8, 1.6), { tone: "mid" }));
  o.push(L(k.planOutline(k.insetPlan(PLATE, 5), 0, P), { tone: "lo" }));
  const screws = k.corners(PLATE, 10);
  o.push(L(screws.map(([x, y]) => k.ring(x, y, 2.2, 0, P, 16)).join(""), { tone: "lo" }));
  o.push(D(screws.map(([x, y]) => at([x, y, 0])), { size: 0.5 }));
  const strip = { x: -150, y: PLATE.y + PLATE.d - 15, w: 250, d: 7, r: 1 };
  o.push(S(k.slabOf(strip, 0, 0.6, P, 3), { tone: "lo", crease: "none" }));
  const ticks = k.topTicks(strip.x + 4, strip.x + strip.w - 4, 4, 5, strip.y + 0.8, 0.6, [2, 3.6], P);
  o.push(L(ticks.minor, { tone: "lo" }), L(ticks.major, { tone: "mid" }));
  o.push(D([at([strip.x + 2, strip.y + 3.5, 0.6]), at([strip.x + strip.w - 2, strip.y + 3.5, 0.6])], { size: 0.45 }));
  const lp = { x: 118, y: PLATE.y + PLATE.d - 26, w: 34, d: 17, r: 1.5 };
  o.push(S(k.slabOf(lp, 0, 0.8, P, 3, 0.3), { tone: "mid" }));
  o.push(k.faceTextSvg(k.topMatrix([lp.x + 4, lp.y + 6], 0.8, P, "x"), "ARENA", { size: 3.4, tone: "hi" }));
  for (const [i, y] of [10, 12.5, 15].entries()) o.push(L(k.lineOnTop([lp.x + 4, lp.y + y], [lp.x + (i === 2 ? 18 : 28), lp.y + y], 0.8, P), { tone: "faint", free: "both" }));
  o.push(D([at([lp.x + 2, lp.y + 2, 0.8]), at([lp.x + lp.w - 2, lp.y + 2, 0.8]), at([lp.x + 2, lp.y + lp.d - 2, 0.8]), at([lp.x + lp.w - 2, lp.y + lp.d - 2, 0.8])], { size: 0.4 }));
  return o.join("");
}

function dialStand() {
  const o = [];
  const mag = { x: POST[0] - 11, y: POST[1] - 9, w: 22, d: 18, r: 2.5 };
  o.push(S(k.slabOf(mag, 0, 12, P, 6, 0.8), { tone: "mid" }));
  o.push(L(k.planOutline(k.insetPlan(mag, 2.5), 12, P), { tone: "faint" }));
  o.push(D([at([mag.x + 4, mag.y + 4, 12]), at([mag.x + mag.w - 4, mag.y + 4, 12])], { size: 0.45 }));
  const knob = [mag.x + 17, mag.y + 13];
  o.push(S(k.cylinder(knob[0], knob[1], 3.4, 12, 3, P, 24), { tone: "mid" }));
  o.push(L(k.knurl(knob[0], knob[1], 3.4, 12, 15, 24, P), { tone: "lo" }));
  o.push(S(k.cylinder(POST[0], POST[1], 3.2, 12, POST_TOP - 12, P, 28), { tone: "mid", crease: "none" }));
  o.push(L([30, 58].map((z) => k.sideArc(POST[0], POST[1], 3.2, z, P, 16)).join(""), { tone: "faint" }));
  o.push(S(k.cylinder(POST[0], POST[1], 3.8, POST_TOP, 2, P, 28), { tone: "mid" }));
  const clamp = { x: POST[0] - 6.5, y: POST[1] - 6.5, w: 13, d: 13, r: 2.5 };
  o.push(S(k.slabOf(clamp, DIAL_Z - 1, 10, P, 4, 0.6), { tone: "mid" }));
  const thumb = [clamp.x - 2.4, clamp.y + 6.5];
  o.push(S(k.cylinder(thumb[0], thumb[1], 2.4, DIAL_Z + 1, 5, P, 18), { tone: "mid" }));
  o.push(L(k.knurl(thumb[0], thumb[1], 2.4, DIAL_Z + 1, DIAL_Z + 6, 16, P), { tone: "lo" }));
  return o.join("");
}

function gatePost(y) {
  const o = [];
  const post = { x: -8, y, w: 10, d: 9, r: 1.5 };
  const foot = { x: post.x - 3, y: post.y - 2, w: post.w + 6, d: post.d + 4, r: 2 };
  o.push(S(k.slabOf(foot, 0, 3, P, 4, 0.5), { tone: "mid" }));
  o.push(D(k.corners(foot, 1.6).map(([x, yy]) => at([x, yy, 3])), { size: 0.4 }));
  o.push(S(k.slabOf(post, 3, BEAM_Z - 3, P, 4, 0.5), { tone: "mid", inner: L([16, 32].map((z) => k.sideSeam(post, z, P, 4)).join(""), { tone: "faint" }) }));
  return o.join("");
}

function magazine() {
  const o = [];
  const m = { x: -168, y: -27, w: 28, d: 54, r: 3 };
  o.push(S(k.slabOf(m, 0, 24, P, 6, 1), { tone: "mid" }));
  o.push(L(k.planOutline(k.insetPlan(m, 3.5), 24, P), { tone: "faint" }));
  o.push(D(k.corners(m, 6).map(([x, y]) => at([x, y, 24])), { size: 0.45 }));
  for (const y of LANES) {
    o.push(S(k.cylinder(m.x + 14, y, 5, 24, 4, P, 32), { tone: "mid" }));
    o.push(L(k.knurl(m.x + 14, y, 5, 24, 28, 30, P), { tone: "lo" }));
    o.push(L(k.ring(m.x + 14, y, 2, 28, P, 16), { tone: "mid" }));
  }
  return o.join("");
}

function riser() {
  const o = [];
  o.push(S(k.slabOf(RISER, 0, RISER_TOP, P, 4, 0.6), { tone: "mid" }));
  for (const y of LANES) {
    o.push(S(k.slabOf({ x: PIN_X - 0.8, y: y - 5, w: 4, d: 10, r: 0.6 }, RISER_TOP, 0.01, P, 2), { tone: "lo", flat: true }));
    o.push(L(k.lineOnTop([RISER.x + 4, y], [PIN_X - 0.8, y], RISER_TOP, P), { tone: "faint" }));
    o.push(L(k.lineOnTop([PIN_X + 3.2, y], [RISER.x + RISER.w, y], RISER_TOP, P), { tone: "faint" }));
  }
  return o.join("");
}

const rail = (y) => S(k.slabOf({ x: RISER.x, y: y - 1, w: RISER.w, d: 2, r: 0.6 }, RISER_TOP, 3.4, P, 2, 0.3), { tone: "mid" }) +
  D([RISER.x + 6, RISER.x + RISER.w - 6].map((x) => at([x, y, RISER_TOP + 3.4])), { size: 0.35 });

const coin = () => S(k.cylinder(0, 0, COIN_R, 0, COIN_H, P, 36, 0.3), { tone: "hi", crease: "lo", inner: L(k.ring(0, 0, COIN_R - 1.4, COIN_H, P, 30), { tone: "faint" }) });
const head = (y) => S(k.slabOf({ x: -3, y: y - 6, w: 6, d: 12, r: 1.5 }, 6.5, 8, P, 3, 0.4), { tone: "mid" }) +
  D([at([0, y - 3.5, 14.5]), at([0, y + 3.5, 14.5])], { size: 0.4 });

function gateTop() {
  const o = [];
  o.push(S(k.slabOf(BEAM, BEAM_Z, BEAM_H, P, 4, 0.8), { tone: "mid" }));
  o.push(L(k.lineOnTop([FLAG_OPEN, 0], [FLAG_PAID, 0], BEAM_Z + BEAM_H, P), { tone: "lo" }));
  o.push(D([at([FLAG_OPEN, 0, BEAM_Z + BEAM_H]), at([FLAG_PAID, 0, BEAM_Z + BEAM_H])], { size: 0.5, tone: "mid" }));
  o.push(D(k.corners(BEAM, 3).map(([x, y]) => at([x, y, BEAM_Z + BEAM_H])), { size: 0.45 }));
  for (const y of LANES) o.push(L(k.planOutline({ x: PIN_X - 0.6, y: y - 4.6, w: 3.6, d: 9.2, r: 0.6 }, BEAM_Z + BEAM_H, P, 2), { tone: "faint" }));
  return o.join("");
}
const flag = () => S(k.slabOf({ x: -3, y: -6, w: 6, d: 12, r: 1.2 }, BEAM_Z + BEAM_H, 4, P, 3, 0.4), { tone: "hi", crease: "lo" });

function pan() {
  const o = [];
  const [x, y] = PAN;
  o.push(`<path class="iso-halo" d="${k.haloOf({ x: x - 13, y: y - 13, w: 26, d: 26, r: 13 }, 0, 2, P)}"/>`);
  o.push(S(k.cylinder(x, y, 13, 0, 2.2, P, 40, 0.5), { tone: "mid" }));
  o.push(L(k.knurl(x, y, 13, 0.3, 2, 60, P, 0.3), { tone: "lo" }));
  o.push(S(k.cylinder(x, y, 4, 2.2, PAN_Z - 2.2, P, 24), { tone: "mid", crease: "none" }));
  o.push(S(k.cylinder(x, y, PAN_R, PAN_Z, PAN_TOP - PAN_Z, P, 56, 0.5), { tone: "mid" }));
  o.push(L(k.ring(x, y, PAN_R - 2.4, PAN_TOP, P, 56), { tone: "lo" }));
  return o.join("");
}

function dialArm() {
  const arm = { x: PAN[0] - 3, y: POST[1] + 5, w: 6, d: -POST[1] - 5 - DIAL_R + 1.5, r: 1.5 };
  return S(k.slabOf(arm, DIAL_Z + 1, 4, P, 3, 0.4), { tone: "mid" }) + D([at([PAN[0], arm.y + 4, DIAL_Z + 5]), at([PAN[0], arm.y + arm.d - 4, DIAL_Z + 5])], { size: 0.4 });
}
const plunger = () => S(k.cylinder(PAN[0], PAN[1], 2.4, 0, 1.4, P, 20), { tone: "hi", lit: true }) + S(k.cylinder(PAN[0], PAN[1], 1.2, 1.4, ROD_LEN, P, 16), { tone: "hi", crease: "none", lit: true });

function dial() {
  const o = [];
  const [x, y] = PAN;
  o.push(S(k.cylinder(x, y, DIAL_R, DIAL_Z, DIAL_H, P, 64, 0.8), { tone: "hi", crease: "lo" }));
  o.push(L(k.knurl(x, y, DIAL_R, DIAL_TOP - 2.6, DIAL_TOP, 72, P, 0.3), { tone: "lo" }));
  o.push(L(k.ring(x, y, DIAL_R - 2, DIAL_TOP, P, 64), { tone: "lo" }));
  const t = k.radialTicks(x, y, DIAL_R - 2.6, 40, 10, DIAL_TOP, [1, 2.4], P);
  o.push(L(t.minor, { tone: "lo" }), L(t.major, { tone: "mid" }));
  o.push(L(k.ring(x, y, 1.4, DIAL_TOP, P, 16), { tone: "mid" }));
  return o.join("");
}
// Needle: zero (12 o'clock) = the receiver got exactly the limit. One quarter turn = one payment beyond it.
function needleAt(beyond) {
  const a = beyond * Math.PI / 2, x = PAN[0], y = PAN[1];
  return lineOnTop([x - Math.sin(a) * 3, y + Math.cos(a) * 3], [x + Math.sin(a) * (DIAL_R - 3.4), y - Math.cos(a) * (DIAL_R - 3.4)], DIAL_TOP + 0.2, P);
}
const lineOnTop = k.lineOnTop;

const g = (part, inner, transform = "", extra = "") => `<g data-part="${part}"${transform ? ` transform="${transform}"` : ""}${extra}>${inner}</g>`;
const laneParts = (i) => {
  const y = LANES[i];
  return [
    g(`rod${i}`, ""),
    g(`head${i}`, head(y), k.translateAlong(P, [HEAD_REST, 0, 0])),
    g(`coin${i}`, coin(), k.translateAlong(P, [START_X, y, RISER_TOP])),
    g(`pin${i}`, ""),
  ].join("");
};

const svg = k.figureSvg({
  width: W, height: H,
  label: "A test bench. On the left, a feeder with two plungers pushes one payment coin down each of two lanes at the same moment. In the middle, the guard is a gate over the lanes with a stop pin in each lane and a 'paid' flag that slides along its top beam when the guard records a payment. On the right, coins land on the receiver's pan, and a dial indicator resting on the stack reads how far the receiver was paid beyond the limit.",
  body: [
    base(), dialStand(), gatePost(-35), magazine(), riser(),
    rail(-23), laneParts(0), rail(0), laneParts(1), rail(23),
    gatePost(26), gateTop(), g("flag", flag(), k.translateAlong(P, [FLAG_OPEN, 0, 0])),
    pan(),
    g("stack0", coin(), "", ' opacity="0"'), g("stack1", coin(), "", ' opacity="0"'),
    dialArm(), g("plunger", plunger(), k.translateAlong(P, [0, 0, PAN_TOP])), dial(),
    `<path data-part="needle" class="iso-line" data-tone="lit" data-free="start" d="${needleAt(-1)}" style="stroke-width:1.1"/>`,
  ],
});

// ---------------------------------------------------------------- live replay
const live = `
const P = ${JSON.stringify(P)};
const C = ${JSON.stringify({ LANES, COIN_R, COIN_H, START_X, CHECK_X, LANE_END, HEAD_REST, HEAD_PUSH, PIN_X, PIN_TOP, RISER_TOP, FLAG_OPEN, FLAG_PAID, PAN, PAN_TOP, DIAL_R, DIAL_TOP })};
const SC = ${JSON.stringify(scenarios.map(({ id, label, where, fixed, coin, limit, paid, beyond, log, links, source, trials }) => ({ id, label, where, fixed, coin, limit, paid, beyond, log, links, source, trials })))};
const PAN = C.PAN, DIAL_R = C.DIAL_R, DIAL_TOP = C.DIAL_TOP;
${needleAt.toString()}
const fig = document.querySelector("[data-fig]");
const svg = fig.querySelector("svg");
const $ = (n) => svg.querySelector('[data-part="' + n + '"]');
const readout = document.querySelector("[data-readout]");
const logBox = document.querySelector("[data-log]");
const meta = document.querySelector("[data-meta]");
const tabs = [...document.querySelectorAll("[data-scenario]")];
const still = matchMedia("(prefers-reduced-motion: reduce)");
const ease = (t) => t <= 0 ? 0 : t >= 1 ? 1 : t * t * (3 - 2 * t);
const span = (t, a, b) => ease((t - a) / (b - a));
const lerp = (a, b, u) => a + (b - a) * u;
const END = 8.6;
let sc = SC[0], clock = 0, last = 0, frame = 0, visible = false, shown = -1, tip = { at: C.PAN_TOP, v: 0 }, needle = -1;
const rodSvg = (plan) => solidSvg(slabOf(plan, 9, 2.4, P, 3, 0.3), { tone: "mid" });
function laneState(i, t) {
  const y = C.LANES[i], blocked = sc.fixed && i === 1;
  const headX = lerp(C.HEAD_REST, C.HEAD_PUSH, span(t, 0.3, 0.9)) - (C.HEAD_PUSH - C.HEAD_REST) * span(t, 1.0, 1.6);
  let x = lerp(C.START_X, C.CHECK_X, span(t, 0.6, 1.8)), inLane = true, stackU = 0;
  if (!blocked) {
    const d = i === 0 ? 0 : 0.2;
    if (t >= 1.8) x = lerp(C.CHECK_X, C.LANE_END, span(t, 1.9 + d, 3.0 + d));
    if (t >= 3.0 + d) { inLane = false; stackU = span(t, 3.0 + d, 3.5 + d); }
  } else if (t > 4.2) {
    x = lerp(C.CHECK_X, C.START_X, span(t, 4.2, 5.2));
  }
  const pinUp = blocked ? span(t, 1.8, 2.05) * (1 - span(t, 5.4, 5.8)) : 0;
  return { y, headX, x, inLane, stackU, pinUp };
}
const landed = (t) => [0, 1].filter((i) => !(sc.fixed && i === 1) && t >= 3.5 + (i ? 0.2 : 0)).length;
function draw(t) {
  const fade = 1 - span(t, END - 0.5, END);
  for (const i of [0, 1]) {
    const s = laneState(i, t);
    $("head" + i).setAttribute("transform", translateAlong(P, [s.headX, 0, 0]));
    const rodTo = s.headX - 3;
    $("rod" + i).innerHTML = rodTo > -139.8 ? rodSvg({ x: -140, y: s.y - 1.2, w: rodTo + 140, d: 2.4, r: 0.5 }) : "";
    const lane = $("coin" + i), stack = $("stack" + i);
    lane.setAttribute("transform", translateAlong(P, [s.x, s.y, C.RISER_TOP]));
    lane.setAttribute("opacity", s.inLane ? "1" : "0");
    if (!s.inLane) {
      const sx = lerp(C.LANE_END, C.PAN[0], s.stackU), sy = lerp(s.y, C.PAN[1], s.stackU);
      const sz = lerp(C.RISER_TOP, C.PAN_TOP + i * C.COIN_H, s.stackU) + Math.sin(Math.PI * s.stackU) * 5;
      stack.setAttribute("transform", translateAlong(P, [sx, sy, sz]));
      stack.setAttribute("opacity", String(fade));
    } else stack.setAttribute("opacity", "0");
    const h = (C.PIN_TOP - C.RISER_TOP) * s.pinUp;
    $("pin" + i).innerHTML = h > 0.3 ? solidSvg(slabOf({ x: C.PIN_X, y: s.y - 4, w: 2.4, d: 8, r: 0.5 }, C.RISER_TOP, h, P, 2, 0.2), { tone: "hi", lit: true }) : "";
  }
  const flagAt = (sc.fixed ? span(t, 1.8, 2.1) : span(t, 3.9, 4.2)) * fade;
  $("flag").setAttribute("transform", translateAlong(P, [lerp(C.FLAG_OPEN, C.FLAG_PAID, flagAt), 0, 0]));
  return landed(t);
}
const escHtml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
function writeLog(t) {
  const due = sc.log.filter((l) => t >= l.at).length + (t >= 5.0 ? 1 : 0);
  if (due === shown) return;
  shown = due;
  const lines = sc.log.slice(0, Math.min(due, sc.log.length)).map((l) => "<li>" + escHtml(l.text) + "</li>");
  if (due > sc.log.length) lines.push('<li class="result">receiver got ' + sc.paid + " on a " + sc.limit + " limit: " + sc.beyond + " tokens paid beyond policy</li>");
  logBox.innerHTML = lines.join("");
}
function setReadout(t) {
  const paid = landed(t) * sc.coin;
  const text = t < 3.4 ? "paid 0 · limit " + sc.limit : "paid " + paid + " · beyond policy " + Math.max(0, paid - sc.limit);
  if (readout.textContent !== text) readout.textContent = text;
}
function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  clock += dt;
  if (clock > END) { clock = 0; shown = -1; }
  const n = draw(clock);
  const want = C.PAN_TOP + n * C.COIN_H * (1 - span(clock, END - 0.5, END));
  for (let s = 0; s < 4; s++) { tip.v += ((want - tip.at) * 380 - tip.v * 26) * dt / 4; tip.at += tip.v * dt / 4; }
  $("plunger").setAttribute("transform", translateAlong(P, [0, 0, tip.at - C.PAN_TOP]));
  needle += ((tip.at - C.PAN_TOP) / C.COIN_H - 1 - needle) * (1 - Math.exp(-dt / 0.12));
  $("needle").setAttribute("d", needleAt(needle));
  writeLog(clock); setReadout(clock);
  frame = visible ? requestAnimationFrame(tick) : 0;
}
function finalFrame() {
  clock = 6; const n = draw(clock); tip.at = C.PAN_TOP + n * C.COIN_H;
  $("plunger").setAttribute("transform", translateAlong(P, [0, 0, tip.at - C.PAN_TOP]));
  $("needle").setAttribute("d", needleAt(n - 1)); shown = -1; writeLog(clock); setReadout(clock);
}
function start() { if (!frame && visible && !still.matches) { last = 0; frame = requestAnimationFrame(tick); } }
function choose(id) {
  sc = SC.find((s) => s.id === id) || SC[0];
  tabs.forEach((b) => { const on = b.dataset.scenario === sc.id; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
  const link = sc.links.map(([l, u]) => '<a href="' + u + '" rel="noopener">' + l + " on nearblocks</a>").join(" · ");
  meta.innerHTML = "<span>" + sc.where + "</span>" + (sc.trials ? "<span>all " + sc.trials.length + " trials paid: " + sc.trials.join(", ") + "</span>" : "") + (link ? "<span>" + link + "</span>" : "") + "<span>source: " + sc.source + "</span>";
  clock = 0; shown = -1; tip = { at: C.PAN_TOP, v: 0 }; needle = -1;
  if (still.matches) finalFrame(); else start();
}
tabs.forEach((b) => b.addEventListener("click", () => choose(b.dataset.scenario)));
document.querySelector("[data-tablist]").addEventListener("keydown", (e) => {
  const i = tabs.findIndex((b) => b.getAttribute("aria-selected") === "true");
  const j = e.key === "ArrowRight" ? (i + 1) % tabs.length : e.key === "ArrowLeft" ? (i + tabs.length - 1) % tabs.length : -1;
  if (j < 0) return; e.preventDefault(); tabs[j].focus(); choose(tabs[j].dataset.scenario);
});
new IntersectionObserver((es) => { visible = es[es.length - 1].isIntersecting; start(); }, { rootMargin: "80px 0px" }).observe(fig);
const dark = matchMedia("(prefers-color-scheme: dark)");
const setTheme = () => { document.body.dataset.theme = dark.matches ? "dark" : "light"; };
setTheme(); dark.addEventListener("change", setTheme);
choose(SC[0].id);
const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("on"); io.unobserve(e.target); } }), { rootMargin: "0px 0px -8% 0px" });
document.querySelectorAll(".reveal").forEach((el) => io.observe(el));
`;

// ---------------------------------------------------------------- labels
// A labelled drawing. The labels sit in their own layer over the figure, in the empty
// margins, so the machine itself stays clean. Each points at a world position projected with the
// figure's own camera. Under 768 px the layer hides and the same labels show as a numbered list.
const CALLOUTS = [
  { n: 1, part: [-154, 0, 28], at: [6, 62], anchor: "start", text: ["Agent", "two calls at once"] },
  { n: 2, part: [BEAM.x + BEAM.w / 2, BEAM.y + 4, BEAM_Z + BEAM_H], at: [420, 26], anchor: "start", text: ["Guard", "checks \"paid?\" for each call"] },
  { n: 3, part: [PIN_X + 1.2, LANES[1], RISER_TOP + 8], at: [196, 336], anchor: "start", text: ["Stop pin", "rises when the guard refuses"] },
  { n: 4, part: [PAN[0], PAN[1] + PAN_R - 2, PAN_TOP], at: [560, 404], anchor: "start", text: ["Receiver", "coins that landed"] },
  { n: 5, part: [PAN[0] + DIAL_R - 2, PAN[1], DIAL_TOP], at: [616, 140], anchor: "start", text: ["Dial", "paid beyond the limit"] },
];
const calloutSvg = `<g class="callouts" aria-hidden="true">${CALLOUTS.map((c) => {
  const [px, py] = at(c.part), [tx, ty] = c.at;
  // Start the leader on the side of the label that faces the part, so it never crosses the text.
  const w = Math.max(c.text[0].length + 3, c.text[1].length) * 5.75;
  const [lx, ly] = px > tx + w ? [tx + w + 4, ty - 4] : py > ty + 14 ? [tx + 2, ty + 17] : [tx - 6, ty - 4];
  return `<path d="M${lx.toFixed(1)} ${ly.toFixed(1)}L${px.toFixed(1)} ${py.toFixed(1)}"/><circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="1.8"/>` +
    `<text x="${tx}" y="${ty}" text-anchor="${c.anchor}"><tspan class="t">${c.n}  ${esc(c.text[0])}</tspan><tspan x="${tx}" dy="12">${esc(c.text[1])}</tspan></text>`;
}).join("")}</g>`;
const calloutList = `<ol class="callout-list">${CALLOUTS.map((c) => `<li><b>${esc(c.text[0])}</b> ${esc(c.text[1])}</li>`).join("")}</ol>`;

// ---------------------------------------------------------------- page
const plate = k.plateHtml({
  fig: "Fig 1", title: "Two keys, one invoice", hint: "Pick a run above", readout: `paid 0 · limit ${flawT.limit}`,
  keys: [{ mark: "lit", label: "Dial zero is the invoice limit. Past zero means paid beyond policy." }],
  caption: "",
  body: `<div data-fig class="iso-stage">${svg.slice(0, svg.lastIndexOf("</svg>")) + calloutSvg + "</svg>"}</div>${calloutList}`,
});

const guardMeta = { A: "Invoice payer with a payee list and a daily cap", B: "Native-NEAR vault with caps, approvals and a pause switch", C: "Company treasury with a bill pot and a profit pot" };
const guardRows = ["A", "B", "C"].map((G) => `
  <details class="guard">
    <summary><span class="g-letter">${G}</span><span class="g-what">${esc(guardMeta[G])}</span><span class="g-n">${covCount(G, "claimed", true)}/${covCount(G, "claimed")}</span></summary>
    <div class="card"><table><thead><tr><th>Test</th><th>What we tried</th><th>Result</th><th>Paid (limit)</th></tr></thead><tbody>
    ${cov[G].rows.map((r) => `<tr><td>${md(r.test)}</td><td>${md(r.tried)}</td><td>${md(r.result)}</td><td class="num">${md(r.paid)}</td></tr>`).join("")}
    </tbody></table></div>
  </details>`).join("");

const cap = (n) => n[0].toUpperCase() + n.slice(1);
const injRows = inj.map((r) => `<tr><td>${esc(r.scenario)}</td><td class="num${r.wrong.length ? " bad" : ""}">${r.wrong.length ? r.wrong.map(([n, v]) => `${v} to ${cap(n)}`).join(", ") : "0"}</td><td class="num">${r.policy}</td></tr>`).join("");

const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arena</title>
${FAVICON}
<meta name="description" content="Arena tests the guards that stop AI agents overspending on NEAR, and scores them from final token balances.">
${FONTS}
<style>${k.ISO_CSS}
${themeCss()}
body.iso{--anatomy-page:var(--bg);--anatomy-card:var(--card);--anatomy-text:var(--ink);--anatomy-mono:var(--mono)}
h1{font:600 clamp(36px,5.4vw,58px)/1.04 var(--sans);letter-spacing:-.035em;margin:16px 0 18px;max-width:15ch;text-wrap:balance}
h2{font:600 28px/1.15 var(--sans);letter-spacing:-.025em;margin:0 0 10px}
.sub{color:var(--muted);max-width:56ch;margin:0 0 28px}
/* hero: text left, the contrast right */
.hero{display:grid;grid-template-columns:1.15fr 1fr;gap:56px;align-items:center;padding:72px 0 64px}
.lede{font-size:17px;max-width:40ch;margin:0 0 28px}
.ctas{display:flex;gap:10px;flex-wrap:wrap}
.contrast{display:grid;grid-template-rows:auto auto;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--card)}
.contrast > div{padding:28px 30px}
.contrast .n{font:500 64px/1 var(--sans);letter-spacing:-.04em;font-variant-numeric:tabular-nums}
.contrast .k{font:500 12px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase;margin-top:10px}
.contrast .note{font-size:13px;color:var(--muted);margin-top:6px}
.contrast .bad{background:var(--bad-bg);color:var(--bad)}.contrast .bad .note{color:var(--bad);opacity:.8}
.held{font:13px/1.5 var(--mono);color:var(--muted);margin-top:14px}
section{padding:64px 0;border-top:1px solid var(--line)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 14px}
.tabs button{font:500 13px/1.2 var(--sans);color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 14px;cursor:pointer;text-align:left}
.tabs button small{display:block;font:11px/1.3 var(--mono);color:var(--muted);margin-top:3px}
.tabs button[aria-selected="true"]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.tabs button[aria-selected="true"] small{color:inherit;opacity:.7}
.tabs button:active{transform:scale(.98)}
.tabs button:focus-visible{outline:2px solid var(--muted);outline-offset:2px}
.iso-figure{margin:0}
.iso-figure figcaption:empty{display:none}
.callouts path{stroke:var(--muted);stroke-width:.6;fill:none}.callouts circle{fill:var(--ink)}
.callouts text{font:9.5px var(--mono);fill:var(--muted)}.callouts .t{fill:var(--ink);font-weight:500}
.callout-list{display:none}
.meta{display:flex;flex-wrap:wrap;gap:4px 16px;font:12px/1.5 var(--mono);color:var(--muted);margin:12px 0 8px}
.meta a{color:var(--ink)}
ol.log{list-style:none;margin:0;padding:14px 18px;min-height:168px;background:var(--card);border:1px solid var(--line);border-radius:8px;font:12.5px/1.75 var(--mono);counter-reset:s}
ol.log li{counter-increment:s;animation:in .5s cubic-bezier(.16,1,.3,1) both}
ol.log li::before{content:counter(s,decimal-leading-zero) "  ";color:var(--muted)}
ol.log li.result{font-weight:500;margin-top:6px}ol.log li.result::before{content:"=   "}
@keyframes in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
/* where the 450 went: rule left, table right */
.split{display:grid;grid-template-columns:1fr 1.5fr;gap:48px;align-items:start}
.rule{font-size:20px;line-height:1.4;letter-spacing:-.01em;margin:0 0 16px;max-width:24ch}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{font:500 10.5px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
td{padding:11px 12px;vertical-align:top}
tbody tr + tr td{border-top:1px solid var(--line)}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}td.bad{color:var(--bad);font-weight:500}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 6px;overflow-x:auto}
.small{font-size:13px;color:var(--muted);margin:12px 0 0}
details.guard{border-bottom:1px solid var(--line)}
details.guard summary{list-style:none;display:grid;grid-template-columns:48px 1fr auto 24px;gap:16px;align-items:center;padding:20px 4px;cursor:pointer}
details.guard summary::-webkit-details-marker{display:none}
details.guard summary::after{content:"+";font:400 20px/1 var(--mono);color:var(--muted);text-align:right}
details.guard[open] summary::after{content:"\\2212"}
details.guard[open] .card{margin-bottom:20px}
.g-letter{font:600 28px/1 var(--sans);letter-spacing:-.03em}.g-what{color:var(--muted)}.g-n{font:500 14px var(--mono)}
.run{display:grid;grid-template-columns:1fr 1fr;gap:48px;align-items:start}.run.solo{grid-template-columns:1fr}
pre{font:12.5px/1.8 var(--mono);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;overflow-x:auto;margin:0}
ul.limits{padding:0;margin:0;list-style:none}ul.limits li{padding:10px 0}ul.limits li + li{border-top:1px solid var(--line)}
/* links under the hero: rows, in the same language as the guard list */
.paths{margin:0;border-top:1px solid var(--line)}
.paths a:last-child{border-bottom:0}
.paths a{display:grid;grid-template-columns:220px 1fr 24px;gap:16px;align-items:baseline;padding:18px 4px;border-bottom:1px solid var(--line);text-decoration:none}
.paths .p-k{font:600 17px/1.3 var(--sans);letter-spacing:-.015em}
.paths .p-d{color:var(--muted)}
.paths .p-go{font:400 18px/1 var(--mono);color:var(--muted);text-align:right;transition:transform .2s cubic-bezier(.16,1,.3,1)}
.paths a:hover .p-go{transform:translateX(3px);color:var(--ink)}
.paths a:hover .p-k{text-decoration:underline;text-underline-offset:3px;text-decoration-thickness:1px}
/* test your own guard */
.mini{font:500 11px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:28px 0 10px}
.check-cmd{font-size:14px;margin:0 0 4px}
ul.guides{list-style:none;margin:0;padding:0}ul.guides li{padding:8px 0}ul.guides li + li{border-top:1px solid var(--line)}
ul.guides span{display:block;color:var(--muted);font-size:13.5px}
.check-gif{margin:0 0 16px}.check-gif img{display:block;width:100%;height:auto;border:1px solid var(--line);border-radius:var(--radius-card)}
.card.sample{padding:20px 22px}
.sample-top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}
.sample-nums{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.sample-nums .s{background:var(--card);padding:14px 14px 12px}
.sample-nums .n{font:500 32px/1 var(--sans);letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.sample-nums .k{font:500 10.5px/1.35 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:8px}
.sample-nums .s.bad{background:var(--bad-bg)}.sample-nums .s.bad .n,.sample-nums .s.bad .k{color:var(--bad)}
.site-foot code{font-size:11.5px}
.reveal{opacity:0;transform:translateY(12px);transition:opacity .6s cubic-bezier(.16,1,.3,1),transform .6s cubic-bezier(.16,1,.3,1)}.reveal.on{opacity:1;transform:none}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}.reveal{opacity:1;transform:none;transition:none}ol.log li{animation:none}}
@media (max-width:768px){.callouts{display:none}.callout-list{display:block;margin:10px 0 0;padding-left:20px;font-size:13px;color:var(--muted)}.callout-list b{color:var(--ink);font-weight:500}.hero,.split,.run{grid-template-columns:1fr;gap:28px}.hero{padding:48px 0 40px}.contrast .n{font-size:48px}.tabs button{flex:1 1 45%}details.guard summary{grid-template-columns:32px 1fr auto 18px;gap:10px}.g-letter{font-size:22px}section{padding:48px 0}.paths a{grid-template-columns:1fr 18px;gap:4px 12px}.paths .p-d{grid-column:1;grid-row:2;font-size:14px}.paths .p-go{grid-row:1/3;grid-column:2;align-self:center}.sample-nums{grid-template-columns:1fr 1fr}}
</style></head>
<body class="iso" data-theme="light">
${topbar("results")}
<div class="wrap">
<header class="hero">
  <div>
    <div class="eyebrow">NEAR hackathon · AI Security</div>
    <h1>the guard broke zero rules. the owner still lost ${worst}.</h1>
    <p class="lede">Arena attacks AI payment guards on NEAR, then proves whether they can pay what you didn't mean.</p>
    <div class="ctas"><a class="btn primary" href="#replay">Watch it break</a><a class="btn ghost" href="#run">Run the proof</a></div>
  </div>
  <div>
    <div class="contrast">
      <div><div class="n">${worstPolicy}</div><div class="k">tokens paid beyond policy</div><div class="note">Every guard rule held.</div></div>
      <div class="bad"><div class="n">${worst}</div><div class="k">tokens paid against the owner's intent</div><div class="note">In one run: the worst case our proof tool (z3) found, replayed twice on a local test chain.</div></div>
    </div>
    <div class="held">${claimedHeld}/${claimedTests} tests of their own rules held, on three teams' guards</div>
  </div>
</header>

<nav class="paths" aria-label="More in Arena">
  <a href="board.html"><span class="p-k">Results board</span><span class="p-d">Every attack against every guard, with the latest result. ${boardAttacks} attacks, ${boardGuards.length} guards.</span><span class="p-go" aria-hidden="true">&rarr;</span></a>
  <a href="lookup.html"><span class="p-k">Look up a guard</span><span class="p-d">Type a guard's account on NEAR testnet. See what Arena tested.</span><span class="p-go" aria-hidden="true">&rarr;</span></a>
  <a href="#check"><span class="p-k">Test your own guard</span><span class="p-d">One command runs all ${checkCount} attacks against your guard, on your own machine.</span><span class="p-go" aria-hidden="true">&rarr;</span></a>
</nav>

<section id="replay" class="reveal">
  <h2>Two keys, one invoice</h2>
  <p class="sub">Two pay calls for one invoice, sent at once. A guard that records "paid" too late pays twice.</p>
  <div class="tabs" role="tablist" data-tablist aria-label="Runs to replay">
    ${scenarios.map((s, i) => `<button role="tab" data-scenario="${s.id}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}">${esc(s.label)}<small>${esc(s.where)}</small></button>`).join("")}
  </div>
  ${plate}
  <div class="meta" data-meta></div>
  <ol class="log" data-log aria-live="polite"></ol>
</section>

<section class="reveal">
  <div class="split">
    <div>
      <h2>Where ${injWrong} went, over five runs</h2>
      <p class="rule">The owner's rule, set before any run: pay Sam 100. Nothing else.</p>
      <p class="sub">Five separate runs of a scripted agent that obeys every injection, added up. No single run paid more than ${injMaxRun}. Every payment went to a creditor the owner had approved, so the guard allowed it.</p>
    </div>
    <div>
      <div class="card"><table><thead><tr><th>Injected through</th><th>Against intent</th><th>Beyond policy</th></tr></thead><tbody>${injRows}</tbody></table></div>
      <p class="small">The real model, Muse Spark 1.3, was fooled 0 times in 52 runs.</p>
    </div>
  </div>
</section>

<section class="reveal">
  <h2>Three teams' guards: ${claimedHeld} of ${claimedTests} held</h2>
  <p class="sub">We tested each guard against the rules it wrote down: ${claimedTests} tests, ${claimedHeld} held. We also ran ${stressTests} stress test on a rule Guard ${stressGuards.join(", ")} never promised (it held), and ${honestPays} normal payments, one per guard, to check each guard works (all ${honestSettled} went through). Guards are named by letter.</p>
  ${guardRows}
</section>

<section id="check" class="reveal">
  <div class="run${gifHtml || sampleHtml ? "" : " solo"}">
    <div>
      <h2>Test your own guard</h2>
      <p class="sub">One command runs all ${checkCount} attacks ${checkWhere} against your guard. It runs on a local NEAR sandbox, a private copy of NEAR on your own machine, and writes a report card.</p>
<pre class="check-cmd">./arena check my_guard.wasm</pre>
      <div class="mini">On every pull request</div>
      <p class="sub" style="margin:0">A GitHub Action runs the same check on every pull request. Start from ${repoPath("examples/workflows/arena-check.yml")}. It has not run on GitHub yet.</p>
      <div class="mini">Guides</div>
      <ul class="guides">
        <li>${repoPath("docs/CHECK-YOUR-GUARD.md")}<span>How to test your guard and read the report card.</span></li>
        <li>${repoPath("docs/CHECK-BEFORE-YOU-PAY.md")}<span>How to look up a guard before you pay it.</span></li>
      </ul>
    </div>
    ${gifHtml || sampleHtml ? `<div>${gifHtml}${sampleHtml}</div>` : ""}
  </div>
</section>

<section id="run" class="reveal">
  <div class="run">
    <div>
      <h2>Run it yourself</h2>
      <p class="sub">Needs Rust and Python 3. The proofs also need Kani and z3, and near-tla needs Java 17+. Each check prints PASS or FAIL.</p>
      <p class="sub">The proof on any number of calls covers the model only. The model matches the real code in every case we checked: up to 4 pay calls (4,555 states), and 2 in the full world with faults (21,345 states). A review of our proofs found a bug in our own fix: <code>reconcile</code> reopened a bill, which paid 200 on 100. We fixed it and re-ran both proof scripts.</p>
    </div>
<pre>./verify.sh fast   # 5 checks, about 8 min
./verify.sh        # 43 checks, about 16 min
proofs/run.sh      # 30 checks, about 25 min
tla/run.sh         # near-tla, 25 checks, about 46 min
ARENA_AGENT=compromised python3 -I tools/injection/run.py
python3 -I tools/injection/rescore.py</pre>
  </div>
</section>

<section class="reveal">
  <h2>Limits</h2>
  <ul class="limits">
    <li>Only our planted flaw and its fix ran on testnet, both on the current build (<code>0382023b…</code>, Nov 10). The <code>reconcile</code> fix itself was not tested on testnet, because the race never reaches it. The three teams' guards ran on a local sandbox.</li>
    <li>${claimedHeld}/${claimedTests} means each guard kept the rules it wrote down, in these tests. It is not a security proof.</li>
    <li>The ${injWrong} is five scripted runs added up. The ${worst} is one run: the worst case our proof tool (z3) found, replayed on a local test chain. Neither came from the real model.</li>
    <li>Anyone can look up our results on NEAR testnet. The broken and fixed guards share one code fingerprint, so a lookup must also read the guard's mode.</li>
    <li>Races were tested at a few spacings on a local test chain: the second payment checked in the same block, one block later, or 4 and 8 blocks later while a slow test token held the first answer back.</li>
  </ul>
</section>

</div>
${footer("Numbers are read from <code>evidence/</code> at build time. Fig 1 uses the anatomy kit (MIT, © 2026 Ryan).")}
<script type="module">${(kitScript() + live).replace(/<\/(script)/gi, "<\\/$1")}</script>
</body></html>`;

if (/\/Users\/|\/home\//.test(page)) throw new Error("site/index.html would contain an absolute local path");
writeFileSync(join(HERE, "index.html"), page);
// lookup.html shares the theme and top bar; rebuild it too so the pages never drift apart.
const { buildLookup } = await import("./build-lookup.mjs");
buildLookup();
console.log("wrote site/lookup.html and copied the lookup modules");
console.log(`wrote site/index.html (${(page.length / 1024).toFixed(0)} KB): ${scenarios.length} runs, ${claimedHeld}/${claimedTests} guard tests held (+${stressTests} stress, ${honestPays} honest payments), ${worst} against intent in one run, ${injWrong} over five runs`);
