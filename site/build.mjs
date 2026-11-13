// Builds site/index.html, Arena's home page: the hero, the problem, how Arena works (methods), results,
// limits and how to try it, with Fig 1, a live replay of real testnet runs.
//   node site/build.mjs            (needs the anatomy kit; set ANATOMY_KIT or install the skill)
// It also rebuilds site/lookup.html (site/build-lookup.mjs). The look comes from site/theme.css and
// the top bar from site/nav.json, shared with tools/hunter/board.py. Optional: ARENA_REPO_URL, ARENA_REPO_REF.
// Every count on the page is read at build time from evidence/ (mostly evidence/MANIFEST.json) and
// site/board-data.json. The few fixed figures typed in the words are listed in the comment above `page`. The figure is drawn with the anatomy kit (MIT, (c) 2026 Ryan).
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { homedir } from "node:os";
import { themeCss, topbar, footer, FONTS, FAVICON, NAV } from "./chrome.mjs";

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

// The "Try it in 2 minutes" block links the double pay on testnet.nearblocks.io. The two transaction hashes come
// from evidence/testnet-2026-11-11.md: the planted-flaw trial whose accounts were kept alive (so the guard can also
// be looked up). They are cross-checked with that trial's raw file; the build stops if anything disagrees.
function keptDoublePay() {
  const mdText = readFileSync(ev("testnet-2026-11-11.md"), "utf8");
  const lines = mdText.split("\n").filter((l) => /vulnerable_fixture trial \d+:/.test(l) && l.includes("**kept alive**"));
  if (lines.length !== 1) throw new Error(`evidence/testnet-2026-11-11.md: expected one kept-alive vulnerable_fixture trial, found ${lines.length}`);
  const m = lines[0].match(/guard `([^`]+)`, receiver `([^`]+)`;.*full hashes A `([1-9A-HJ-NP-Za-km-z]{43,44})` B `([1-9A-HJ-NP-Za-km-z]{43,44})`/);
  if (!m) throw new Error("evidence/testnet-2026-11-11.md: could not read the kept-alive trial's guard and hashes");
  const [, guard, receiver, a, b] = m;
  const row = mdText.split("\n").find((l) => l.startsWith("|") && l.includes(`txns/${a})`) && l.includes(`txns/${b})`));
  if (!row) throw new Error("evidence/testnet-2026-11-11.md: no results row with both kept-alive hashes");
  const cells = row.split("|").map((c) => c.trim());
  const trialNo = Number(cells[1]), block = Number(cells[6].split(" ")[0]), got = Number(cells[11]);
  const raw = TESTNET.flatMap((f) => json(f).trials).filter((t) => t.pay_a?.tx === a && t.pay_b?.tx === b);
  if (raw.length !== 1) throw new Error("the kept-alive trial's hashes are not in exactly one raw testnet trial");
  const r = raw[0];
  if (!r.kept_alive || r.mode !== "vulnerable_fixture" || Number(r.receiver_received) !== got || got !== 200 || Number(r.invoice_amount) !== 100 || !Number.isInteger(block))
    throw new Error("the kept-alive trial's raw file disagrees with evidence/testnet-2026-11-11.md");
  const date = new Date(Number(r.pay_a.sent_unix_ms)).toISOString().slice(0, 10);
  const trials = mdText.split("\n").filter((l) => /^\| \d+ \| run\d \| vulnerable_fixture \|/.test(l)).length;
  return { guard, receiver, a, b, block, got, limit: Number(r.invoice_amount), invoice: r.invoice_id, date, trialNo, trials };
}
const dp = keptDoublePay();
const tx = (h) => `https://testnet.nearblocks.io/txns/${h}`;

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


// ---------------------------------------------------------------- counts from evidence/MANIFEST.json
// MANIFEST.json is written by tools/admission/manifest.py. Every attack count on the page comes from it,
// so a new admission run changes the page on the next build with no edit here.
const MAN = json("MANIFEST.json");
const num = (v, what) => { if (!Number.isInteger(v) || v < 0) throw new Error(`evidence/MANIFEST.json: ${what} is not a count (${v})`); return v; };
const lib = {
  all: num(MAN.attacks.library_intents, "attacks.library_intents"),
  token: num(MAN.attacks.library_token, "attacks.library_token"),
  validated: num(MAN.attacks.classes.validated ?? 0, "classes.validated"),
  partial: num(MAN.attacks.classes["partially-validated"] ?? 0, "classes.partially-validated"),
  unvalidated: num(MAN.attacks.classes.unvalidated ?? 0, "classes.unvalidated"),
};
if (lib.validated + lib.partial + lib.unvalidated !== lib.all)
  throw new Error(`evidence/MANIFEST.json: validated + partial + unvalidated (${lib.validated + lib.partial + lib.unvalidated}) is not the library size (${lib.all})`);
lib.intentsOnly = lib.all - lib.token;
// How many counted runs the gate needs: read from the validated rows ("... in 3 counted runs ..."), and
// stop if the rows disagree, so the page never states a rule the evidence does not show.
const runsSeen = [...new Set(MAN.attacks.rows.filter((r) => r.class === "validated").map((r) => (String(r.why).match(/in (\d+) counted runs/) || [])[1]).filter(Boolean))];
if (lib.validated > 0 && runsSeen.length !== 1) throw new Error(`evidence/MANIFEST.json: validated rows give different counted-run numbers (${runsSeen.join(", ")})`);
const gateRuns = runsSeen.length ? Number(runsSeen[0]) : null;
const hidden = { count: num(MAN.hidden_set.attack_count, "hidden_set.attack_count"), date: String(MAN.hidden_set.created_at || "").slice(0, 10) };
const hunts = { runs: num(MAN.hunts.runs, "hunts.runs"), proposed: num(MAN.hunts.attacks_proposed, "hunts.attacks_proposed"), saved: num(MAN.hunts.attacks_saved, "hunts.attacks_saved"), papers: num(MAN.hunts.papers_read, "hunts.papers_read") };
const mutants = { planted: num(MAN.mutants.planted, "mutants.planted"), caught: MAN.mutants.caught.length };

// The library as `arena check` loads it (tools/hunter/catalog.py), less the honest-payment control. It must
// equal the manifest's token count: if it does not, MANIFEST.json is stale and the page would show two numbers.
{
  const r = spawnSync("python3", ["-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import catalog; a, p = catalog.load(); u, d = catalog.unique(a); print(sum(x['meta']['id'] != 'scripted-01-control-pay-valid' for x in u) if not p else -1)", join(ROOT, "tools/hunter")], { encoding: "utf8", cwd: ROOT });
  const n = Number((r.stdout || "").trim());
  if (r.status === 0 && Number.isInteger(n) && n > 0 && n !== lib.token)
    throw new Error(`arena check loads ${n} attacks but evidence/MANIFEST.json says ${lib.token}: re-run tools/admission/manifest.py, then build`);
}

// ---------------------------------------------------------------- results on Arena's own guards
// One `arena check` per guard, all from the same day and the same library (evidence/invoice-fixes-2026-11-12).
const CHECKS = "evidence/invoice-fixes-2026-11-12/checks";
function check(dir) {
  const r = JSON.parse(readFileSync(join(ROOT, CHECKS, dir, "report.json"), "utf8"));
  const t = r.totals || {};
  for (const f of ["attacks", "ran", "held", "broke", "beyond_policy"]) num(t[f], `${CHECKS}/${dir} totals.${f}`);
  return { dir, status: r.status, attacks: t.attacks, ran: t.ran, held: t.held, broke: t.broke, key: t.stopped_by_key || 0, na: t.not_applicable || 0,
    beyond: t.beyond_policy, intent: t.against_intent ?? null, intentAttacks: t.intent_attacks ?? null, date: String(r.finished_utc || "").slice(0, 10), path: `${CHECKS}/${dir}/report.json` };
}
const ref = check("vault-a"), leaky = check("leaky-control-v2"), outflow = check("planted-outflow");
if (ref.status !== "held" || ref.broke !== 0 || leaky.status !== "broke" || outflow.status !== "broke")
  throw new Error("evidence changed: the reference guard no longer holds or a planted-flaw guard no longer breaks; update the words on the page");
const sameRun = [ref, leaky, outflow].every((c) => c.attacks === ref.attacks);
if (!sameRun) throw new Error("the three reference checks ran different attack counts; the results table says they ran the same attacks");

// ---------------------------------------------------------------- the other teams' proofs
// The one results row of evidence/proofs-all-2026-11-11.md: claims, hold, hold for the contract's part,
// counterexamples, bounds, planted flaws caught. Counts only: the file never says which guard is which.
const PROOFS = "proofs-all-2026-11-11.md";
const proofRow = readFileSync(ev(PROOFS), "utf8").split("\n").map((l) => l.match(/^\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*\**(\d+)\**\s*\|([^|]*)\|\s*(\d+) of (\d+)\s*\|\s*$/)).find(Boolean);
if (!proofRow) throw new Error(`evidence/${PROOFS}: the four-guard results row is missing`);
const teams = { claims: +proofRow[1], hold: +proofRow[2], part: +proofRow[3], counter: +proofRow[4], bounds: proofRow[5].trim().replace(/\s*\(.*\)\s*$/, ""), flawsCaught: +proofRow[6], flaws: +proofRow[7] };
if (teams.hold + teams.part + teams.counter !== teams.claims) throw new Error(`evidence/${PROOFS}: the claim counts do not add up`);

// ---------------------------------------------------------------- tests of their own claims (Guards A, B, C)
const cov = coverage();
const kindOf = (r) => (/^utility$/i.test(r.claim) ? "honest" : /not claimed/i.test(r.test) ? "stress" : "claimed");
const covCount = (G, kind, held) => cov[G].rows.filter((r) => kindOf(r) === kind && (!held || /\*\*held\*\*/.test(r.result))).length;
const claimedTests = ["A", "B", "C"].reduce((a, G) => a + covCount(G, "claimed"), 0);
const claimedHeld = ["A", "B", "C"].reduce((a, G) => a + covCount(G, "claimed", true), 0);

// ---------------------------------------------------------------- the testnet replay (Fig 1)
const scenarios = [testnetScenario("vulnerable_fixture", "Planted flaw"), testnetScenario("fixed", "Fixed guard")];
for (const s of scenarios) s.beyond = Math.max(0, s.paid - s.limit);
const flawT = scenarios[0];
if (flawT.paid !== 200 || scenarios[1].paid !== 100 || flawT.trials.some((v) => v !== 200) || scenarios[1].trials.some((v) => v !== 100))
  throw new Error("evidence changed: the testnet trials no longer pay 200 and 100; update the words on the page");

// ---------------------------------------------------------------- the board
// site/board-data.json (written by tools/hunter/board.py) says how many attacks the board shows and how many
// of them are in the library; the page uses the same words as the board.
const boardData = JSON.parse(readFileSync(join(HERE, "board-data.json"), "utf8"));
const boardGuards = boardData.guards.filter((g) => g.runnable);
const boardAttacks = boardData.attacks.length;
const boardInLib = boardData.attacks.filter((a) => a.in_library).length;
const boardDates = [...new Set(boardData.cells.map((c) => c.date).filter(Boolean))].sort();
if (!boardDates.length) throw new Error("site/board-data.json has no dated cells");
const boardRange = boardDates.length === 1 ? boardDates[0] : `${boardDates[0]} to ${boardDates[boardDates.length - 1]}`;

// ---------------------------------------------------------------- links into the repo
// Doc and file names link into the public repo (site/nav.json "repo", at its ref). ARENA_REPO_URL and
// ARENA_REPO_REF override it; ARENA_REPO_URL=none turns every link back into a plain code-font path.
// Every linked path must exist in this checkout, or the build stops: no dead links.
const REPO = (() => {
  const env = process.env.ARENA_REPO_URL;
  if (env === "none") return null;
  const base = (env || NAV.repo?.url || "").replace(/\/+$/, "");
  const ref = process.env.ARENA_REPO_REF || NAV.repo?.ref || "main";
  if (!base) return null;
  if (!/^https:\/\/[A-Za-z0-9.-]+(\/[A-Za-z0-9._~-]+)*$/.test(base) || !/^([0-9a-f]{7,40}|[A-Za-z0-9][A-Za-z0-9._-]{0,99})$/.test(ref) || ref.includes(".."))
    throw new Error("the repo URL must be a plain https URL and the ref a commit id or simple branch name");
  return { base, ref };
})();
const repoHref = (p) => {
  if (!existsSync(join(ROOT, p.replace(/#.*$/, "")))) throw new Error(`site/build.mjs links to ${p}, which is not in the repo`);
  return REPO ? `${REPO.base}/${p.endsWith("/") ? "tree" : "blob"}/${REPO.ref}/${p.replace(/\/$/, "")}` : null;
};
const repoPath = (p, label = p) => { const h = repoHref(p); return h ? `<a href="${esc(h)}" rel="noopener"><code>${esc(label)}</code></a>` : `<code>${esc(label)}</code>`; };
const README = repoHref("README.md") || "#try";

// ---------------------------------------------------------------- the terminal recording
// The GIF is one real `arena check` run. Its words (command, headline, counts, the attacks that broke) are
// read from that run's report.json, and shown as text too: on a phone the GIF's text is too small to read.
const GIF = "img/arena-check.gif";
const GIF_RUN = "evidence/check-fixes-2-2026-11-11/leaky-control-v2/report.json";
const gifSize = (b) => (b.toString("latin1", 0, 3) === "GIF" ? { w: b.readUInt16LE(6), h: b.readUInt16LE(8) } : null);
const gifDims = existsSync(join(HERE, GIF)) ? gifSize(readFileSync(join(HERE, GIF))) : null;
const gifRun = JSON.parse(readFileSync(join(ROOT, GIF_RUN), "utf8"));
const gifT = gifRun.totals;
const brokeRows = (gifRun.attacks || []).filter((a) => a.status === "broke");
const transcript = [
  `$ ${gifRun.command.replace(/ --out .*$/, "")}`,
  `arena: ${gifRun.headline}`,
  `honest payment: ${gifRun.control?.result ?? "no result"}`,
  `tokens paid beyond the guard's own rules: ${gifT.beyond_policy}`,
  `attacks: ${gifT.held} held, ${gifT.broke} broke, ${gifT.not_applicable} not applicable`,
  ...brokeRows.map((a) => `BROKE ${a.id}: +${a.beyond_policy}`),
].join("\n");
const gifDate = String(gifRun.finished_utc || "").slice(0, 10);
const gifHtml = existsSync(join(HERE, GIF)) ? `<figure class="term">
  <img class="term-gif" src="${GIF}"${gifDims ? ` width="${gifDims.w}" height="${gifDims.h}" style="aspect-ratio:${gifDims.w}/${gifDims.h}"` : ""} alt="A terminal running ./arena check on Arena's leaky-on-purpose guard. The attacks run one by one, then the report card says broke ${gifT.broke} of ${gifT.attacks}." decoding="async">
  <details class="term-text"><summary>Read the run as text</summary><pre tabindex="0" aria-label="The recorded run, as text">${esc(transcript)}</pre></details>
  <div class="mini term-phone-k">The recorded run, as text</div>
  <pre class="term-phone" tabindex="0" aria-label="The recorded run, as text">${esc(transcript)}</pre>
  <figcaption>Recorded ${esc(gifDate)} on <code>leaky-control-v2</code>, Arena's leaky-on-purpose guard. The library had ${gifT.attacks} attacks that day. From ${repoPath(GIF_RUN)}.</figcaption>
</figure>` : "";


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
// The log always holds the run's whole record, so the box is never empty (before the replay starts, between
// loops, in a screenshot). Lines the replay has not reached yet are dimmed; each lights up when its step plays.
function fillLog() {
  logBox.innerHTML = sc.log.map((l) => "<li>" + escHtml(l.text) + "</li>").join("") +
    '<li class="result">receiver got ' + sc.paid + " on a " + sc.limit + " limit: " + sc.beyond + " tokens paid beyond policy</li>";
}
function writeLog(t) {
  const n = sc.log.filter((l) => t >= l.at).length, done = t >= 5.0 && n === sc.log.length;
  const due = n + (done ? 1 : 0);
  if (due === shown) return;
  shown = due;
  [...logBox.children].forEach((li, k) => li.classList.toggle("todo", k < sc.log.length ? k >= n : !done));
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
  fillLog(); clock = 0; shown = -1; tip = { at: C.PAN_TOP, v: 0 }; needle = -1;
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
`;

// The fade-in of each section as it scrolls into view. Its own small classic script, apart from the figure's
// module: it hides the sections only once it can show them again, so if this script (or the module) fails,
// or the browser has no IntersectionObserver, every section simply stays visible.
const revealJs = `(function(){
  if (typeof window.IntersectionObserver !== "function") return;
  document.documentElement.classList.add("reveal-js");
  var io = new IntersectionObserver(function(es){ es.forEach(function(e){ if (e.isIntersecting) { e.target.classList.add("on"); io.unobserve(e.target); } }); }, { rootMargin: "0px 0px -8% 0px" });
  document.querySelectorAll(".reveal").forEach(function(el){ io.observe(el); });
})();`;

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
// Fixed figures typed into the words below (no file the build reads gives them): the proof bound
// "up to 4 pay calls" (README.md, Limits), the run times "about 8 / 25 / 46 min" (README.md), and
// "Only the planted flaw and its fix ran on NEAR testnet" (README.md, Limits). Refresh them by hand.
const plate = k.plateHtml({
  fig: "Fig 1", title: "Two keys, one invoice", hint: "Pick a run above", readout: `paid 0 · limit ${flawT.limit}`,
  keys: [{ mark: "lit", label: "Dial zero is the invoice limit. Past zero means paid beyond policy." }],
  caption: "",
  body: `<div data-fig class="iso-stage">${svg.slice(0, svg.lastIndexOf("</svg>")) + calloutSvg + "</svg>"}</div>${calloutList}`,
});

const pct = (n) => `${((100 * n) / lib.all).toFixed(2)}%`;
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const ev2 = (...paths) => `<p class="m-ev">Evidence: ${paths.join(", ")}</p>`;

// The methods, in the order a reader needs them. Each names the file that backs it.
const METHODS = [
  { k: "Attacks from papers, incidents and people",
    d: `The hunter is a language model that reads new security papers and hack news and writes attacks as data: a list of steps from a small fixed vocabulary, never code. Real incidents and hand-written attacks fill in the rest. Each hunt can add attacks, which is how the arena keeps growing: ${plural(hunts.runs, "hunt", "hunts")} so far proposed ${hunts.proposed} attacks from ${hunts.papers} paper reads and the news, and Arena kept ${hunts.saved}.`,
    e: [repoPath("evidence/hunts/"), repoPath("docs/ADD-AN-ATTACK.md")] },
  { k: "An admission gate",
    d: `An attack counts as validated only when it holds on a guard known to be good and breaks a copy with exactly one planted flaw, by the exact amount${gateRuns ? `, in ${gateRuns} runs each` : ""}. Partly validated means every run matched but a piece is missing, such as proof that two race calls overlapped. Unvalidated attacks still run on every guard. They stay out of the validated count.`,
    extra: `<div class="gate" role="img" aria-label="${lib.validated} validated, ${lib.partial} partly validated, ${lib.unvalidated} unvalidated, of ${lib.all} attacks">
      <div class="bar"><span class="v" style="width:${pct(lib.validated)}"></span><span class="p" style="width:${pct(lib.partial)}"></span><span class="u" style="width:${pct(lib.unvalidated)}"></span></div>
      <ul class="gate-k"><li><i class="v"></i><b>${lib.validated}</b> validated</li><li><i class="p"></i><b>${lib.partial}</b> partly validated</li><li><i class="u"></i><b>${lib.unvalidated}</b> unvalidated</li><li class="of">of ${lib.all} attacks in the library</li></ul>
    </div>
    <p class="m-d">We also planted ${mutants.planted} single mistakes in Arena's own guard, one at a time. The library caught ${mutants.caught} of them.</p>`,
    e: [repoPath("evidence/MANIFEST.md"), repoPath("tools/admission/admit.py")] },
  { k: "A hidden set",
    d: `Arena keeps ${hidden.count} more attacks off GitHub and publishes only a hash of the set${hidden.date ? ` (${hidden.date})` : ""}. Nobody can tune a guard to a list they cannot see, and anyone can check later that the set did not change.`,
    e: [repoPath("hidden-set/COMMITMENT.json"), repoPath("EVALUATE.md", "EVALUATE.md, section 4b")] },
  { k: "Scored from chain balances",
    d: "Arena runs every attack on a throwaway local NEAR sandbox and reads each receiver's balance before and after every step. The score is the money that moved. What the guard or the agent says about it never enters the score.",
    e: [repoPath("docs/CHECK-YOUR-GUARD.md")] },
  { k: "NEAR's access key, counted apart",
    d: `The agent's key may call only <code>pay</code>, so NEAR refuses some attacks before the guard's code runs. Those tested the key, so Arena reports them as "stopped by the access key" and leaves them out of the held count: ${ref.key} of ${ref.attacks} on a guard that pays in tokens.`,
    e: [repoPath(`${CHECKS}/vault-a/summary.md`)] },
  { k: "Proofs on top of tests",
    d: `For the money rules that matter most (no double pay, payee list, per-payment cap, approval threshold, daily budget), Arena also checks every case up to a bound, and proves the double-pay fix on a model of the guard for any number of calls. On four other teams' guards the checker caught ${teams.flawsCaught} of ${teams.flaws} planted flaws.`,
    e: [repoPath(`evidence/${PROOFS}`), repoPath("proofs/properties/README.md")] },
  { k: "Results on NEAR testnet",
    d: `Arena saves results on NEAR testnet. The <a href="lookup.html">lookup page</a> reads which code a guard runs and in which mode, then shows Arena's result for that exact code, so an agent can check a guard before it trusts it with money.`,
    e: [repoPath("docs/CHECK-BEFORE-YOU-PAY.md")] },
];
const methodsHtml = `<ol class="methods">${METHODS.map((m, i) => `<li class="method">
  <span class="m-n">${String(i + 1).padStart(2, "0")}</span>
  <div><h3>${esc(m.k)}</h3><p class="m-d">${m.d}</p>${m.extra || ""}${ev2(...m.e)}</div>
</li>`).join("")}</ol>`;

const refRow = (c, who, what) => `<tr><td><b>${esc(who)}</b><small><code>${esc(c.dir)}</code>, ${esc(what)}</small></td>
  <td data-label="Result"><span class="st ${c.status === "broke" ? "st-broke" : "st-held"}">${esc(c.status)}</span></td>
  <td class="num" data-label="Attacks that ran">${c.status === "broke" ? `${c.broke} broke of ${c.ran}` : `${c.held} held of ${c.ran}`}</td>
  <td class="num${c.beyond > 0 ? " bad" : ""}" data-label="Paid beyond policy">${c.beyond}</td></tr>`;

const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arena</title>
${FAVICON}
<meta name="description" content="Arena is a constantly growing crash test for AI-controlled money: attacks from papers, incidents and people, run against payment guards on NEAR and scored from chain balances.">
${FONTS}
<style>${k.ISO_CSS}
${themeCss()}
body.iso{--anatomy-page:var(--bg);--anatomy-card:var(--card);--anatomy-text:var(--ink);--anatomy-mono:var(--mono)}
h1{font:600 clamp(40px,6vw,68px)/1.02 var(--sans);letter-spacing:-.04em;margin:18px 0 20px;max-width:13ch;text-wrap:balance}
h2{font:600 30px/1.15 var(--sans);letter-spacing:-.025em;margin:0 0 10px}
h3{font:600 18px/1.3 var(--sans);letter-spacing:-.015em;margin:0 0 6px}
.sub{color:var(--muted);max-width:60ch;margin:0 0 28px}
.hero{display:grid;grid-template-columns:1.2fr 1fr;gap:56px;align-items:center;padding:80px 0 72px}
.lede{font-size:20px;line-height:1.45;letter-spacing:-.01em;max-width:30ch;margin:0 0 32px}
.ctas{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.ctas .btn{display:inline-flex;align-items:center;gap:7px}.btn code{background:transparent;color:inherit;font-size:13px;padding:0}
.btn.primary:hover{background:#111;color:#fff}
@media (prefers-color-scheme:dark){.btn.primary:hover{background:#fff;color:#111}}
.hero-note{font-size:13.5px;color:var(--muted);margin:14px 0 0;max-width:46ch}
.today{border:1px solid var(--line);border-radius:var(--radius-card);background:var(--card);overflow:hidden}
.today .eyebrow{display:block;padding:18px 22px 0}
.today-grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);margin-top:16px;border-top:1px solid var(--line)}
.today-grid > div{background:var(--card);padding:18px 22px 20px}
.today .n{font:500 44px/1 var(--sans);letter-spacing:-.04em;font-variant-numeric:tabular-nums}
.today .k{font:500 11px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase;margin-top:10px}
.today .note{font-size:12.5px;line-height:1.45;color:var(--muted);margin-top:4px}
section{padding:72px 0;border-top:1px solid var(--line)}
.problem{display:grid;grid-template-columns:1fr 1.4fr;gap:48px;align-items:start}
.problem p{font-size:17px;line-height:1.6;margin:0 0 14px;max-width:58ch}
.problem p:last-child{margin:0}
ol.methods{list-style:none;margin:28px 0 0;padding:0;border-top:1px solid var(--line)}
li.method{display:grid;grid-template-columns:64px 1fr;gap:16px;padding:26px 4px;border-bottom:1px solid var(--line)}
.m-n{font:500 13px/1.8 var(--mono);color:var(--muted)}
.m-d{margin:0 0 10px;max-width:72ch}
.m-ev{font-size:13px;color:var(--muted);margin:0}
.m-ev a code{text-decoration:underline;text-underline-offset:2px;text-decoration-color:var(--line)}
.gate{margin:16px 0 14px;max-width:640px}
.bar{display:flex;height:12px;border-radius:4px;overflow:hidden;background:var(--code);gap:2px}
.bar span{display:block;height:100%}
.v{background:var(--ink)}.p{background:var(--muted)}.u{background:transparent;box-shadow:inset 0 0 0 1px var(--muted)}
.gate-k{list-style:none;display:flex;flex-wrap:wrap;gap:6px 20px;margin:10px 0 0;padding:0;font-size:13.5px}
.gate-k li{display:flex;align-items:center;gap:7px}.gate-k b{font-weight:600;font-variant-numeric:tabular-nums}
.gate-k i{display:inline-block;width:10px;height:10px;border-radius:2px}.gate-k .of{color:var(--muted)}
.quick{padding:40px 0 56px;border-top:1px solid var(--line)}
.quick h2{margin-bottom:6px}
ol.qsteps{list-style:none;margin:20px 0 0;padding:0;display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--radius-card);overflow:hidden;counter-reset:q}
ol.qsteps li{background:var(--card);padding:20px 22px;counter-increment:q;min-width:0}
ol.qsteps li::before{content:counter(q);display:block;font:500 12px/1 var(--mono);color:var(--muted);margin-bottom:10px}
ol.qsteps h3{font-size:16.5px;margin:0 0 8px}
ol.qsteps p{margin:0 0 12px;font-size:14px;max-width:46ch}
ol.qsteps .go{display:flex;flex-wrap:wrap;gap:8px}
ol.qsteps .tag{font:500 10.5px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
.r-block{margin:40px 0 0}
.r-block > h3{margin-bottom:4px}
.r-block > .sub{margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{font:500 10.5px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:14px;vertical-align:top}
td small{display:block;color:var(--muted);font-size:12.5px;margin-top:2px}
tbody tr + tr td{border-top:1px solid var(--line)}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}td.bad{color:var(--bad);font-weight:500}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 6px;overflow-x:auto}
.small{font-size:13px;color:var(--muted);margin:12px 0 0}
.intent{margin:16px 0 0;padding:20px 24px;border:1px solid var(--line);border-radius:12px;background:var(--card);display:grid;grid-template-columns:auto 1fr;gap:6px 24px;align-items:baseline}
.intent .n{font:500 40px/1 var(--sans);letter-spacing:-.04em;color:var(--bad);font-variant-numeric:tabular-nums;grid-row:1/3}
.intent .k{font:500 11px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase}
.intent p{margin:0;font-size:14px;color:var(--muted);max-width:70ch}
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
.meta{display:flex;flex-wrap:wrap;gap:4px 16px;font:12px/1.5 var(--mono);color:var(--muted);margin:12px 0 8px;overflow-wrap:anywhere}
.meta a{color:var(--ink)}
ol.log{list-style:none;margin:0;padding:14px 18px;min-height:168px;background:var(--card);border:1px solid var(--line);border-radius:8px;font:12.5px/1.75 var(--mono);counter-reset:s}
ol.log li{counter-increment:s;transition:opacity .45s cubic-bezier(.16,1,.3,1)}ol.log li.todo{opacity:.3}
ol.log li::before{content:counter(s,decimal-leading-zero) "  ";color:var(--muted)}
ol.log li.result{font-weight:500;margin-top:6px}ol.log li.result::before{content:"=   "}
.teams{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.teams > div{background:var(--card);padding:18px 20px}
.teams .n{font:500 36px/1 var(--sans);letter-spacing:-.04em;font-variant-numeric:tabular-nums}
.teams .k{font:500 10.5px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:8px}
.teams .bad{background:var(--bad-bg)}.teams .bad .n,.teams .bad .k{color:var(--bad)}
ul.notes{margin:14px 0 0;padding:0 0 0 18px;max-width:76ch}ul.notes li{margin:6px 0}
ul.limits{padding:0;margin:0;list-style:none;max-width:80ch}ul.limits li{padding:12px 0}ul.limits li + li{border-top:1px solid var(--line)}
ul.limits li:first-child{font:500 19px/1.45 var(--sans);letter-spacing:-.01em;padding-top:0}
.run{display:grid;grid-template-columns:1fr 1fr;gap:48px;align-items:start}
/* code boxes: they wrap instead of running off the right edge, and keyboard users can reach them */
pre{font:13px/1.75 var(--mono);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 18px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere;overflow-x:auto}
pre:focus-visible{outline:2px solid var(--muted);outline-offset:2px}
pre.cmd{font-size:15px;margin:0 0 6px}
pre .c{color:var(--muted)}
ul.paths{list-style:none;margin:24px 0 0;padding:0;border-top:1px solid var(--line)}
ul.paths li{padding:14px 0;border-bottom:1px solid var(--line)}
ul.paths b{display:block;font-weight:600}
ul.paths span{display:block;color:var(--muted);font-size:14px}
.mini{font:500 11px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:28px 0 10px}
figure.term{margin:0}
.term-gif{display:block;width:100%;height:auto;border:1px solid var(--line);border-radius:var(--radius-card)}
.term-text{margin:10px 0 0}
.term-text summary{cursor:pointer;font-size:13.5px;font-weight:500;padding:6px 0}
.term-text pre,.term-phone{font-size:12px;line-height:1.65;margin-top:8px}.term-phone,.term-phone-k{display:none}
figure.term figcaption{font-size:13px;color:var(--muted);margin-top:10px}
.site-foot code{font-size:11.5px}
@media (max-width:560px){
  table.stack thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
  table.stack,table.stack tbody,table.stack tr,table.stack td{display:block}
  table.stack tr{padding:14px 12px}
  table.stack td{padding:0;border:0}
  table.stack tbody tr + tr td{border-top:0}
  table.stack tbody tr + tr{border-top:1px solid var(--line)}
  table.stack td:first-child{margin-bottom:8px}
  table.stack td[data-label]{display:flex;justify-content:space-between;gap:12px;margin-top:4px;white-space:normal}
  table.stack td[data-label]::before{content:attr(data-label);font:500 10.5px/1.9 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
}
.reveal-js .reveal{opacity:0;transform:translateY(12px);transition:opacity .6s cubic-bezier(.16,1,.3,1),transform .6s cubic-bezier(.16,1,.3,1)}.reveal-js .reveal.on{opacity:1;transform:none}
@media print{.reveal-js .reveal{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}.reveal-js .reveal{opacity:1;transform:none;transition:none}ol.log li{transition:none}}
@media (max-width:768px){.callouts{display:none}.callout-list{display:block;margin:10px 0 0;padding-left:20px;font-size:13px;color:var(--muted)}.callout-list b{color:var(--ink);font-weight:500}
  .hero,.run,.problem{grid-template-columns:1fr;gap:28px}.hero{padding:48px 0 48px}.lede{font-size:18px}.today .n{font-size:34px}
  section{padding:52px 0}.tabs button{flex:1 1 45%}li.method{grid-template-columns:36px 1fr;gap:10px;padding:22px 0}
  ol.qsteps{grid-template-columns:1fr}
  .teams{grid-template-columns:1fr 1fr}.teams .n{font-size:30px}.intent{grid-template-columns:1fr}.intent .n{grid-row:auto}
  /* phones: the terminal recording's text is too small to read, so the page shows the same run as text */
  .term-gif,.term-text{display:none}.term-phone,.term-phone-k{display:block}.term-phone-k{margin-top:0}}
@media (max-width:400px){.today-grid > div{padding:16px 16px 18px}.today .eyebrow{padding:16px 16px 0}}
</style></head>
<body class="iso" data-theme="light">
${topbar(null)}
<main class="wrap">
<header class="hero">
  <div>
    <div class="eyebrow">Arena · AI security on NEAR</div>
    <h1>Can your guard survive the arena?</h1>
    <p class="lede">The arena is a constantly growing crash test for AI-controlled money.</p>
    <div class="ctas"><a class="btn primary" href="${esc(README)}" rel="noopener">Run <code>./arena check your_guard.wasm</code></a><a class="btn ghost" href="board.html">See the board</a></div>
    <p class="hero-note">One command runs Arena's attacks against your guard on a private NEAR sandbox on your machine, and writes a report card.</p>
  </div>
  <div class="today">
    <span class="eyebrow">The arena today</span>
    <div class="today-grid">
      <div><div class="n">${lib.all}</div><div class="k">attacks in the library</div><div class="note">${lib.token} fit a guard that pays in tokens or NEAR</div></div>
      <div><div class="n">${lib.validated}</div><div class="k">validated</div><div class="note">shown to catch the one flaw they name</div></div>
      <div><div class="n">${hidden.count}</div><div class="k">hidden attacks</div><div class="note">kept off GitHub, published as a hash</div></div>
      <div><div class="n">${hunts.runs}</div><div class="k">hunts so far</div><div class="note">${hunts.proposed} attacks proposed from papers and news</div></div>
    </div>
  </div>
</header>

<section id="quick" class="quick" aria-labelledby="quick-h">
  <h2 id="quick-h">Try it in 2 minutes</h2>
  <p class="sub">No login, no install. Three links.</p>
  <ol class="qsteps">
    <li>
      <h3>See the double pay on the public explorer</h3>
      <p class="tag">Recorded on NEAR testnet, ${esc(dp.date)}</p>
      <p>Both transactions call <code>pay</code> for the same invoice, <code>${esc(dp.invoice)}</code>, in block ${dp.block}, and each moves ${dp.limit} test tokens from the guard to the receiver: ${dp.got} paid on one ${dp.limit}-token invoice. Trial ${dp.trialNo} of ${dp.trials} in ${repoPath("evidence/testnet-2026-11-11.md")}.</p>
      <div class="go"><a class="btn primary" href="${esc(tx(dp.a))}" rel="noopener">Call A on nearblocks</a><a class="btn ghost" href="${esc(tx(dp.b))}" rel="noopener">Call B</a></div>
    </li>
    <li>
      <h3>Look up a guard live</h3>
      <p class="tag">Live, reads NEAR testnet</p>
      <p>Opens the lookup with this planted-flaw guard filled in. It reads testnet when you open it and answers <b>broke</b>. The "fixed guard" button next to it answers <b>held</b>.</p>
      <div class="go"><a class="btn primary" href="lookup.html?account=${esc(encodeURIComponent(dp.guard))}">Look up the planted-flaw guard</a></div>
    </li>
    <li>
      <h3>See the board</h3>
      <p class="tag">Recorded local sandbox runs, ${esc(boardRange)}</p>
      <p>Every attack a hunt ran against each guard, on a local NEAR sandbox: ${boardAttacks} attacks, ${boardGuards.length} guards. Not live.</p>
      <div class="go"><a class="btn primary" href="board.html">See the board</a><a class="btn ghost" href="docs.html">How to use Arena</a></div>
    </li>
  </ol>
</section>

<section id="problem" class="reveal">
  <div class="problem">
    <h2>The problem</h2>
    <div>
      <p>AI agents will hold money and pay bills for people. A guard is the contract that limits what an agent can pay: which payees, how much a day, which bills.</p>
      <p>Most teams test their guard with tests they wrote themselves. Those tests share the guard's blind spots. Arena attacks the guard with attacks its team did not write, and keeps adding more.</p>
    </div>
  </div>
</section>

<section id="methods" class="reveal">
  <h2>How Arena works</h2>
  <p class="sub">Seven parts. Each names the file that backs it.</p>
  ${methodsHtml}
</section>

<section id="results" class="reveal">
  <h2>Results</h2>
  <p class="sub">Arena's own guards, then other teams' guards, named by letter only.</p>

  <div class="r-block">
    <h3>Arena's own guards: the same ${ref.attacks} attacks, ${esc(ref.date)}</h3>
    <p class="sub">A reference guard Arena expects to hold, and two copies with flaws planted on purpose. If the planted copies did not break, the bench could not see a break.</p>
    <div class="card"><table class="stack"><thead><tr><th>Guard</th><th>Result</th><th>Attacks that ran</th><th>Paid beyond policy</th></tr></thead><tbody>
      ${refRow(ref, "Reference guard", "Arena's own")}
      ${refRow(leaky, "Leaky on purpose", "several planted flaws")}
      ${refRow(outflow, "Planted outflow flaw", "pays the agent")}
    </tbody></table></div>
    <p class="small">Each ran ${ref.attacks} attacks. NEAR's access key stopped ${ref.key} before the guard's code ran, so ${ref.ran} count. From ${repoPath(CHECKS + "/")}.</p>
    ${ref.intent ? `<div class="intent"><div class="n">${ref.intent}</div><div class="k">tokens the owner did not mean to pay, on Arena's reference guard</div>
      <p>The guard kept every rule and the owner still lost money. ${ref.intentAttacks} prompt-injection attacks carry a written owner intent. In them, a scripted agent that obeys every injection paid payees on the owner's list for bills the owner never meant to pay. The ${ref.intent} is the sum over all ${ref.intentAttacks}. Arena reports it on its own line and never adds it to broke. It comes from Arena's reference guard, not from any team.</p></div>` : ""}
  </div>

  <div class="r-block">
    <h3>Two keys, one invoice, on NEAR testnet</h3>
    <p class="sub">Two pay calls for one ${flawT.limit}-token invoice, sent at once. The planted flaw records "paid" too late and pays ${flawT.paid}, in ${flawT.trials.length} of ${flawT.trials.length} trials. The fixed guard pays ${scenarios[1].paid}.</p>
    <div class="tabs" role="tablist" data-tablist aria-label="Runs to replay">
      ${scenarios.map((s, i) => `<button role="tab" data-scenario="${s.id}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}">${esc(s.label)}<small>${esc(s.where)}</small></button>`).join("")}
    </div>
    ${plate}
    <div class="meta" data-meta></div>
    <ol class="log" data-log aria-live="polite">${scenarios[0].log.map((l) => `<li>${esc(l.text)}</li>`).join("")}<li class="result">receiver got ${scenarios[0].paid} on a ${scenarios[0].limit} limit: ${scenarios[0].beyond} tokens paid beyond policy</li></ol>
  </div>

  <div class="r-block">
    <h3>Four other teams' guards, checked against their own claims</h3>
    <p class="sub">We wrote down each guard's money claims before any run, then checked every case up to a bound: ${esc(teams.bounds)}.</p>
    <div class="teams">
      <div><div class="n">${teams.claims}</div><div class="k">money claims checked</div></div>
      <div><div class="n">${teams.hold}</div><div class="k">hold</div></div>
      <div><div class="n">${teams.part}</div><div class="k">hold for the contract's part</div></div>
      <div class="bad"><div class="n">${teams.counter}</div><div class="k">${teams.counter === 1 ? "counterexample" : "counterexamples"}</div></div>
    </div>
    <ul class="notes">
      <li>In one of the four guards, a refund that lands after UTC midnight comes off the new day's total, so that day can pay over its daily cap. We do not say which guard.</li>
      <li>The ${teams.part} partial claims hold inside the contract. Their other half is a NEAR rule about keys that our model leaves out.</li>
      <li>The checker caught ${teams.flawsCaught} of ${teams.flaws} flaws we planted in these guards to test it.</li>
      <li>Guards A, B and C also passed ${claimedHeld} of ${claimedTests} tests written from their own claims, on a local sandbox (${repoPath("evidence/coverage-table.md")}).</li>
    </ul>
    <p class="small">From ${repoPath(`evidence/${PROOFS}`)}. The teams' source and harnesses stay private to keep them anonymous.</p>
  </div>
</section>

<section id="limits" class="reveal">
  <h2>Limits</h2>
  <ul class="limits">
    <li>Held means these attacks found nothing. Another attack could still break the guard.</li>
    <li>Almost everything runs on a local NEAR sandbox. Only the planted flaw and its fix ran on NEAR testnet.</li>
    <li>${lib.unvalidated} of ${lib.all} attacks are unvalidated: they run on every guard, but nobody has shown yet that they catch the flaw they name. Each has a measured reason in ${repoPath("evidence/MANIFEST.md")}: most need two planted flaws at once, ask only for valid payments, or are stopped by the agent's access key before the guard sees them.</li>
    <li>The proofs stop at their bounds. For the other teams' guards: ${esc(teams.bounds)}. The proof for any number of calls covers a model of Arena's guard, matched to the real code up to 4 pay calls.</li>
    <li>The prompt-injection attacks run scripted steps. No model reads the email in those runs.</li>
    <li>The hidden set rests on the operator's honesty. Nothing in hardware proves which attacks ran.</li>
    <li>The hunter's daily schedule on GitHub has never run. We started every hunt so far by hand.</li>
  </ul>
  <p class="small">Every limit, with its evidence: ${repoPath("README.md#limits", "README.md, Limits")}.</p>
</section>

<section id="try" class="reveal">
  <div class="run">
    <div>
      <h2>Try it on your guard</h2>
      <p class="sub">Arena runs the library's ${lib.token} attacks for a guard that pays in tokens or NEAR (${lib.all} for one that pays into NEAR Intents) on a local NEAR sandbox on your machine.</p>
<pre class="cmd" tabindex="0" aria-label="Command">./arena check your_guard.wasm</pre>
      <ul class="paths">
        <li>${repoPath("docs/CHECK-YOUR-GUARD.md")}<span>How to test your guard and read the report card.</span></li>
        <li>${repoPath("examples/workflows/arena-check.yml")}<span>Runs the same check on every pull request. It has not run on GitHub yet.</span></li>
        <li><a href="lookup.html"><b>Look up a guard</b></a><span>Type a guard's account on NEAR testnet and see what Arena tested for the code it runs.</span></li>
        <li><a href="board.html"><b>Results board</b></a><span>${boardAttacks} attacks that hunts have run against ${boardGuards.length} guards: ${boardInLib} from the library, ${boardAttacks - boardInLib} the hunter tried and did not keep.</span></li>
      </ul>
      <div class="mini">Check our evidence</div>
<pre tabindex="0" aria-label="Commands to re-run Arena's checks">./verify.sh fast   <span class="c"># about 8 min</span>
proofs/run.sh      <span class="c"># about 25 min</span>
tla/run.sh         <span class="c"># about 46 min</span></pre>
      <p class="small">Needs Rust and Python 3. The proofs also need Kani and z3, and tla/run.sh needs Java 17 or newer. ${repoPath("EVALUATE.md")} lists every claim with its command.</p>
    </div>
    <div>${gifHtml}</div>
  </div>
</section>

</main>
${footer("Every number on this page is read from <code>evidence/</code> at build time. Fig 1 uses the anatomy kit (MIT, © 2026 Ryan).")}
<script>${revealJs}</script>
<script type="module">${(kitScript() + live).replace(/<\/(script)/gi, "<\\/$1")}</script>
</body></html>`;

if (/\/Users\/|\/home\//.test(page)) throw new Error("site/index.html would contain an absolute local path");
if (/[–—]/.test(page.replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, ""))) throw new Error("site/index.html would contain an en or em dash");
writeFileSync(join(HERE, "index.html"), page);
// lookup.html shares the theme and top bar; rebuild it too so the pages never drift apart.
const { buildLookup } = await import("./build-lookup.mjs");
buildLookup();
console.log("wrote site/lookup.html and copied the lookup modules");
const { buildDocs } = await import("./build-docs.mjs");
const docsOut = buildDocs({ repoPath });
console.log(`wrote site/docs.html (${(docsOut.bytes / 1024).toFixed(0)} KB)`);
console.log(`wrote site/index.html (${(page.length / 1024).toFixed(0)} KB): library ${lib.all} (${lib.validated} validated, ${lib.partial} partly, ${lib.unvalidated} unvalidated), hidden ${hidden.count}, ${hunts.runs} hunts; teams ${teams.hold}/${teams.claims}; board ${boardAttacks} (${boardInLib} in library)`);
