// Builds site/docs.html ("How to use Arena"): one section per kind of user, each a list of
// "do this, see that" steps with the exact command and what it prints. Every step is taken from the
// repo's own docs (docs/*.md, EVALUATE.md, README.md), and each section links to the doc it came from.
// The two example headlines are read from saved arena check reports in evidence/ at build time.
//   Run by site/build.mjs at the end (it passes its repoPath, so file links match index.html).
// Do not edit site/docs.html by hand: it is overwritten on every build.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { themeCss, topbar, footer, FONTS, FAVICON } from "./chrome.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// Saved arena check runs on Arena's own guards (the same folder site/build.mjs reads for its results table).
const CHECKS = "evidence/invoice-fixes-2026-11-12/checks";
const report = (dir) => {
  const r = JSON.parse(readFileSync(join(ROOT, CHECKS, dir, "report.json"), "utf8"));
  if (typeof r.headline !== "string" || !r.headline) throw new Error(`${CHECKS}/${dir}/report.json has no headline`);
  return { headline: `arena: ${r.headline}`, date: String(r.finished_utc || "").slice(0, 10) };
};

const LOOKUP_EXAMPLE = "r11cfx4-guard.arena-race-funder-1111.testnet"; // the kept fixed guard (evidence/testnet-2026-11-11.md)
const RECEIPTS = "receipts.dev-20261109195231-98743803426969.testnet"; // docs/ON-CHAIN.md

export function buildDocs({ repoPath }) {
  const held = report("vault-a");
  const broke = report("leaky-control-v2");
  const pre = (text, label) => `<pre tabindex="0" aria-label="${esc(label)}">${esc(text)}</pre>`;
  // One step: what to do (with an optional command) and what you see (with optional output).
  const step = (s) => `<li class="step">
  <div class="do"><span class="k">Do</span><p>${s.do}</p>${s.cmd ? pre(s.cmd, "Command") : ""}</div>
  <div class="see"><span class="k">You see</span><p>${s.see}</p>${s.out ? pre(s.out, "What it prints") : ""}</div>
</li>`;
  const section = (id, title, who, steps, more) => `<section id="${id}">
  <h2>${esc(title)}</h2>
  <p class="sub">${who}</p>
  <ol class="steps">${steps.map(step).join("")}</ol>
  <p class="more">Full guide: ${more}</p>
</section>`;

  const builders = [
    { do: "Get Arena and build your guard the way you normally do. You need its <code>.wasm</code> file.",
      cmd: "git clone <arena repo> arena && cd arena",
      see: "Nothing to see yet. The first check also builds Arena's harness, which takes a few minutes once." },
    { do: "Run every attack in the library against your guard, on a local NEAR sandbox on your machine (no testnet, no real money).",
      cmd: "./arena check path/to/your_guard.wasm",
      see: `One line per attack, then a headline. Two recorded runs on Arena's own guards (${esc(held.date)}): the reference guard, and a copy that is leaky on purpose. Exit code 0 means held, 1 broke, 2 the check could not finish. A full check took about 4 minutes on our Mac.`,
      out: `${held.headline}\n\n${broke.headline}` },
    { do: "Open the report card, <code>arena-report/report.html</code>, in a browser. It is one page and needs no internet.",
      see: "The badge (<code>held N/N</code> or <code>broke K of N</code>), then every attack with its step log. Attacks your guard's rules do not cover are <b>not applicable</b>, never held. Attacks NEAR refused at the agent's access key are <b>stopped by the agent's access key</b>: they tested the key, not your guard. Two numbers are never added together: tokens paid <b>beyond your guard's own rules</b> (any value above 0 is a failure), and tokens paid <b>against the owner's intent</b> (your rules allowed them)." },
    { do: "If your guard starts differently or is a different shape, describe it in a config file and pass it with <code>--config</code>. Examples for each shape are in " + repoPath("examples/configs/") + ".",
      cmd: "./arena check your_guard.wasm --config guard.json\n./arena check your_guard.wasm --pays-in native\n./arena check your_guard.wasm --config guard.json --mapping mapping.json",
      see: "The same report. Use <code>\"features\"</code> for rules your guard does not have (payee list, cancel, expiry, daily cap), <code>\"pays_in\": \"native\"</code> for plain NEAR, <code>\"pays_in\": \"intents\"</code> for a guard that pays into NEAR Intents, <code>\"signs_via\": \"chain-signatures\"</code> for a guard that asks Chain Signatures to sign, and a mapping file when your method names differ. Intents withdrawals and Chain Signatures are checked against Arena's local stand-ins: nothing is sent to another chain and nothing is really signed. A guard with no invoices, where the agent names the receiver, uses <code>python3 tools/check/direct_check.py --wasm your_guard.wasm --guard-config guard.json --out report-dir</code>." },
    { do: "Run the check on every pull request: copy " + repoPath("examples/workflows/arena-check.yml") + " into your repo's <code>.github/workflows/</code>, fill in the lines marked <code>&lt;- your ...</code>, and replace the <code>ARENA_OWNER/arena@ARENA_COMMIT</code> placeholders.",
      see: "The badge and numbers in the job summary, and the report as a downloadable file. This workflow has not run on GitHub yet; only its script step was run, locally on macOS." },
    { do: "Replay one saved attack against your guard, with no model call.",
      cmd: "./run-arena.sh replay sequences-paper/<file>.json --wasm your_guard.wasm",
      see: "That attack's result against your guard." },
  ];

  const payers = [
    { do: `In a browser, open <a href="lookup.html?account=${esc(LOOKUP_EXAMPLE)}">the lookup page</a> (this link fills in Arena's fixed guard) and type any guard account on NEAR testnet.`,
      see: "A status word and one sentence, the guard's code fingerprint and mode, and each result Arena published for that code, with its transaction link. It only reads testnet; it never sends a transaction." },
    { do: "From a terminal (Node 18 or newer, no keys):",
      cmd: `node tools/lookup/cli.mjs ${LOOKUP_EXAMPLE}`,
      see: "A first line that starts as below, then <code>status:    held</code> and <code>opt-in:    opted_in</code>. Exit code 0 means held, 1 any other answer, 2 bad input or the lookup could not finish.",
      out: "Held the double-pay race test (5 of 5 runs held, 0 paid over the limit) ..." },
    { do: "From your own JavaScript (no dependencies, uses <code>fetch</code>):",
      cmd: `import { lookup } from "./tools/lookup/arena-lookup.mjs";\nconst a = await lookup("${LOOKUP_EXAMPLE}");\nif (a.status !== "held") askUserToConfirm(); // anything else is not a pass, including errors`,
      see: "The same answer as an object: <code>a.status</code>, <code>a.sentence</code>, and <code>a.receipts</code> with each publish transaction, date and evidence file." },
    { do: `From another contract: call <code>arena_result(guard_code_hash, suite, arena_commit)</code> on <code>${esc(RECEIPTS)}</code>. Name the suite when one code runs in more than one mode, for example <code>race-double-pay:mode=fixed</code>.`,
      see: "An answer with <code>status</code>: <code>held</code>, <code>broke</code>, <code>incomplete</code> or <code>not_tested</code>, never null. A full near-sdk example that asks before paying is in " + repoPath("receipts/example-caller/src/lib.rs") + "." },
  ];

  const authors = [
    { do: "Write the attack as data: copy " + repoPath("sequences-scripted/02-race-double-pay.json") + " and change its steps. A step is a call by the agent or an outsider, a view, a race of 2 to 4 calls sent at once, a wait, or an attempt to add a key. Then add a <code>meta</code> block saying who wrote it and what it tries to break.",
      see: "A JSON file. You write data, not code. The rules are in " + repoPath("schema/attack.schema.json") + "." },
    { do: "Fill in the fingerprint, then validate the file.",
      cmd: "python3 -I -c \"import sys,json; sys.path.insert(0,'tools/hunter'); import validate as V; d=json.load(open(sys.argv[1])); print(V.steps_hash(d['steps']))\" your-file.json\npython3 -I tools/hunter/validate.py your-file.json",
      see: "The fingerprint to paste into <code>meta.steps_sha256</code>, then either a pass or exactly what is wrong, for example <code>step 2: wait_seconds must be 1-30</code>." },
    { do: "Run it against one guard, the leaky-on-purpose control.",
      cmd: "./run-arena.sh replay your-file.json --target control",
      see: "<b>broke</b> if a receiver got tokens beyond that guard's policy, <b>held</b> if not. Put the file in <code>sequences-paper/</code> and the next <code>./run-arena.sh hunt --library</code> runs it against every registered guard." },
    { do: "Ask the admission gate whether the attack catches the flaw it names. The gate runs it 3 times on a guard known to be good (it must hold) and 3 times on a copy with exactly that one flaw (it must break, by the exact amount), from the guards its <code>meta.spec</code> names. It needs the build from <code>./verify.sh fast</code>.",
      cmd: "python3 -I tools/admission/admit.py your-file.json --runs 3",
      see: "One line with the class: <code>validated</code>, <code>partially-validated</code> or <code>unvalidated</code>, with the reason. For a library attack it reads, for example, <code>ADMISSION scripted-03-sequential-second-pay: validated (every reference matched in 3 counted runs; matched known-bad: mutant:M4)</code> (about 37 s). Saving an attack does not validate it; only the gate's runs count." },
  ];

  const verify = [
    { do: "Re-run the headline result on your machine (about 8 minutes the first time).",
      cmd: "./verify.sh fast",
      see: "PASS or FAIL per check, ending with the line below. It shows the planted-flaw guard paying 200 on one 100-token invoice, and the bench catching the leaky-on-purpose guard.",
      out: "verify: 5 passed, 0 failed (mode=fast)" },
    { do: "See the fixed guard pay once.",
      cmd: "./run.sh t2_",
      see: "The fixed guard's payout in each of 5 trials.",
      out: "RESULT fixed race payouts per trial: [100, 100, 100, 100, 100]" },
  ];

  const body = `${topbar("docs")}
<main class="wrap">
<header class="intro">
  <div class="eyebrow">Arena · documentation</div>
  <h1>How to use Arena</h1>
  <p class="lede">Arena runs a library of attacks against a payment guard (a NEAR contract that limits what an AI agent can pay) and reports, from final balances, whether the guard held or broke. Pick the part that fits you. Each step says what to do and what you should see.</p>
  <nav class="jump" aria-label="Sections"><a href="#builders">I build a guard</a><a href="#payers">My agent or wallet pays a guard</a><a href="#authors">I want to add an attack</a><a href="#verify">I want to check Arena's results</a></nav>
  <div class="needs">
    <h2>What you need</h2>
    <ul>
      <li><b>No install</b> for the lookup page and the results board: they run in a browser.</li>
      <li><b>Rust</b>, through rustup (<code>curl https://sh.rustup.rs -sSf | sh</code>). The repo pins the toolchain, so the right version comes on first build.</li>
      <li><b>The NEAR sandbox</b>: nothing to install. The scripts download it on the first run, so that run needs the internet.</li>
      <li><b>Python 3</b>, for <code>arena check</code> and the tool tests. <b>Node 18 or newer</b>, for the lookup tool.</li>
      <li>For the proofs only: Kani, z3, and Java 17 or newer (setup in ${repoPath("README.md#check-it-yourself", "README.md")}).</li>
      <li><b>Tested on macOS (Apple silicon).</b> Nothing has been run on Linux or on GitHub's runners yet.</li>
      <li><b>Time:</b> about 4 minutes for one <code>arena check</code> after the first build; about 8 minutes for <code>./verify.sh fast</code> on a fresh copy.</li>
    </ul>
  </div>
</header>
${section("builders", "Guard builders: test your guard", "You wrote a payment guard and want to know which attacks get money past it.", builders, repoPath("docs/CHECK-YOUR-GUARD.md") + ", " + repoPath("docs/REGISTER-A-GUARD.md") + " (put your guard on the board), " + repoPath("docs/ON-CHAIN.md") + " (opt in on NEAR testnet).")}
${section("payers", "Agents and wallets: check a guard before paying it", "Your agent or wallet is about to send money to a guard, and you want to know what Arena found. Only <code>held</code> is a pass. Every other answer, including a network error, is not.", payers, repoPath("docs/CHECK-BEFORE-YOU-PAY.md") + ", " + repoPath("docs/ON-CHAIN.md") + ".")}
${section("authors", "Attack authors: add an attack", "You know a way to make a guard overpay and want it in the library.", authors, repoPath("docs/ADD-AN-ATTACK.md") + ", and the admission rules in " + repoPath("EVALUATE.md") + " section 4b.")}
${section("verify", "Reviewers: check Arena's own results", "You want to re-run what Arena claims instead of reading it.", verify, repoPath("EVALUATE.md") + " lists every claim with its command, the line you should see, our time and our saved log.")}
<section id="limits-short">
  <h2>What these results do not show</h2>
  <ul class="plain">
    <li>Held means the attacks Arena ran found nothing. Another attack could still break the guard.</li>
    <li>Almost everything runs on a local NEAR sandbox. NEAR Intents withdrawals and Chain Signatures are checked against Arena's local stand-ins.</li>
    <li>Arena reads each payment as one whole invoice amount, so a guard that pays part of an invoice could be scored held where a part-payment reading would be broke.</li>
  </ul>
  <p class="more">Every limit: ${repoPath("README.md#limits", "README.md, Limits")}.</p>
</section>
</main>
${footer("This page is built from the repo's docs by <code>site/build-docs.mjs</code>. The two example headlines are read from <code>" + esc(CHECKS) + "</code>.")}`;

  const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>How to use Arena</title>
${FAVICON}
<meta name="description" content="How to use Arena: test your payment guard, check a guard before paying it, or add an attack. Each step gives the command and what it prints.">
${FONTS}
<style>${themeCss()}
h1{font:600 clamp(34px,5vw,52px)/1.05 var(--sans);letter-spacing:-.035em;margin:16px 0 16px}
h2{font:600 26px/1.2 var(--sans);letter-spacing:-.02em;margin:0 0 8px}
.intro{padding:56px 0 40px}
.lede{font-size:18px;line-height:1.5;max-width:62ch;margin:0 0 22px}
.sub{color:var(--muted);max-width:66ch;margin:0 0 22px}
.jump{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 28px}
.jump a{font:500 13.5px/1 var(--sans);text-decoration:none;border:1px solid var(--line);background:var(--card);border-radius:var(--radius-btn);padding:11px 14px}
.jump a:hover{background:var(--code)}
.needs{border:1px solid var(--line);border-radius:var(--radius-card);background:var(--card);padding:20px 24px}
.needs h2{font-size:18px}
.needs ul,.plain{margin:0;padding:0 0 0 18px;max-width:80ch}.needs li,.plain li{margin:6px 0}
section{padding:56px 0;border-top:1px solid var(--line)}
ol.steps{list-style:none;margin:0;padding:0;counter-reset:s;display:grid;gap:14px}
li.step{counter-increment:s;display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--radius-card);overflow:hidden}
li.step > div{background:var(--card);padding:16px 20px;min-width:0}
li.step p{margin:0 0 10px;max-width:64ch}
li.step .k{display:block;font:500 10.5px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
li.step .do .k::before{content:counter(s) ". "}
pre{font:12.5px/1.7 var(--mono);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
pre:focus-visible{outline:2px solid var(--muted);outline-offset:2px}
.more{font-size:13.5px;color:var(--muted);margin:18px 0 0}
.site-foot code{font-size:11.5px}
@media (max-width:768px){li.step{grid-template-columns:1fr}.intro{padding:36px 0 28px}section{padding:40px 0}}
</style></head>
<body>
${body}
</body></html>`;

  if (/\/Users\/|\/home\//.test(page)) throw new Error("site/docs.html would contain an absolute local path");
  if (/[–—]/.test(page.replace(/<style[\s\S]*?<\/style>/g, ""))) throw new Error("site/docs.html would contain an en or em dash");
  writeFileSync(join(HERE, "docs.html"), page);
  return { bytes: page.length };
}
