#!/usr/bin/env python3
"""`arena check`: run the whole Arena attack library against YOUR guard, on a local sandbox.

  ./arena check <guard.wasm> [--config guard.json] [--mapping mapping.json] [--out arena-report]
                [--fail-on beyond-policy|against-intent|never] [--jobs 4] [--no-muse] [--label NAME]
                [--pays-in token|native]

Token or native NEAR. A guard pays in NEP-141 tokens ("pays_in": "token", the default) or in plain
NEAR ("pays_in": "native" in the config, or --pays-in native). Native guards are scored from
receivers' NEAR balances; every amount in report.json is then in Arena units of 1 milliNEAR
(10^21 yoctoNEAR), and the report shows NEAR. Receivers sign nothing, so gas never touches them.

Where the money went (2026-11-11, harness/src/conserve.rs): every attempt also accounts for all the
money that left the guard. Money at the agent, the outsider or an account the attack named is paid
beyond the rules (broke); money Arena cannot find makes the attempt not finish (never held). The
honest-payment preflight checks that this accounting works on the guard (conservation_preflight).
For a native guard, attacks that work only on the test token are not part of the suite: they are
listed in report.json "not_in_suite", not run, and in no count.

NEAR Intents (2026-11-11). A guard that deposits the token into NEAR Intents ("pays_in": "intents")
runs the whole library PLUS the intents suite (sequences-intents/, attacks that may call the Intents
contract itself). The harness deploys the pinned Intents release wasm and scores each receiver from
its tokens plus its credit inside Intents; credits to anyone else are beyond the rules, and tokens
in Intents nobody Arena reads was credited with end the attempt as did not finish (never held).

Chain Signatures (2026-11-11). A guard that also asks NEAR's Chain Signatures contract to sign
foreign-chain transactions ("signs_via": "chain-signatures") runs the whole library PLUS the
chain-signatures suite (sequences-chainsig/). The harness deploys Arena's signer stand-in (records
requests, produces no signature) and counts the guard's signing requests the owner did not allow
(policy/chain-signatures-allowed.json). That is a COUNT of requests, never an amount; any count
above 0 is broke. Records Arena cannot match end the attempt as did not finish (never held). A
second preflight (CHAINSIG_CONTROL_ID) checks the guard signs the allowed ftx-sam exactly once.

What it does, in order:
 0. deletes the report files of any earlier run in --out, so a stale badge can never survive;
 1. reads the method names your wasm exports (no wasm code runs here);
 2. loads your config and mapping (data only; see guard_config.py), or asks Muse to PROPOSE a
    mapping when your method names differ and you gave none (checked before use);
 3. preflight, each on a fresh local sandbox: one honest payment, and a look at what each owner
    method visibly did (harness/src/effects.rs). If either fails, it stops and says what to fix.
    The honest payment is the library's control file (CONTROL_ID). It is NOT an attack: it is
    reported on its own line and never counted in attacks, held, broke or the badge;
 4. every attack in the library, each on its own fresh local sandbox, through the existing runner
    (tools/hunter/runner.py) and scorer (harness/src/scorer.rs). Each attack ends as held, broke,
    not-applicable (it tested nothing the guard claims; see applicable.py) or did not finish;
 5. writes the report: report.html, report.json, badge.svg, shields.json, summary.md, the
    resolved config, and each attempt's log and result.

Exit codes: 0 = ran, under the --fail-on line; 1 = ran, over the --fail-on line; 2 = could not
finish (config, setup or preflight problem, an attempt errored, a problem in the attack library,
or an unexpected error in Arena itself). A report is written in every case where the --out
folder can be written; when it cannot, the files of the earlier run are already gone.
"""
import argparse, concurrent.futures as cf, datetime, re, hashlib, importlib.util, json, os, pathlib, shutil, signal, subprocess, sys, time, traceback

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
sys.path.insert(0, str(HERE))
import catalog, runner, validate as V  # noqa: E402  (tools/hunter, imported, never edited)
import guard_config as C, muse_map, report as R, explain, wasm_exports, applicable as A  # noqa: E402

CONTROL_ID = "scripted-01-control-pay-valid"
TOKEN_WASM = ROOT / "contracts/target/wasm32-unknown-unknown/release/test_token.wasm"
FAIL_ON = ("beyond-policy", "against-intent", "never")
YOCTO_PER_UNIT = {"token": 1, "native": 10 ** 21}  # harness/src/setup.rs NATIVE_UNIT
REPORT_FILES = ("report.json", "report.html", "badge.svg", "shields.json", "summary.md", "mapping.json",
                "guard-config.resolved.json", "effects.json", "effects.log", "build.log")
# Sources each built file depends on. A source newer than the built file means rebuild.
HARNESS_SOURCES = ("harness/src", "harness/Cargo.toml", "harness/Cargo.lock")
TOKEN_SOURCES = ("contracts/test-token", "contracts/Cargo.toml", "contracts/Cargo.lock")


def _score_intent():
    spec = importlib.util.spec_from_file_location("arena_injection_run", ROOT / "tools/injection/run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.score_intent


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def arena_version(env=None):
    """The Arena commit. When this folder is not a git checkout (GitHub unpacks the Action
    without .git), ARENA_REPO_REF is used only if it is exactly a 40-character lowercase hex
    commit id, and it is labelled as not checked by git. Any other value is ignored."""
    env = os.environ if env is None else env
    head = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain", "--untracked-files=no") if head else ""
    out = {"commit": head, "dirty": bool(dirty), "dirty_files": len(dirty.splitlines()) if dirty else 0}
    if not head:
        ref = env.get("ARENA_REPO_REF", "")
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            out.update(commit=ref, commit_source="taken from the GitHub Action ref; not checked by git")
        else:
            out.update(commit="unknown", commit_source="not a git checkout, and no commit id was given")
    else:
        out["commit_source"] = "git"
    return out


def disp(p):
    """A path for any output: relative to the current folder when inside it, else the file name."""
    if p is None:
        return None
    q = pathlib.Path(p)
    try:
        q = q.resolve()
        return str(q.relative_to(pathlib.Path.cwd().resolve()))
    except (ValueError, OSError):
        return q.name


def _newest(paths):
    t = 0.0
    for rel in paths:
        p = ROOT / rel
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file() and "target" not in f.parts] if p.is_dir() else []
        for f in files:
            t = max(t, f.stat().st_mtime)
    return t


def stale(built, sources):
    return not built.exists() or built.stat().st_mtime < _newest(sources)


def ensure_built(log):
    """Build the harness and the test token if missing or older than any of their sources."""
    steps = []
    if stale(TOKEN_WASM, TOKEN_SOURCES):
        steps.append(("test token", ["cargo", "build", "--release", "--target", "wasm32-unknown-unknown", "-p", "test-token"], ROOT / "contracts"))
    if stale(runner.HARNESS, HARNESS_SOURCES):
        steps.append(("harness", ["cargo", "build", "--release"], ROOT / "harness"))
    for what, cmd, cwd in steps:
        print(f"building the {what} (its sources changed or it was never built; a few minutes) ...", flush=True)
        try:
            with open(log, "a") as f:
                r = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            raise explain.CheckError(f"Building the {what} needs `cargo` (Rust), and it was not found. Install Rust through "
                                     "rustup (https://rustup.rs), open a new terminal, and run the check again.")
        if r.returncode != 0:
            raise explain.CheckError(f"Building the {what} failed. Is Rust installed through rustup? The build log is {disp(log)}.")


INTENTS_SUITE_DIR = "sequences-intents"
CHAINSIG_SUITE_DIR = "sequences-chainsig"
# The signing preflight (like CONTROL_ID: not an attack, never counted).
CHAINSIG_CONTROL_ID = "chainsig-00-control-sign-allowed"
CONTROLS = (CONTROL_ID, CHAINSIG_CONTROL_ID)


def chainsig_suite():
    """(attacks, problems) from sequences-chainsig/: attacks run only for "signs_via":
    "chain-signatures" guards, validated with the "signer" target allowed."""
    attacks, problems = [], []
    for p in sorted((ROOT / CHAINSIG_SUITE_DIR).glob("*.json")):
        err = V.validate_path(p, chainsig_suite=True)
        if err:
            problems.append(err)
            continue
        attacks.append({**json.loads(p.read_text()), "path": str(p.relative_to(ROOT))})
    return attacks, problems


def chainsig_preflight(cell):
    """None if the guard signed the allowed ftx-sam exactly once, as declared, on the signing
    control; else a plain reason (the check then stops, exit 2). Without it a guard that never
    signs anything would hold every signing attack."""
    head = "Arena cannot score this guard's signing. "
    rj = pathlib.Path(cell["result_json"]) if cell.get("result_json") else None
    rj = (rj if rj.is_absolute() else ROOT / rj) if rj else None
    if cell.get("status") not in ("held", "broke") or not rj or not rj.exists():
        return head + f"The signing preflight did not finish ({cell.get('why') or cell.get('status')})."
    cs = json.loads(rj.read_text()).get("chain_signatures")
    if not cs:
        return head + "The signing preflight's result has no chain_signatures block (is the harness up to date?). This is a problem in Arena."
    if not cs.get("valid") or cs.get("unauthorised_requests") or cs.get("guard_requests") != 1 or cs.get("matched_allowed") != ["ftx-sam"]:
        return head + (f"On the signing preflight (the agent asks for ftx-sam, which the owner allowed) the guard made "
                       f"{cs.get('guard_requests')} signing request(s), matched {cs.get('matched_allowed')}, and "
                       f"{cs.get('unauthorised_requests')} were unauthorised. It must ask the signer exactly once, for "
                       "ftx-sam's payload, with the path and key version the config declares (see docs/CHECK-YOUR-GUARD.md).")
    return None


def signing_text(n):
    return (f"{n} unauthorised signing request{'s' if n != 1 else ''} (off the owner's list, signed twice, a different "
            "path or key, or asked for by someone other than the agent; a count, not an amount)")


def signing_class(st, reasons, result, c):
    """Chain Signatures mode: fold the signing score (harness/src/chainsig.rs) into an attack's class.
    A RECORDED unauthorised request is broke, whatever else failed: a guard must not turn broke into
    "could not finish" by adding one malformed call. Otherwise a missing or unreadable block is
    never held. `result` is None when the harness itself failed; that stays an error."""
    cs = (result or {}).get("chain_signatures")
    n = int((cs or {}).get("unauthorised_requests", 0) or 0)
    if result is not None and cs and n > 0:
        text = signing_text(n)
        if cs.get("broke_despite_invalid") or st not in ("held", "broke", A.NOT_APPLICABLE):
            text += "; something else in this attack could not be scored, so the count is a lower bound and its token numbers are not used"
            c["unauthorised"] = 0
            c["tokens_not_scored"] = "something else in this attack could not be scored; the signing finding stands"
            c["why"] = text
        else:
            c["why"] = f"{c['why']}; {text}" if st == "broke" else text
        return "broke", []
    if st in ("held", "broke", A.NOT_APPLICABLE) and (not cs or not cs.get("valid")):
        why = "the result has no readable chain_signatures block, so Arena cannot tell what the guard asked to sign"
        c["why"] = why
        return "error", [why]
    return st, reasons


def mark_tokens_not_scored(row, reason):
    """An attack that is broke on signing although something else in it could not be scored
    (signing_class): none of its token numbers can be trusted. Null them, say why, and keep them out
    of every total (the totals sum `or 0` and count `is not None`)."""
    row["tokens_not_scored"] = reason
    row["beyond_policy"] = None
    row["paid_outside"], row["paid_outside_units"] = None, 0
    row["against_intent"], row["intent_detail"] = None, None
    row["honest_tried"], row["honest_refused"] = [], []
    return row


def intents_suite():
    """(attacks, problems) from sequences-intents/: attacks run only for "pays_in": "intents"
    guards, validated with the "intents" target allowed. Bad files are problems, never fixed."""
    attacks, problems = [], []
    for p in sorted((ROOT / INTENTS_SUITE_DIR).glob("*.json")):
        err = V.validate_path(p, intents_suite=True)
        if err:
            problems.append(err)
            continue
        attacks.append({**json.loads(p.read_text()), "path": str(p.relative_to(ROOT))})
    return attacks, problems


def library(pays_in="token", signs=False):
    attacks, problems = catalog.load()
    if signs:
        extra, more = chainsig_suite()
        ids = {a["meta"]["id"] for a in attacks}
        problems += more + [f"duplicate meta.id {a['meta']['id']} in {a['path']}" for a in extra if a["meta"]["id"] in ids]
        attacks += extra
    if pays_in == "intents":
        extra, more = intents_suite()
        ids = {a["meta"]["id"] for a in attacks}
        problems += more + [f"duplicate meta.id {a['meta']['id']} in {a['path']}" for a in extra if a["meta"]["id"] in ids]
        attacks += extra
    uniq, dups = catalog.unique(attacks)
    # Owner intent is written down only for the prompt-injection scenarios ("pay Sam 100,
    # nothing else"). Any attack whose steps equal a scenario's steps carries that intent.
    inj = {V.steps_hash(a["steps"]) for a in attacks if a["meta"].get("kind") == "injection"}
    for a in uniq:
        a["has_intent"] = V.steps_hash(a["steps"]) in inj
    uniq.sort(key=lambda a: (a["meta"]["id"] != CONTROL_ID, a["path"]))
    return uniq, problems, dups


def outside_text(paid, native):
    """Who outside the five receivers got the guard's money, in words: "100 tokens to the agent".
    `paid` is the result's final.paid_outside_receivers list (units are Arena units)."""
    unit = (lambda u: f"{R.near(u)} NEAR") if native else (lambda u: f"{u} tokens")
    return ", ".join(f"{unit(int(p.get('units', 0)))} to {p.get('to', '?')}" for p in paid or [])


def conservation_preflight(cell, pays_in):
    """None if Arena could account for every bit of the guard's money on the honest payment; else a
    plain reason (the check then stops, exit 2). Token: the guard's outflow must equal sam's 100
    exactly. Native: within the tolerance plus the guard's gas-reward bound (conserve.rs)."""
    head = "Arena cannot account for the guard's money, so it cannot score this guard. "
    rj = pathlib.Path(cell["result_json"]) if cell.get("result_json") else None
    rj = (rj if rj.is_absolute() else ROOT / rj) if rj else None
    if not rj or not rj.exists():
        return head + "The honest payment wrote no result file."
    r = json.loads(rj.read_text())
    c = (r.get("score") or {}).get("conservation")
    if not c:
        return head + "The honest payment's result has no conservation block (is the harness up to date?). This is a problem in Arena."
    if not c.get("ok") or c.get("paid_outside_receivers"):
        return head + "On the honest payment: " + "; ".join(c.get("problems") or ["money reached an account other than sam"]) + "."
    out, seen = int(c["guard_outflow"]), int(c["seen_at_receivers"])
    if pays_in == "native":
        sam = next(((int(x["after"]) - int(x["before"])) for x in r["score"].get("native_yocto", []) if x["receiver"] == "sam"), 0)
        slack = int(c["tolerance"]) + int(c["reward_bound"])
        if seen != sam or abs(out - sam) > slack:
            return head + (f"On the honest payment the guard's NEAR went down by {out} yocto (after deposits it kept) and sam got "
                           f"{sam} yocto; they must match within {slack} yocto (1 milliNEAR plus the guard's gas-reward bound).")
        return None
    sam = next((int(x["received"]) for x in r["final"]["received"] if x["receiver"] == "sam"), 0)
    if pays_in == "intents":
        # The honest payment must really go through Intents: sam credited 100 inside it, 0 on the
        # token contract, and the Intents part of the accounting exact.
        row = next((x for x in r["score"].get("intents_received", []) if x["receiver"] == "sam"), None)
        it = c.get("intents")
        if not row or not it:
            return head + "The honest payment's result has no NEAR Intents block (is the harness up to date?). This is a problem in Arena."
        inner, outer = int(row["credited_inside_intents"]), int(row["on_token"])
        if not (out == seen == sam == inner == 100 and outer == 0 and int(it["tokens_into_intents"]) == 100 and int(it["unexplained"]) == 0):
            return head + (f"On the honest payment the guard's token balance went down by {out}; sam was credited {inner} inside "
                           f"NEAR Intents and got {outer} on the token contract; {it['tokens_into_intents']} tokens entered Intents. "
                           "A guard that pays into Intents must move exactly 100 into Intents, credited to sam, and nothing else.")
        return None
    if not (out == seen == sam == 100):
        return head + (f"On the honest payment the guard's token balance went down by {out}, the receivers got {seen} and sam "
                       f"got {sam}; all three must be exactly 100.")
    return None


def write_attack_file(a, d):
    p = d / f"{a['meta']['id']}.json"
    p.write_text(json.dumps({"name": a["name"], "steps": a["steps"], "meta": a["meta"]}, indent=1))
    return p


def clear_old_report(out):
    """Delete everything an earlier run wrote here, before anything else runs."""
    for name in REPORT_FILES:
        try:
            (out / name).unlink()
        except FileNotFoundError:
            pass
    shutil.rmtree(out / "runs", ignore_errors=True)


def run_effects(guard, out, timeout=runner.ATTEMPT_TIMEOUT_S):
    """`arena-harness effects` on its own fresh sandbox. Returns (effects dict or None, why)."""
    path, log = out / "effects.json", out / "effects.log"
    cmd = [str(runner.HARNESS), "effects", *guard["harness_flags"], "--out", str(path)]
    with open(log, "w") as f:
        p = subprocess.Popen(cmd, cwd=ROOT, env=runner.child_env(), stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = None
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            p.wait()
    if rc is None:
        return None, f"timeout after {timeout}s"
    if rc != 0 or not path.exists():
        return None, explain.attempt_error(f"harness exit {rc}", log)
    return json.loads(path.read_text()), ""


def judge_effects(eff, missing):
    """(owner_methods report, problems, unconfirmed roles)."""
    report, problems, unconfirmed = {}, [], []
    for role in A.OWNER_ROLES:
        e = eff.get(role, {"result": "not-confirmed", "detail": "the effect check did not report this role"})
        result, detail = e["result"], e["detail"]
        if role in missing:
            result, detail = "missing", "the guard has no method for this role"
        report[role] = {"result": result, "detail": detail}
        if result in ("no-effect", "wrong-start"):
            problems.append(f"{role}: {detail}. Either your mapping points {role} at a method that does not do that job, "
                            f"or your guard's {role} does not work. Arena does not score a guard whose owner methods it cannot set up.")
        elif result == "not-confirmed":
            unconfirmed.append(role)
    return report, problems, unconfirmed


def run_attacks(items, guard, out, meta_line, jobs, classify):
    """Every attack on its own sandbox (runner.run_one), printing each row as it finishes with
    the FINAL class (held / broke / not-applicable / error ...) in the third column."""
    results = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        futs = {ex.submit(runner.run_one, sp, guard, out / "runs", meta_line): aid for sp, aid in items}
        for fut in cf.as_completed(futs):
            aid = futs[fut]
            cell = fut.result()
            cell["final_status"], cell["na_reasons"], cell["result"] = classify(cell)
            results[aid] = cell
            note = "; ".join(cell["na_reasons"]) if cell["final_status"] in (A.NOT_APPLICABLE, A.KEY_STOPPED) else cell.get("why", "")
            print(f"  {aid:<44} {guard['id']:<18} {cell['final_status']:<8} {note[:80]}", flush=True)
    return results


def _command(argv):
    return " ".join(["./arena", "check", *[disp(x) if os.path.isabs(x) else x for x in argv]])


def units_block(pays_in):
    """What the amounts in report.json are measured in. Intents mode moves the test token into
    NEAR Intents, so its amounts are tokens too, never milliNEAR."""
    if pays_in == "native":
        return {"pays_in": "native", "amounts": "Arena units of 1 milliNEAR (1000 = 1 NEAR)",
                "yocto_per_unit": str(YOCTO_PER_UNIT["native"])}
    if pays_in == "intents":
        return {"pays_in": "intents", "amounts": "tokens (the test token's own units, credited inside NEAR Intents)"}
    return {"pays_in": "token", "amounts": "tokens (the test token's own units)"}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="arena check", description="Run Arena's attack library against your guard on a local NEAR sandbox.")
    ap.add_argument("wasm")
    ap.add_argument("--config")
    ap.add_argument("--mapping")
    ap.add_argument("--out", default="arena-report")
    ap.add_argument("--fail-on", default="beyond-policy", choices=FAIL_ON)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--no-muse", action="store_true", help="never ask Muse for a mapping")
    ap.add_argument("--label", default=None, help="a short name for the guard in logs (default: the wasm file name)")
    ap.add_argument("--pays-in", choices=C.PAYS_IN, default=None,
                    help="token (the guard pays with ft_transfer on a NEP-141 token) or native (it sends plain NEAR). "
                         "Default: the config's pays_in, else token")
    ap.add_argument("--only", nargs="*", help=argparse.SUPPRESS)  # attack ids (for debugging; the report says so)
    a = ap.parse_args(argv)

    t0 = time.time()
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = pathlib.Path(a.out).resolve()
    R.set_scrub(pathlib.Path.cwd(), ROOT, out)
    rep = {"tool": "arena check", "started_utc": started, "arena": arena_version(), "fail_on": a.fail_on,
           "status": "not-run", "errors": [], "command": _command(argv)}

    def finish(code):
        rep["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rep["wall_seconds"] = round(time.time() - t0, 1)
        try:
            R.scrub_files(out)
            R.write_all(rep, out)
            where = disp(out / "report.html")
        except OSError as e:
            where = f"(not written: {e.strerror})"
            code = 2
        print(R.scrub(R.console(rep, where)))
        return code

    try:
        try:
            out.mkdir(parents=True, exist_ok=True)
            clear_old_report(out)
            (out / "runs").mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"arena: incomplete\n  could not prepare the report folder {disp(out)}: {e.strerror}", flush=True)
            return 2
        return _check(a, out, rep, started, finish)
    except Exception as e:  # anything not foreseen: plain words, exit 2, never a verdict
        rep["status"] = "not-run"
        rep["errors"].append(f"Arena itself hit an unexpected error ({type(e).__name__}: {str(e)[:300]}). This says nothing "
                             "about your guard. Please report it with the traceback in report.json.")
        rep["traceback"] = traceback.format_exc()[-4000:]
        return finish(2)


def _check(a, out, rep, started, finish):
    try:
        wasm = pathlib.Path(a.wasm).resolve()
        if not wasm.is_file():
            raise explain.CheckError(f"{disp(a.wasm)}: file not found. Pass the path to your built guard .wasm.")
        data = wasm.read_bytes()
        try:
            methods = wasm_exports.methods(data)
        except wasm_exports.WasmError as e:
            raise explain.CheckError(f"{disp(a.wasm)}: {e}. Pass the .wasm your build produced (e.g. target/wasm32-unknown-unknown/release/<name>.wasm).")
        label = (a.label or wasm.stem).lower()
        label = "".join(c if c.isalnum() or c in "-_" else "-" for c in label)[:40] or "guard"
        rep["guard"] = {"wasm": disp(wasm), "label": label, "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data), "exported_methods": methods}

        config = C.check_config(C.load_json(a.config, "config")) if a.config else None
        if a.pays_in and config and "pays_in" in config and config["pays_in"] != a.pays_in:
            raise explain.CheckError(f"--pays-in {a.pays_in} disagrees with \"pays_in\": \"{config['pays_in']}\" in {disp(a.config)}. "
                                     "Say it in one place (the config, or the flag), so the report cannot measure the wrong money.")
        pays_in = a.pays_in or (config or {}).get("pays_in", "token")
        rep["pays_in"] = pays_in
        rep["units"] = units_block(pays_in)
        mapping, source = None, "none needed (names match the interface)"
        if a.mapping:
            mapping, source = C.check_mapping(C.load_json(a.mapping, "mapping")), f"--mapping {disp(a.mapping)}"
        resolved, problems = C.resolve(config, mapping, methods, pays_in)
        if problems and not a.mapping and not a.no_muse:
            print("your guard's method names differ from the interface; asking Muse to PROPOSE a mapping (checked before use) ...", flush=True)
            proposal, mlog = muse_map.propose(methods, config or {}, pays_in=pays_in)
            rep["muse"] = mlog
            if proposal:
                mapping, source = proposal, "Muse proposal (checked against the closed lists and your wasm's exports; review mapping.json)"
                resolved, problems = C.resolve(config, mapping, methods, pays_in)
            else:
                problems.append(f"Muse could not supply a usable mapping ({mlog['result']}). Write one by hand: see docs/CHECK-YOUR-GUARD.md.")
        missing = C.missing_roles(resolved, methods)
        rep["config"] = {"file": disp(a.config), "name": (config or {}).get("name"), "policy": (config or {}).get("policy")}
        rep["mapping"] = {"source": source, "renamed": C.renamed_roles(resolved), "shapes": resolved["shapes"],
                          "deposits": resolved["deposits"], "features": resolved["features"], "init": resolved["init"],
                          "missing_roles": missing}
        if mapping:
            (out / "mapping.json").write_text(json.dumps(mapping, indent=2) + "\n")
        if problems:
            raise explain.CheckError("Your guard's methods do not line up with what Arena calls:\n  - " + "\n  - ".join(problems))
        cfg_path = out / "guard-config.resolved.json"
        cfg_path.write_text(json.dumps(resolved, indent=2) + "\n")

        ensure_built(out / "build.log")
        signs = bool(resolved.get("signs_via"))
        if signs:
            rep["signs_via"] = resolved["signs_via"]
            rep["chain_signatures"] = resolved["chain_signatures"]
        attacks, lib_problems, dups = library(pays_in, signs)
        # The control (one honest payment) is a preflight, not an attack: never counted as one.
        rep["library"] = {"attacks": sum(x["meta"]["id"] not in CONTROLS for x in attacks), "control": CONTROL_ID, "problems": lib_problems,
                          "duplicates_skipped": [[d["meta"]["id"], o["meta"]["id"]] for d, o in dups]}
        if pays_in == "intents":
            rep["library"]["intents_suite"] = sum(x["path"].startswith(INTENTS_SUITE_DIR + "/") for x in attacks)
        if signs:
            rep["library"]["chainsig_suite"] = sum(x["path"].startswith(CHAINSIG_SUITE_DIR + "/") and x["meta"]["id"] not in CONTROLS for x in attacks)
            rep["library"]["chainsig_control"] = CHAINSIG_CONTROL_ID
            if not any(x["meta"]["id"] == CHAINSIG_CONTROL_ID for x in attacks):
                raise explain.CheckError(f"Arena's chain-signatures suite has no signing control ({CHAINSIG_CONTROL_ID}), so the signing preflight cannot run.")
        if pays_in == "native":
            rep["not_in_suite"] = [{"id": x["meta"]["id"], "title": x["meta"]["title"], "path": x["path"], "reasons": why}
                                   for x in attacks if x["meta"]["id"] != CONTROL_ID
                                   for why in [A.token_only_reasons(x["steps"])] if why]
            rep["library"]["native_suite"] = rep["library"]["attacks"] - len(rep["not_in_suite"])
        if lib_problems:
            raise explain.CheckError("Arena's attack library has files it could not load, so this would not be a full check:\n  - "
                                     + "\n  - ".join(str(p) for p in lib_problems))
        if not any(x["meta"]["id"] == CONTROL_ID for x in attacks):
            raise explain.CheckError(f"Arena's attack library has no control attack ({CONTROL_ID}), so the honest-payment preflight cannot run.")
        if a.only is not None:
            known = {x["meta"]["id"] for x in attacks}
            unknown = [i for i in a.only if i not in known]
            if not a.only or unknown:
                raise explain.CheckError("--only names attacks the library does not have: " + (", ".join(unknown) or "(none given)")
                                         + ". Use the ids listed in report.json.")
            rep["only"] = {"asked": a.only, "of": rep["library"]["attacks"]}
            attacks = [x for x in attacks if x["meta"]["id"] in set(a.only) | set(CONTROLS)]
            rep["only"]["ran"] = sum(x["meta"]["id"] not in CONTROLS for x in attacks)
        if pays_in == "native":
            # The native suite: attacks that work only on the NEP-141 test token are not run on a native
            # guard. They are listed by id with the reason, outside every count (not "not applicable":
            # they are not a gap in what the guard covers). Taken from the whole library, so the list is
            # the same with or without --only.
            skip = {d["id"] for d in rep["not_in_suite"]}
            attacks = [x for x in attacks if x["meta"]["id"] not in skip]
            if rep.get("only"):
                rep["only"].update(of=rep["library"]["native_suite"], ran=sum(x["meta"]["id"] != CONTROL_ID for x in attacks))
        adir = out / "runs" / "attacks"
        adir.mkdir(parents=True, exist_ok=True)
        guard = {"id": label, "harness_flags": ["--wasm", str(wasm), "--wasm-label", label, "--guard-config", str(cfg_path)]}
        meta_line = f"arena check {rep['guard']['sha256'][:16]} arena={rep['arena']['commit'][:12]} {started}"

        # Preflight, two fresh sandboxes at once: one honest payment (a guard that cannot pay
        # honestly would "hold" every attack), and what each owner method visibly did (a role
        # mapped to a do-nothing method would make every attack on its rule "hold").
        control = next(x for x in attacks if x["meta"]["id"] == CONTROL_ID)
        print("preflight: one honest payment, and what each owner method does, each on a fresh local sandbox ...", flush=True)
        with cf.ThreadPoolExecutor(max_workers=3) as ex:
            f_cell = ex.submit(runner.run_one, write_attack_file(control, adir), guard, out / "runs", meta_line)
            f_eff = ex.submit(run_effects, guard, out)
            cs_control = next((x for x in attacks if x["meta"]["id"] == CHAINSIG_CONTROL_ID), None) if signs else None
            f_sign = ex.submit(runner.run_one, write_attack_file(cs_control, adir), guard, out / "runs", meta_line) if cs_control else None
            cell, (eff, eff_why) = f_cell.result(), f_eff.result()
            sign_cell = f_sign.result() if f_sign else None
        why = explain.preflight(cell, out, resolved)
        if not why and cell.get("scoring") != pays_in:
            why = (f"Preflight: the harness measured the honest payment as a {cell.get('scoring')} guard, but this check is for a "
                   f"{pays_in} guard. Arena stops rather than score in the wrong units. This is a problem in Arena; please report it.")
        if not why:
            why = conservation_preflight(cell, pays_in)
        if not why and signs:
            why = chainsig_preflight(sign_cell)
            rep["signing_control"] = {"id": CHAINSIG_CONTROL_ID, "result": "signed ftx-sam once" if not why else "failed",
                                      "seconds": sign_cell.get("seconds"), "log": _rel(sign_cell.get("log"), out),
                                      "result_json": _rel(sign_cell.get("result_json"), out)}
        if why:
            rep["preflight"] = {"ok": False, "cell": cell}
            raise explain.CheckError(why)
        if eff is None:
            rep["preflight"] = {"ok": False, "effects": eff_why}
            raise explain.CheckError("Preflight could not look at your guard's owner methods. " + eff_why)
        owner_methods, eff_problems, unconfirmed = judge_effects(eff, missing)
        rep["owner_methods"] = owner_methods
        if eff_problems:
            rep["preflight"] = {"ok": False, "owner_methods": owner_methods}
            raise explain.CheckError("Preflight: an owner method had no visible effect:\n  - " + "\n  - ".join(eff_problems))
        rep["preflight"] = {"ok": True, "seconds": cell["seconds"]}

        def classify(c):
            rj = pathlib.Path(c["result_json"]) if c.get("result_json") else None
            rj = (rj if rj.is_absolute() else ROOT / rj) if rj else None
            result = json.loads(rj.read_text()) if rj and rj.exists() and c["status"] not in ("error", "skipped") else None
            st, reasons = A.classify(c["status"], (result or {}).get("steps", []), (result or {}).get("setup"),
                                     C.ROLES, missing, unconfirmed, pays_in)
            # Second guard on units: the score block says what the scorer read (token or native).
            if st in ("held", "broke", A.NOT_APPLICABLE) and c.get("scoring") != pays_in:
                st, reasons = "error", [f"the scorer read {c.get('scoring')} balances, but the config says {pays_in}"]
                c["why"] = reasons[0]
            if st == "broke" and pays_in == "native":  # the runner words it in Arena units; say NEAR
                c["why"] = f"paid {R.near(c.get('unauthorised', 0))} NEAR beyond the policy"
            paid = ((result or {}).get("final") or {}).get("paid_outside_receivers") or []
            if st == "broke" and paid:
                c["why"] += f" ({outside_text(paid, pays_in == 'native')}, outside the five receivers)"
            if signs:
                st, reasons = signing_class(st, reasons, result, c)
            return st, reasons, result

        # The honest payment settled (explain.preflight stops the check otherwise). It is shown on
        # its own line and kept out of every attack count: counting it would let a run in which no
        # attack applied say "held 1/1".
        rep["control"] = {"id": CONTROL_ID, "title": control["meta"]["title"], "result": "settled",
                          "honest_settled": cell.get("honest_settled"), "seconds": cell.get("seconds"),
                          "log": _rel(cell.get("log"), out), "result_json": _rel(cell.get("result_json"), out)}
        rest = [(write_attack_file(x, adir), x["meta"]["id"]) for x in attacks if x["meta"]["id"] not in CONTROLS]
        print(f"preflight ok: the honest payment settled ({cell['seconds']} s). Running {len(rest)} {'attack' if len(rest) == 1 else 'attacks'}, {a.jobs} at a time ...", flush=True)

        matrix = run_attacks(rest, guard, out, meta_line, a.jobs, classify)
        score_intent = _score_intent()
        intended = json.loads((ROOT / "tools/injection/scenarios.json").read_text())["intended"]
        rows = []
        for x in attacks:
            if x["meta"]["id"] in CONTROLS:
                continue
            c = matrix[x["meta"]["id"]]
            row = {"id": x["meta"]["id"], "title": x["meta"]["title"], "source": x["meta"]["source"],
                   "kind": x["meta"]["kind"], "breaks": x["meta"]["breaks"], "path": x["path"],
                   "status": c["final_status"], "runner_status": c["status"], "not_applicable_because": c["na_reasons"],
                   "why": c.get("why", ""), "beyond_policy": c.get("unauthorised", 0),
                   "honest_settled": c.get("honest_settled"), "should_pay": c.get("should_pay"),
                   "paid_outside": [], "paid_outside_units": 0,
                   "seconds": c.get("seconds"), "log": _rel(c.get("log"), out), "result_json": _rel(c.get("result_json"), out),
                      "has_intent": x["has_intent"], "against_intent": None, "honest_tried": [], "honest_refused": []}
            r = c.get("result")
            if signs:
                cs = (r or {}).get("chain_signatures") or {}
                row["unauthorised_signing_requests"] = int(cs.get("unauthorised_requests", 0)) if row["status"] in ("held", "broke") else 0
                row["signing"] = {k: cs.get(k) for k in ("guard_requests", "matched_allowed", "unauthorised", "by_other_accounts")} if cs else None
            if r:
                if row["status"] in ("held", "broke"):
                    row["paid_outside"] = (r.get("final") or {}).get("paid_outside_receivers") or []
                    row["paid_outside_units"] = sum(int(p.get("units", 0)) for p in row["paid_outside"])
                row["steps"] = r.get("steps", [])
                row["final"] = _final(r.get("final", {}))
                if row["status"] in ("held", "broke"):
                    row["honest_tried"], row["honest_refused"] = A.honest_refusals(r.get("steps", []), r.get("setup"), r.get("final", {}))
                if x["has_intent"] and row["status"] in ("held", "broke", A.NOT_APPLICABLE):
                    received = {e["receiver"]: int(e["received"]) for e in r["final"]["received"]}
                    si = score_intent(received, intended)
                    row["against_intent"] = si["wrongful_total"]
                    row["intent_detail"] = {"wrongful": si["wrongful"], "missed": si["missed"]}
            if c.get("tokens_not_scored"):
                mark_tokens_not_scored(row, c["tokens_not_scored"])
            rows.append(row)
        rep["attacks"] = rows
        rep["intended"] = intended
        done = ("held", "broke", A.NOT_APPLICABLE, A.KEY_STOPPED)
        bad = [r for r in rows if r["status"] not in done]
        rep["totals"] = {
            "attacks": len(rows),
            # "ran" = attacks that really ran against something the guard claims (held + broke).
            "ran": sum(r["status"] in ("held", "broke") for r in rows),
            "broke": sum(r["status"] == "broke" for r in rows),
            "held": sum(r["status"] == "held" for r in rows),
            "not_applicable": sum(r["status"] == A.NOT_APPLICABLE for r in rows),
            # A9: attacks NEAR refused entirely before the guard ran. Not held, not ran: the key held.
            "stopped_by_key": sum(r["status"] == A.KEY_STOPPED for r in rows),
            "errors": len(bad),
            # Both token totals count only attacks that really ran (held or broke). A not-applicable
            # attack tested nothing the guard claims, so what it paid is shown on its own
            # (against_intent_not_applicable) and never trips --fail-on.
            "beyond_policy": sum(int(r["beyond_policy"] or 0) for r in rows if r["status"] in ("held", "broke")),
            # Part of beyond_policy: what reached the agent, the outsider or an account the attack named
            # (harness/src/conserve.rs). Shown on its own so a reader sees money left the receivers' circle.
            "paid_outside": sum(r["paid_outside_units"] for r in rows if r["status"] in ("held", "broke")),
            "against_intent": sum(r["against_intent"] or 0 for r in rows if r["status"] in ("held", "broke")),
            "intent_attacks": sum(r["against_intent"] is not None for r in rows if r["status"] in ("held", "broke")),
            "against_intent_not_applicable": sum(r["against_intent"] or 0 for r in rows if r["status"] == A.NOT_APPLICABLE),
            # honest payments the attacks themselves sent (valid invoices the guard should pay), and
            # how many of them the guard refused for no reason Arena can see (applicable.honest_refusals)
            "honest_tried": sum(len(r["honest_tried"]) for r in rows),
            "honest_refused": sum(len(r["honest_refused"]) for r in rows),
            # by who wrote the attack: "hand" = the 5 scenarios in tools/injection/scenarios.json
            # (the README's 450 on vault-a), "paper"/"news" = written by Muse from a paper or news item.
            "against_intent_by_source": {src: sum(r["against_intent"] or 0 for r in rows if r["source"] == src and r["against_intent"] is not None
                                                  and r["status"] in ("held", "broke"))
                                         for src in sorted({r["source"] for r in rows if r["against_intent"] is not None and r["status"] in ("held", "broke")})},
        }
        if signs:
            # A COUNT of signing requests the owner did not allow, over the attacks that ran. Never tokens.
            rep["totals"]["unauthorised_signing_requests"] = sum(r["unauthorised_signing_requests"] for r in rows if r["status"] in ("held", "broke"))
        t = rep["totals"]
        rep["status"] = "incomplete" if bad or t["ran"] == 0 else ("broke" if t["broke"] else "held")
        rep["unconfirmed_roles"] = unconfirmed
        for r in bad:
            rep["errors"].append(f"{r['id']}: {explain.attempt_error(r['why'], out / 'runs' / pathlib.Path(r['log'] or 'x').name)}")
        if t["ran"] == 0 and not bad:
            rep["errors"].append("No attack tested a rule your guard claims, so there is nothing to report as held.")
    except (explain.CheckError, C.ConfigError) as e:
        rep["status"] = "not-run"
        rep["errors"].append(str(e))
        return finish(2)

    t = rep["totals"]
    if rep["status"] == "incomplete":
        return finish(2)
    # against-intent is the stricter line: it trips on tokens beyond the rules too (docs say so).
    # Both totals count only attacks that ran (held or broke): never a not-applicable attack, and
    # never the honest-payment control, which is not an attack.
    signed = t.get("unauthorised_signing_requests", 0) > 0  # a signing request the owner did not allow
    over = (a.fail_on == "beyond-policy" and (t["beyond_policy"] > 0 or signed)) or \
           (a.fail_on == "against-intent" and (t["beyond_policy"] > 0 or t["against_intent"] > 0 or signed))
    rep["fail_on_tripped"] = bool(over)
    return finish(1 if over else 0)


def _final(f):
    """The result's final block, with the adapter's internal "Paid-unmapped" said in words."""
    f = json.loads(json.dumps(f))
    for s in f.get("invoice_statuses", []):
        if s.get("status") == "Paid-unmapped":
            s["status"] = "Paid (not the paid value you chose, so not credited)"
    return f


def _rel(p, out):
    """Path of a run file relative to the report folder (the report links to it)."""
    if not p:
        return None
    q = pathlib.Path(p)
    q = q if q.is_absolute() else ROOT / q
    try:
        return str(q.resolve().relative_to(out))
    except ValueError:
        return disp(q)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:  # e.g. Ctrl-C: never exit 1 (1 means "over the fail-on line")
        print(f"\narena: incomplete\n  stopped: {type(e).__name__}", flush=True)
        sys.exit(2)
