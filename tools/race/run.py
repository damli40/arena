"""Race-ordering matched pairs on the local sandbox (RACE-ORDERING-DESIGN sections 5 to 7).

    python3 -I tools/race/run.py [--out DIR] [--jobs 3] [--counted 3] [--tries 5] [--only S2]
    python3 -I tools/race/run.py hitrate <sequence.json> <guard> [--n 20] [--out DIR]
    python3 -I tools/race/run.py timeout [--out DIR]     the slow token's timeout path (about 2 minutes)

Each CELL is one scenario on one guard with what must happen: a race scenario must be judged
`overlap-proven` (tools/race/ordering.py) and then the flawed guard must break by exactly 100 and
the fixed guard must hold; a sequential twin must be judged `sequential` and hold on the flawed
guard. A try whose ordering is not the one asked for (`not-produced`, `tie-unproven`, or a race
that came out sequential) is NOT COUNTED, never held or broke: it is retried, up to --tries. A cell
passes only with --counted counted tries that all match.

"held"  = valid score, 0 beyond policy, and the invoice's receiver got exactly 100 (one payment).
"broke" = valid score and exactly 100 beyond policy (the receiver got 200).
Anything else on a counted try is a MISMATCH and fails the cell.

Writes every try's result JSON and log, summary.json and summary.md into --out (default
runs/<UTC time>-race/, gitignored). Last line:
    race-c2: <n> cells, <m> passed; counted tries <c>, not counted <x>; ...
Exit 0 only if every cell passed. Local sandbox only.
"""
import argparse, concurrent.futures as cf, datetime, json, pathlib, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "race"))
import ordering as O  # noqa: E402

HARNESS = ROOT / "harness" / "target" / "release" / "arena-harness"
GUARDS = {
    "guard-vulnerable": ["--target", "guard-vulnerable"],
    "guard-fixed": ["--target", "guard-fixed"],
    "vault-a": ["--target", "vault"],
    "M5": ["--wasm", str(ROOT / "mutants" / "M5" / "vault_a.wasm"), "--wasm-label", "M5"],
    "race-m1": ["--wasm", str(ROOT / "mutants" / "race-m1" / "vault_a.wasm"), "--wasm-label", "race-m1"],
    "race-m2": ["--wasm", str(ROOT / "mutants" / "race-m2" / "vault_a.wasm"), "--wasm-label", "race-m2"],
    "race-m3": ["--wasm", str(ROOT / "mutants" / "race-m3" / "vault_a.wasm"), "--wasm-label", "race-m3"],
}
SLOW = ["--token", "slow"]
SLOW_WASM = ROOT / "contracts" / "slow-token" / "target" / "wasm32-unknown-unknown" / "release" / "slow_token.wasm"
SEQ = ROOT / "sequences-race"
# (scenario file stem, guard, must: broke | held, ordering the try must have to count, why)
CELLS = [
    ("s1-same-block", "guard-vulnerable", "broke", O.OVERLAP, "P1 flawed: writes paid only in the callback"),
    ("s1-same-block", "guard-fixed", "held", O.OVERLAP, "P1 fixed twin (same wasm bytes, fixed mode)"),
    ("s1-same-block", "M5", "broke", O.OVERLAP, "P1b flawed: vault-a without the in-flight mark"),
    ("s1-same-block", "vault-a", "held", O.OVERLAP, "P1b / P2 fixed"),
    ("s1-same-block", "race-m1", "held", O.OVERLAP, "negative control: a same-block lock does stop a same-block race"),
    ("s2-next-block", "race-m1", "broke", O.OVERLAP, "P2 flawed: in-flight lock only within one block"),
    ("s2-next-block", "vault-a", "held", O.OVERLAP, "P2 fixed"),
    ("s2-next-block", "guard-vulnerable", "broke", O.OVERLAP, "P1 flawed, second check one block later"),
    ("s2-next-block", "guard-fixed", "held", O.OVERLAP, "P1 fixed"),
    ("s2-next-block", "M5", "broke", O.OVERLAP, "P1b flawed, second check one block later"),
    ("s1-twin-sequential", "guard-vulnerable", "held", O.SEQUENTIAL, "sequential twin of S1 on P1 flawed"),
    ("s1-twin-sequential", "M5", "held", O.SEQUENTIAL, "sequential twin of S1 on P1b flawed"),
    ("s2-twin-sequential", "race-m1", "held", O.SEQUENTIAL, "sequential twin of S2 on P2 flawed"),
    ("s2-twin-sequential", "guard-vulnerable", "held", O.SEQUENTIAL, "sequential twin of S2 on P1 flawed"),
    ("s2-twin-sequential", "M5", "held", O.SEQUENTIAL, "sequential twin of S2 on P1b flawed"),
    ("s5-too-late", "guard-vulnerable", "held", O.SEQUENTIAL, "S5: the judge must say sequential, never a race"),
    ("s5-too-late", "guard-fixed", "held", O.SEQUENTIAL, "S5 on the fixed guard"),
    # Checkpoint 3: the slow token (yield/resume) and the daily-cap race.
    ("s3-held-answer", "race-m2", "broke", O.OVERLAP, "P3 flawed: in-flight lock wears off after 2 blocks"),
    ("s3-held-answer", "vault-a", "held", O.OVERLAP, "P3 fixed"),
    ("s3-held-answer", "guard-vulnerable", "broke", O.OVERLAP, "P1 flawed, second check 4 blocks later while the answer is held"),
    ("s3-held-answer", "guard-fixed", "held", O.OVERLAP, "P1 fixed, same"),
    ("s3-twin-sequential", "race-m2", "held", O.SEQUENTIAL, "sequential twin of S3 on P3 flawed (slow token, holding off)"),
    ("s1-same-block", "race-m2", "held", O.OVERLAP, "negative control: race-m2 holds with the normal token, same block"),
    ("s2-next-block", "race-m2", "held", O.OVERLAP, "negative control: race-m2 holds with the normal token, next block"),
    ("s2-next-block", "race-m1", "broke", O.OVERLAP, "P2 flawed on the slow token with holding off (the slow token adds nothing)"),
    ("s4-cap-timed", "race-m3", "cap-broke", O.OVERLAP, "P4 flawed: day's spend counted in the callback"),
    ("s4-cap-timed", "vault-a", "cap-held", O.OVERLAP, "P4 fixed"),
    ("s4-cap-held", "race-m3", "cap-broke", O.OVERLAP, "P4 flawed, checks 0/4/8 blocks apart while answers are held"),
    ("s4-cap-held", "vault-a", "cap-held", O.OVERLAP, "P4 fixed, held"),
    ("s4-twin-sequential", "race-m3", "cap-held", O.SEQUENTIAL, "sequential twin of S4 on P4 flawed"),
]
# Cells that run with --token slow: every held scenario, plus two controls showing that the slow
# token with holding off changes nothing (race-m2 twin, race-m1 on S2 under the slow token).
SLOW_CELLS = {("s3-held-answer", g) for g in ("race-m2", "vault-a", "guard-vulnerable", "guard-fixed")} | {
    ("s3-twin-sequential", "race-m2"), ("s4-cap-held", "race-m3"), ("s4-cap-held", "vault-a")}
SLOW_CONTROL = ("s2-next-block", "race-m1")  # the one CELLS entry for s2/race-m1 listed second runs slow
# The timeout negative control: nobody releases; must come out not-produced (HOLD-TIMEOUT), never held/broke.
TIMEOUT_CELL = ("s3-no-release", "guard-vulnerable")


def legs_idx(r):
    race = [i for i, s in enumerate(r["steps"]) if s["kind"] == "race-call"]
    return race or [i for i, s in enumerate(r["steps"]) if s["kind"] == "call" and s["method"] == "pay"]


def received(r, name="sam"):
    for x in r["final"]["received"]:
        if x["receiver"] == name:
            return int(x["received"])
    return None


def outcome_of(r, must="broke"):
    """broke | held | cap-broke | cap-held | other, from the score only (never from the trace)."""
    s = r["score"]
    if not s.get("valid"):
        return "other", "score invalid: " + "; ".join(s.get("invalid_reasons") or [])
    if must.startswith("cap-"):
        cap, total = int(s["above_cap"]), sum(int(x["received"]) for x in r["final"]["received"])
        if cap == 100 and total == 600:
            return "cap-broke", f"above cap {cap}, receivers got {total} in all"
        if cap == 0 and total == 500 and int(s["beyond_authorised"]) == 0:
            return "cap-held", f"above cap 0, receivers got {total} in all"
        return "other", f"above cap {cap}, beyond policy {s['beyond_authorised']}, receivers got {total}"
    beyond, got = int(s["beyond_authorised"]), received(r)
    if beyond == 100 and got == 200:
        return "broke", f"beyond policy {beyond}, receiver got {got}"
    if beyond == 0 and got == 100:
        return "held", f"beyond policy 0, receiver got {got}"
    return "other", f"beyond policy {beyond}, receiver got {got}"


def attempt(seq, guard, out, tag, must="broke", slow=False):
    res = out / f"{tag}.result.json"
    log = out / f"{tag}.log"
    t0 = time.time()
    with open(log, "w") as fh:
        p = subprocess.run([str(HARNESS), "attempt", str(seq), *GUARDS[guard], *(SLOW if slow else []), "--out", str(res)],
                           cwd=ROOT / "harness", stdout=fh, stderr=subprocess.STDOUT)
    secs = round(time.time() - t0, 1)
    if p.returncode != 0 or not res.exists():
        return {"tag": tag, "error": f"harness exit {p.returncode} (see {log.name})", "secs": secs}
    r = json.loads(res.read_text())
    v = O.ordering_verdict(O.legs_of(r, legs_idx(r)))
    oc, why = outcome_of(r, must)
    return {"tag": tag, "secs": secs, "token": (r.get("token") or {}).get("kind", "test"), "verdict": v["verdict"], "achieved_offsets": v["achieved_offsets"],
            "last_check": v["last_check"], "first_cb": v["first_cb"], "reasons": v["reasons"],
            "outcome": oc, "outcome_why": why, "wasm": r.get("target_wasm_sha256", "")[:16]}


def run_cell(cell, out, counted, tries):
    scen, guard, must, want, why, slow = cell
    tries_out, n_counted, ok = [], 0, True
    tok = "-slow" if slow else ""
    for t in range(1, tries + 1):
        a = attempt(SEQ / f"{scen}.json", guard, out, f"{scen}--{guard}{tok}--try{t}", must, slow)
        a["counted"] = a.get("verdict") == want
        if a["counted"]:
            n_counted += 1
            a["match"] = a["outcome"] == must
            ok = ok and a["match"]
        tries_out.append(a)
        if n_counted >= counted:
            break
    passed = ok and n_counted >= counted
    return {"scenario": scen, "guard": guard, "token": "slow" if slow else "test", "must": must, "ordering_needed": want, "why": why,
            "counted": n_counted, "tries": len(tries_out), "passed": passed, "runs": tries_out}


def fmt_cell(c):
    counted = [r for r in c["runs"] if r["counted"]]
    got = ", ".join(sorted({r["outcome"] for r in counted})) or "-"
    blocks = "; ".join(f"checks to callback {r['last_check']}→{r['first_cb']} offs {r['achieved_offsets']}" for r in counted)
    skipped = "; ".join(f"try {i+1}: {r.get('verdict') or r.get('error')}" for i, r in enumerate(c["runs"]) if not r["counted"])
    return (f"| {c['scenario']} | {c['guard']} | {c['token']} | {c['must']} | {got} | {c['counted']} of {c['tries']} | "
            f"{'PASS' if c['passed'] else 'FAIL'} | {blocks} | {skipped or '-'} |")


def ensure_built():
    if not HARNESS.exists():
        subprocess.run(["cargo", "build", "--release"], cwd=ROOT / "harness", check=True)
    if not SLOW_WASM.exists():
        subprocess.run(["cargo", "build", "--release", "--target", "wasm32-unknown-unknown"], cwd=ROOT / "contracts" / "slow-token", check=True)
    for g in ("M5", "race-m1", "race-m2", "race-m3"):
        w = pathlib.Path(GUARDS[g][1])
        if not w.exists():
            sys.exit(f"missing {w} (race mutants: tools/race/build_mutant.sh <id>)")


def default_out(name):
    return ROOT / "runs" / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{name}")


def main_cells(a):
    out = (pathlib.Path(a.out) if a.out else default_out("race")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    ensure_built()
    cells, seen = [], set()
    for c in CELLS:
        key = (c[0], c[1])
        slow = key in SLOW_CELLS or (key == SLOW_CONTROL and key in seen)
        seen.add(key)
        cells.append((*c, slow))
    cells = [c for c in cells if not a.only or any(c[0].startswith(o) for o in a.only)]
    t0 = time.time()
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        results = list(ex.map(lambda c: run_cell(c, out, a.counted, a.tries), cells))
    lines = ["| scenario | guard | token | must | counted tries were | counted | cell | blocks (last check → first callback, achieved offsets) | not counted |",
             "|---|---|---|---|---|---|---|---|---|"] + [fmt_cell(c) for c in results]
    n_c = sum(c["counted"] for c in results)
    n_x = sum(c["tries"] - c["counted"] for c in results)
    passed = sum(c["passed"] for c in results)
    tag = "race-c3" if any(c["scenario"].startswith(("s3", "s4")) for c in results) else "race-c2"
    last = (f"{tag}: {len(results)} cells, {passed} passed; counted tries {n_c}, not counted {n_x}; "
            f"wall {round(time.time() - t0)} s")
    (out / "summary.json").write_text(json.dumps({"cells": results, "line": last}, indent=1))
    (out / "summary.md").write_text("\n".join(lines) + "\n\n" + last + "\n")
    print("\n".join(lines))
    print(f"results: {out}")
    print(last)
    return 0 if passed == len(results) else 1


def main_hitrate(a):
    out = (pathlib.Path(a.out) if a.out else default_out("race-hitrate")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    ensure_built()
    seq = pathlib.Path(a.seq).resolve()
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        runs = list(ex.map(lambda n: attempt(seq, a.guard, out, f"{seq.stem}--{a.guard}--{n:02d}"), range(1, a.n + 1)))
    counts = {}
    for r in runs:
        k = r.get("verdict") or "error"
        counts[k] = counts.get(k, 0) + 1
    offs = {}
    for r in runs:
        k = str(r.get("achieved_offsets"))
        offs[k] = offs.get(k, 0) + 1
    (out / "hitrate.json").write_text(json.dumps({"runs": runs, "verdicts": counts, "achieved_offsets": offs}, indent=1))
    hit = counts.get(O.OVERLAP, 0)
    print(f"achieved offsets: {offs}")
    print(f"race-hitrate: {seq.stem} on {a.guard}: {hit} of {a.n} produced the requested ordering; verdicts {dict(sorted(counts.items()))}")
    return 0


def main_timeout(a):
    """Negative control: hold, never release. Must be not-produced (HOLD-TIMEOUT), never held or broke."""
    out = (pathlib.Path(a.out) if a.out else default_out("race-timeout")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    ensure_built()
    r = attempt(SEQ / "s3-no-release.json", "guard-vulnerable", out, "s3-no-release--guard-vulnerable-slow", "broke", True)
    timeouts = 0
    p = out / "s3-no-release--guard-vulnerable-slow.result.json"
    if p.exists():
        res = json.loads(p.read_text())
        timeouts = sum(1 for st in res["steps"] for l in st.get("logs") or [] if "HOLD-TIMEOUT" in l)
    ok = r.get("verdict") == O.NOT_PRODUCED and timeouts > 0
    print(f"race-timeout: verdict {r.get('verdict') or r.get('error')}; HOLD-TIMEOUT logs {timeouts}; "
          f"{'counted as nothing (correct)' if ok else 'WRONG: a run nobody released must be not-produced'}; {r.get('secs')} s")
    return 0 if ok else 1


def main(argv):
    if argv[:1] == ["timeout"]:
        p = argparse.ArgumentParser(); p.add_argument("--out")
        return main_timeout(p.parse_args(argv[1:]))
    if argv[:1] == ["hitrate"]:
        p = argparse.ArgumentParser()
        p.add_argument("seq"); p.add_argument("guard", choices=sorted(GUARDS))
        p.add_argument("--n", type=int, default=20); p.add_argument("--jobs", type=int, default=3); p.add_argument("--out")
        return main_hitrate(p.parse_args(argv[1:]))
    p = argparse.ArgumentParser()
    p.add_argument("--out"); p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--counted", type=int, default=3); p.add_argument("--tries", type=int, default=5)
    p.add_argument("--only", nargs="*")
    return main_cells(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
