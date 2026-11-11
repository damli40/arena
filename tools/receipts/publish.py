#!/usr/bin/env python3
"""Publish Arena scores to the arena-receipts contract on NEAR testnet.

Every number is parsed from an existing evidence file; nothing is typed by hand.
evidence_sha256 is computed from that file; harness_commit comes from `git rev-parse HEAD`.

    python3 -I tools/receipts/publish.py --dry-run             # print the receipts, send nothing
    python3 -I tools/receipts/publish.py --contract <id>        # publish (signed by <id>'s key in ~/.near-credentials/testnet)
    python3 -I tools/receipts/publish.py --contract <id> --check   # only run the live `passes` calls
    python3 -I tools/receipts/publish.py --results --dry-run       # the same scores as code-hash-bound results
    python3 -I tools/receipts/publish.py --results --contract <id> # publish them with publish_result (clean tree only)

Results (added 2026-11-11) are what other contracts read with `arena_result(code_hash, suite, commit)`.
Each names the exact Arena commit (a dirty tree is refused, by this script and by the contract) and
may carry `attestation_sha256`: the sha256 of a hardware attestation report for the run. Nothing
fills that field yet; pass --attestations FILE ({"<evidence_path>": "<sha256>"}) once a hunt saves one.

The chain calls go through receipts/host (receipts-cli, near-workspaces 0.24), the same tooling as the
Nov 9 testnet race. Testnet only.
"""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "evidence"
CLI = ROOT / "receipts/host/target/release/receipts-cli"
DAY_NS = str(86_400 * 10**9)
HEX64 = re.compile(r"[0-9a-f]{64}")


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def harness_commit() -> str:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    return head + ("-dirty" if dirty else "")


def table_rows(text: str):
    """Yield the cells of every markdown table row (skipping header separators)."""
    for line in text.splitlines():
        if line.startswith("|") and not re.match(r"^\|[\s\-|]+\|$", line):
            yield [c.strip() for c in line.strip().strip("|").split("|")]


def section(text: str, heading_prefix: str) -> str:
    """The text from the heading that starts with `heading_prefix` up to the next heading of that level."""
    level = heading_prefix.split(" ")[0]
    m = re.search(r"^" + re.escape(heading_prefix) + r".*$", text, re.M)
    if not m:
        sys.exit(f"heading not found: {heading_prefix}")
    rest = text[m.end():]
    nxt = re.search(r"^" + re.escape(level) + r" ", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def receipt(path: Path, commit: str, **f) -> dict:
    assert HEX64.fullmatch(f["guard_code_hash"]), f
    return {**f, "beyond_policy": str(f["beyond_policy"]),
            "against_intent": None if f["against_intent"] is None else str(f["against_intent"]),
            "harness_commit": commit, "evidence_sha256": sha256(path), "evidence_path": str(path.relative_to(ROOT))}


# The testnet race evidence to publish. Defaults = the Nov 9 run (guard fcce82bf...). After a new testnet
# race (e.g. with the Nov 11 guard, 0382023b...), pass --race-md and --race-raw for that run's files.
RACE_MD = "testnet-2026-11-09.md"
RACE_RAW = ["testnet-2026-11-09-run8-raw.json", "testnet-2026-11-09-run9-raw.json"]


def race(commit: str, md: str = RACE_MD, raws=None):
    p = EV / md
    t = p.read_text()
    code_hash = re.search(r"guard\.wasm sha256 `([0-9a-f]{64})`", t).group(1)
    limit = int(re.search(r"may pay at most its amount \((\d+) test tokens\)", t).group(1))
    for raw in (raws or RACE_RAW):
        h = json.loads((EV / raw).read_text())["header"]["guard_wasm_sha256"]
        assert h == code_hash, f"{raw} ran {h}, md says {code_hash}"
    # Count only trials where both pays reached the chain and overlapped (rows 1-10 of the full table).
    trials = {}
    for c in table_rows(t):
        if len(c) == 13 and c[0].isdigit() and c[8] == "2" and c[9] == "True":
            trials.setdefault(c[2], []).append((int(c[10]), c[12].strip("*").lower()))
    out = []
    for mode, label in (("vulnerable_fixture", "planted-flaw"), ("fixed", "fixed")):
        rows = trials[mode]
        out.append(receipt(p, commit, guard_code_hash=code_hash, guard_label=f"{label} (mode={mode})",
                           suite=f"race-double-pay:mode={mode}",
                           beyond_policy=max(max(got - limit, 0) for got, _ in rows),  # worst single trial
                           against_intent=None, tests_run=len(rows),
                           tests_held=sum(1 for _, held in rows if held == "yes")))
    return out


def vault_a_hash() -> str:
    h = re.search(r"sha256 vault_a\.wasm\s+([0-9a-f]{64})", (ROOT / "targets/vault-a/FROZEN.txt").read_text()).group(1)
    for run in ("injection-2026-11-09-compromised", "injection-2026-11-10-compromised-narrow"):
        for f in sorted((EV / run).glob("seq-*.result.json")):
            ran = json.loads(f.read_text())["target_wasm_sha256"]
            assert ran == h, f"{f} ran {ran}, FROZEN says {h}"
    return h


def injection_broad(commit: str, code_hash: str):
    p = EV / "injection-intent-by-recipient.md"
    sec = section(p.read_text(), "## Scripted fooled agent")
    rows = [c for c in table_rows(sec) if len(c) == 4 and c[0] != "Trial"]
    wrong = sum(int(n) for c in rows for n in re.findall(r":\s*(\d+)", c[1]))
    beyond = [int(c[3]) for c in rows]
    return receipt(p, commit, guard_code_hash=code_hash, guard_label="vault-a", suite="injection-scripted",
                   beyond_policy=sum(beyond), against_intent=wrong, tests_run=len(rows),
                   tests_held=sum(1 for b in beyond if b == 0))


def injection_narrow(commit: str, code_hash: str):
    p = EV / "injection-narrow-policy.md"
    rows = [c for c in table_rows(p.read_text()) if len(c) == 9 and c[1] == "narrow"]
    per = [c for c in rows if not c[0].startswith("**")]
    total = [c for c in rows if c[0] == "**total**"]
    assert len(total) == 1, total
    against, beyond = int(total[0][5].strip("*")), int(total[0][7].strip("*"))
    assert against == sum(int(c[5]) for c in per) and beyond == sum(int(c[7]) for c in per), "total row disagrees with its rows"
    return receipt(p, commit, guard_code_hash=code_hash, guard_label="vault-a", suite="injection-scripted-narrow",
                   beyond_policy=beyond, against_intent=against, tests_run=len(per),
                   tests_held=sum(1 for c in per if c[7] == "0"))


def coverage(commit: str):
    p = EV / "coverage-table.md"
    t = p.read_text()
    out = []
    for letter in "ABC":
        sec = section(t, f"## Guard {letter} ")
        code_hash = HEX64.search(sec.split("**wasm sha256:**", 1)[1]).group(0)
        frozen = (ROOT / f"targets/entrant-{letter}/FROZEN.txt").read_text()
        assert code_hash in frozen, f"Guard {letter}: {code_hash} not in FROZEN.txt"
        m = re.search(r"\*\*Verdict: (\d+) overpaid, (\d+) of (\d+) held\.\*\*", sec)
        overpaid, held, run = map(int, m.groups())
        out.append(receipt(p, commit, guard_code_hash=code_hash, guard_label=f"Guard {letter}", suite="claims-coverage",
                           beyond_policy=overpaid, against_intent=None, tests_run=run, tests_held=held))
    return out


def proof(commit: str):
    """2026-11-11, opt-in (--with-proof). One receipt for proofs/run.sh on the Nov 11 guard source.
    Scoped name on purpose: it covers the pay/callback race and the bounded full world, plus the
    inductive step ON THE MODEL; it is not a claim that no invoice can ever be paid twice."""
    p = EV / "proofs-inductive-2026-11-11.md"
    t = p.read_text()
    code_hash = re.search(r"guard\.wasm sha256 `([0-9a-f]{64})`", t).group(1)
    con = (EV / "proofs-2026-11-11/console.log").read_text()
    m = re.search(r"^proofs: (\d+) passed, (\d+) failed", con, re.M)
    held, failed = int(m.group(1)), int(m.group(2))
    return [receipt(p, commit, guard_code_hash=code_hash, guard_label="fixed (mode=fixed), proofs on source + model",
                    suite="proof-pay-race-inductive", beyond_policy=0 if failed == 0 else 1,
                    against_intent=None, tests_run=held + failed, tests_held=held)]


# What a result's setup condition is, per suite. A result applies only to a guard set up this way.
# "mode=<m>" is readable on chain (get_mode); the others name a setting no contract can read.
def suite_setup(suite: str):
    if suite.startswith("race-double-pay:mode="):
        return "mode=" + suite.split("=", 1)[1]
    return {"proof-pay-race-inductive": "mode=fixed",
            "injection-scripted": "spending policy set by the vault owner (not readable on chain)",
            "injection-scripted-narrow": "spending policy set by the vault owner (not readable on chain)",
            "claims-coverage": "setup arguments the guard was started with (not readable on chain)"}.get(suite, "unknown setup (not readable on chain)")


SUITE_VERSION = "1"  # bump when a suite's attacks change, so old results stay distinguishable


def to_result(r: dict, attestation_sha256=None) -> dict:
    """One receipt -> one result for publish_result. held = every test held and nothing was lost."""
    beyond, against = int(r["beyond_policy"]), None if r["against_intent"] is None else int(r["against_intent"])
    lost = beyond > 0 or (against or 0) > 0
    if lost:
        status = "broke"
    elif r["tests_run"] > 0 and r["tests_held"] == r["tests_run"]:
        status = "held"
    else:
        status = "incomplete"
    if attestation_sha256 is not None:
        assert HEX64.fullmatch(attestation_sha256), f"attestation_sha256 must be 64 lowercase hex: {attestation_sha256!r}"
    return {"guard_code_hash": r["guard_code_hash"], "suite": r["suite"], "suite_version": SUITE_VERSION, "status": status,
            "attacks_ran": r["tests_run"], "not_applicable": 0, "beyond_policy": r["beyond_policy"],
            "against_intent": r["against_intent"], "setup": suite_setup(r["suite"]), "arena_commit": r["harness_commit"],
            "evidence_sha256": r["evidence_sha256"], "evidence_path": r["evidence_path"],
            "attestation_sha256": attestation_sha256}


def all_results(rs, attestations=None):
    """Results only for Arena's own guards. Guards A, B and C are other teams' guards that never
    opted in: their receipts stay as a record, but they get no result a contract can query, so they
    are never on the board (a result is what a wallet contract reads before it pays)."""
    att = attestations or {}
    rs = [r for r in rs if r["suite"] != "claims-coverage"]
    unknown = set(att) - {r["evidence_path"] for r in rs}
    assert not unknown, f"--attestations names evidence files with no result: {sorted(unknown)}"
    return [to_result(r, att.get(r["evidence_path"])) for r in rs]


def all_receipts(race_md: str = RACE_MD, race_raw=None, with_proof: bool = False):
    commit = harness_commit()
    va = vault_a_hash()
    rs = race(commit, race_md, race_raw) + [injection_broad(commit, va), injection_narrow(commit, va)] + coverage(commit)
    return rs + (proof(commit) if with_proof else [])


def cli(*args) -> list:
    out = subprocess.run([str(CLI), *args], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"receipts-cli failed: {out.stderr.strip()[-2000:]}")
    return [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]


def checks(rs):
    by = {(r["guard_label"], r["suite"]): r["guard_code_hash"] for r in rs}
    pf = by[("planted-flaw (mode=vulnerable_fixture)", "race-double-pay:mode=vulnerable_fixture")]
    va = by[("vault-a", "injection-scripted")]
    ga = by[("Guard A", "claims-coverage")]
    # (name, hash, suite, max_beyond_policy, max_against_intent, expected)
    pr = [("proof, pay race (fixed)", r["guard_code_hash"], r["suite"], "0", None, True)
          for r in rs if r["suite"] == "proof-pay-race-inductive"]
    return pr + [
        ("planted flaw", pf, "race-double-pay:mode=vulnerable_fixture", "0", None, False),
        ("fixed", pf, "race-double-pay:mode=fixed", "0", None, True),
        ("vault-a injection broad", va, "injection-scripted", "0", "0", False),
        ("vault-a injection narrow", va, "injection-scripted-narrow", "0", "0", True),
        ("Guard A", ga, "claims-coverage", "0", None, True),
        ("Guard A, intent limit set", ga, "claims-coverage", "0", "0", False),
        ("unknown hash", "0" * 64, "claims-coverage", str(10**30), None, False),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print the receipts, send nothing")
    ap.add_argument("--contract", help="arena-receipts contract account id on testnet")
    ap.add_argument("--check", action="store_true", help="skip publishing; only run the live passes calls")
    ap.add_argument("--race-md", default=RACE_MD, help="testnet race evidence file in evidence/ (default: the Nov 9 run)")
    ap.add_argument("--race-raw", nargs="+", default=None, help="that run's raw JSON files in evidence/")
    ap.add_argument("--with-proof", action="store_true", help="also publish the proof-pay-race-inductive receipt (Nov 11 guard)")
    ap.add_argument("--results", action="store_true", help="publish code-hash-bound results (publish_result) instead of receipts")
    ap.add_argument("--attestations", help='JSON file {"<evidence_path>": "<attestation sha256>"} (optional; nothing writes it yet)')
    a = ap.parse_args()
    rs = all_receipts(a.race_md, a.race_raw, a.with_proof)
    if a.results:
        att = json.loads(Path(a.attestations).read_text()) if a.attestations else None
        res = all_results(rs, att)
        if a.dry_run or not a.contract:
            print(json.dumps(res, indent=2))
            if not a.dry_run:
                print("(no --contract given: nothing sent)", file=sys.stderr)
            return
        if res[0]["arena_commit"].endswith("-dirty"):
            sys.exit("refusing to publish results from a dirty tree: a result must name the exact commit. Commit, or publish from a clean worktree.")
        tmp = ROOT / "receipts/host/target/results-to-publish.json"
        tmp.write_text(json.dumps(res))
        bad = 0
        for line in cli("publish-results", a.contract, str(tmp)):
            print(json.dumps(line))
            bad += not line["ok"]
        sys.exit(1 if bad else 0)
    if a.dry_run or not a.contract:
        print(json.dumps(rs, indent=2))
        if not a.dry_run:
            print("(no --contract given: nothing sent)", file=sys.stderr)
        return
    if not a.check:
        tmp = ROOT / "receipts/host/target/receipts-to-publish.json"
        tmp.write_text(json.dumps(rs))
        for line in cli("publish", a.contract, str(tmp)):
            print(json.dumps(line))
            if not line["ok"]:
                sys.exit("publish failed")
    bad = 0
    for name, h, suite, mb, mi, want in checks(rs):
        args = {"guard_code_hash": h, "suite": suite, "max_beyond_policy": mb, "max_against_intent": mi, "max_age_ns": DAY_NS}
        got = cli("view", a.contract, "passes", json.dumps(args))[0]["result"]
        bad += got != want
        print(json.dumps({"check": name, "args": args, "passes": got, "expected": want, "match": got == want}))
    print(f"checks: {len(checks(rs)) - bad} matched the plan, {bad} did not")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
