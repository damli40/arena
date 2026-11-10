#!/usr/bin/env python3
"""Publish Arena scores to the arena-receipts contract on NEAR testnet.

Every number is parsed from an existing evidence file; nothing is typed by hand.
evidence_sha256 is computed from that file; harness_commit comes from `git rev-parse HEAD`.

    python3 -I tools/receipts/publish.py --dry-run             # print the receipts, send nothing
    python3 -I tools/receipts/publish.py --contract <id>        # publish (signed by <id>'s key in ~/.near-credentials/testnet)
    python3 -I tools/receipts/publish.py --contract <id> --check   # only run the live `passes` calls

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


def race(commit: str):
    p = EV / "testnet-2026-11-09.md"
    t = p.read_text()
    code_hash = re.search(r"guard\.wasm sha256 `([0-9a-f]{64})`", t).group(1)
    limit = int(re.search(r"may pay at most its amount \((\d+) test tokens\)", t).group(1))
    for raw in ("testnet-2026-11-09-run8-raw.json", "testnet-2026-11-09-run9-raw.json"):
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


def all_receipts():
    commit = harness_commit()
    va = vault_a_hash()
    return race(commit) + [injection_broad(commit, va), injection_narrow(commit, va)] + coverage(commit)


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
    return [
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
    a = ap.parse_args()
    rs = all_receipts()
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
