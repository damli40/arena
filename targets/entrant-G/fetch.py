"""Fetch Guard G's deployed code from NEAR testnet and refuse it unless it matches the frozen fingerprint.

    python3 targets/entrant-G/fetch.py            # writes targets/entrant-G/guard_g.wasm (untracked)
    python3 targets/entrant-G/fetch.py --check    # only checks an already-fetched file, no network

Why this exists: Guard G is another team's code. Arena does not redistribute it (see FROZEN.txt).
Instead, anyone re-running the Guard G check reads the code the team itself deployed, with one
read-only RPC call (`query`, `request_type: view_code`, `finality: final`). Nothing is signed or sent.

Which account: this file never names it. Give it one of two ways:
  - the environment variable ARENA_GUARD_G_ACCOUNT, or
  - one line in targets/entrant-G/account.private (gitignored; never committed).
The RPC endpoint defaults to the public testnet one; ARENA_TESTNET_RPC overrides it.

The fetched file is accepted only if its sha256 equals FINGERPRINT below. On any mismatch, or any
network error, nothing is written (an older cached file is not touched) and the exit code is
non-zero; `--check` tells whether the cached file matches. The Guard G check (direct_check.py) also pins the same hash in
guard-config.json and reports "could not finish" if the wasm is missing or different.
"""
import argparse, base64, hashlib, json, os, pathlib, sys, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
FINGERPRINT = "b0d6ee101aa477c35c3cb0235b51a1f750768ba0e6915d496328faecdf96db66"
SIZE = 277735
OUT = HERE / "guard_g.wasm"
ACCOUNT_FILE = HERE / "account.private"
DEFAULT_RPC = "https://rpc.testnet.near.org"


def account():
    a = os.environ.get("ARENA_GUARD_G_ACCOUNT", "").strip()
    if not a and ACCOUNT_FILE.exists():
        a = ACCOUNT_FILE.read_text().strip()
    if not a:
        sys.exit("fetch: no account given. Set ARENA_GUARD_G_ACCOUNT or write it to targets/entrant-G/account.private")
    if not a.endswith(".testnet"):
        sys.exit("fetch: refusing: the account must be a .testnet account (this script only reads testnet)")
    return a


def check_file(p):
    if not p.exists():
        return False, f"{p.name} not found"
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != FINGERPRINT:
        return False, f"{p.name} sha256 {h} is not the frozen {FINGERPRINT}"
    return True, f"{p.name} sha256 {h} matches the frozen fingerprint ({p.stat().st_size} bytes)"


def fetch():
    rpc = os.environ.get("ARENA_TESTNET_RPC", DEFAULT_RPC)
    body = json.dumps({"jsonrpc": "2.0", "id": "arena", "method": "query",
                       "params": {"request_type": "view_code", "finality": "final", "account_id": account()}}).encode()
    req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json", "User-Agent": "arena-fetch/1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            reply = json.loads(r.read())
    except Exception as e:  # network, TLS, JSON
        return None, f"RPC call failed: {type(e).__name__}: {e}"
    if "error" in reply or "result" not in reply or "code_base64" not in reply["result"]:
        return None, f"RPC returned no code: {str(reply.get('error', reply))[:300]}"
    return base64.b64decode(reply["result"]["code_base64"]), "fetched"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="check the cached file only; no network")
    a = ap.parse_args(argv)
    if a.check:
        ok, why = check_file(OUT)
        print(("ok: " if ok else "REFUSED: ") + why)
        return 0 if ok else 1
    code, why = fetch()
    if code is None:
        print("REFUSED: " + why + "; nothing written")
        return 1
    h = hashlib.sha256(code).hexdigest()
    if h != FINGERPRINT:
        print(f"REFUSED: deployed code sha256 {h} ({len(code)} bytes) is not the frozen {FINGERPRINT} ({SIZE} bytes). "
              "The team may have redeployed; Arena's Guard G result applies only to the frozen code. Nothing written.")
        return 1
    tmp = OUT.with_suffix(".wasm.tmp")
    tmp.write_bytes(code)
    tmp.replace(OUT)
    print(f"ok: wrote {OUT.relative_to(HERE.parents[1])}, sha256 {h} matches the frozen fingerprint ({len(code)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
