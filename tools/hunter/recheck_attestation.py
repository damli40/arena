"""Re-check a saved NEAR AI attestation report, offline. No key, no network.

    python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json

It reads the hunt record, finds the saved report next to it, checks the file's sha256 against the
one in the record, then runs the same byte-level checks the hunt ran before its first model call
(nonce echoed, report data binds the signing key and the nonce, debug mode off, the configuration
text matches the measured one, the event log replays). Intel's signature on the quote and NVIDIA's
GPU evidence need the network and are not checked here.

What it does not show: that any attack is good, that a guard result is right, or that the software
inside the sealed machine has no bugs. Exit 0 if every check passes, 1 if any fails, 2 on bad input.
"""
import hashlib, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nearai  # noqa: E402


def main(argv):
    if len(argv) != 2:
        print("usage: python3 -I tools/hunter/recheck_attestation.py <evidence/hunts/HUNT.json>",
              file=sys.stderr)
        return 2
    rec_path = pathlib.Path(argv[1])
    try:
        rec = json.loads(rec_path.read_text())
        att = rec.get("attestation")
        if not isinstance(att, dict) or not att.get("attested"):
            why = (att or {}).get("why") if isinstance(att, dict) else None
            print("recheck: this hunt record has no attestation to check"
                  + (f" ({why})" if why else " (hunts before Nov 11 ran on Muse, which has none)"),
                  file=sys.stderr)
            return 2
        report_path = rec_path.with_suffix("") / att["report_file"]
        raw = report_path.read_bytes()
        report = json.loads(raw)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"recheck: cannot read the hunt record or its report: {e}", file=sys.stderr)
        return 2
    ok = True
    digest = hashlib.sha256(raw).hexdigest()
    same = digest == att.get("report_sha256") == rec.get("attestation_sha256")
    ok &= same
    print(f"report file   {report_path}")
    print(f"sha256        {digest}  {'matches the record' if same else 'DOES NOT match the record'}")
    parts = [("gateway", report.get("gateway_attestation"))]
    parts += [(f"model {i + 1}", r) for i, r in enumerate(report.get("model_attestations") or [])]
    if len(parts) < 2:
        ok = False
        print("models        FAIL: the report has no model attestation")
    for name, part in parts:
        try:
            out = nearai.check_report_offline(part or {}, att["nonce"])
            failed = [k for k in nearai.REQUIRED if not out[k]]
        except nearai.AttestationError as e:
            failed = [str(e)]
        ok &= not failed
        print(f"{name:<13} {'pass' if not failed else 'FAIL: ' + ', '.join(failed)}")
    print(f"model         {att.get('model')} on {att.get('base')}")
    print("recheck: " + ("all checks pass" if ok else "a check failed")
          + " (Intel and NVIDIA signatures are not checked offline)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
