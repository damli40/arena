"""Turn a TLC counterexample for Guard.tla into one line per step.

Usage: python3 -I trace.py <tlc-output-file>

For each state it finds the receipts in flight (rq and post), so a step that
removes one says which receipt ran. It also prints the guard's invoice status,
the receivers' token balances and the guard's ledger. Reads TLC's text output
only; standard library only.
"""
import re
import sys


def blocks(text):
    parts = re.split(r"^State (\d+): <([^>]*)>\s*$", text, flags=re.M)
    # parts = [pre, n1, label1, body1, n2, label2, body2, ...]
    for k in range(1, len(parts) - 2, 3):
        yield int(parts[k]), parts[k + 1], parts[k + 2]


def var(body, name):
    m = re.search(r"^/\\ " + re.escape(name) + r" = (.*?)(?=^/\\ |\Z)", body, flags=re.M | re.S)
    return m.group(1) if m else ""


def receipts(s):
    """(id, method, tx, ok) for each receipt record in the text of rq or post."""
    out = []
    # each receipt record has "id |-> N" and "m |-> "x""; split on the record start "[ g |->"
    for rec in re.split(r"\[\s*g \|->", s)[1:]:
        mid = re.search(r"\bid \|-> (\d+)", rec)
        mm = re.search(r"\bm \|-> \"([^\"]+)\"", rec)
        mt = re.search(r"\btx \|-> (\d+)", rec)
        if mid and mm:
            out.append((int(mid.group(1)), mm.group(1), int(mt.group(1)) if mt else 0))
    return out


def main(path):
    text = open(path).read()
    viol = re.search(r"Invariant (\S+) is violated", text)
    prev = None
    lines = []
    for n, label, body in blocks(text):
        inflight = {r[0]: r for r in receipts(var(body, "rq")) + receipts(var(body, "post"))}
        tk = var(body, "tk")
        bal = dict(re.findall(r"(sam2?) \|-> (\d+)", tk.split("sup")[0])) if tk else {}
        gv = var(body, "g")
        st = re.search(r"st \|-> <<([^>]*)>>", gv)
        exp = re.search(r"exp \|-> (\d+)", gv)
        state = "status=%s received=%s" % (st.group(1).strip() if st else "?",
                                           ",".join(f"{k}:{v}" for k, v in sorted(bal.items())))
        if exp:
            state += " ledger=%s" % exp.group(1)
        kind = label.split()[0]
        if prev is None:
            what = "start"
        else:
            gone = [prev[i] for i in prev if i not in inflight]
            new = [inflight[i] for i in inflight if i not in prev]
            if kind in ("PayTx", "RecTx"):
                what = "%s signed (tx %d)" % ("pay" if kind == "PayTx" else "reconcile",
                                              new[0][2] if new else 0)
            elif kind == "Fault":
                what = "FORCED FAILURE of " + ", ".join(f"{m} (tx {t})" for _, m, t in gone)
            else:
                what = "ran " + ", ".join(f"{m} (tx {t})" for _, m, t in gone)
                if new:
                    what += " -> created " + ", ".join(f"{m}" for _, m, t in new)
        lines.append(f"{n:>2}. {what:<60} | {state}")
        prev = inflight
    if viol:
        lines.append(f"=> invariant {viol.group(1)} violated in the last state")
    print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1])
