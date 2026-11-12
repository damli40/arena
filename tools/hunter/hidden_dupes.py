"""The hunter's duplicate check against the hidden test set, by steps hash only.

A hunt drops a proposed attack whose steps are the same as an attack already in the public library
(catalog.index_by_hash). This module adds the same check against the hidden set, which is NOT in the
repo: the operator passes the private set folder (`hunt.py --hidden-set <dir>` or ARENA_HIDDEN_SET).

    load(dir) -> {"set_sha256", "hashes"}   refuses unless the folder's set hash equals the committed
                                           one in hidden-set/COMMITMENT.json (so the check runs
                                           against the set the public results name, not another)
    match(state, steps_sha256) -> bool

What goes into the public hunt record: only that a proposal matched "a hidden-set attack" and the set
hash. Never which hidden attack, its family, its file name or its spec. The proposal's own steps are
public anyway (the model's raw reply is saved with the hunt), so a match means that hidden attack's
steps are now public: it is listed for retirement (`retire`) and must be replaced at the next set.
Without a private folder the check does not run, and the record says so; it never claims "no match".
"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMMITMENT = ROOT / "hidden-set" / "COMMITMENT.json"


def _hidden():
    sys.path.insert(0, str(ROOT / "tools" / "hidden"))
    import hidden  # noqa: E402
    return hidden


def not_run(why):
    return {"ran": False, "why": why, "set_sha256": None, "hashes": frozenset(), "matches": 0}


def load(d):
    """Private set folder -> state. Raises ValueError when the folder is not the committed set."""
    if not COMMITMENT.exists():
        raise ValueError("no hidden-set/COMMITMENT.json in this repo: nothing to check against")
    d = pathlib.Path(d).resolve()
    if d.is_relative_to(ROOT):
        raise ValueError("the hidden set must live outside the repo")
    H = _hidden()
    docs = H.load_set(d)
    if not docs:
        raise ValueError(f"{d}: no attack files")
    got = H.set_sha256(docs)
    want = json.loads(COMMITMENT.read_text())["set_sha256"]
    if got != want:
        raise ValueError(f"the private folder's set hash {got[:16]}... is not the committed {want[:16]}...")
    return {"ran": True, "why": "", "set_sha256": want, "hashes": frozenset(doc["meta"]["steps_sha256"] for _, doc in docs), "matches": 0}


def match(state, steps_sha256):
    hit = state["ran"] and steps_sha256 in state["hashes"]
    if hit:
        state["matches"] += 1
    return hit


def record(state):
    """The public part of the state (no hashes)."""
    out = {"ran": state["ran"], "set_sha256": state["set_sha256"], "matches": state["matches"]}
    if not state["ran"]:
        out["why"] = state["why"]
    if state["matches"]:
        out["retire"] = (f"{state['matches']} proposal(s) had the same steps as a hidden-set attack; those hidden "
                         "attacks' steps are now public (this hunt's raw model replies) and are replaced at the next set")
    return out
