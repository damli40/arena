"""Extended direct mode, the Python side (the harness side is harness/src/direct_ext.rs).

direct_check.py calls these few hooks; a config without a `direct.ext` block gets exactly the
old behaviour from every one of them.

  methods(cfg)          extra methods G0 must find in the wasm (setup calls, set-policy calls,
                        the nonce view)
  window_claim(claims)  the guard's one window claim (window_utc_day, window_rolling,
                        window_anchored or window_lifetime), or None
  gate_extra(cfg, claims)  extra gate sequences: the time-travel sequence that proves the
                        window's KIND (an ext config only)
  attack_rule(rule, claims)  attacks written for "window_utc_day" test "the total in one window
                        stays under the limit"; within one short attempt that holds for every
                        window kind, so they run against the guard's real window claim

Window kinds are validated by behaviour: each kind has a gate sequence (g8-window-<kind>) that
moves the sandbox clock with fast-forward and expects the money only that kind would allow. A
guard whose window is a different kind fails it, so a wrong label (for example a rolling 24 h
window labelled as a UTC day) leaves the window rule unvalidated and its attacks "could not finish".
"""
import json, os, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE_EXT_DIR = ROOT / "sequences-direct-gate-ext"
WINDOW_CLAIMS = ("window_utc_day", "window_rolling", "window_anchored", "window_lifetime")
# The calendar UTC day keeps its existing proof (in-window pairs plus "the attempt stayed inside one
# UTC day"); proving its midnight reset would need up to 24 h of fast-forward per run.
KIND_SEQ = {
    "window_rolling": "g8-window-rolling",
    "window_anchored": "g8-window-anchored",
    "window_lifetime": "g8-window-lifetime",
}


def ext_of(cfg):
    return (cfg.get("direct") or {}).get("ext")


def methods(cfg):
    x = ext_of(cfg) or {}
    m = [c.get("method") for c in x.get("setup", []) + x.get("set_policy_calls", [])]
    n = x.get("nonce")
    if isinstance(n, dict) and isinstance(n.get("view"), dict):
        m.append(n["view"].get("method"))
    return [y for y in m if y]


def window_claim(claims):
    w = [c for c in claims if c in WINDOW_CLAIMS]
    return w[0] if w else None


# The most sandbox clock (seconds) one window-kind proof may move. Fast-forward moves the clock by
# (min + max block-production delay) / 2 per skipped block. A sequence that moves the clock runs on
# a sandbox whose max delay is 20 s (harness direct_ext::sandbox), so a skipped block moves about
# 10 s instead of 0.31 s. Measured on 2026-11-12: 26.4 h of clock in about 95 s of wall time. The
# default, 14 days, covers every window Arena accepts (up to 7 days; a lifetime proof waits 2
# windows). Lower it with ARENA_MAX_ADVANCE_SECS if you cannot wait.
MAX_ADVANCE_SECS = int(os.environ.get("ARENA_MAX_ADVANCE_SECS", str(14 * 86400)))
# Wall-clock budget for a proof: assume no faster than 100 clock-seconds per wall-second (measured
# about 1,000 on a quiet machine).
ADVANCE_RATE_FLOOR = 100
ADVANCE_WINDOWS = {"window_rolling": 1.1, "window_anchored": 1.1, "window_lifetime": 2.0}


def window_secs(cfg):
    w = (ext_of(cfg) or {}).get("window") or {}
    return w.get("secs") or (w.get("hours") or 0) * 3600


def gate_extra(cfg, claims):
    """(sequences to run, {sequence: reason it was not run}) for an ext config's window kind."""
    if ext_of(cfg) is None:
        return [], {}
    w = window_claim(claims)
    if w not in KIND_SEQ:
        return [], {}
    need = ADVANCE_WINDOWS[w] * window_secs(cfg)
    if need > MAX_ADVANCE_SECS:
        return [], {KIND_SEQ[w]: (f"not run: proving a {window_secs(cfg)} s {w} by behaviour needs {int(need)} s of sandbox clock, "
                                  f"above the {MAX_ADVANCE_SECS} s Arena moves per proof (ARENA_MAX_ADVANCE_SECS); the window rule stays unvalidated")}
    return [KIND_SEQ[w]], {}


def timeout_for(cfg, seq_name, default):
    """Wall-clock budget for one sequence: a window-kind proof gets time for its fast-forward
    (ADVANCE_RATE_FLOOR clock-seconds per wall-second, for the clock this window's proof moves)."""
    if seq_name in KIND_SEQ.values():
        w = next((k for k, v in KIND_SEQ.items() if v == seq_name), None)
        need = ADVANCE_WINDOWS.get(w, 2.0) * window_secs(cfg)
        return int(default + need / ADVANCE_RATE_FLOOR)
    return default


def gate_seqs():
    return {p.stem: p for p in sorted(GATE_EXT_DIR.glob("*.json"))}


def attack_rule(rule, claims):
    if rule == "window_utc_day":
        return window_claim(claims) or rule
    return rule


def load(cfg_path):
    return json.loads(pathlib.Path(cfg_path).read_text())
