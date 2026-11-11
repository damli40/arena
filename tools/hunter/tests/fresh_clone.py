"""Let the offline hunt tests run on a fresh clone, before anything is built.

The hunt tests run `hunt.main(... "--no-run" ...)`: no sandbox, no attack is run. But hunt.main
still fingerprints every guard in guards/registry.json, and two of them (guard-fixed,
guard-vulnerable) point at contracts/target/.../guard.wasm, which exists only after a build
(`./verify.sh fast` builds it, or `cd contracts && cargo build --release --target
wasm32-unknown-unknown -p guard`). A missing wasm marks the hunt untrusted (exit 1), so on a fresh
clone 11 tests failed for a reason unrelated to what they test.

This stub changes one case only: a guard whose wasm file is MISSING is reported as fingerprint ok,
with a "test stub" note. A wasm that exists is still checked for real, so a changed or wrong
wasm still fails these tests. Nothing outside these tests uses it.
"""
from unittest import mock

import registry

_real = registry.fingerprint


def _fingerprint(g):
    fp = _real(g)
    if fp["wasm_sha256"] is None and not fp["ok"] and fp["why"].startswith(f"{g['wasm']} missing"):
        return {"wasm_sha256": None, "ok": True, "why": f"test stub: {g['wasm']} not built (fresh clone)"}
    return fp


_patch = mock.patch.object(registry, "fingerprint", _fingerprint)


def start():
    _patch.start()


def stop():
    _patch.stop()
