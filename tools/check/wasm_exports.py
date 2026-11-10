"""Read the list of functions a NEAR contract exports, straight from its .wasm bytes.

A wasm file carries a table of the functions outside callers may call (its "export section").
On NEAR those are exactly the contract's callable methods. We read that table and nothing else:
no wasm code is run. The file is untrusted, so every length is bounds-checked.
"""
import re

MAX_WASM_BYTES = 8 * 1024 * 1024
MAX_EXPORTS = 2000
NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")


class WasmError(ValueError):
    pass


def _leb(b, i):
    """Unsigned LEB128 at b[i] -> (value, next index)."""
    out, shift = 0, 0
    while True:
        if i >= len(b):
            raise WasmError("truncated number")
        x = b[i]
        i += 1
        out |= (x & 0x7F) << shift
        if not x & 0x80:
            return out, i
        shift += 7
        if shift > 35:
            raise WasmError("number too long")


def exports(data):
    """Function export names, in file order. Raises WasmError on anything that is not a wasm file."""
    if len(data) > MAX_WASM_BYTES:
        raise WasmError(f"file is {len(data)} bytes; the limit is {MAX_WASM_BYTES}")
    if data[:4] != b"\0asm":
        raise WasmError("not a wasm file (it does not start with the wasm magic bytes \\0asm)")
    if data[4:8] != b"\x01\0\0\0":
        raise WasmError("unsupported wasm version")
    i, names = 8, []
    while i < len(data):
        sid = data[i]
        size, i = _leb(data, i + 1)
        end = i + size
        if end > len(data):
            raise WasmError("section runs past the end of the file")
        if sid == 7:
            n, j = _leb(data, i)
            if n > MAX_EXPORTS:
                raise WasmError(f"{n} exports; the limit is {MAX_EXPORTS}")
            for _ in range(n):
                ln, j = _leb(data, j)
                if j + ln > end:
                    raise WasmError("export name runs past its section")
                name = data[j:j + ln].decode("utf-8", errors="replace")
                j += ln
                kind = data[j]
                _, j = _leb(data, j + 1)
                if kind == 0:
                    names.append(name)
        i = end
    return names


def methods(data):
    """Exported functions that look like NEAR methods (lowercase names; drops wasm internals
    such as `memory` or names a caller could not type)."""
    return [n for n in exports(data) if NAME_RE.match(n)]


if __name__ == "__main__":
    import sys
    print("\n".join(methods(open(sys.argv[1], "rb").read())))
