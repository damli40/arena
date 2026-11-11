"""NEAR AI Cloud private inference for the attacker: fetch the hardware attestation report before the
first model call, check what can be checked here, and check the signature NEAR returns for every reply.

Plain version. NEAR AI Cloud runs some open models inside sealed hardware (Intel TDX confidential
VMs with NVIDIA confidential-computing GPUs). Before the hunt sends anything, we ask NEAR for a report
that the sealed machine signs, with a random number (a "nonce") we just made. After each reply, we ask
NEAR for that reply's signature and check that the key which signed it is the key named in the report.

What each check means (from NEAR's docs: docs.near.ai/cloud/verification/...):
- nonce echoed back, and the quote's report_data = signing address (zero-padded to 32 bytes) + our
  nonce: the report was made for this request, now, and names this signing key. Checked here by
  reading the quote bytes, always.
- MRCONFIGID = 01 + sha256(app_compose) + 15 zero bytes, and the RTMR3 event log replays to the
  quote's RTMR3: the configuration text in the report is the one the machine measured. Always.
- Intel's signature chain on the quote (dcap-qvl): the quote really comes from Intel TDX hardware with
  this TCB status. Only when the `dcap_qvl` package is installed; otherwise the record says
  "quote not verified here". Without it, the bindings above are checked on bytes nobody vouched for.
- NVIDIA GPU evidence: sent to NVIDIA's NRAS service, which answers true/false. Optional, network.
- Reply signature (`provider_tee`): text = "<model>:<sha256 request bytes>:<sha256 response bytes>",
  EIP-191 signer recovered here (pure Python, no library) must equal exactly one model report's
  signing address. NEAR's docs: instances of one model share one key, so this does not prove the
  report and the reply came from the same server instance.

What none of this proves: that an attack is good, that a guard result is right, or that the software
inside the sealed machine has no bugs. Scoring stays plain code on a local sandbox.

The key comes from NEARAI_API_KEY (CI) or ~/.config/arena/nearai.env. It is never printed or saved.
"""
import hashlib, json, os, pathlib, struct, time, urllib.error, urllib.parse, urllib.request

DEFAULT_BASE = "https://cloud-api.near.ai/v1"
SIGNING_ALGO = "ecdsa"
ATTESTED_OWNER = "nearai"          # /v1/models owned_by for NEAR's own private TEE models
ACCEPTED_TCB = {"UpToDate"}         # Intel TCB statuses we call "verified"; others are recorded as warnings
NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
HTTP_TIMEOUT_S = 90
SIG_TRIES = 3


class AttestationError(RuntimeError):
    """The report is missing, malformed, or fails a binding check: refuse the hunt."""


class Unattested(AttestationError):
    """The model has no NEAR model attestation (not a private TEE model)."""


def load_key():
    k = os.environ.get("NEARAI_API_KEY", "").strip()
    if k:
        return k
    f = pathlib.Path.home() / ".config/arena/nearai.env"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.startswith("NEARAI_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


# ---- Keccak-256 (Ethereum's hash; not hashlib.sha3_256, which pads differently) ----

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _keccak_f(A):
    for rc in _RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                B[y][(2 * x + 3 * y) % 5] = ((A[x][y] << r) | (A[x][y] >> (64 - r))) & _M if r else A[x][y]
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 2) % rate) + b"\x80"
    if len(msg) % rate:  # the 0x01 and 0x80 landed in the same byte
        raise AssertionError("keccak padding")
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        A = _keccak_f(A)
    out = b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# ---- secp256k1 public-key recovery (enough to recover an Ethereum signer) ----

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def address_of_private_key(d: int) -> str:
    """Only used by the tests (sign/recover round trip with a known key)."""
    x, y = _mul(d, _G)
    return "0x" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()


def eip191_hash(text: str) -> bytes:
    m = text.encode("utf-8")
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(m)).encode() + m)


def sign_eip191(text: str, d: int, k: int) -> str:
    """Test helper: a plain ECDSA signature with a caller-chosen k (never for real keys)."""
    z = int.from_bytes(eip191_hash(text), "big")
    R = _mul(k, _G)
    r = R[0] % _N
    s = pow(k, -1, _N) * (z + r * d) % _N
    v = R[1] & 1
    if s > _N // 2:
        s, v = _N - s, v ^ 1
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + v]).hex()


def recover_eip191(text: str, signature_hex: str) -> str:
    """Ethereum personal_sign recovery: returns the 0x address (lower case) that signed `text`."""
    sig = bytes.fromhex(signature_hex.removeprefix("0x"))
    if len(sig) != 65:
        raise ValueError("signature must be 65 bytes")
    r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    v = v - 27 if v >= 27 else v
    if v not in (0, 1) or not (0 < r < _N and 0 < s < _N):
        raise ValueError("bad signature values")
    x = r
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        raise ValueError("r is not on the curve")
    if y & 1 != v:
        y = _P - y
    z = int.from_bytes(eip191_hash(text), "big")
    rinv = pow(r, -1, _N)
    Q = _add(_mul(s * rinv % _N, (x, y)), _mul((-z * rinv) % _N, _G))
    if Q is None:
        raise ValueError("recovery failed")
    return "0x" + keccak256(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))[-20:].hex()


# ---- Intel TDX quote: read fields WITHOUT verifying Intel's signature (that is dcap-qvl's job) ----

def parse_td_quote(quote_hex: str) -> dict:
    """Quote v4, TDX: 48-byte header, then the 584-byte TD report body. Offsets from Intel's TDX DCAP
    quote layout; the tests check them against dcap-qvl's own parse of a real NEAR quote."""
    q = bytes.fromhex(quote_hex)
    if len(q) < 48 + 584:
        raise AttestationError("quote too short")
    version, tee_type = struct.unpack_from("<H", q, 0)[0], struct.unpack_from("<I", q, 4)[0]
    if version != 4 or tee_type != 0x81:
        raise AttestationError(f"not a TDX v4 quote (version {version}, tee_type {tee_type:#x})")
    b = 48
    return {"td_attributes": q[b + 120:b + 128], "mr_td": q[b + 136:b + 184], "mr_config_id": q[b + 184:b + 232],
            "rt_mr3": q[b + 472:b + 520], "report_data": q[b + 520:b + 584]}


def _json(v):
    return json.loads(v) if isinstance(v, str) else v


def replay_rtmr3(event_log) -> bytes:
    """NEAR's replay rule: SHA-384(event_type LE32 || ':' || event || ':' || payload), extended from zeros."""
    rt = bytes(48)
    for e in _json(event_log):
        if e.get("imr") != 3:
            continue
        d = hashlib.sha384(struct.pack("<I", e["event_type"]) + b":" + e["event"].encode("utf-8") + b":"
                           + bytes.fromhex(e.get("event_payload") or "")).digest()
        if e.get("digest") and bytes.fromhex(e["digest"]) != d:
            raise AttestationError(f"event log digest mismatch for {e.get('event')!r}")
        rt = hashlib.sha384(rt + d).digest()
    return rt


def _identity(report):
    algo = report.get("signing_algo")
    ident = bytes.fromhex(str(report.get("signing_address", "")).removeprefix("0x"))
    if {"ecdsa": 20, "ed25519": 32}.get(algo) != len(ident):
        raise AttestationError(f"unsupported signing identity ({algo}, {len(ident)} bytes)")
    return ident


def check_report_offline(report: dict, nonce_hex: str) -> dict:
    """The checks NEAR's docs list, run on the quote bytes as given (Intel's signature not checked here).
    Returns a dict of booleans; raises AttestationError on a malformed report."""
    for k in ("intel_quote", "signing_address", "signing_algo", "request_nonce", "event_log", "info"):
        if k not in report:
            raise AttestationError(f"report has no {k}")
    q = parse_td_quote(report["intel_quote"])
    ident = _identity(report)
    if report.get("tls_cert_fingerprint"):
        bound = hashlib.sha256(ident + bytes.fromhex(report["tls_cert_fingerprint"])).digest()
    else:
        bound = ident.ljust(32, b"\0")
    out = {"nonce_echoed": str(report["request_nonce"]).lower() == nonce_hex.lower(),
           "report_data_binds_signer_and_nonce": q["report_data"] == bound + bytes.fromhex(nonce_hex),
           "debug_mode_off": not (q["td_attributes"][0] & 1)}
    if report.get("report_data"):
        out["report_data_field_matches_quote"] = str(report["report_data"]).lower() == q["report_data"].hex()
    tcb = _json(report["info"].get("tcb_info")) if isinstance(report["info"], dict) else _json(_json(report["info"]).get("tcb_info"))
    ac = (tcb or {}).get("app_compose")
    out["mrconfigid_matches_app_compose"] = (isinstance(ac, str) and
                                             q["mr_config_id"] == b"\x01" + hashlib.sha256(ac.encode("utf-8")).digest() + bytes(15))
    try:
        out["rtmr3_replays"] = replay_rtmr3(report["event_log"]) == q["rt_mr3"]
    except (AttestationError, KeyError, ValueError, TypeError):
        out["rtmr3_replays"] = False
    out["mr_td"] = q["mr_td"].hex()
    out["compose_sha256"] = hashlib.sha256(ac.encode("utf-8")).hexdigest() if isinstance(ac, str) else None
    return out


REQUIRED = ("nonce_echoed", "report_data_binds_signer_and_nonce", "debug_mode_off",
            "mrconfigid_matches_app_compose", "rtmr3_replays")


def verify_quote_dcap(report: dict) -> dict:
    """Intel's signature chain on the quote, via dcap-qvl (named by NEAR's docs). Collateral comes from
    Phala's PCCS by default (network). Returns {"ran": False, "why": ...} when the package is absent."""
    try:
        import asyncio
        import dcap_qvl  # optional dependency
    except ImportError:
        return {"ran": False, "why": "dcap-qvl not installed: quote not verified here"}
    try:
        v = asyncio.run(dcap_qvl.get_collateral_and_verify(bytes.fromhex(report["intel_quote"])))
        q = json.loads(v.to_json())["report"]["TD10"]
    except Exception as e:  # noqa: BLE001  any failure = not verified, with the reason
        return {"ran": True, "ok": False, "why": f"{type(e).__name__}: {str(e)[:200]}"}
    ver = getattr(dcap_qvl, "__version__", None)
    return {"ran": True, "ok": True, "tool": "dcap-qvl" + (f" {ver}" if ver else ""), "tcb_status": v.status,
            "advisory_ids": list(v.advisory_ids), "tcb_accepted": v.status in ACCEPTED_TCB,
            "report_data_matches_parse": q.get("report_data", "").lower() == parse_td_quote(report["intel_quote"])["report_data"].hex()}


def verify_gpu_nras(report: dict, nonce_hex: str, opener=None) -> dict:
    """NEAR's minimal GPU flow: nonce in the payload must be ours; NVIDIA NRAS answers true/false.
    The verdict is trusted over TLS; the JWT signature is not checked locally."""
    p = report.get("nvidia_payload")
    if not p:
        return {"ran": False, "why": "no GPU evidence in this report"}
    try:
        payload = _json(p)
        if str(payload.get("nonce", "")).lower() != nonce_hex.lower():
            return {"ran": True, "ok": False, "why": "GPU payload nonce is not ours"}
        req = urllib.request.Request(NRAS_URL, json.dumps(payload).encode(), {"Content-Type": "application/json", "Accept": "application/json"})
        with (opener or urllib.request.urlopen)(req, timeout=HTTP_TIMEOUT_S) as r:
            out = json.loads(r.read(4 * 1024 * 1024))
        tok = out[0][1]
        import base64
        body = tok.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        res = claims.get("x-nvidia-overall-att-result")
        return {"ran": True, "ok": res is True, "overall_result": res, "eat_nonce_matches": str(claims.get("eat_nonce", "")).lower() == nonce_hex.lower()}
    except Exception as e:  # noqa: BLE001
        return {"ran": True, "ok": False, "why": f"{type(e).__name__}: {str(e)[:200]}"}


# ---- HTTP ----

def _get(url, key=None, headers=None, opener=None):
    h = {"Accept": "application/json", "Accept-Encoding": "identity", **(headers or {})}
    if key:
        h["Authorization"] = "Bearer " + key
    with (opener or urllib.request.urlopen)(urllib.request.Request(url, headers=h), timeout=HTTP_TIMEOUT_S) as r:
        return r.read(8 * 1024 * 1024)


def model_listing(base, model, opener=None):
    """Returns (entry or None, prices {'in','out'} per 1M tokens or None)."""
    raw = _get(base + "/models", opener=opener)
    data = json.loads(raw)
    for m in data.get("data", data) if isinstance(data, dict) else data:
        if isinstance(m, dict) and m.get("id") == model:
            pr = m.get("pricing") or {}
            prices = {"in": float(pr["input"]), "out": float(pr["output"])} if "input" in pr and "output" in pr else None
            return m, prices
    return None, None


def preflight(base, model, out_dir, nonce_hex, allow_unattested=False, opener=None, gpu=True, dcap=True):
    """Run once, before any chat call. Saves the exact report bytes to out_dir/attestation-report.json and
    returns the record for the hunt JSON. Raises Unattested / AttestationError to refuse the hunt."""
    out_dir = pathlib.Path(out_dir)
    rec = {"provider": "nearai", "base": base, "model": model, "signing_algo": SIGNING_ALGO, "nonce": nonce_hex,
           "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "attested": False}
    try:
        entry, prices = model_listing(base, model, opener)
    except (OSError, ValueError) as e:
        raise AttestationError(f"model list unreachable: {type(e).__name__}")
    rec["owned_by"] = entry.get("owned_by") if entry else None
    rec["prices_per_million_usd"] = prices
    problems = []
    if entry is None:
        problems.append(f"{model} is not in {base}/models")
    elif entry.get("owned_by") != ATTESTED_OWNER:
        problems.append(f"{model} is owned_by {entry.get('owned_by')!r}, not {ATTESTED_OWNER!r} (not one of NEAR's private TEE models)")
    q = urllib.parse.urlencode({"model": model, "provider": "near", "include_tls_fingerprint": "false",
                                "signing_algo": SIGNING_ALGO, "nonce": nonce_hex})
    raw = None
    try:
        raw = _get(base + "/attestation/report?" + q, headers={"x-no-aliasing": "true"}, opener=opener)
    except urllib.error.HTTPError as e:
        problems.append(f"attestation report HTTP {e.code}")
    except OSError as e:
        problems.append(f"attestation report unreachable: {type(e).__name__}")
    rep = None
    if raw is not None:
        try:
            rep = json.loads(raw)
        except json.JSONDecodeError:
            problems.append("attestation report is not JSON")
    cands = [m for m in (rep or {}).get("model_attestations") or [] if isinstance(m, dict)]
    if rep is not None and not cands:
        problems.append("report has no model_attestations (no NEAR model evidence)")
    if cands and any(c.get("model_name") not in (None, model) for c in cands):
        problems.append("a model report names a different model")
    if problems:
        rec["unattested_why"] = problems
        if raw is not None:
            (out_dir / "attestation-report.json").write_bytes(raw)
            rec["report_file"] = "attestation-report.json"
            rec["report_sha256"] = hashlib.sha256(raw).hexdigest()
        if not allow_unattested:
            raise Unattested("; ".join(problems))
        rec["allow_unattested"] = True
        return rec
    (out_dir / "attestation-report.json").write_bytes(raw)
    rec.update(report_file="attestation-report.json", report_sha256=hashlib.sha256(raw).hexdigest(),
               report_bytes=len(raw))
    gw = rep.get("gateway_attestation") or {}
    reports = [("gateway", gw)] + [(f"model[{i}]", c) for i, c in enumerate(cands)]
    rec["reports"] = []
    for label, r in reports:
        chk = check_report_offline(r, nonce_hex)
        bad = [k for k in REQUIRED if not chk.get(k)] + (["report_data_field_matches_quote"] if chk.get("report_data_field_matches_quote") is False else [])
        entry_r = {"which": label, "signing_address": str(r.get("signing_address", "")).lower(), "signing_algo": r.get("signing_algo"),
                   "app_id": (r.get("info") or {}).get("app_id") if isinstance(r.get("info"), dict) else None, "checks": chk}
        if bad:
            raise AttestationError(f"{label} report fails {bad} (nonce or binding mismatch: refusing)")
        if dcap:
            entry_r["intel_quote"] = d = verify_quote_dcap(r)
            if d.get("ran") and not d.get("ok"):
                raise AttestationError(f"{label} Intel quote verification failed: {d.get('why')}")
        if gpu and label != "gateway":
            entry_r["gpu"] = verify_gpu_nras(r, nonce_hex, opener=opener)
        rec["reports"].append(entry_r)
    rec["model_signing_addresses"] = sorted({e["signing_address"] for e in rec["reports"] if e["which"] != "gateway"})
    rec["gateway_signing_address"] = rec["reports"][0]["signing_address"]
    intel = [e.get("intel_quote", {}) for e in rec["reports"]]
    rec["intel_quote_verified"] = bool(intel) and all(i.get("ran") and i.get("ok") for i in intel)
    rec["intel_tcb_statuses"] = sorted({i.get("tcb_status") for i in intel if i.get("tcb_status")})
    rec["gpu_verified"] = all((e.get("gpu") or {}).get("ok") for e in rec["reports"] if e["which"] != "gateway") if gpu else None
    rec["attested"] = True
    return rec


def fetch_signature(base, key, chat_id, opener=None, sleep=time.sleep):
    """GET /v1/signature/<id>; a 404 or an error_code body is retried briefly, then 'unavailable'.
    Returns (json or None, why, requests_made)."""
    url = f"{base}/signature/{urllib.parse.quote(chat_id, safe='')}?signing_algo={SIGNING_ALGO}"
    why, n = "unavailable", 0
    for i in range(SIG_TRIES):
        n += 1
        try:
            j = json.loads(_get(url, key=key, opener=opener))
            if isinstance(j, dict) and "signature" in j and "text" in j:
                return j, None, n
            why = f"no signature ({str((j or {}).get('error_code') if isinstance(j, dict) else 'bad body')[:60]})"
        except urllib.error.HTTPError as e:
            why = f"HTTP {e.code}"
        except (OSError, ValueError) as e:
            why = type(e).__name__
        if i + 1 < SIG_TRIES:
            sleep(2)
    return None, why, n


def check_signature(sig, model, req_bytes, resp_bytes, model_addresses):
    """Bind one reply to the attested model key. Returns a dict; 'verified' is the one-word answer."""
    req_h, resp_h = hashlib.sha256(req_bytes).hexdigest(), hashlib.sha256(resp_bytes).hexdigest()
    out = {"request_sha256": req_h, "response_sha256": resp_h, "verified": False}
    if not sig:
        out["why"] = "no signature"
        return out
    out.update({k: sig.get(k) for k in ("signature_kind", "signing_address", "signing_algo", "text", "signature")})
    expected = f"{model}:{req_h}:{resp_h}"
    out["text_matches_bytes"] = sig.get("text") == expected
    try:
        out["recovered_address"] = rec = recover_eip191(sig.get("text", ""), sig.get("signature", "")) if sig.get("signing_algo") == "ecdsa" else None
    except ValueError as e:
        out["recovered_address"], rec = None, None
        out["why"] = f"signature does not recover: {e}"
    addrs = {a.lower() for a in model_addresses}
    signer = str(sig.get("signing_address", "")).lower()
    out["signer_matches_one_model_report"] = rec is not None and rec == signer and signer in addrs and len(addrs & {signer}) == 1
    out["verified"] = (sig.get("signature_kind") == "provider_tee" and sig.get("signing_algo") == SIGNING_ALGO
                       and out["text_matches_bytes"] and out["signer_matches_one_model_report"])
    if not out["verified"] and "why" not in out:
        out["why"] = ("not a provider_tee signature" if sig.get("signature_kind") != "provider_tee" else
                      "signed text does not match our exact bytes" if not out["text_matches_bytes"] else
                      "signer is not the attested model key")
    return out


def cost_usd(usage, prices):
    if not usage or not prices:
        return None
    return round((usage.get("prompt_tokens") or 0) * prices["in"] / 1e6 + (usage.get("completion_tokens") or 0) * prices["out"] / 1e6, 6)
