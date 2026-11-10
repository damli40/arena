"""Run attacks against guards on the LOCAL sandbox, through the harness's fixed actions only.

One attempt = `arena-harness attempt <seq.json> <guard flags> --out <result.json>`: a fresh
sandbox, the harness's one setup function, the attack's steps, the existing scorer. Each attempt
runs in its own process group with a hard timeout; on timeout the whole group (harness + its
neard sandbox) is killed and the cell is recorded as "error: timeout", never as "held".
"""
import concurrent.futures as cf
import json, os, pathlib, signal, subprocess, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS = ROOT / "harness" / "target" / "release" / "arena-harness"
ATTEMPT_TIMEOUT_S = 240


def _kill_group(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_one(seq_path, guard, out_dir, meta_line, timeout=ATTEMPT_TIMEOUT_S):
    out_dir = pathlib.Path(out_dir)
    stem = f"{pathlib.Path(seq_path).stem}__{guard['id']}"
    rjson, rlog = out_dir / f"{stem}.result.json", out_dir / f"{stem}.log"
    cmd = [str(HARNESS), "attempt", str(seq_path), *guard["harness_flags"], "--out", str(rjson), "--meta", meta_line]
    t0 = time.time()
    with open(rlog, "w") as logf:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(p)
            p.wait()
            rc = None
        finally:
            _kill_group(p)  # the sandbox neard is a child: never leave it running
    cell = {"guard": guard["id"], "seconds": round(time.time() - t0, 1),
            "result_json": str(rjson.relative_to(ROOT)) if rjson.is_relative_to(ROOT) else str(rjson),
            "log": str(rlog.relative_to(ROOT)) if rlog.is_relative_to(ROOT) else str(rlog)}
    if rc is None:
        return {**cell, "status": "error", "why": f"timeout after {timeout}s (process group killed)"}
    if rc != 0 or not rjson.exists():
        tail = rlog.read_text(errors="replace").strip().splitlines()[-3:]
        return {**cell, "status": "error", "why": f"harness exit {rc}: " + " | ".join(t[:200] for t in tail)}
    r = json.loads(rjson.read_text())
    s = r["score"]
    steps = r.get("steps", [])
    out = {**cell,
           "unauthorised": int(s["unauthorised_payout"]),
           "honest_settled": s["honest_settled"], "should_pay": s["should_pay"],
           "scoring": s["scoring"], "valid": s["valid"],
           "steps_ok": sum(1 for x in steps if x["success"]),
           "steps_protocol_rejected": sum(1 for x in steps if x["outcome"] == "protocol-rejected"),
           "steps_total": len(steps),
           "target_wasm_sha256": r.get("target_wasm_sha256")}
    if not s["valid"]:
        out.update(status="invalid", why="; ".join(s.get("invalid_reasons", []))[:400])
    elif out["unauthorised"] > 0:
        out.update(status="broke", why=f"paid {out['unauthorised']} beyond the policy")
    else:
        out.update(status="held", why="")
    return out


def run_matrix(attacks, guards, out_dir, meta_line, jobs=4, deadline=None, timeout=ATTEMPT_TIMEOUT_S):
    """attacks: [(seq_path, attack_id, guard_ids or None = all)]. Returns {attack_id: {guard_id: cell}}. Cells not started
    before `deadline` (epoch seconds) are recorded as skipped, not run."""
    pathlib.Path(out_dir).mkdir(parents=True, exist_ok=True)
    results = {aid: {} for _, aid, _ in attacks}
    jobs_list = [(sp, aid, g) for sp, aid, only in attacks for g in guards if only is None or g["id"] in only]

    def task(sp, aid, g):
        if deadline and time.time() > deadline:
            return aid, g["id"], {"guard": g["id"], "status": "skipped", "why": "hunt timeout reached before this attempt started"}
        return aid, g["id"], run_one(sp, g, out_dir, meta_line, timeout)

    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        for aid, gid, cell in ex.map(lambda t: task(*t), jobs_list):
            results[aid][gid] = cell
            print(f"  {aid:<44} {gid:<18} {cell['status']:<8} {cell.get('why', '')[:80]}", flush=True)
    return results
