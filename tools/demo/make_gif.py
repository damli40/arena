#!/usr/bin/env python3
"""Make the README demo GIF by replaying a REAL `./arena check` console capture.

Nothing in the GIF is typed by hand. Every output line comes from the capture file you pass in
(a saved console log of a real run), shown faster than it happened. The caption at the bottom of
every frame says so, with the real run time and the capture's path.

    python3 -I tools/demo/make_gif.py CAPTURE.txt --report REPORT.html --out site/img/arena-check.gif

The command shown is the capture's own "$ ..." line. If the capture has none, pass --command; if you pass
one that differs from the capture's, the script stops rather than show a command that did not run.

How it works: this script writes one small HTML page per frame (a terminal window with the lines
shown so far), takes a picture of each with headless Chrome, and joins the pictures with ffmpeg.
The last frames are a picture of the real report page, if --report is given.

Needs Google Chrome and ffmpeg. Uses a throwaway Chrome profile in a temp folder.
"""
import argparse, html, pathlib, re, shutil, subprocess, sys, tempfile

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
W, H = 960, 600
ROWS = 21          # terminal lines visible at once
WRAP = 104         # characters per terminal line

CSS = """
*{box-sizing:border-box}html,body{margin:0;width:%dpx;height:%dpx;background:#0b0b0c;overflow:hidden}
.win{position:absolute;inset:14px 14px 54px 14px;border:1px solid #2a2a2c;border-radius:10px;background:#111113;overflow:hidden}
.bar{height:30px;border-bottom:1px solid #2a2a2c;display:flex;align-items:center;padding:0 12px;gap:7px}
.dot{width:10px;height:10px;border-radius:50%%;background:#3a3a3d}
.ttl{margin-left:10px;font:12px Menlo,monospace;color:#77777a}
pre{margin:0;padding:12px 16px;font:13px/1.55 Menlo,monospace;color:#d6d6d3;white-space:pre}
.dim{color:#6f6f72}.ok{color:#d6d6d3}.bad{color:#ff6b5e;font-weight:700}.hd{color:#fff;font-weight:700}
.cap{position:absolute;left:16px;right:16px;bottom:9px;height:34px;font:11.5px/17px Menlo,monospace;color:#8a8a8d;
overflow:hidden}
.cur{display:inline-block;width:8px;height:15px;background:#d6d6d3;vertical-align:-2px}
""" % (W, H)


def wrap(line):
    """Hard-wrap one long line the way a terminal would."""
    if len(line) <= WRAP:
        return [line]
    return [line[i:i + WRAP] for i in range(0, len(line), WRAP)]


def paint(line):
    """One capture line -> HTML, coloured by what it says. The text itself is never changed."""
    e = html.escape(line)
    if line.startswith("$ "):
        return f'<span class="hd">{e}</span>'
    m = re.match(r"^arena: (held|broke|incomplete|not run)", line)
    if m:
        # broke = red (the one colour). held and incomplete are plain: green would read as "safe",
        # and the tool itself says held only means these attacks found nothing
        cls = {"held": "ok", "broke": "bad"}.get(m.group(1), "hd")
        return f'<span class="{cls}" style="font-weight:700">{e}</span>'
    if line.lstrip().startswith("BROKE"):
        return f'<span class="bad">{e}</span>'
    m = re.match(r"^(  \S+\s+\S+\s+)(held|broke|error|skipped|not-applicable)(\s.*|)$", line)
    if m:
        cls = {"held": "ok", "broke": "bad"}.get(m.group(2), "dim")
        return f'<span class="dim">{html.escape(m.group(1))}</span><span class="{cls}">{m.group(2)}{html.escape(m.group(3))}</span>'
    return e


def page(lines, caption, cursor=False):
    shown = [w for ln in lines for w in wrap(ln)][-ROWS:]
    body = "\n".join(paint(ln) for ln in shown) + ('<span class="cur"></span>' if cursor else "")
    return (f"<!doctype html><meta charset=utf-8><style>{CSS}</style><div class=win><div class=bar>"
            f"<i class=dot></i><i class=dot></i><i class=dot></i><span class=ttl>arena check</span></div>"
            f"<pre>{body}</pre></div><div class=cap>{html.escape(caption).replace(chr(10), '<br>')}</div>")


def shoot(url, png, profile):
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                    "--force-device-scale-factor=1", f"--user-data-dir={profile}", f"--window-size={W},{H}",
                    f"--screenshot={png}", url], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=60)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("capture", help="saved console output of a real ./arena check run")
    ap.add_argument("--command", help="the command line to show. Not needed when the capture has its own "
                                      "'$ ...' line: that line is used, so the command shown is the one that ran")
    ap.add_argument("--report", help="that run's report.html; shown as the last frames")
    ap.add_argument("--out", required=True)
    ap.add_argument("--source-note", help="path of the capture as it should read in the caption")
    ap.add_argument("--batch", type=int, default=4, help="attack lines added per frame")
    a = ap.parse_args()
    if not pathlib.Path(CHROME).exists() or not shutil.which("ffmpeg"):
        sys.exit("needs Google Chrome and ffmpeg")

    raw = pathlib.Path(a.capture).read_text(errors="replace").splitlines()
    # Keep the tool's own output; drop the shell's `time` lines and exit marker after it.
    lines, captured_cmd = [], None
    for ln in raw:
        if re.match(r"^(real|user|sys)\s+[\d.]+$", ln) or ln.startswith("exit="):
            continue
        if ln.startswith("$ "):          # the capture's own record of the command that ran
            captured_cmd = captured_cmd or ln[2:].strip()
            continue
        lines.append(ln.rstrip())
    if captured_cmd and a.command and a.command.strip() != captured_cmd:
        sys.exit(f"--command does not match the capture.\n  capture ran: {captured_cmd}\n  you passed:  {a.command}\n"
                 "Drop --command to show what really ran.")
    command = captured_cmd or a.command
    if not command:
        sys.exit("the capture has no '$ ...' line, so pass --command with the command that made it")
    m = re.search(r"wall-clock: ([\d.]+) s", "\n".join(lines))
    took = f"{float(m.group(1)):.0f} s" if m else "several minutes"
    # The part a reader must not miss comes first; the log path comes last, on its own line.
    caption = (f"Replay of a real run, shown faster (the run took {took}). Local sandbox only.\n"
               f"Log: {a.source_note or a.capture}")

    # Frames: (lines so far, cursor?, seconds on screen)
    frames, cmd = [], "$ " + command
    for n in range(2, len(cmd) + 1, 3):
        frames.append(([cmd[:n]], True, 0.05))
    frames.append(([cmd], True, 0.7))
    start = next((i for i, ln in enumerate(lines) if re.match(r"^arena: (held|broke|incomplete|not run)", ln)), len(lines))
    head = [ln for ln in lines[:start]]
    pre = [ln for ln in head if ln.startswith("preflight")]
    rows = [ln for ln in head if not ln.startswith("preflight")]
    shown = [cmd]
    for ln in pre:
        shown = shown + [ln]
        frames.append((shown, False, 0.8))
    for i in range(0, len(rows), a.batch):
        shown = shown + rows[i:i + a.batch]
        frames.append((shown, False, 0.22))
    shown = shown + lines[start:]
    frames.append((shown, False, 5.0))

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="arena-gif-"))
    profile = tmp / "chrome-profile"
    concat = []
    for k, (ls, cur, secs) in enumerate(frames):
        h = tmp / f"f{k:03d}.html"
        h.write_text(page(ls, caption, cur))
        png = tmp / f"f{k:03d}.png"
        shoot(h.as_uri(), png, profile)
        concat += [f"file '{png}'", f"duration {secs}"]
    if a.report:
        png = tmp / "report.png"
        shoot(pathlib.Path(a.report).resolve().as_uri(), png, profile)
        concat += [f"file '{png}'", "duration 4.0"]
    concat += [concat[-2]]  # ffmpeg's concat needs the last file named twice to honour its duration
    (tmp / "list.txt").write_text("\n".join(concat) + "\n")
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(tmp / "list.txt"),
                    "-vf", "split[a][b];[a]palettegen=max_colors=48:stats_mode=diff[p];[b][p]paletteuse=dither=none",
                    "-fps_mode", "vfr", "-loop", "0", str(out)], check=True)
    total = sum(s for _, _, s in frames) + (4.0 if a.report else 0)
    print(f"{out}: {len(frames) + (1 if a.report else 0)} frames, {total:.1f} s, {out.stat().st_size / 1024:.0f} KiB")
    print(f"frames kept in {tmp}")


if __name__ == "__main__":
    main()
