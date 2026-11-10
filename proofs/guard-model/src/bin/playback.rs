//! Replays a Kani counterexample (its concrete values, from
//! `cargo kani ... -Z concrete-playback --concrete-playback=print`) through the SAME
//! `world()` code and prints the schedule in plain words.
//!
//!   cargo run --bin playback -- <vulnerable_fixture|fixed|mutant> <file with the printed test>
use guard_model::world::*;
use guard_model::Mode;

struct Replay {
    vals: Vec<Vec<u8>>,
    pos: usize,
    lines: Vec<String>,
    failed: Vec<&'static str>,
    dead: bool,
}
impl Replay {
    fn next(&mut self) -> Vec<u8> {
        let v = self.vals.get(self.pos).cloned().unwrap_or_else(|| vec![0; 8]);
        self.pos += 1;
        v
    }
}
impl Oracle for Replay {
    fn any_bool(&mut self) -> bool {
        self.next()[0] != 0
    }
    fn any_usize(&mut self) -> usize {
        let b = self.next();
        let mut a = [0u8; 8];
        a[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
        usize::from_le_bytes(a)
    }
    fn assume(&mut self, c: bool) {
        if !c {
            self.dead = true;
            panic!("replay violated an assume: not a valid Kani trace");
        }
    }
    fn cover(&mut self, _c: bool, _w: Cover) {}
    fn check(&mut self, c: bool, what: Check) {
        if !c {
            self.failed.push(what.msg());
            self.lines.push(format!("  -> CHECK FAILED: {}", what.msg()));
            // Stop here, as Kani does after a failed assertion.
            panic!("stop");
        }
    }
    fn note(&mut self, line: impl FnOnce() -> String) {
        self.lines.push(line());
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (mode, mutant) = match a.get(1).map(|s| s.as_str()) {
        Some("vulnerable_fixture") => (Mode::VulnerableFixture, false),
        Some("fixed") => (Mode::Fixed, false),
        Some("mutant") => (Mode::Fixed, true),
        _ => panic!("usage: playback <vulnerable_fixture|fixed|mutant> <file>"),
    };
    let text = std::fs::read_to_string(&a[2]).expect("read playback file");
    // Kani prints one test per failing check and per satisfied cover. Take the one
    // generated for the P1 assertion.
    let p1 = text.find("Check for `assertion`: \"P1:").expect("no playback test for the P1 assertion");
    let body = text[p1..].split("concrete_vals: Vec<Vec<u8>> = vec![").nth(1).expect("no concrete_vals");
    let body = body.split("];").next().unwrap();
    let vals: Vec<Vec<u8>> = body
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("vec!["))
        .map(|l| l.trim_start_matches("vec![").trim_end_matches("],").trim_end_matches(']').split(',').filter(|x| !x.trim().is_empty()).map(|x| x.trim().parse().unwrap()).collect())
        .collect();
    let mut r = Replay { vals, pos: 0, lines: vec![], failed: vec![], dead: false };
    std::panic::set_hook(Box::new(|_| {}));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| world::<_, 3>(&mut r, mode, mutant)));
    let _ = res;
    for l in &r.lines {
        println!("{l}");
    }
    if r.dead {
        println!("RESULT replay=INVALID");
        std::process::exit(2);
    }
    println!("RESULT failed_checks={:?}", r.failed);
}
