//! Kani harnesses over `world.rs`. Anti-vacuity: the cover lines must come back
//! SATISFIED where expected, and the vulnerable and mutant harnesses must FAIL.
use crate::world::*;
use crate::Mode;

struct Kani;
impl Oracle for Kani {
    fn any_bool(&mut self) -> bool {
        kani::any()
    }
    fn any_usize(&mut self) -> usize {
        kani::any()
    }
    fn assume(&mut self, c: bool) {
        kani::assume(c)
    }
    fn cover(&mut self, c: bool, which: Cover) {
        match which {
            Cover::RaceTwoInFlight => kani::cover!(c, "race: two inv-a payments in flight at once"),
            Cover::DoublePay => kani::cover!(c, "double pay reached: 200 sent on the 100 invoice"),
            Cover::PaidOnce => kani::cover!(c, "inv-a paid exactly once"),
            Cover::RefusedInFlight => kani::cover!(c, "a pay refused because a payment is in flight"),
            Cover::RetriedAfterFailure => kani::cover!(c, "a pay accepted again after a failed transfer"),
        }
    }
    fn check(&mut self, c: bool, what: Check) {
        match what {
            Check::Amount => kani::assert(c, "receipt amount is the invoice amount"),
            Check::P1 => kani::assert(c, "P1: tokens sent for an invoice never exceed its amount"),
            Check::Steps => kani::assert(c, "every schedule ends within 3N steps"),
            Check::P2Approved => kani::assert(c, "P2: an invoice with nothing sent is Approved"),
            Check::P2Payable => kani::assert(c, "P2: an invoice with nothing sent is payable again"),
            Check::P2Paid => kani::assert(c, "P2 corollary: an invoice with tokens sent is Paid"),
        }
    }
}

/// Expected: VERIFICATION FAILED on P1 (the planted flaw).
#[kani::proof]
#[kani::unwind(10)] // MAX_STEPS + 1, unwinding assertions on
fn vulnerable_fixture_n3() {
    world::<_, 3>(&mut Kani, Mode::VulnerableFixture, false);
}

/// Expected: VERIFICATION SUCCESSFUL (P1, P2 hold for up to N = 3 pays).
#[kani::proof]
#[kani::unwind(10)]
fn fixed_n3() {
    world::<_, 3>(&mut Kani, Mode::Fixed, false);
}

/// Must-fail mutant: `fixed` without line 186. Expected: VERIFICATION FAILED on P1.
#[kani::proof]
#[kani::unwind(10)]
fn fixed_mutant_no_pending_write_n3() {
    world::<_, 3>(&mut Kani, Mode::Fixed, true);
}

/// Bound check: too small an unwind must FAIL its unwinding assertion,
/// so a too-short bound cannot pass silently.
#[kani::proof]
#[kani::unwind(5)]
fn fixed_n3_bound_too_small() {
    world::<_, 3>(&mut Kani, Mode::Fixed, false);
}

/// Extra bound (not pre-registered as the headline): N = 4 pays. unwind = 3*4 + 1.
#[kani::proof]
#[kani::unwind(13)]
fn fixed_n4() {
    world::<_, 4>(&mut Kani, Mode::Fixed, false);
}

/// The planted flaw at N = 4 (must still fail).
#[kani::proof]
#[kani::unwind(13)]
fn vulnerable_fixture_n4() {
    world::<_, 4>(&mut Kani, Mode::VulnerableFixture, false);
}
