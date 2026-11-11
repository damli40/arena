//! Example: an agent's wallet asks Arena before paying a guard.
//!
//! It calls `arena_result` on the Arena contract (a cross-contract view call), then decides in
//! the callback. The rule here is deliberately strict:
//!   may_pay = status is "held" AND the answer is for the exact code hash asked about
//!             AND (the result has no setup condition, OR it matches the setup the caller expects).
//! Anything else, including "not_tested" or a failed call, is a no.
//!
//! "held" means the attacks Arena ran found nothing. It is not a promise about other attacks.
use near_sdk::{env, ext_contract, near, AccountId, Gas, Promise, PromiseError};

/// The fields this example reads from Arena's answer. Other fields are ignored.
#[near(serializers = [json])]
pub struct Answer {
    pub guard_code_hash: String,
    pub status: String,
    pub setup: Option<String>,
    pub arena_commit: Option<String>,
}

#[near(serializers = [json])]
pub struct Decision {
    pub may_pay: bool,
    pub status: String,
    pub arena_commit: Option<String>,
    pub why: String,
}

#[ext_contract(arena)]
#[allow(dead_code)]
trait Arena {
    fn arena_result(&self, guard_code_hash: String, suite: Option<String>, arena_commit: Option<String>) -> Answer;
}

#[near(contract_state)]
#[derive(Default)]
pub struct Caller {}

#[near]
impl Caller {
    /// Ask `arena` about `guard_code_hash` (64 hex). Returns a Decision via the callback.
    pub fn ask(
        &self,
        arena: AccountId,
        guard_code_hash: String,
        suite: Option<String>,
        arena_commit: Option<String>,
        expected_setup: Option<String>,
    ) -> Promise {
        arena::ext(arena)
            .with_static_gas(Gas::from_tgas(10))
            .arena_result(guard_code_hash.clone(), suite, arena_commit)
            .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(10)).on_answer(guard_code_hash, expected_setup))
    }

    #[private]
    pub fn on_answer(
        &self,
        guard_code_hash: String,
        expected_setup: Option<String>,
        #[callback_result] answer: Result<Answer, PromiseError>,
    ) -> Decision {
        let no = |status: &str, commit: Option<String>, why: &str| Decision {
            may_pay: false, status: status.into(), arena_commit: commit, why: why.into(),
        };
        let Ok(a) = answer else { return no("error", None, "the call to Arena failed, so do not pay") };
        if a.guard_code_hash != guard_code_hash {
            return no(&a.status, a.arena_commit, "the answer is for a different code hash");
        }
        if a.status != "held" {
            return no(&a.status, a.arena_commit, "Arena did not report held for this code");
        }
        if a.setup.is_some() && a.setup != expected_setup {
            return no(&a.status, a.arena_commit, "the result is for a different guard setup than expected");
        }
        Decision { may_pay: true, status: a.status, arena_commit: a.arena_commit,
                   why: "held: the attacks Arena ran found nothing (other attacks might)".into() }
    }
}
