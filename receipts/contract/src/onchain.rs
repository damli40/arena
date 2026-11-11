//! Added 2026-11-11, on top of the receipts contract, without touching it.
//!
//! 1. Opt-in on chain. A guard owner signs `opt_in` to say "Arena may attack this guard, with this
//!    exact code". Only the guard account itself, or the account directly above it (its parent,
//!    `x.parent` -> `parent`), may sign. That is checked here, on chain.
//! 2. Results other contracts can ask for before paying: `arena_result(code_hash, suite, commit)`.
//!    Every result is stored under the guard's code hash and names the Arena commit that produced it,
//!    so a result for old code can never answer for new code.
//!
//! Storage layout: everything here lives under its own storage key (`X`), read and written by
//! `Ext::load` / `Ext::save`. The receipts' state (`STATE`, prefix `r`) is never read or written by
//! this file, so the four receipts methods behave exactly as before.
//!
//! "held" means only: the attacks Arena ran found nothing. It is never a promise about attacks
//! Arena did not run.
use near_sdk::json_types::{U128, U64};
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{env, near, require, AccountId, NearToken, Promise};

use crate::{require_hex64, Receipts, ReceiptsExt};

const EXT_KEY: &[u8] = b"X";
const MAX_CONTACT: usize = 128;
const MAX_TEXT: usize = 256;
const MAX_PAGE: u32 = 100;

/// What a result says. `NotTested` is only ever returned by a view, never stored.
#[near(serializers = [borsh, json])]
#[serde(rename_all = "snake_case")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// The attacks in this suite found no way past the guard. Other attacks might.
    Held,
    /// At least one attack got money out beyond the guard's policy or against the user's intent.
    Broke,
    /// The suite did not finish, so it says nothing either way.
    Incomplete,
    /// Arena has no result for this code hash (and suite / commit, if asked).
    NotTested,
}

impl Status {
    fn meaning(self) -> &'static str {
        match self {
            Status::Held => "held: the attacks Arena ran found no way past this guard. Attacks Arena did not run might.",
            Status::Broke => "broke: an attack Arena ran got money out beyond the guard's rules or against the user's wishes.",
            Status::Incomplete => "incomplete: the attacks did not all finish, so this result says nothing either way.",
            Status::NotTested => "not_tested: Arena has no result for this exact code.",
        }
    }
    /// Worse = higher. Used when a caller asks across every suite.
    fn rank(self) -> u8 {
        match self {
            Status::Held => 1,
            Status::NotTested => 2,
            Status::Incomplete => 3,
            Status::Broke => 4,
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct OptIn {
    pub guard: AccountId,
    /// sha256 of the guard's wasm, 64 lowercase hex characters (NEAR shows it as base58).
    pub code_hash: String,
    pub contact: Option<String>,
    /// Nanoseconds since the Unix epoch. After this, the opt-in no longer counts.
    pub expires_at: Option<U64>,
    /// "token" or "native": how the guard pays, so Arena scores the right balance. None = not said.
    pub pays_in: Option<String>,
    /// Who signed: the guard itself, or its parent account.
    pub signed_by: AccountId,
    /// "guard" or "parent".
    pub signer_role: String,
    pub opted_in_at: U64,
}

#[near(serializers = [json])]
pub struct OptInView {
    #[serde(flatten)]
    pub opt_in: OptIn,
    /// False once `expires_at` has passed.
    pub active: bool,
}

/// What Arena sends with `publish_result`. `published_at` is added by the contract.
#[near(serializers = [json])]
pub struct ResultInput {
    pub guard_code_hash: String,
    pub suite: String,
    pub suite_version: String,
    pub status: Status,
    pub attacks_ran: u32,
    pub not_applicable: u32,
    pub beyond_policy: U128,
    pub against_intent: Option<U128>,
    /// The result applies only to a guard set up this way (e.g. "mode=fixed"). None = no setup choice.
    pub setup: Option<String>,
    /// 40 lowercase hex characters: the exact Arena git commit. A dirty tree cannot publish.
    pub arena_commit: String,
    pub evidence_sha256: String,
    pub evidence_path: String,
    /// sha256 of a hardware attestation report for the run, when there is one.
    pub attestation_sha256: Option<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct ArenaResult {
    pub guard_code_hash: String,
    pub suite: String,
    pub suite_version: String,
    pub status: Status,
    pub attacks_ran: u32,
    pub not_applicable: u32,
    pub beyond_policy: U128,
    pub against_intent: Option<U128>,
    pub setup: Option<String>,
    pub arena_commit: String,
    pub evidence_sha256: String,
    pub evidence_path: String,
    pub attestation_sha256: Option<String>,
    pub published_at: U64,
}

/// The answer to "was this code tested?". Always returned, never null: an unknown hash gives
/// `status = not_tested` and every measured field empty.
#[near(serializers = [json])]
pub struct ArenaAnswer {
    pub guard_code_hash: String,
    pub status: Status,
    /// One plain sentence saying what `status` means. "held" is never "safe".
    pub status_means: String,
    pub suite: Option<String>,
    pub suite_version: Option<String>,
    pub attacks_ran: Option<u32>,
    pub not_applicable: Option<u32>,
    pub beyond_policy: Option<U128>,
    pub against_intent: Option<U128>,
    /// If set, the result applies only to a guard set up this way. Your contract must check it.
    pub setup: Option<String>,
    pub arena_commit: Option<String>,
    pub evidence_sha256: Option<String>,
    pub evidence_path: Option<String>,
    pub attestation_sha256: Option<String>,
    pub published_at: Option<U64>,
    /// How many suites' latest results were looked at (more than 1 only when no suite was given).
    pub suites_considered: u32,
}

#[near(serializers = [borsh])]
struct Ext {
    opt_ins: IterableMap<AccountId, OptIn>,
    /// Guards that opted out themselves. Their parent cannot opt them back in; only they can.
    refused_by_guard: LookupMap<AccountId, U64>,
    /// guard_code_hash -> every result for it, oldest first. Never edited or deleted.
    results: LookupMap<String, Vec<ArenaResult>>,
}

impl Ext {
    fn load() -> Self {
        match env::storage_read(EXT_KEY) {
            Some(bytes) => near_sdk::borsh::from_slice(&bytes).unwrap_or_else(|_| env::panic_str("bad X state")),
            None => Ext {
                opt_ins: IterableMap::new(b"o".to_vec()),
                refused_by_guard: LookupMap::new(b"n".to_vec()),
                results: LookupMap::new(b"v".to_vec()),
            },
        }
    }
    fn save(&mut self) {
        self.opt_ins.flush();
        self.refused_by_guard.flush();
        self.results.flush();
        env::storage_write(EXT_KEY, &near_sdk::borsh::to_vec(self).unwrap());
    }
}

/// "guard" if the caller is the guard, "parent" if the guard is exactly `<name>.<caller>`.
fn signer_role(caller: &AccountId, guard: &AccountId) -> Option<&'static str> {
    if caller == guard {
        return Some("guard");
    }
    let name = guard.as_str().strip_suffix(caller.as_str())?.strip_suffix('.')?;
    (!name.is_empty() && !name.contains('.')).then_some("parent")
}

fn require_text(name: &str, s: &str, max: usize) {
    require!(!s.is_empty() && s.len() <= max, format!("{name} must be 1 to {max} bytes"));
}

fn require_commit(s: &str) {
    let ok = s.len() == 40 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    require!(ok, "arena_commit must be 40 lowercase hex characters (a clean git commit, no -dirty)");
}

/// Charge the caller for the bytes added since `before`; refund the rest of the deposit.
fn charge_storage(before: u64) {
    let added = env::storage_usage().saturating_sub(before) as u128;
    let cost = env::storage_byte_cost().saturating_mul(added);
    let paid = env::attached_deposit();
    require!(paid >= cost, format!("attach at least {cost} for storage"));
    let refund = paid.saturating_sub(cost);
    if refund > NearToken::from_yoctonear(0) {
        Promise::new(env::predecessor_account_id()).transfer(refund).detach();
    }
}

fn event(name: &str, data: near_sdk::serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        near_sdk::serde_json::json!({"standard": "arena-onchain", "version": "1.0.0", "event": name, "data": [data]})
    ));
}

fn view(o: &OptIn) -> OptInView {
    let active = o.expires_at.map_or(true, |e| env::block_timestamp() < e.0);
    OptInView { opt_in: o.clone(), active }
}

fn answer(hash: String, r: Option<&ArenaResult>, suites_considered: u32) -> ArenaAnswer {
    match r {
        None => ArenaAnswer {
            guard_code_hash: hash, status: Status::NotTested, status_means: Status::NotTested.meaning().into(),
            suite: None, suite_version: None, attacks_ran: None, not_applicable: None, beyond_policy: None,
            against_intent: None, setup: None, arena_commit: None, evidence_sha256: None, evidence_path: None,
            attestation_sha256: None, published_at: None, suites_considered,
        },
        Some(r) => ArenaAnswer {
            guard_code_hash: hash, status: r.status, status_means: r.status.meaning().into(),
            suite: Some(r.suite.clone()), suite_version: Some(r.suite_version.clone()),
            attacks_ran: Some(r.attacks_ran), not_applicable: Some(r.not_applicable),
            beyond_policy: Some(r.beyond_policy), against_intent: r.against_intent, setup: r.setup.clone(),
            arena_commit: Some(r.arena_commit.clone()), evidence_sha256: Some(r.evidence_sha256.clone()),
            evidence_path: Some(r.evidence_path.clone()), attestation_sha256: r.attestation_sha256.clone(),
            published_at: Some(r.published_at), suites_considered,
        },
    }
}

#[near]
impl Receipts {
    // ---------------------------------------------------------------- opt-in

    /// Opt a guard in. The caller must be the guard account itself or its direct parent, and must
    /// attach NEAR for the storage (the rest is refunded). A deposit also means a full-access key
    /// signed: a limited function-call key cannot attach one. Opting in again replaces the record.
    #[payable]
    pub fn opt_in(
        &mut self,
        guard: AccountId,
        code_hash: String,
        contact: Option<String>,
        expires_at: Option<U64>,
        pays_in: Option<String>,
    ) -> OptIn {
        let caller = env::predecessor_account_id();
        let role = signer_role(&caller, &guard)
            .unwrap_or_else(|| env::panic_str("only the guard account itself or its parent account can opt it in"));
        require_hex64("code_hash", &code_hash);
        require!(code_hash.bytes().any(|b| b != b'0'), "code_hash is all zeros: that account has no contract");
        if let Some(c) = &contact {
            require_text("contact", c, MAX_CONTACT);
        }
        if let Some(e) = expires_at {
            require!(e.0 > env::block_timestamp(), "expires_at is in the past");
        }
        if let Some(p) = &pays_in {
            require!(p == "token" || p == "native", "pays_in must be \"token\" or \"native\"");
        }
        let before = env::storage_usage();
        let mut x = Ext::load();
        if role == "parent" {
            require!(!x.refused_by_guard.contains_key(&guard), "this guard opted out itself; only the guard account can opt it back in");
        } else {
            x.refused_by_guard.remove(&guard);
        }
        let o = OptIn {
            guard: guard.clone(), code_hash, contact, expires_at, pays_in, signed_by: caller,
            signer_role: role.into(), opted_in_at: U64(env::block_timestamp()),
        };
        x.opt_ins.insert(guard, o.clone());
        x.save();
        charge_storage(before);
        event("opt_in", near_sdk::serde_json::to_value(&o).unwrap());
        o
    }

    /// Opt a guard out. Same signers as `opt_in`; attach 1 yoctoNEAR (so a full-access key signs).
    /// If the guard itself opts out, its parent cannot opt it back in. Storage is not refunded.
    #[payable]
    pub fn opt_out(&mut self, guard: AccountId) -> bool {
        let caller = env::predecessor_account_id();
        let role = signer_role(&caller, &guard)
            .unwrap_or_else(|| env::panic_str("only the guard account itself or its parent account can opt it out"));
        require!(env::attached_deposit() >= NearToken::from_yoctonear(1), "attach 1 yoctoNEAR");
        let mut x = Ext::load();
        let was = x.opt_ins.remove(&guard).is_some();
        if role == "guard" {
            x.refused_by_guard.insert(guard.clone(), U64(env::block_timestamp()));
        }
        x.save();
        event("opt_out", near_sdk::serde_json::json!({"guard": guard, "signed_by": caller, "signer_role": role, "was_opted_in": was}));
        was
    }

    /// The opt-in for one guard account, or null. `active` is false once it has expired.
    pub fn opt_in_of(&self, guard: AccountId) -> Option<OptInView> {
        Ext::load().opt_ins.get(&guard).map(view)
    }

    /// Every opt-in, a page at a time (at most 100). Includes expired ones, marked `active: false`.
    pub fn opt_ins(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<OptInView> {
        let x = Ext::load();
        let from = from_index.unwrap_or(0) as usize;
        let n = limit.unwrap_or(MAX_PAGE).min(MAX_PAGE) as usize;
        x.opt_ins.values().skip(from).take(n).map(view).collect()
    }

    pub fn opt_in_count(&self) -> u32 {
        Ext::load().opt_ins.len()
    }

    // ---------------------------------------------------------------- results

    /// Owner only. Stores one result under its code hash. The contract refuses a "held" with any
    /// money lost, a "broke" with none, and any commit that is not a clean 40-hex git commit.
    #[payable]
    pub fn publish_result(&mut self, result: ResultInput) -> ArenaResult {
        require!(env::predecessor_account_id() == self.owner, "only the owner can publish");
        require_hex64("guard_code_hash", &result.guard_code_hash);
        require_hex64("evidence_sha256", &result.evidence_sha256);
        if let Some(a) = &result.attestation_sha256 {
            require_hex64("attestation_sha256", a);
        }
        require_commit(&result.arena_commit);
        require_text("suite", &result.suite, MAX_TEXT);
        require_text("suite_version", &result.suite_version, MAX_TEXT);
        require_text("evidence_path", &result.evidence_path, MAX_TEXT);
        if let Some(s) = &result.setup {
            require_text("setup", s, MAX_TEXT);
        }
        let lost = result.beyond_policy.0 > 0 || result.against_intent.map_or(false, |a| a.0 > 0);
        match result.status {
            Status::Held => require!(result.attacks_ran > 0 && !lost, "held needs attacks_ran > 0 and nothing paid beyond policy or against intent"),
            Status::Broke => require!(lost, "broke needs something paid beyond policy or against intent"),
            Status::Incomplete => {}
            Status::NotTested => env::panic_str("not_tested cannot be published"),
        }
        let before = env::storage_usage();
        let r = ArenaResult {
            guard_code_hash: result.guard_code_hash, suite: result.suite, suite_version: result.suite_version,
            status: result.status, attacks_ran: result.attacks_ran, not_applicable: result.not_applicable,
            beyond_policy: result.beyond_policy, against_intent: result.against_intent, setup: result.setup,
            arena_commit: result.arena_commit, evidence_sha256: result.evidence_sha256,
            evidence_path: result.evidence_path, attestation_sha256: result.attestation_sha256,
            published_at: U64(env::block_timestamp()),
        };
        let mut x = Ext::load();
        x.results.entry(r.guard_code_hash.clone()).or_default().push(r.clone());
        x.save();
        charge_storage(before);
        event("publish_result", near_sdk::serde_json::to_value(&r).unwrap());
        r
    }

    /// Every result for this code hash, oldest first.
    pub fn arena_results_for(&self, guard_code_hash: String) -> Vec<ArenaResult> {
        Ext::load().results.get(&guard_code_hash).cloned().unwrap_or_default()
    }

    /// "Was the guard with this code hash tested, and what did it show?"
    ///
    /// - `suite` given: the newest result in that suite.
    /// - `suite` omitted: the newest result of each suite, and the WORST of those is returned
    ///   (broke > incomplete > held), so one good suite never hides a bad one.
    /// - `arena_commit` given: only results produced by that exact Arena commit count.
    ///
    /// Never null. Unknown hash, suite or commit -> `status = not_tested`.
    pub fn arena_result(&self, guard_code_hash: String, suite: Option<String>, arena_commit: Option<String>) -> ArenaAnswer {
        let x = Ext::load();
        let empty = Vec::new();
        let all = x.results.get(&guard_code_hash).unwrap_or(&empty);
        let fits = |r: &&ArenaResult| arena_commit.as_ref().map_or(true, |c| &r.arena_commit == c);
        if let Some(s) = suite {
            let r = all.iter().rev().filter(fits).find(|r| r.suite == s);
            return answer(guard_code_hash, r, r.is_some() as u32);
        }
        let mut latest: Vec<&ArenaResult> = Vec::new();
        for r in all.iter().rev().filter(fits) {
            if !latest.iter().any(|l| l.suite == r.suite) {
                latest.push(r);
            }
        }
        // `latest` is newest first, so on a tie the newest result wins.
        let worst = latest.iter().copied().fold(None::<&ArenaResult>, |w, r| match w {
            Some(w) if w.status.rank() >= r.status.rank() => Some(w),
            _ => Some(r),
        });
        answer(guard_code_hash, worst, latest.len() as u32)
    }
}
