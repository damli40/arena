//! arena signer stand-in. NOT the NEAR MPC network. It holds no key and produces no signature.
//!
//! What it is for (Arena, 2026-11-11): a guard that asks NEAR's Chain Signatures contract
//! (`v1.signer`) to sign a transaction for another chain hands it a 32-byte fingerprint (a hash)
//! of that transaction. Arena cannot run the real MPC network on a local sandbox, so it deploys
//! this small contract in its place. It takes the SAME `sign` request shape as `v1.signer`
//! (github.com/near/mpc, crates/contract: `sign(request: SignRequestArgs)`), refuses the call
//! under the same basic rules (at least 1 yoctoNEAR attached, at least 10 TGas, an Ecdsa payload
//! of exactly 32 bytes), and then does two things only:
//!
//!   1. it RECORDS the request: who called (`predecessor`), the payload hash, the derivation
//!      path, the key version (the legacy `key_version`, or `domain_id` in the current form),
//!      the block height and the deposit. Arena reads these records with the free views
//!      `request_count()` and `requests(from_index, limit)`;
//!   2. it returns a FAKE signature (all zeros) with a field that says so, right away. The real
//!      contract answers later, through yield/resume, once the MPC nodes have signed.
//!
//! Differences from the real contract, on purpose: no yield/resume, no timeout, no key, no
//! derivation (`public_key` and `derived_public_key` return a fixed text that says there is no
//! key), and the deposit is kept rather than the excess refunded (so the caller's NEAR change is
//! exactly its gas plus its deposit). Nothing here can tell you whether the real MPC network
//! would accept a request or whether a foreign chain would accept the transaction.

use near_sdk::store::Vector;
use near_sdk::{env, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault};
use borsh::BorshSerialize;

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Requests,
}

/// Same rule as the real contract's README: at least 10 TGas must be attached to `sign`.
const MIN_SIGN_GAS: Gas = Gas::from_tgas(10);
/// The real contract accepts Eddsa payloads of 32 to 1232 bytes.
const EDDSA_MIN: usize = 32;
const EDDSA_MAX: usize = 1232;
/// At most this many records per `requests` view.
const MAX_PAGE: u64 = 100;

pub const NOT_A_SIGNATURE: &str =
    "NOT A SIGNATURE. Arena's signer stand-in records signing requests; it is not the NEAR MPC network and holds no key.";

/// `payload_v2` as the real contract takes it: `{"Ecdsa": "<hex>"}` or `{"Eddsa": "<hex>"}`.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub enum PayloadV2 {
    Ecdsa(String),
    Eddsa(String),
}

/// The real `SignRequestArgs`: the current form (`payload_v2` + `domain_id`) or the older form
/// (`payload` as 32 bytes + `key_version`). Exactly one form per request.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SignRequestArgs {
    pub payload_v2: Option<PayloadV2>,
    pub payload: Option<Vec<u8>>,
    pub path: String,
    pub domain_id: Option<u64>,
    pub key_version: Option<u32>,
}

/// One recorded request.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Record {
    pub index: u64,
    pub predecessor: AccountId,
    /// "payload_v2-ecdsa", "payload_v2-eddsa" or "legacy"
    pub form: String,
    /// lowercase hex of the payload bytes
    pub payload: String,
    pub path: String,
    /// the legacy key_version, or domain_id in the current form
    pub key_version: u32,
    pub block_height: u64,
    /// yoctoNEAR attached, as a decimal string
    pub deposit: String,
}

#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct SignerStandin {
    requests: Vector<Record>,
}

fn hex_bytes(s: &str) -> Vec<u8> {
    require!(s.len() % 2 == 0, "payload hex must have an even number of characters");
    let digit = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => env::panic_str("payload must be hex"),
        }
    };
    s.as_bytes().chunks(2).map(|p| digit(p[0]) * 16 + digit(p[1])).collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[near]
impl SignerStandin {
    #[init]
    pub fn new() -> Self {
        Self { requests: Vector::new(StorageKey::Requests) }
    }

    /// Same method name and argument as `v1.signer`'s `sign`. Records the request and returns a
    /// fake signature that says it is fake.
    #[payable]
    pub fn sign(&mut self, request: SignRequestArgs) -> near_sdk::serde_json::Value {
        require!(env::attached_deposit() >= NearToken::from_yoctonear(1), "sign needs at least 1 yoctoNEAR attached");
        require!(env::prepaid_gas() >= MIN_SIGN_GAS, "sign needs at least 10 TGas attached");
        let (form, bytes, version) = match (&request.payload_v2, &request.payload) {
            (Some(_), Some(_)) => env::panic_str("give payload_v2 or payload, not both"),
            (None, None) => env::panic_str("a sign request needs payload_v2 (or the older payload)"),
            (Some(p), None) => {
                require!(request.key_version.is_none(), "key_version belongs to the older form; use domain_id with payload_v2");
                let domain = request.domain_id.unwrap_or_else(|| env::panic_str("payload_v2 needs domain_id"));
                match p {
                    PayloadV2::Ecdsa(h) => {
                        require!(domain == 0, "an Ecdsa payload needs domain_id 0 (secp256k1)");
                        let b = hex_bytes(h);
                        require!(b.len() == 32, "an Ecdsa payload must be exactly 32 bytes");
                        ("payload_v2-ecdsa", b, domain as u32)
                    }
                    PayloadV2::Eddsa(h) => {
                        require!(domain == 1, "an Eddsa payload needs domain_id 1 (ed25519)");
                        let b = hex_bytes(h);
                        require!((EDDSA_MIN..=EDDSA_MAX).contains(&b.len()), "an Eddsa payload must be 32 to 1232 bytes");
                        ("payload_v2-eddsa", b, domain as u32)
                    }
                }
            }
            (None, Some(b)) => {
                require!(request.domain_id.is_none(), "domain_id belongs to payload_v2; use key_version with the older payload");
                require!(b.len() == 32, "the older payload must be exactly 32 bytes");
                ("legacy", b.clone(), request.key_version.unwrap_or(0))
            }
        };
        let index = self.requests.len() as u64;
        let rec = Record {
            index,
            predecessor: env::predecessor_account_id(),
            form: form.to_string(),
            payload: to_hex(&bytes),
            path: request.path.clone(),
            key_version: version,
            block_height: env::block_height(),
            deposit: env::attached_deposit().as_yoctonear().to_string(),
        };
        env::log_str(&format!(
            "ARENA_SIGNER_STANDIN request #{index} from {} form={form} payload={} path={:?} key_version={version} (recorded; no signature produced)",
            rec.predecessor, rec.payload, rec.path
        ));
        self.requests.push(rec);
        near_sdk::serde_json::json!({
            "scheme": if form == "payload_v2-eddsa" { "Ed25519" } else { "Secp256k1" },
            "big_r": {"affine_point": "00".repeat(33)},
            "s": {"scalar": "00".repeat(32)},
            "recovery_id": 0,
            "arena_stand_in": NOT_A_SIGNATURE,
        })
    }

    pub fn request_count(&self) -> u64 {
        self.requests.len() as u64
    }

    pub fn requests(&self, from_index: u64, limit: u64) -> Vec<Record> {
        let n = self.requests.len() as u64;
        let end = n.min(from_index.saturating_add(limit.min(MAX_PAGE)));
        (from_index..end).filter_map(|i| self.requests.get(i as u32).cloned()).collect()
    }

    /// The real contract returns its root public key. The stand-in has none.
    pub fn public_key(&self, domain_id: Option<u64>) -> String {
        let _ = domain_id;
        "arena-signer-standin: no key (not the MPC network)".to_string()
    }

    /// The real contract derives a public key from (predecessor, path). The stand-in has none.
    pub fn derived_public_key(&self, path: String, predecessor: Option<AccountId>, domain_id: Option<u64>) -> String {
        let _ = (path, predecessor, domain_id);
        "arena-signer-standin: no key (not the MPC network)".to_string()
    }
}
