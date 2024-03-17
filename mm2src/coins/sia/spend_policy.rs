// use super::address::v1_standard_address_from_pubkey;
use crate::sia::blake2b_internal::{Accumulator, timelock_leaf, public_key_leaf, sigs_required_leaf, standard_unlock_hash};
use crate::sia::address::Address;
use ed25519_dalek::PublicKey;
use rpc::v1::types::H256;
pub trait Policy {}

pub enum SpendPolicy {
    Above(PolicyTypeAbove),
    After(PolicyTypeAfter),
    PublicKey(PolicyTypePublicKey),
    Hash(PolicyTypeHash),
    Threshold(PolicyTypeThreshold),
    Opaque(PolicyTypeOpaque),
    UnlockConditions(PolicyTypeUnlockConditions), // For v1 compatibility
}

impl Policy for SpendPolicy {}

pub struct PolicyTypeAbove(u64);

pub struct PolicyTypeAfter(u64);
pub struct PolicyTypePublicKey(PublicKey);

pub struct PolicyTypeHash(H256);

pub struct PolicyTypeThreshold {
    pub n: u8,
    pub of: Vec<SpendPolicy>,
}

pub struct PolicyTypeOpaque(Address);

// Compatibility with Sia's "UnlockConditions"
pub struct PolicyTypeUnlockConditions(UnlockCondition);

#[derive(Debug)]
pub struct UnlockCondition {
    pubkeys: Vec<PublicKey>,
    timelock: u64,
    sigs_required: u64,
}

impl UnlockCondition {
    pub fn new(pubkeys: Vec<PublicKey>, timelock: u64, sigs_required: u64) -> Self {
        // TODO check go implementation to see if there should be limitations or checks imposed here
        UnlockCondition { pubkeys, timelock, sigs_required }
    }

    pub fn unlock_hash(&self) -> H256 {
        // almost all UnlockConditions are standard, so optimize for that case
        if self.timelock == 0 && self.pubkeys.len() == 1 && self.sigs_required == 1{
            return standard_unlock_hash(&self.pubkeys[0]);
        }

        let mut accumulator = Accumulator::default();

        accumulator.add_leaf(timelock_leaf(self.timelock));

        for pubkey in &self.pubkeys {
            accumulator.add_leaf(public_key_leaf(pubkey));
        }
        
        accumulator.add_leaf(sigs_required_leaf(self.sigs_required));
        accumulator.root()
    }

    pub fn address(&self) -> Address {
        Address(self.unlock_hash())
    }
}

impl SpendPolicy {
    pub fn above(height: u64) -> Self { SpendPolicy::Above(PolicyTypeAbove(height)) }

    pub fn after(time: u64) -> Self { SpendPolicy::After(PolicyTypeAfter(time)) }

    pub fn public_key(pk: PublicKey) -> Self { SpendPolicy::PublicKey(PolicyTypePublicKey(pk)) }

    pub fn hash(h: H256) -> Self { SpendPolicy::Hash(PolicyTypeHash(h)) }

    pub fn threshold(n: u8, of: Vec<SpendPolicy>) -> Self { SpendPolicy::Threshold(PolicyTypeThreshold { n, of }) }

    pub fn opaque(_p: SpendPolicy) -> Self { unimplemented!() }

    pub fn anyone_can_spend() -> Self { SpendPolicy::threshold(0, vec![]) }

    pub fn address(self) -> Address { unimplemented!() }
}

#[test]
fn test_unlock_condition_unlock_hash_standard() {
    let pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let unlock_condition = UnlockCondition::new(vec![pubkey], 0, 1);

    let hash = unlock_condition.unlock_hash();
    let expected = H256::from("72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515d");
    assert_eq!(hash, expected);
}

#[test]
fn test_unlock_condition_unlock_hash_2of2_multisig() {
    let pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let pubkey2 = PublicKey::from_bytes(
        &hex::decode("0101010000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let unlock_condition = UnlockCondition::new(vec![pubkey, pubkey2], 0, 2);

    let hash = unlock_condition.unlock_hash();
    let expected = H256::from("1e94357817d236167e54970a8c08bbd41b37bfceeeb52f6c1ce6dd01d50ea1e7");
    assert_eq!(hash, expected);
}

#[test]
fn test_unlock_condition_unlock_hash_1of2_multisig() {
    let pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let pubkey2 = PublicKey::from_bytes(
        &hex::decode("0101010000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let unlock_condition = UnlockCondition::new(vec![pubkey, pubkey2], 0, 1);

    let hash = unlock_condition.unlock_hash();
    let expected = H256::from("d7f84e3423da09d111a17f64290c8d05e1cbe4cab2b6bed49e3a4d2f659f0585");
    assert_eq!(hash, expected);
}