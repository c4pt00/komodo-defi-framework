// use super::address::v1_standard_address_from_pubkey;
// use crate::sia::blake2b_internal::unlock_hash;
#![allow(dead_code)] // FIXME Alright
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
pub struct PolicyTypeUnlockConditions {
    pubkeys: Vec<PublicKey>,
    timelock: u64,
    sigs_required: u64,
}

impl SpendPolicy {
    pub fn above(height: u64) -> Self { SpendPolicy::Above(PolicyTypeAbove(height)) }

    pub fn after(time: u64) -> Self { SpendPolicy::After(PolicyTypeAfter(time)) }

    pub fn public_key(pk: PublicKey) -> Self { SpendPolicy::PublicKey(PolicyTypePublicKey(pk)) }

    pub fn hash(h: H256) -> Self { SpendPolicy::Hash(PolicyTypeHash(h)) }

    pub fn threshold(n: u8, of: Vec<SpendPolicy>) -> Self { SpendPolicy::Threshold(PolicyTypeThreshold { n, of }) }

    pub fn opaque(p: SpendPolicy) -> Self { unimplemented!() }

    pub fn anyone_can_spend() -> Self { SpendPolicy::threshold(0, vec![]) }

    pub fn address(self) -> Address { unimplemented!() }
}
