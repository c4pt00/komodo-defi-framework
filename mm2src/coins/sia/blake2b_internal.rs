#![allow(dead_code)]
use blake2b_simd::Params;
use ed25519_dalek::PublicKey;
use rpc::v1::types::H256;

#[cfg(test)] use hex;
#[cfg(test)] use std::convert::TryInto;

const LEAF_HASH_PREFIX: [u8; 1] = [0u8];
const NODE_HASH_PREFIX: [u8; 1] = [1u8];

const ED25519_IDENTIFIER: [u8; 16] = [
    0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

// Precomputed hash values used for all standard v1 addresses
// a standard address has 1 ed25519 public key, requires 1 signature and has a timelock of 0
// https://github.com/SiaFoundation/core/blob/b5b08cde6b7d0f1b3a6f09b8aa9d0b817e769efb/types/hash.go#L94
const STANDARD_TIMELOCK_BLAKE2B_HASH: [u8; 32] = [
    0x51, 0x87, 0xb7, 0xa8, 0x02, 0x1b, 0xf4, 0xf2, 0xc0, 0x04, 0xea, 0x3a, 0x54, 0xcf, 0xec, 0xe1, 0x75, 0x4f, 0x11,
    0xc7, 0x62, 0x4d, 0x23, 0x63, 0xc7, 0xf4, 0xcf, 0x4f, 0xdd, 0xd1, 0x44, 0x1e,
];
const STANDARD_SIGS_REQUIRED_BLAKE2B_HASH: [u8; 32] = [
    0xb3, 0x60, 0x10, 0xeb, 0x28, 0x5c, 0x15, 0x4a, 0x8c, 0xd6, 0x30, 0x84, 0xac, 0xbe, 0x7e, 0xac, 0x0c, 0x4d, 0x62,
    0x5a, 0xb4, 0xe1, 0xa7, 0x6e, 0x62, 0x4a, 0x87, 0x98, 0xcb, 0x63, 0x49, 0x7b,
];

// pub struct Accumulator {
//     trees: [[u8; 32]; 64],
//     num_leaves: u64,
// }

fn sigs_required_leaf(sigs_required: u64) -> H256 {
    let sigs_required_array: [u8; 8] = sigs_required.to_le_bytes();
    let mut combined = Vec::new();
    combined.extend_from_slice(&LEAF_HASH_PREFIX);
    combined.extend_from_slice(&sigs_required_array);

    hash_blake2b_single(&combined)
}

// public key leaf is
// blake2b(leafHashPrefix + 16_byte_ascii_algorithm_identifier + public_key_length_u64 + public_key)
fn public_key_leaf(pubkey: &PublicKey) -> H256 {
    let mut combined = Vec::new();
    combined.extend_from_slice(&LEAF_HASH_PREFIX);
    combined.extend_from_slice(&ED25519_IDENTIFIER);
    combined.extend_from_slice(&32u64.to_le_bytes());
    combined.extend_from_slice(pubkey.as_bytes());
    hash_blake2b_single(&combined)
}

fn timelock_leaf(timelock: u64) -> H256 {
    let timelock: [u8; 8] = timelock.to_le_bytes();
    let mut combined = Vec::new();
    combined.extend_from_slice(&LEAF_HASH_PREFIX);
    combined.extend_from_slice(&timelock);

    hash_blake2b_single(&combined)
}

// https://github.com/SiaFoundation/core/blob/b5b08cde6b7d0f1b3a6f09b8aa9d0b817e769efb/types/hash.go#L96
// An UnlockHash is the Merkle root of UnlockConditions. Since the standard
// UnlockConditions use a single public key, the Merkle tree is:
//
//           ┌─────────┴──────────┐
//     ┌─────┴─────┐              │
//  timelock     pubkey     sigsrequired
pub fn unlock_hash(pubkey: &PublicKey, timelock: u64, sigs_required: u64) -> H256 {
    let pubkey_leaf = public_key_leaf(pubkey);
    let timelock_leaf = timelock_leaf(timelock);
    let sigs_required_leaf = sigs_required_leaf(sigs_required);
    let timelock_pubkey_node = hash_blake2b_pair(&NODE_HASH_PREFIX, &timelock_leaf.0, &pubkey_leaf.0);
    hash_blake2b_pair(&NODE_HASH_PREFIX, &timelock_pubkey_node.0, &sigs_required_leaf.0)
}

pub fn standard_unlock_hash(pubkey: &PublicKey) -> H256 { unlock_hash(pubkey, 0u64, 1u64) }

#[test]
fn test_standard_unlock_hash() {
    let pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();

    let hash = standard_unlock_hash(&pubkey);
    let expected = H256::from("72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515d");
    assert_eq!(hash, expected)
}

fn hash_blake2b_single(preimage: &[u8]) -> H256 {
    let hash = Params::new().hash_length(32).to_state().update(preimage).finalize();
    let ret_array = hash.as_array();
    ret_array[0..32].into()
}

fn hash_blake2b_pair(prefix: &[u8], leaf1: &[u8], leaf2: &[u8]) -> H256 {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(prefix)
        .update(leaf1)
        .update(leaf2)
        .finalize();
    let ret_array = hash.as_array();
    ret_array[0..32].into()
}

#[test]
fn test_hash_blake2b_pair() {
    let left: [u8; 32] = hex::decode("cdcce3978a58ceb6c8480d218646db4eae85eb9ea9c2f5138fbacb4ce2c701e3")
        .unwrap()
        .try_into()
        .unwrap();
    let right: [u8; 32] = hex::decode("b36010eb285c154a8cd63084acbe7eac0c4d625ab4e1a76e624a8798cb63497b")
        .unwrap()
        .try_into()
        .unwrap();

    let hash = hash_blake2b_pair(&NODE_HASH_PREFIX, &left, &right);
    let expected = H256::from("72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515d");
    assert_eq!(hash, expected)
}

#[test]
fn test_create_ed25519_identifier() {
    let mut ed25519_identifier: [u8; 16] = [0; 16];

    let bytes = "ed25519".as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        ed25519_identifier[i] = byte;
    }
    assert_eq!(ed25519_identifier, ED25519_IDENTIFIER);
}

#[test]
fn test_timelock_leaf() {
    let hash = timelock_leaf(0);
    let expected = H256::from(STANDARD_TIMELOCK_BLAKE2B_HASH);
    assert_eq!(hash, expected)
}

#[test]
fn test_sigs_required_leaf() {
    let hash = sigs_required_leaf(1u64);
    let expected = H256::from(STANDARD_SIGS_REQUIRED_BLAKE2B_HASH);
    assert_eq!(hash, expected)
}

#[test]
fn test_hash_blake2b_single() {
    let hash = hash_blake2b_single(&hex::decode("006564323535313900000000000000000020000000000000000102030000000000000000000000000000000000000000000000000000000000").unwrap());
    let expected = H256::from("21ce940603a2ee3a283685f6bfb4b122254894fd1ed3eb59434aadbf00c75d5b");
    assert_eq!(hash, expected)
}

#[test]
fn test_public_key_leaf() {
    let pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();

    let hash = public_key_leaf(&pubkey);
    let expected = H256::from("21ce940603a2ee3a283685f6bfb4b122254894fd1ed3eb59434aadbf00c75d5b");
    assert_eq!(hash, expected)
}
