use crate::sia::address::Address;
use crate::sia::encoding::{Encodable, Encoder};
use crate::sia::spend_policy::{SpendPolicy, UnlockCondition};
use ed25519_dalek::Signature;
use rpc::v1::types::H256;

#[cfg(test)] use ed25519_dalek::PublicKey;
#[cfg(test)] use std::str::FromStr;

type SiacoinOutputID = H256;

#[derive(Clone)]
pub struct Currency {
    lo: u64,
    hi: u64,
}

pub enum CurrencyVersion {
    V1(Currency),
    V2(Currency),
}

impl Currency {
    pub fn new(lo: u64, hi: u64) -> Self { Currency { lo, hi } }
}

impl From<u64> for Currency {
    fn from(value: u64) -> Self { Currency { lo: value, hi: 0 } }
}

impl Encodable for CurrencyVersion {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            CurrencyVersion::V1(currency) => currency.encode(encoder),
            CurrencyVersion::V2(currency) => {
                encoder.write_u64(currency.lo);
                encoder.write_u64(currency.hi);
            },
        }
    }
}

impl Encodable for Currency {
    fn encode(&self, encoder: &mut Encoder) {
        let mut buffer = [0u8; 16];

        buffer[8..].copy_from_slice(&self.lo.to_be_bytes());
        buffer[..8].copy_from_slice(&self.hi.to_be_bytes());

        // Trim leading zero bytes from the buffer
        let trimmed_buf = match buffer.iter().position(|&x| x != 0) {
            Some(index) => &buffer[index..],
            None => &buffer[..], // In case all bytes are zero
        };
        encoder.write_len_prefixed_bytes(trimmed_buf);
    }
}

pub struct SatisfiedPolicy {
    pub policy: SpendPolicy,
    pub signatures: Vec<Signature>,
    pub preimages: Vec<Vec<u8>>,
}

pub struct StateElement {
    pub id: H256,
    pub leaf_index: u64,
    pub merkle_proof: Vec<H256>,
}

impl Encodable for StateElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.id.encode(encoder);
        encoder.write_u64(self.leaf_index);
        encoder.write_u64(self.merkle_proof.len() as u64);
        for proof in &self.merkle_proof {
            proof.encode(encoder);
        }
    }
}

pub struct SiacoinElement {
    pub state_element: StateElement,
    pub siacoin_output: SiacoinOutput,
    pub maturity_height: u64,
}

impl Encodable for SiacoinElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.state_element.encode(encoder);
        SiacoinOutputVersion::V2(self.siacoin_output.clone()).encode(encoder);
        encoder.write_u64(self.maturity_height);
    }
}

pub enum SiacoinInput {
    V1(SiacoinInputV1),
    V2(SiacoinInputV2),
}

// https://github.com/SiaFoundation/core/blob/6c19657baf738c6b730625288e9b5413f77aa659/types/types.go#L197-L198
pub struct SiacoinInputV1 {
    pub parent_id: SiacoinOutputID,
    pub unlock_condition: UnlockCondition,
}

pub struct SiacoinInputV2 {
    pub parent: SiacoinElement,
    pub satisfied_policy: SatisfiedPolicy,
}

impl Encodable for SiacoinInputV1 {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent_id.encode(encoder);
        self.unlock_condition.encode(encoder);
    }
}

impl Encodable for SiacoinInputV2 {
    fn encode(&self, encoder: &mut Encoder) { self.parent.encode(encoder); }
}

impl Encodable for SiacoinInput {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            SiacoinInput::V1(v1) => v1.encode(encoder),
            SiacoinInput::V2(v2) => v2.encode(encoder),
        }
    }
}

// SiacoinOutput remains the same data structure between V1 and V2 however the encoding changes
pub enum SiacoinOutputVersion {
    V1(SiacoinOutput),
    V2(SiacoinOutput),
}

#[derive(Clone)]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

impl Encodable for SiacoinOutput {
    fn encode(&self, encoder: &mut Encoder) {
        self.value.encode(encoder);
        self.address.encode(encoder);
    }
}

impl Encodable for SiacoinOutputVersion {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            SiacoinOutputVersion::V1(v1) => {
                v1.encode(encoder);
            },
            SiacoinOutputVersion::V2(v2) => {
                CurrencyVersion::V2(v2.value.clone()).encode(encoder);
                v2.address.encode(encoder);
            },
        }
    }
}

pub struct FileContract {
    pub filesize: u64,
    pub file_merkle_root: H256,
    pub window_start: u64,
    pub window_end: u64,
    pub payout: Currency,
    pub valid_proof_outputs: Vec<SiacoinOutput>,
    pub missed_proof_outputs: Vec<SiacoinOutput>,
    pub unlock_hash: H256,
    pub revision_number: u64,
}

// TODO temporary stubs
type FileContractRevision = Vec<u8>;
type StorageProof = Vec<u8>;
type SiafundInput = Vec<u8>;
type SiafundOutput = Vec<u8>;
type TransactionSignature = Vec<u8>;

pub struct TransactionV1 {
    pub siacoin_inputs: Vec<SiacoinInput>,
    pub siacoin_outputs: Vec<SiacoinOutput>,
    pub file_contracts: Vec<FileContract>,
    pub file_contract_revisions: Vec<FileContractRevision>,
    pub storage_proofs: Vec<StorageProof>,
    pub siafund_inputs: Vec<SiafundInput>,
    pub siafund_outputs: Vec<SiafundOutput>,
    pub miner_fees: Vec<Currency>,
    pub arbitrary_data: Vec<Vec<u8>>,
    pub signatures: Vec<TransactionSignature>,
}

#[test]
fn test_siacoin_input_encode() {
    let public_key = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let unlock_condition = UnlockCondition::new(vec![public_key], 0, 1);

    let vin = SiacoinInputV1 {
        parent_id: H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
        unlock_condition,
    };

    let hash = Encoder::encode_and_hash(&vin);
    let expected = H256::from("1d4b77aaa82c71ca68843210679b380f9638f8bec7addf0af16a6536dd54d6b4");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v1() {
    let currency: Currency = 1.into();

    let hash = Encoder::encode_and_hash(&currency);
    let expected = H256::from("a1cc3a97fc1ebfa23b0b128b153a29ad9f918585d1d8a32354f547d8451b7826");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v2() {
    let currency: Currency = 1.into();

    let hash = Encoder::encode_and_hash(&CurrencyVersion::V2(currency));
    let expected = H256::from("a3865e5e284e12e0ea418e73127db5d1092bfb98ed372ca9a664504816375e1d");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v1_max() {
    let currency = Currency::new(u64::MAX, u64::MAX);

    let hash = Encoder::encode_and_hash(&currency);
    let expected = H256::from("4b9ed7269cb15f71ddf7238172a593a8e7ffe68b12c1bf73d67ac8eec44355bb");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v2_max() {
    let currency = Currency::new(u64::MAX, u64::MAX);

    let hash = Encoder::encode_and_hash(&CurrencyVersion::V2(currency));
    let expected = H256::from("681467b3337425fd38fa3983531ca1a6214de9264eebabdf9c9bc5d157d202b4");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_output_encode_v1() {
    let vout = SiacoinOutput {
        value: 1.into(),
        address: Address::from_str("addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a")
            .unwrap(),
    };

    let hash = Encoder::encode_and_hash(&vout);
    let expected = H256::from("3253c57e76600721f2bdf03497a71ed47c09981e22ef49aed92e40da1ea91b28");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_output_encode_v2() {
    let vout = SiacoinOutput {
        value: 1.into(),
        address: Address::from_str("addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a")
            .unwrap(),
    };
    let wrapped_vout = SiacoinOutputVersion::V2(vout);

    let hash = Encoder::encode_and_hash(&wrapped_vout);
    let expected = H256::from("c278eceae42f594f5f4ca52c8a84b749146d08af214cc959ed2aaaa916eaafd3");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_element_encode() {
    let state_element = StateElement {
        id: H256::from("0102030000000000000000000000000000000000000000000000000000000000"),
        leaf_index: 1,
        merkle_proof: vec![
            H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
            H256::from("0708090000000000000000000000000000000000000000000000000000000000"),
        ],
    };
    let siacoin_element = SiacoinElement {
        state_element,
        siacoin_output: SiacoinOutput {
            value: 1.into(),
            address: Address::from_str(
                "addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a",
            )
            .unwrap(),
        },
        maturity_height: 0,
    };

    let hash = Encoder::encode_and_hash(&siacoin_element);
    let expected = H256::from("3c867a54b7b3de349c56585f25a4365f31d632c3e42561b615055c77464d889e");
    assert_eq!(hash, expected);
}

#[test]
fn test_state_element_encode() {
    let state_element = StateElement {
        id: H256::from("0102030000000000000000000000000000000000000000000000000000000000"),
        leaf_index: 1,
        merkle_proof: vec![
            H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
            H256::from("0708090000000000000000000000000000000000000000000000000000000000"),
        ],
    };

    let hash = Encoder::encode_and_hash(&state_element);
    let expected = H256::from("bf6d7b74fb1e15ec4e86332b628a450e387c45b54ea98e57a6da8c9af317e468");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_input_encode_v1() {
    let vin = SiacoinInputV1 {
        parent_id: H256::default(),
        unlock_condition: UnlockCondition::new(vec![], 0, 0),
    };
    let vin_wrapped = SiacoinInput::V1(vin);

    let hash = Encoder::encode_and_hash(&vin_wrapped);
    let expected = H256::from("2f806f905436dc7c5079ad8062467266e225d8110a3c58d17628d609cb1c99d0");
    assert_eq!(hash, expected);
}

#[test]
#[ignore] // FIXME WIP
fn test_siacoin_input_encode_v2() {
    let policy = SpendPolicy::Above(0);

    let vin = SiacoinInputV2 {
        parent: SiacoinElement {
            state_element: StateElement {
                id: H256::default(),
                leaf_index: 0,
                merkle_proof: vec![],
            },
            siacoin_output: SiacoinOutput {
                value: 1.into(),
                address: Address::from_str(
                    "addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a",
                )
                .unwrap(),
            },
            maturity_height: 0,
        },
        satisfied_policy: SatisfiedPolicy {
            policy,
            signatures: vec![],
            preimages: vec![],
        },
    };
    let vin_wrapped = SiacoinInput::V2(vin);

    let hash = Encoder::encode_and_hash(&vin_wrapped);
    let expected = H256::from("2f806f905436dc7c5079ad8062467266e225d8110a3c58d17628d609cb1c99d0");
    assert_eq!(hash, expected);
}
