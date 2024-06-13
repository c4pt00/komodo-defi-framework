use crate::sia::address::Address;
use crate::sia::encoding::{Encodable, Encoder};
use crate::sia::spend_policy::{SpendPolicy, UnlockCondition};
use ed25519_dalek::{PublicKey, Signature};
use rpc::v1::types::H256;

#[cfg(test)]
use crate::sia::spend_policy::{spend_policy_atomic_swap_refund, spend_policy_atomic_swap_success, PolicyTypeThreshold};
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

impl Encodable for Signature {
    fn encode(&self, encoder: &mut Encoder) { encoder.write_slice(&self.to_bytes()); }
}

impl Encodable for SatisfiedPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.policy.encode(encoder);
        let mut sigi: usize = 0;
        let mut prei: usize = 0;

        fn rec(policy: &SpendPolicy, encoder: &mut Encoder, sigi: &mut usize, prei: &mut usize, sp: &SatisfiedPolicy) {
            match policy {
                SpendPolicy::PublicKey(_) => {
                    sp.signatures[*sigi].encode(encoder);
                    *sigi += 1;
                },
                SpendPolicy::Hash(_) => {
                    encoder.write_len_prefixed_bytes(&sp.preimages[*prei]);
                    *prei += 1;
                },
                SpendPolicy::Threshold(threshold) => {
                    for p in &threshold.of {
                        rec(p, encoder, sigi, prei, sp);
                    }
                },
                SpendPolicy::UnlockConditions(uc) => {
                    for unlock_key in &uc.unlock_keys {
                        rec(&SpendPolicy::PublicKey(unlock_key.public_key), encoder, sigi, prei, sp);
                    }
                },
                _ => {},
            }
        }

        rec(&self.policy, encoder, &mut sigi, &mut prei, self);
    }
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
fn test_signature_encode() {
    let signature = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();

    let hash = Encoder::encode_and_hash(&signature);
    let expected = H256::from("1e6952fe04eb626ae759a0090af2e701ba35ee6ad15233a2e947cb0f7ae9f7c7");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_public_key() {
    let public_key = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();

    let policy = SpendPolicy::PublicKey(public_key);

    let signature = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![signature],
        preimages: vec![],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("51832be911c7382502a2011cbddf1a9f689c4ca08c6a83ae3d021fb0dc781822");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_hash_empty() {
    let policy = SpendPolicy::Hash(H256::default());

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![],
        preimages: vec![vec![]], // vec!(1u8, 2u8, 3u8, 4u8)
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("86b4b84950016d711732617d2501bd22e41614535f2705a65bd5b0e95c992a44");
    assert_eq!(hash, expected);
}

// Adding a signature to SatisfiedPolicy of PolicyHash should have no effect
#[test]
fn test_satisfied_policy_encode_hash_frivulous_signature() {
    let policy = SpendPolicy::Hash(H256::default());

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec!(Signature::from_bytes(
            &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap()),
        preimages: vec!(vec!(1u8, 2u8, 3u8, 4u8)),
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("7424653d0ca3ffded9a029bebe75f9ae9c99b5f284e23e9d07c0b03456f724f9");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_hash() {
    let policy = SpendPolicy::Hash(H256::default());

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![],
        preimages: vec![vec![1u8, 2u8, 3u8, 4u8]],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("7424653d0ca3ffded9a029bebe75f9ae9c99b5f284e23e9d07c0b03456f724f9");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_unlock_condition_standard() {
    let pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();

    let unlock_condition = UnlockCondition::new(vec![pubkey], 0, 1);

    let policy = SpendPolicy::UnlockConditions(unlock_condition);

    let signature = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![signature],
        preimages: vec![],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("c749f9ac53395ec557aed7e21d202f76a58e0de79222e5756b27077e9295931f");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_unlock_condition_complex() {
    let pubkey0 = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let pubkey1 = PublicKey::from_bytes(
        &hex::decode("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").unwrap(),
    )
    .unwrap();
    let pubkey2 = PublicKey::from_bytes(
        &hex::decode("BE043906FD42297BC0A03CAA6E773EF27FC644261C692D090181E704BE4A88C3").unwrap(),
    )
    .unwrap();

    let unlock_condition = UnlockCondition::new(vec![pubkey0, pubkey1, pubkey2], 77777777, 3);

    let policy = SpendPolicy::UnlockConditions(unlock_condition);

    let sig0 = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();
    let sig1 = Signature::from_bytes(
        &hex::decode("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A").unwrap()).unwrap();
    let sig2 = Signature::from_bytes(
        &hex::decode("482A2A905D7A6FC730387E06B45EA0CF259FCB219C9A057E539E705F60AC36D7079E26DAFB66ED4DBA9B9694B50BCA64F1D4CC4EBE937CE08A34BF642FAC1F0C").unwrap()).unwrap();

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![sig0, sig1, sig2],
        preimages: vec![],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("13806b6c13a97478e476e0e5a0469c9d0ad8bf286bec0ada992e363e9fc60901");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_threshold_simple() {
    let sub_policy = SpendPolicy::Hash(H256::default());
    let policy = SpendPolicy::Threshold(PolicyTypeThreshold {
        n: 1,
        of: vec![sub_policy],
    });

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![],
        preimages: vec![vec![1u8, 2u8, 3u8, 4u8]],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("50f4808b0661f56842472aed259136a43ed2bd7d59a88a3be28de9883af4a92d");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_threshold_atomic_swap_success() {
    let alice_pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let bob_pubkey = PublicKey::from_bytes(
        &hex::decode("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").unwrap(),
    )
    .unwrap();

    let secret_hash = H256::from("0100000000000000000000000000000000000000000000000000000000000000");

    let policy = spend_policy_atomic_swap_success(alice_pubkey, bob_pubkey, 77777777, secret_hash);
    let signature = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![signature],
        preimages: vec![vec![1u8, 2u8, 3u8, 4u8]],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("c835e516bbf76602c897a9160c17bfe0e4a8bc9044f62b3e5e45a381232a2f86");
    assert_eq!(hash, expected);
}

#[test]
fn test_satisfied_policy_encode_threshold_atomic_swap_refund() {
    let alice_pubkey = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let bob_pubkey = PublicKey::from_bytes(
        &hex::decode("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").unwrap(),
    )
    .unwrap();

    let secret_hash = H256::from("0100000000000000000000000000000000000000000000000000000000000000");

    let policy = spend_policy_atomic_swap_refund(alice_pubkey, bob_pubkey, 77777777, secret_hash);
    let signature = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();

    let satisfied_policy = SatisfiedPolicy {
        policy,
        signatures: vec![signature],
        preimages: vec![vec![1u8, 2u8, 3u8, 4u8]],
    };

    let hash = Encoder::encode_and_hash(&satisfied_policy);
    let expected = H256::from("8975e8cf990d5a20d9ec3dae18ed3b3a0c92edf967a8d93fcdef6a1eb73bb348");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_input_encode_v2() {
    let sub_policy = SpendPolicy::Hash(H256::default());
    let policy = SpendPolicy::Threshold(PolicyTypeThreshold {
        n: 1,
        of: vec![sub_policy],
    });

    let satisfied_policy = SatisfiedPolicy {
        policy: policy.clone(),
        signatures: vec![],
        preimages: vec![vec![1u8, 2u8, 3u8, 4u8]],
    };

    let vin = SiacoinInputV2 {
        parent: SiacoinElement {
            state_element: StateElement {
                id: H256::default(),
                leaf_index: 0,
                merkle_proof: vec![H256::default()],
            },
            siacoin_output: SiacoinOutput {
                value: 1.into(),
                address: policy.address(),
            },
            maturity_height: 0,
        },
        satisfied_policy,
    };
    let vin_wrapped = SiacoinInput::V2(vin);

    let hash = Encoder::encode_and_hash(&vin_wrapped);
    let expected = H256::from("a8ab11b91ee19ce68f2d608bd4d19212841842f0c50151ae4ccb8e9db68cd6c4");
    assert_eq!(hash, expected);
}
