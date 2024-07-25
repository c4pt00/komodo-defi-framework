use crate::encoding::{Encodable, Encoder, HexArray64, PrefixedH256, PrefixedPublicKey, PrefixedSignature};
use crate::spend_policy::{SpendPolicy, SpendPolicyHelper, UnlockCondition, UnlockKey};
use crate::types::{Address, ChainIndex};
use ed25519_dalek::{PublicKey, Signature};
use rpc::v1::types::H256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_with::{serde_as, FromInto};
use std::str::FromStr;

#[cfg(test)]
use crate::spend_policy::{spend_policy_atomic_swap_refund, spend_policy_atomic_swap_success};
#[cfg(test)] use crate::types::v1_standard_address_from_pubkey;

type SiacoinOutputID = H256;
const V2_REPLAY_PREFIX: u8 = 2;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Currency {
    lo: u64,
    hi: u64,
}

// TODO does this also need to be able to deserialize from an integer?
// walletd API returns this as a string
impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CurrencyVisitor;

        impl<'de> serde::de::Visitor<'de> for CurrencyVisitor {
            type Value = Currency;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing a u128 value")
            }

            fn visit_str<E>(self, value: &str) -> Result<Currency, E>
            where
                E: serde::de::Error,
            {
                let u128_value = u128::from_str(value).map_err(E::custom)?;
                let lo = u128_value as u64;
                let hi = (u128_value >> 64) as u64;
                Ok(Currency::new(lo, hi))
            }
        }

        deserializer.deserialize_str(CurrencyVisitor)
    }
}

impl Serialize for Currency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_u128().to_string())
    }
}

impl Currency {
    pub fn new(lo: u64, hi: u64) -> Self { Currency { lo, hi } }

    pub fn to_u128(&self) -> u128 { ((self.hi as u128) << 64) | (self.lo as u128) }
}

impl From<u64> for Currency {
    fn from(value: u64) -> Self { Currency { lo: value, hi: 0 } }
}

// Currency remains the same data structure between V1 and V2 however the encoding changes
#[derive(Clone, Debug)]
pub enum CurrencyVersion<'a> {
    V1(&'a Currency),
    V2(&'a Currency),
}

impl<'a> Encodable for CurrencyVersion<'a> {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            CurrencyVersion::V1(currency) => {
                let mut buffer = [0u8; 16];

                buffer[8..].copy_from_slice(&currency.lo.to_be_bytes());
                buffer[..8].copy_from_slice(&currency.hi.to_be_bytes());

                // Trim leading zero bytes from the buffer
                let trimmed_buf = match buffer.iter().position(|&x| x != 0) {
                    Some(index) => &buffer[index..],
                    None => &buffer[..], // In case all bytes are zero
                };
                encoder.write_len_prefixed_bytes(trimmed_buf);
            },
            CurrencyVersion::V2(currency) => {
                encoder.write_u64(currency.lo);
                encoder.write_u64(currency.hi);
            },
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SatisfiedPolicy {
    #[serde_as(as = "FromInto<SpendPolicyHelper>")]
    pub policy: SpendPolicy,
    #[serde_as(as = "Vec<FromInto<PrefixedSignature>>")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Signature>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
                    if *sigi < sp.signatures.len() {
                        sp.signatures[*sigi].encode(encoder);
                        *sigi += 1;
                    } else {
                        // Sia Go code panics here but our code assumes encoding will always be successful
                        // TODO: check if Sia Go will fix this
                        encoder.write_string("Broken PublicKey encoding, see SatisfiedPolicy::encode")
                    }
                },
                SpendPolicy::Hash(_) => {
                    if *prei < sp.preimages.len() {
                        encoder.write_len_prefixed_bytes(&sp.preimages[*prei]);
                        *prei += 1;
                    } else {
                        // Sia Go code panics here but our code assumes encoding will always be successful
                        // consider changing the signature of encode() to return a Result
                        encoder.write_string("Broken Hash encoding, see SatisfiedPolicy::encode")
                    }
                },
                SpendPolicy::Threshold { n: _, of } => {
                    for p in of {
                        rec(p, encoder, sigi, prei, sp);
                    }
                },
                SpendPolicy::UnlockConditions(uc) => {
                    for unlock_key in &uc.unlock_keys {
                        if let UnlockKey::Ed25519(public_key) = unlock_key {
                            rec(&SpendPolicy::PublicKey(*public_key), encoder, sigi, prei, sp);
                        }
                        // else FIXME consider when this is possible, is it always developer error or could it be forced maliciously?
                    }
                },
                _ => {},
            }
        }

        rec(&self.policy, encoder, &mut sigi, &mut prei, self);
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StateElement {
    #[serde_as(as = "FromInto<PrefixedH256>")]
    pub id: H256,
    pub leaf_index: u64,
    #[serde_as(as = "Option<Vec<FromInto<PrefixedH256>>>")]
    pub merkle_proof: Option<Vec<H256>>,
}

impl Encodable for StateElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.id.encode(encoder);
        encoder.write_u64(self.leaf_index);

        match &self.merkle_proof {
            Some(proof) => {
                encoder.write_u64(proof.len() as u64);
                for p in proof {
                    p.encode(encoder);
                }
            },
            None => {
                encoder.write_u64(0u64);
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiafundElement {
    #[serde(flatten)]
    pub state_element: StateElement,
    pub siafund_output: SiafundOutput,
    pub claim_start: Currency,
}

impl Encodable for SiafundElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.state_element.encode(encoder);
        SiafundOutputVersion::V2(&self.siafund_output).encode(encoder);
        CurrencyVersion::V2(&self.claim_start).encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinElement {
    #[serde(flatten)]
    pub state_element: StateElement,
    pub siacoin_output: SiacoinOutput,
    pub maturity_height: u64,
}

impl Encodable for SiacoinElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.state_element.encode(encoder);
        SiacoinOutputVersion::V2(&self.siacoin_output).encode(encoder);
        encoder.write_u64(self.maturity_height);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInputV2 {
    pub parent: SiafundElement,
    pub claim_address: Address,
    pub satisfied_policy: SatisfiedPolicy,
}

impl Encodable for SiafundInputV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent.encode(encoder);
        self.claim_address.encode(encoder);
        self.satisfied_policy.encode(encoder);
    }
}

// https://github.com/SiaFoundation/core/blob/6c19657baf738c6b730625288e9b5413f77aa659/types/types.go#L197-L198
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SiacoinInputV1 {
    pub parent_id: SiacoinOutputID,
    pub unlock_condition: UnlockCondition,
}

impl Encodable for SiacoinInputV1 {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent_id.encode(encoder);
        self.unlock_condition.encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInputV2 {
    pub parent: SiacoinElement,
    pub satisfied_policy: SatisfiedPolicy,
}

impl Encodable for SiacoinInputV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent.encode(encoder);
        self.satisfied_policy.encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SiafundOutput {
    pub value: u64,
    pub address: Address,
}

// SiafundOutput remains the same data structure between V1 and V2 however the encoding changes
#[derive(Clone, Debug)]
pub enum SiafundOutputVersion<'a> {
    V1(&'a SiafundOutput),
    V2(&'a SiafundOutput),
}

impl<'a> Encodable for SiafundOutputVersion<'a> {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            SiafundOutputVersion::V1(v1) => {
                CurrencyVersion::V1(&Currency::from(v1.value)).encode(encoder);
                v1.address.encode(encoder);
            },
            SiafundOutputVersion::V2(v2) => {
                encoder.write_u64(v2.value);
                v2.address.encode(encoder);
            },
        }
    }
}

// SiacoinOutput remains the same data structure between V1 and V2 however the encoding changes
#[derive(Clone, Debug)]
pub enum SiacoinOutputVersion<'a> {
    V1(&'a SiacoinOutput),
    V2(&'a SiacoinOutput),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

impl<'a> Encodable for SiacoinOutputVersion<'a> {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            SiacoinOutputVersion::V1(v1) => {
                CurrencyVersion::V1(&v1.value).encode(encoder);
                v1.address.encode(encoder);
            },
            SiacoinOutputVersion::V2(v2) => {
                CurrencyVersion::V2(&v2.value).encode(encoder);
                v2.address.encode(encoder);
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoveredFields {
    pub whole_transaction: bool,
    pub siacoin_inputs: Vec<u64>,
    pub siacoin_outputs: Vec<u64>,
    pub file_contracts: Vec<u64>,
    pub file_contract_revisions: Vec<u64>,
    pub storage_proofs: Vec<u64>,
    pub siafund_inputs: Vec<u64>,
    pub siafund_outputs: Vec<u64>,
    pub miner_fees: Vec<u64>,
    pub arbitrary_data: Vec<u64>,
    pub signatures: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionSignature {
    pub parent_id: H256,
    pub public_key_index: u64,
    pub timelock: u64,
    pub covered_fields: CoveredFields,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct V2FileContract {
    pub filesize: u64,
    #[serde_as(as = "FromInto<PrefixedH256>")]
    pub file_merkle_root: H256,
    pub proof_height: u64,
    pub expiration_height: u64,
    pub renter_output: SiacoinOutput,
    pub host_output: SiacoinOutput,
    pub missed_host_value: Currency,
    pub total_collateral: Currency,
    #[serde_as(as = "FromInto<PrefixedPublicKey>")]
    pub renter_public_key: PublicKey,
    #[serde_as(as = "FromInto<PrefixedPublicKey>")]
    pub host_public_key: PublicKey,
    pub revision_number: u64,
    #[serde_as(as = "FromInto<PrefixedSignature>")]
    pub renter_signature: Signature,
    #[serde_as(as = "FromInto<PrefixedSignature>")]
    pub host_signature: Signature,
}

impl V2FileContract {
    pub fn with_nil_sigs(&self) -> V2FileContract {
        debug_assert!(
            Signature::from_bytes(&[0u8; 64]).is_ok(),
            "nil signature is valid and cannot return Err"
        );
        V2FileContract {
            renter_signature: Signature::from_bytes(&[0u8; 64]).expect("Err unreachable"),
            host_signature: Signature::from_bytes(&[0u8; 64]).expect("Err unreachable"),
            ..self.clone()
        }
    }
}

impl Encodable for V2FileContract {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u64(self.filesize);
        self.file_merkle_root.encode(encoder);
        encoder.write_u64(self.proof_height);
        encoder.write_u64(self.expiration_height);
        SiacoinOutputVersion::V2(&self.renter_output).encode(encoder);
        SiacoinOutputVersion::V2(&self.host_output).encode(encoder);
        CurrencyVersion::V2(&self.missed_host_value).encode(encoder);
        CurrencyVersion::V2(&self.total_collateral).encode(encoder);
        self.renter_public_key.encode(encoder);
        self.host_public_key.encode(encoder);
        encoder.write_u64(self.revision_number);
        self.renter_signature.encode(encoder);
        self.host_signature.encode(encoder);
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct V2FileContractElement {
    #[serde(flatten)]
    pub state_element: StateElement,
    pub v2_file_contract: V2FileContract,
}

impl Encodable for V2FileContractElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.state_element.encode(encoder);
        self.v2_file_contract.encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct FileContractRevisionV2 {
    pub parent: V2FileContractElement,
    pub revision: V2FileContract,
}

impl FileContractRevisionV2 {
    pub fn with_nil_sigs(&self) -> FileContractRevisionV2 {
        FileContractRevisionV2 {
            revision: self.revision.with_nil_sigs(),
            ..self.clone()
        }
    }
}

impl Encodable for FileContractRevisionV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent.encode(encoder);
        self.revision.encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub public_key: PublicKey,
    pub key: String,
    pub value: Vec<u8>,
    pub signature: Signature,
}

impl Encodable for Attestation {
    fn encode(&self, encoder: &mut Encoder) {
        self.public_key.encode(encoder);
        encoder.write_string(&self.key);
        encoder.write_len_prefixed_bytes(&self.value);
        self.signature.encode(encoder);
    }
}
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageProof {
    pub parent_id: FileContractID,
    pub leaf: HexArray64,
    pub proof: Vec<H256>,
}

type SiafundOutputID = H256;
type FileContractID = H256;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileContractRevision {
    pub parent_id: FileContractID,
    pub unlock_condition: UnlockCondition,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SiafundInputV1 {
    pub parent_id: SiafundOutputID,
    pub unlock_condition: UnlockCondition,
    pub claim_address: Address,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ResolutionType {
    Renewal,
    StorageProof,
    Expiration,
    Finalization,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct V2FileContractResolution {
    pub parent: V2FileContractElement,
    #[serde(rename = "type")]
    pub resolution_type: ResolutionType,
    pub resolution: V2FileContractResolutionWrapper,
}

impl Encodable for V2FileContractResolution {
    fn encode(&self, _encoder: &mut Encoder) { todo!() }
}

impl<'de> Deserialize<'de> for V2FileContractResolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        struct V2FileContractResolutionHelper {
            parent: V2FileContractElement,
            #[serde(rename = "type")]
            resolution_type: ResolutionType,
            resolution: Value,
        }

        let helper = V2FileContractResolutionHelper::deserialize(deserializer)?;

        let resolution_data = match helper.resolution_type {
            ResolutionType::Renewal => serde_json::from_value::<V2FileContractRenewal>(helper.resolution)
                .map(|data| V2FileContractResolutionWrapper::Renewal(Box::new(data)))
                .map_err(serde::de::Error::custom),
            ResolutionType::StorageProof => serde_json::from_value::<V2StorageProof>(helper.resolution)
                .map(V2FileContractResolutionWrapper::StorageProof)
                .map_err(serde::de::Error::custom),
            ResolutionType::Finalization => serde_json::from_value::<V2FileContractFinalization>(helper.resolution)
                .map(|data| V2FileContractResolutionWrapper::Finalization(Box::new(data)))
                .map_err(serde::de::Error::custom),
            // expiration is a special case because it has no data. It is just an empty object, "{}".
            ResolutionType::Expiration => match &helper.resolution {
                Value::Object(map) if map.is_empty() => Ok(V2FileContractResolutionWrapper::Expiration),
                _ => Err(serde::de::Error::custom("expected an empty map for expiration")),
            },
        }?;

        Ok(V2FileContractResolution {
            parent: helper.parent,
            resolution_type: helper.resolution_type,
            resolution: resolution_data,
        })
    }
}

impl Encodable for V2FileContractResolutionWrapper {
    fn encode(&self, _encoder: &mut Encoder) {
        todo!();
    }
}

impl V2FileContractResolution {
    fn with_nil_sigs(&self) -> V2FileContractResolution {
        V2FileContractResolution {
            resolution: self.resolution.with_nil_sigs(),
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum V2FileContractResolutionWrapper {
    Finalization(Box<V2FileContractFinalization>),
    Renewal(Box<V2FileContractRenewal>),
    StorageProof(V2StorageProof),
    #[serde(serialize_with = "serialize_variant_as_empty_object")]
    Expiration,
}

fn serialize_variant_as_empty_object<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str("{}")
}

impl V2FileContractResolutionWrapper {
    fn with_nil_sigs(&self) -> V2FileContractResolutionWrapper {
        match self {
            V2FileContractResolutionWrapper::Finalization(f) => {
                V2FileContractResolutionWrapper::Finalization(Box::new(f.with_nil_sigs()))
            },
            V2FileContractResolutionWrapper::Renewal(r) => {
                V2FileContractResolutionWrapper::Renewal(Box::new(r.with_nil_sigs()))
            },
            V2FileContractResolutionWrapper::StorageProof(s) => {
                V2FileContractResolutionWrapper::StorageProof(s.with_nil_merkle_proof())
            },
            V2FileContractResolutionWrapper::Expiration => V2FileContractResolutionWrapper::Expiration,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct V2FileContractFinalization(pub V2FileContract);

impl V2FileContractFinalization {
    fn with_nil_sigs(&self) -> V2FileContractFinalization { V2FileContractFinalization(self.0.with_nil_sigs()) }
}

// TODO unit test
impl Encodable for V2FileContractFinalization {
    fn encode(&self, encoder: &mut Encoder) { self.0.encode(encoder); }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct V2FileContractRenewal {
    final_revision: V2FileContract,
    new_contract: V2FileContract,
    renter_rollover: Currency,
    host_rollover: Currency,
    #[serde_as(as = "FromInto<PrefixedSignature>")]
    renter_signature: Signature,
    #[serde_as(as = "FromInto<PrefixedSignature>")]
    host_signature: Signature,
}

impl V2FileContractRenewal {
    pub fn with_nil_sigs(&self) -> V2FileContractRenewal {
        debug_assert!(
            Signature::from_bytes(&[0u8; 64]).is_ok(),
            "nil signature is valid and cannot return Err"
        );
        V2FileContractRenewal {
            final_revision: self.final_revision.with_nil_sigs(),
            new_contract: self.new_contract.with_nil_sigs(),
            renter_signature: Signature::from_bytes(&[0u8; 64]).expect("Err unreachable"),
            host_signature: Signature::from_bytes(&[0u8; 64]).expect("Err unreachable"),
            ..self.clone()
        }
    }
}

// TODO unit test
impl Encodable for V2FileContractRenewal {
    fn encode(&self, encoder: &mut Encoder) {
        self.final_revision.encode(encoder);
        self.new_contract.encode(encoder);
        CurrencyVersion::V2(&self.renter_rollover).encode(encoder);
        CurrencyVersion::V2(&self.host_rollover).encode(encoder);
        self.renter_signature.encode(encoder);
        self.host_signature.encode(encoder);
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct V2StorageProof {
    proof_index: ChainIndexElement,
    leaf: HexArray64,
    proof: Vec<H256>,
}

impl V2StorageProof {
    pub fn with_nil_merkle_proof(&self) -> V2StorageProof {
        V2StorageProof {
            proof_index: ChainIndexElement {
                state_element: StateElement {
                    merkle_proof: None,
                    ..self.proof_index.state_element.clone()
                },
                ..self.proof_index.clone()
            },
            ..self.clone()
        }
    }
}

// TODO unit test
impl Encodable for V2StorageProof {
    fn encode(&self, encoder: &mut Encoder) {
        self.proof_index.encode(encoder);
        encoder.write_slice(&self.leaf.0);
        encoder.write_u64(self.proof.len() as u64);
        for proof in &self.proof {
            proof.encode(encoder);
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainIndexElement {
    #[serde(flatten)]
    pub state_element: StateElement,
    pub chain_index: ChainIndex,
}

// TODO unit test
impl Encodable for ChainIndexElement {
    fn encode(&self, encoder: &mut Encoder) {
        self.state_element.encode(encoder);
        self.chain_index.encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileContractElementV1 {
    #[serde(flatten)]
    pub state_element: StateElement,
    pub file_contract: FileContractV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileContractV1 {
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
/*
While implementing this, we faced two options.
    1.) Treat every field as an Option<>
    2.) Always initialize every empty field as a Vec<>

We chose the latter as it allows for simpler encoding of this struct.
It is possible this may need to change in later implementations.
*/
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct V1Transaction {
    pub siacoin_inputs: Vec<SiacoinInputV1>,
    pub siacoin_outputs: Vec<SiacoinOutput>,
    pub file_contracts: Vec<FileContract>,
    pub file_contract_revisions: Vec<FileContractRevision>,
    pub storage_proofs: Vec<StorageProof>,
    pub siafund_inputs: Vec<SiafundInputV1>,
    pub siafund_outputs: Vec<SiafundOutput>,
    pub miner_fees: Vec<Currency>,
    pub arbitrary_data: Vec<u8>,
    pub signatures: Vec<TransactionSignature>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct V2Transaction {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub siacoin_inputs: Vec<SiacoinInputV2>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub siacoin_outputs: Vec<SiacoinOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub siafund_inputs: Vec<SiafundInputV2>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub siafund_outputs: Vec<SiafundOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub file_contracts: Vec<V2FileContract>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub file_contract_revisions: Vec<FileContractRevisionV2>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub file_contract_resolutions: Vec<V2FileContractResolution>, // TODO needs Encodable trait
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<Attestation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arbitrary_data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_foundation_address: Option<Address>,
    pub miner_fee: Currency,
}

impl V2Transaction {
    pub fn with_nil_sigs(&self) -> V2Transaction {
        V2Transaction {
            file_contracts: self.file_contracts.clone(),
            file_contract_revisions: self.file_contract_revisions.clone(),
            file_contract_resolutions: self.file_contract_resolutions.clone(),
            ..self.clone()
        }
    }

    pub fn input_sig_hash(&self) -> H256 {
        let mut encoder = Encoder::default();
        encoder.write_distinguisher("sig/input");
        encoder.write_u8(V2_REPLAY_PREFIX);
        self.encode(&mut encoder);
        encoder.hash()
    }
}

// this encoding corresponds to the Go implementation's "V2TransactionSemantics" rather than "V2Transaction"
impl Encodable for V2Transaction {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u64(self.siacoin_inputs.len() as u64);
        for si in &self.siacoin_inputs {
            si.parent.state_element.id.encode(encoder);
        }

        encoder.write_u64(self.siacoin_outputs.len() as u64);
        for so in &self.siacoin_outputs {
            SiacoinOutputVersion::V2(so).encode(encoder);
        }

        encoder.write_u64(self.siafund_inputs.len() as u64);
        for si in &self.siafund_inputs {
            si.parent.state_element.id.encode(encoder);
        }

        encoder.write_u64(self.siafund_outputs.len() as u64);
        for so in &self.siafund_outputs {
            SiafundOutputVersion::V2(so).encode(encoder);
        }

        encoder.write_u64(self.file_contracts.len() as u64);
        for fc in &self.file_contracts {
            fc.with_nil_sigs().encode(encoder);
        }

        encoder.write_u64(self.file_contract_revisions.len() as u64);
        for fcr in &self.file_contract_revisions {
            fcr.parent.state_element.id.encode(encoder);
            fcr.revision.with_nil_sigs().encode(encoder);
        }

        encoder.write_u64(self.file_contract_resolutions.len() as u64);
        for fcr in &self.file_contract_resolutions {
            fcr.parent.state_element.id.encode(encoder);
            fcr.with_nil_sigs().encode(encoder);
            // FIXME .encode() leads to unimplemented!()
        }

        encoder.write_u64(self.attestations.len() as u64);
        for att in &self.attestations {
            att.encode(encoder);
        }

        encoder.write_len_prefixed_bytes(&self.arbitrary_data);

        encoder.write_bool(self.new_foundation_address.is_some());
        match &self.new_foundation_address {
            Some(addr) => addr.encode(encoder),
            None => (),
        }
        CurrencyVersion::V2(&self.miner_fee).encode(encoder);
    }
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

    let hash = Encoder::encode_and_hash(&CurrencyVersion::V1(&currency));
    let expected = H256::from("a1cc3a97fc1ebfa23b0b128b153a29ad9f918585d1d8a32354f547d8451b7826");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v2() {
    let currency: Currency = 1.into();

    let hash = Encoder::encode_and_hash(&CurrencyVersion::V2(&currency));
    let expected = H256::from("a3865e5e284e12e0ea418e73127db5d1092bfb98ed372ca9a664504816375e1d");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v1_max() {
    let currency = Currency::new(u64::MAX, u64::MAX);

    let hash = Encoder::encode_and_hash(&CurrencyVersion::V1(&currency));
    let expected = H256::from("4b9ed7269cb15f71ddf7238172a593a8e7ffe68b12c1bf73d67ac8eec44355bb");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_currency_encode_v2_max() {
    let currency = Currency::new(u64::MAX, u64::MAX);

    let hash = Encoder::encode_and_hash(&CurrencyVersion::V2(&currency));
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

    let hash = Encoder::encode_and_hash(&SiacoinOutputVersion::V1(&vout));
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

    let hash = Encoder::encode_and_hash(&SiacoinOutputVersion::V2(&vout));
    let expected = H256::from("c278eceae42f594f5f4ca52c8a84b749146d08af214cc959ed2aaaa916eaafd3");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_element_encode() {
    let state_element = StateElement {
        id: H256::from("0102030000000000000000000000000000000000000000000000000000000000"),
        leaf_index: 1,
        merkle_proof: Some(vec![
            H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
            H256::from("0708090000000000000000000000000000000000000000000000000000000000"),
        ]),
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
        merkle_proof: Some(vec![
            H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
            H256::from("0708090000000000000000000000000000000000000000000000000000000000"),
        ]),
    };

    let hash = Encoder::encode_and_hash(&state_element);
    let expected = H256::from("bf6d7b74fb1e15ec4e86332b628a450e387c45b54ea98e57a6da8c9af317e468");
    assert_eq!(hash, expected);
}

#[test]
fn test_state_element_encode_null_merkle_proof() {
    let state_element = StateElement {
        id: H256::from("0102030000000000000000000000000000000000000000000000000000000000"),
        leaf_index: 1,
        merkle_proof: None,
    };

    let hash = Encoder::encode_and_hash(&state_element);
    let expected = H256::from("d69bc48bc797aff93050447aff0a3f7c4d489705378c122cd123841fe7778a3e");
    assert_eq!(hash, expected);
}

#[test]
fn test_siacoin_input_encode_v1() {
    let vin = SiacoinInputV1 {
        parent_id: H256::default(),
        unlock_condition: UnlockCondition::new(vec![], 0, 0),
    };

    let hash = Encoder::encode_and_hash(&vin);
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
    let policy = SpendPolicy::Threshold {
        n: 1,
        of: vec![sub_policy],
    };

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
    let policy = SpendPolicy::Threshold {
        n: 1,
        of: vec![sub_policy],
    };

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
                merkle_proof: Some(vec![H256::default()]),
            },
            siacoin_output: SiacoinOutput {
                value: 1.into(),
                address: policy.address(),
            },
            maturity_height: 0,
        },
        satisfied_policy,
    };

    let hash = Encoder::encode_and_hash(&vin);
    let expected = H256::from("a8ab11b91ee19ce68f2d608bd4d19212841842f0c50151ae4ccb8e9db68cd6c4");
    assert_eq!(hash, expected);
}

#[test]
fn test_attestation_encode() {
    let public_key = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let signature = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();

    let attestation = Attestation {
        public_key,
        key: "HostAnnouncement".to_string(),
        value: vec![1u8, 2u8, 3u8, 4u8],
        signature,
    };

    let hash = Encoder::encode_and_hash(&attestation);
    let expected = H256::from("b28b32c6f91d1b57ab4a9ea9feecca16b35bb8febdee6a0162b22979415f519d");
    assert_eq!(hash, expected);
}

#[test]
fn test_file_contract_v2_encode() {
    let pubkey0 = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let pubkey1 = PublicKey::from_bytes(
        &hex::decode("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").unwrap(),
    )
    .unwrap();

    let sig0 = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();
    let sig1 = Signature::from_bytes(
        &hex::decode("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A").unwrap()).unwrap();

    let address0 = v1_standard_address_from_pubkey(&pubkey0);
    let address1 = v1_standard_address_from_pubkey(&pubkey1);

    let vout0 = SiacoinOutput {
        value: 1.into(),
        address: address0,
    };
    let vout1 = SiacoinOutput {
        value: 1.into(),
        address: address1,
    };

    let file_contract_v2 = V2FileContract {
        filesize: 1,
        file_merkle_root: H256::default(),
        proof_height: 1,
        expiration_height: 1,
        renter_output: vout0,
        host_output: vout1,
        missed_host_value: 1.into(),
        total_collateral: 1.into(),
        renter_public_key: pubkey0,
        host_public_key: pubkey1,
        revision_number: 1,
        renter_signature: sig0,
        host_signature: sig1,
    };

    let hash = Encoder::encode_and_hash(&file_contract_v2);
    let expected = H256::from("6171a8d8ec31e06f80d46efbd1aecf2c5a7c344b5f2a2d4f660654b0cb84113c");
    assert_eq!(hash, expected);
}

#[test]
fn test_file_contract_element_v2_encode() {
    let pubkey0 = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let pubkey1 = PublicKey::from_bytes(
        &hex::decode("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").unwrap(),
    )
    .unwrap();

    let sig0 = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();
    let sig1 = Signature::from_bytes(
        &hex::decode("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A").unwrap()).unwrap();

    let address0 = v1_standard_address_from_pubkey(&pubkey0);
    let address1 = v1_standard_address_from_pubkey(&pubkey1);

    let vout0 = SiacoinOutput {
        value: 1.into(),
        address: address0,
    };
    let vout1 = SiacoinOutput {
        value: 1.into(),
        address: address1,
    };

    let file_contract_v2 = V2FileContract {
        filesize: 1,
        file_merkle_root: H256::default(),
        proof_height: 1,
        expiration_height: 1,
        renter_output: vout0,
        host_output: vout1,
        missed_host_value: 1.into(),
        total_collateral: 1.into(),
        renter_public_key: pubkey0,
        host_public_key: pubkey1,
        revision_number: 1,
        renter_signature: sig0,
        host_signature: sig1,
    };

    let state_element = StateElement {
        id: H256::from("0102030000000000000000000000000000000000000000000000000000000000"),
        leaf_index: 1,
        merkle_proof: Some(vec![
            H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
            H256::from("0708090000000000000000000000000000000000000000000000000000000000"),
        ]),
    };

    let file_contract_element_v2 = V2FileContractElement {
        state_element,
        v2_file_contract: file_contract_v2,
    };

    let hash = Encoder::encode_and_hash(&file_contract_element_v2);
    let expected = H256::from("4cde411635118b2b7e1b019c659a2327ada53b303da0e46524e604d228fcd039");
    assert_eq!(hash, expected);
}

#[test]
fn test_file_contract_revision_v2_encode() {
    let pubkey0 = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();
    let pubkey1 = PublicKey::from_bytes(
        &hex::decode("06C87838297B7BB16AB23946C99DFDF77FF834E35DB07D71E9B1D2B01A11E96D").unwrap(),
    )
    .unwrap();

    let sig0 = Signature::from_bytes(
        &hex::decode("105641BF4AE119CB15617FC9658BEE5D448E2CC27C9BC3369F4BA5D0E1C3D01EBCB21B669A7B7A17CF8457189EAA657C41D4A2E6F9E0F25D0996D3A17170F309").unwrap()).unwrap();
    let sig1 = Signature::from_bytes(
        &hex::decode("0734761D562958F6A82819474171F05A40163901513E5858BFF9E4BD9CAFB04DEF0D6D345BACE7D14E50C5C523433B411C7D7E1618BE010A63C55C34A2DEE70A").unwrap()).unwrap();

    let address0 = v1_standard_address_from_pubkey(&pubkey0);
    let address1 = v1_standard_address_from_pubkey(&pubkey1);

    let vout0 = SiacoinOutput {
        value: 1.into(),
        address: address0,
    };
    let vout1 = SiacoinOutput {
        value: 1.into(),
        address: address1,
    };

    let file_contract_v2 = V2FileContract {
        filesize: 1,
        file_merkle_root: H256::default(),
        proof_height: 1,
        expiration_height: 1,
        renter_output: vout0,
        host_output: vout1,
        missed_host_value: 1.into(),
        total_collateral: 1.into(),
        renter_public_key: pubkey0,
        host_public_key: pubkey1,
        revision_number: 1,
        renter_signature: sig0,
        host_signature: sig1,
    };

    let state_element = StateElement {
        id: H256::from("0102030000000000000000000000000000000000000000000000000000000000"),
        leaf_index: 1,
        merkle_proof: Some(vec![
            H256::from("0405060000000000000000000000000000000000000000000000000000000000"),
            H256::from("0708090000000000000000000000000000000000000000000000000000000000"),
        ]),
    };

    let file_contract_element_v2 = V2FileContractElement {
        state_element,
        v2_file_contract: file_contract_v2.clone(),
    };

    let file_contract_revision_v2 = FileContractRevisionV2 {
        parent: file_contract_element_v2,
        revision: file_contract_v2,
    };

    let hash = Encoder::encode_and_hash(&file_contract_revision_v2);
    let expected = H256::from("22d5d1fd8c2762758f6b6ecf7058d73524ef209ac5a64f160b71ce91677db9a6");
    assert_eq!(hash, expected);
}

#[test]
fn test_v2_transaction_sig_hash() {
    let j = json!(
        {
            "siacoinInputs": [
                {
                    "parent": {
                        "id": "h:b49cba94064a92a75bf8c6f9d32ab18f38bfb14a2252e3e117d04da89d536f29",
                        "leafIndex": 302,
                        "merkleProof": [
                            "h:6f41d366712e9dfa423160b5388f3faf673addf43566d7b3562106d15b833f46",
                            "h:eb7df5e13eccd812a47f29a233bbf3212b7379ca6dd20ba9981524bfd5eadce6",
                            "h:04104cbada51333f8f37a6eb71f1e8cb287da2d62469568a8a36dc8c76602c80",
                            "h:16aac5c671d49d8cfc5493cb4c6f34889e30a0d283745c6473406bd60ab5e754",
                            "h:1b9ccf2b6f555687b1384091faa9ed1c154f41aaff81dcf393295383ca99f518",
                            "h:31337c9db5cdd181f5ff142bd490f779eedb1485e5dd905743280aeac3cd7ac9"
                        ],
                        "siacoinOutput": {
                            "value": "288594172736732570239334030000",
                            "address": "addr:2757c80b7ec2e493a138fed45b906f9f5735a992b68dcbd2069fbdf418c8b25158f3ac7a816b"
                        },
                        "maturityHeight": 0
                    },
                    "satisfiedPolicy": {
                        "policy": {
                            "type": "uc",
                            "policy": {
                                "timelock": 0,
                                "publicKeys": [
                                    "ed25519:7931b69fe8888e354d601a778e31bfa97fa89dc6f625cd01cc8aa28046e557e7"
                                ],
                                "signaturesRequired": 1
                            }
                        },
                        "signatures": [
                            "sig:f43380794a6384e3d24d9908143c05dd37aaac8959efb65d986feb70fe289a5e26b84e0ac712af01a2f85f8727da18aae13a599a51fb066d098591e40cb26902"
                        ]
                    }
                }
            ],
            "siacoinOutputs": [
                {
                    "value": "1000000000000000000000000000",
                    "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
                },
                {
                    "value": "287594172736732570239334030000",
                    "address": "addr:2757c80b7ec2e493a138fed45b906f9f5735a992b68dcbd2069fbdf418c8b25158f3ac7a816b"
                }
            ],
            "minerFee": "0"
        }
    );

    let tx = serde_json::from_value::<V2Transaction>(j).unwrap();
    let hash = tx.input_sig_hash();
    let expected = H256::from("ef2f59bb25300bed9accbdcd95e1a2bd9f146ab6b474002670dc908ad68aacac");
    assert_eq!(hash, expected);
}

#[test]
fn test_v2_transaction_signing() {
    use crate::{Keypair, Signature};
    use ed25519_dalek::Signer;
    let j = json!(
        {
            "siacoinInputs": [
                {
                    "parent": {
                        "id": "h:f59e395dc5cbe3217ee80eff60585ffc9802e7ca580d55297782d4a9b4e08589",
                        "leafIndex": 3,
                        "merkleProof": [
                            "h:ab0e1726444c50e2c0f7325eb65e5bd262a97aad2647d2816c39d97958d9588a",
                            "h:467e2be4d8482eca1f99440b6efd531ab556d10a8371a98a05b00cb284620cf0",
                            "h:64d5766fce1ff78a13a4a4744795ad49a8f8d187c01f9f46544810049643a74a",
                            "h:31d5151875152bc25d1df18ca6bbda1bef5b351e8d53c277791ecf416fcbb8a8",
                            "h:12a92a1ba87c7b38f3c4e264c399abfa28fb46274cfa429605a6409bd6d0a779",
                            "h:eda1d58a9282dbf6c3f1beb4d6c7bdc036d14a1cfee8ab1e94fabefa9bd63865",
                            "h:e03dee6e27220386c906f19fec711647353a5f6d76633a191cbc2f6dce239e89",
                            "h:e70fcf0129c500f7afb49f4f2bb82950462e952b7cdebb2ad0aa1561dc6ea8eb"
                        ],
                        "siacoinOutput": {
                            "value": "300000000000000000000000000000",
                            "address": "addr:f7843ac265b037658b304468013da4fd0f304a1b73df0dc68c4273c867bfa38d01a7661a187f"
                        },
                        "maturityHeight": 145
                    },
                    "satisfiedPolicy": {
                        "policy": {
                            "type": "uc",
                            "policy": {
                                "timelock": 0,
                                "publicKeys": [
                                    "ed25519:cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc"
                                ],
                                "signaturesRequired": 1
                            }
                        },
                        "signatures": [
                            "sig:f0a29ba576eb0dbc3438877ac1d3a6da4f3c4cbafd9030709c8a83c2fffa64f4dd080d37444261f023af3bd7a10a9597c33616267d5371bf2c0ade5e25e61903"
                        ]
                    }
                }
            ],
            "siacoinOutputs": [
                {
                    "value": "1000000000000000000000000000",
                    "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
                },
                {
                    "value": "299000000000000000000000000000",
                    "address": "addr:f7843ac265b037658b304468013da4fd0f304a1b73df0dc68c4273c867bfa38d01a7661a187f"
                }
            ],
            "minerFee": "0"
        }
    );
    let tx = serde_json::from_value::<V2Transaction>(j).unwrap();
    let keypair = Keypair::from_bytes(&hex::decode("0100000000000000000000000000000000000000000000000000000000000000cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc").unwrap()).unwrap();
    let sig_hash = tx.input_sig_hash();

    // test that we can correctly regenerate the signature
    let sig: Signature = keypair.try_sign(&sig_hash.0).unwrap();
    assert_eq!(tx.siacoin_inputs[0].satisfied_policy.signatures[0], sig);
}
