use crate::sia::address::Address;
use crate::sia::encoding::{Encodable, Encoder, PrefixedH256, PrefixedSignature};
use crate::sia::transaction::{Currency, FileContractElementV1, SiacoinElement, SiafundElement, StateElement,
                              TransactionV1, TransactionV2, V2FileContract, V2FileContractElement, V2StorageProof};
use crate::sia::Signature;
use chrono::{DateTime, Utc};
use rpc::v1::types::H256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_with::{serde_as, FromInto};
use std::convert::From;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct BlockID(pub H256);

impl From<BlockID> for H256 {
    fn from(sia_hash: BlockID) -> Self { sia_hash.0 }
}

impl From<H256> for BlockID {
    fn from(h256: H256) -> Self { BlockID(h256) }
}

impl<'de> Deserialize<'de> for BlockID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlockIDVisitor;

        impl<'de> serde::de::Visitor<'de> for BlockIDVisitor {
            type Value = BlockID;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string prefixed with 'bid:' and followed by a 64-character hex string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Some(hex_str) = value.strip_prefix("bid:") {
                    H256::from_str(hex_str)
                        .map(BlockID)
                        .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(value), &self))
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(value), &self))
                }
            }
        }

        deserializer.deserialize_str(BlockIDVisitor)
    }
}

impl Serialize for BlockID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl fmt::Display for BlockID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "bid:{}", self.0) }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainIndex {
    pub height: u64,
    pub id: BlockID,
}

// TODO unit test
impl Encodable for ChainIndex {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u64(self.height);
        let block_id: H256 = self.id.clone().into();
        block_id.encode(encoder);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventV1Transaction {
    pub transaction: TransactionV1,
    pub spent_siacoin_elements: Vec<SiacoinElement>,
    pub spent_siafund_elements: Vec<SiafundElement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventV1ContractResolution {
    pub file_contract: FileContractElementV1,
    pub siacoin_element: SiacoinElement,
    pub missed: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPayout {
    pub siacoin_element: SiacoinElement,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    #[serde_as(as = "FromInto<PrefixedH256>")]
    pub id: H256,
    pub index: ChainIndex,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "maturityHeight")]
    pub maturity_height: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: EventDataWrapper,
    pub relevant: Option<Vec<Address>>,
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        struct EventHelper {
            id: PrefixedH256,
            index: ChainIndex,
            timestamp: DateTime<Utc>,
            #[serde(rename = "maturityHeight")]
            maturity_height: u64,
            #[serde(rename = "type")]
            event_type: String,
            data: Value,
            relevant: Option<Vec<Address>>,
        }

        let helper = EventHelper::deserialize(deserializer)?;
        let event_data = match helper.event_type.as_str() {
            "miner" => serde_json::from_value::<EventPayout>(helper.data)
                .map(EventDataWrapper::MinerPayout)
                .map_err(serde::de::Error::custom),
            "foundation" => serde_json::from_value::<EventPayout>(helper.data)
                .map(EventDataWrapper::FoundationPayout)
                .map_err(serde::de::Error::custom),
            "siafundClaim" => serde_json::from_value::<EventPayout>(helper.data)
                .map(EventDataWrapper::ClaimPayout)
                .map_err(serde::de::Error::custom),
            "v1Transaction" => serde_json::from_value::<EventV1Transaction>(helper.data)
                .map(EventDataWrapper::V1Transaction)
                .map_err(serde::de::Error::custom),
            "v2Transaction" => serde_json::from_value::<TransactionV2>(helper.data)
                .map(EventDataWrapper::V2Transaction)
                .map_err(serde::de::Error::custom),
            // "v1ContractResolution" => serde_json::from_value::<EventV1ContractResolution>(helper.data)
            //     .map(EventDataWrapper::V1FileContractResolution)
            //     .map_err(serde::de::Error::custom),
            "v2ContractResolution" => serde_json::from_value::<V2FileContractResolution>(helper.data)
                .map(EventDataWrapper::V2FileContractResolution)
                .map_err(serde::de::Error::custom),
            // Add other type mappings here...
            _ => Err(serde::de::Error::unknown_variant(&helper.event_type, &[
                "Payout",
                "V2Transaction",
                "V2FileContractResolution",
                "V1Transaction",
                "V1FileContractResolution",
            ])),
        }?;

        Ok(Event {
            id: helper.id.into(),
            index: helper.index,
            timestamp: helper.timestamp,
            maturity_height: helper.maturity_height,
            event_type: helper.event_type,
            data: event_data,
            relevant: helper.relevant,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EventDataWrapper {
    MinerPayout(EventPayout),
    FoundationPayout(EventPayout),
    ClaimPayout(EventPayout),
    V2Transaction(TransactionV2),
    V2FileContractResolution(V2FileContractResolution),
    V1Transaction(EventV1Transaction),
    EventV1ContractResolution(EventV1ContractResolution),
}

#[derive(Clone, Debug, Serialize)]
pub struct V2FileContractResolution {
    pub parent: V2FileContractElement,
    pub resolution: V2FileContractResolutionWrapper,
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
            resolution_type: String,
            resolution: Value,
        }

        let helper = V2FileContractResolutionHelper::deserialize(deserializer)?;
        println!(
            "type: {} helper.data: {:?}",
            helper.resolution_type.as_str(),
            helper.resolution
        );
        let resolution_data = match helper.resolution_type.as_str() {
            "renewal" => serde_json::from_value::<V2FileContractRenewal>(helper.resolution)
                .map(V2FileContractResolutionWrapper::Renewal)
                .map_err(serde::de::Error::custom),
            "storage proof" => serde_json::from_value::<V2StorageProof>(helper.resolution)
                .map(V2FileContractResolutionWrapper::StorageProof)
                .map_err(serde::de::Error::custom),
            "finalization" => serde_json::from_value::<V2FileContractFinalization>(helper.resolution)
                .map(V2FileContractResolutionWrapper::Finalization)
                .map_err(serde::de::Error::custom),
            // expiration is a special case because it has no data. It is just an empty object, "{}".
            "expiration" => match &helper.resolution {
                Value::Object(map) if map.is_empty() => {
                    Ok(V2FileContractResolutionWrapper::Expiration(V2FileContractExpiration))
                },
                _ => Err(serde::de::Error::custom("expected an empty map for expiration")),
            },
            // "finalization"
            _ => Err(serde::de::Error::unknown_variant(&helper.resolution_type, &[
                "renewal",
                "storage proof",
                "expiration",
                "finalization",
            ])),
        }?;

        Ok(V2FileContractResolution {
            parent: helper.parent,
            resolution: resolution_data,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum V2FileContractResolutionWrapper {
    Finalization(V2FileContractFinalization),
    Renewal(V2FileContractRenewal),
    StorageProof(V2StorageProof),
    Expiration(V2FileContractExpiration),
}

type V2FileContractFinalization = V2FileContract;

// FIXME this may need custom serde to handle it as "{}"
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V2FileContractExpiration;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainIndexElement {
    #[serde(flatten)]
    state_element: StateElement,
    chain_index: ChainIndex,
}
