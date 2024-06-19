use crate::sia::encoding::{Encodable, Encoder};
use crate::sia::address::Address;
use crate::sia::transaction::{FileContractElementV1, FileContractElementV2, SiacoinElement, SiafundElement, TransactionV1, TransactionV2};
use rpc::v1::types::H256;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};


pub type BlockID = H256;

#[derive(Clone, Deserialize, Serialize)]
pub struct ChainIndex {
    pub height: u64,
    pub id: BlockID,
}

// TODO unit test
impl Encodable for ChainIndex {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u64(self.height);
        self.id.encode(encoder);
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum EventDataEnum {
    Payout(EventPayout),
    V2Transaction(EventV2Transaction),
    V2FileContractResolution(EventV2ContractResolution),
    V1Transaction(EventV1Transaction),
    V1FileContractResolution(EventV1ContractResolution)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventV1Transaction {
    pub transaction: TransactionV1,
    pub spent_siacoin_elements: Vec<SiacoinElement>,
    pub spent_siafund_elements: Vec<SiafundElement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventV1ContractResolution {
    pub file_contract: FileContractElementV1,
    pub siacoin_element: SiacoinElement,
    pub missed: bool,
}

 // FIXME does this actually need to be wrapped?
 #[derive(Clone, Debug, Deserialize, Serialize)]
 pub struct EventV2Transaction {
    pub transaction: TransactionV2,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventV2ContractResolution {
    pub file_contract: FileContractElementV2,
    pub resolution: String, // TODO stub; should be enum
    pub siacoin_element: SiacoinElement,
    pub missed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventPayout {
    pub siacoin_element: SiacoinElement,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub id: H256,
    pub index: ChainIndex,
    pub timestamp: DateTime<Utc>,
    pub maturity_height: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: EventDataEnum,
    pub relevant: Option<Vec<Address>>,
}