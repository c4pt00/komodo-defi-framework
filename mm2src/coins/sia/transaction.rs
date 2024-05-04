use rpc::v1::types::H256;
use crate::sia::encoding::{EncodeTo, Encoder};
use crate::sia::spend_policy::UnlockCondition;

type SiacoinOutputID = H256;
pub struct SiacoinInput {
    pub parent_id: SiacoinOutputID,
    pub unlock_conditions: UnlockCondition,
}

#[test]
fn test_sia_coin_input() {
    let vout_id: SiacoinOutputID = H256::from("0102030000000000000000000000000000000000000000000000000000000000");
    println!("sia {:?}", vout_id);
}

// TODO temporary stubs
type SiacoinOutput = Vec<u8>;
type FileContract = Vec<u8>;
type FileContractRevision = Vec<u8>;
type StorageProof = Vec<u8>;
type SiafundInput = Vec<u8>;
type SiafundOutput = Vec<u8>;
type Currency = Vec<u8>;
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