use crate::sia::encoding::SiaHash;
use crate::sia::types::Event;
use crate::sia::address::Address;
use crate::sia::transaction::{SiacoinElement, SiacoinOutput, StateElement};

// Ensure the original value matches the value after round-trip (serialize -> deserialize -> serialize)
macro_rules! test_serde {
    ($type:ty, $json_value:expr) => {
        {
            let json_str = $json_value.to_string();
            let value: $type = serde_json::from_str(&json_str).unwrap();
            let serialized = serde_json::to_string(&value).unwrap();
            let serialized_json_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            assert_eq!($json_value, serialized_json_value);
        }
    };
}

#[test]
fn test_serde_address() {
    test_serde!(Address, json!("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f"));
}

#[test]
fn test_serde_sia_hash() {
    test_serde!(SiaHash, json!("h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1"));
}

#[test]
fn test_serde_siacoin_output() {
    let j = json!({
        "value": "300000000000000000000000000000",
        "address": "addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f"
      });
    test_serde!(SiacoinOutput, j);
}

#[test]
fn test_serde_state_element() {
     let j = json!({
        "id": "h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1",
        "leafIndex": 21,
        "merkleProof": null
      });
    serde_json::from_value::<StateElement>(j).unwrap();
}

#[test]
fn test_serde_siacoin_element() {
    let j = json!(  {
            "id": "h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1",
            "leafIndex": 21,
            "merkleProof": ["h:8dfc4731c4ef4bf35f789893e72402a39c7ea63ba9e75565cb11000d0159959e"],
            "siacoinOutput": {
              "value": "300000000000000000000000000000",
              "address": "addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f"
            },
            "maturityHeight": 154
          }
      );
      serde_json::from_value::<SiacoinElement>(j).unwrap();
}

#[test]
fn test_serde_siacoin_element_null_merkle_proof() {
    let j = json!(  {
            "id": "h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1",
            "leafIndex": 21,
            "merkleProof": null,
            "siacoinOutput": {
              "value": "300000000000000000000000000000",
              "address": "addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f"
            },
            "maturityHeight": 154
          }
      );
      serde_json::from_value::<SiacoinElement>(j).unwrap();
}

#[test]
fn test_serde_event() {
    let j = json!(  {
        "id": "h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1",
        "index": {
          "height": 10,
          "id": "bid:00f18dcbca8bbcd114ba99e2d88849ef8fd8b1df055ff4601f725c2700a755c9"
        },
        "timestamp": "2024-06-19T11:27:22Z",
        "maturityHeight": 155,
        "type": "miner",
        "data": {
          "siacoinElement": {
            "id": "h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1",
            "leafIndex": 21,
            "merkleProof": null,
            "siacoinOutput": {
              "value": "300000000000000000000000000000",
              "address": "addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f"
            },
            "maturityHeight": 154
          }
        }
      });

    serde_json::from_value::<Event>(j).unwrap();
}