use crate::sia::address::Address;
use crate::sia::encoding::PrefixedH256;
use crate::sia::spend_policy::UnlockKey;
use crate::sia::transaction::{SiacoinElement, SiacoinOutput, StateElement, V2Transaction};
use crate::sia::types::Event;

// Ensure the original value matches the value after round-trip (serialize -> deserialize -> serialize)
macro_rules! test_serde {
    ($type:ty, $json_value:expr) => {{
        let json_str = $json_value.to_string();
        let value: $type = serde_json::from_str(&json_str).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();
        let serialized_json_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!($json_value, serialized_json_value);
    }};
}

// FIXME reminder to populate the following tests
#[test]
#[ignore]
fn test_serde_block_id() {
    use crate::sia::types::BlockID;
    test_serde!(
        BlockID,
        json!("bid:c67c3b2e57490617a25a9fcb9fd54ab6acbe72fc1e4f1f432cb9334177917667")
    );
    test_serde!(BlockID, json!("bid:badc0de"));
    test_serde!(BlockID, json!("bid:1badc0de"));
    test_serde!(BlockID, json!("1badc0de"));
    test_serde!(BlockID, json!(1));
}

#[test]
fn test_serde_address() {
    test_serde!(
        Address,
        json!("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f")
    );
}

#[test]
fn test_serde_unlock_key() {
    test_serde!(
        UnlockKey,
        json!("ed25519:0102030000000000000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn test_serde_sia_hash() {
    test_serde!(
        PrefixedH256,
        json!("h:dc07e5bf84fbda867a7ed7ca80c6d1d81db05cef16ff38f6ba80b6bf01e1ddb1")
    );
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
fn test_serde_event_v2_contract_resolution_storage_proof() {
    let j = json!(  {
      "id": "h:51e066366b66e445725afe7fc54e85019c8b692aaa7502c36630d99e911ac98c",
      "index": {
        "height": 201,
        "id": "bid:5f4b2533cc467ab64e6032f4663819fa2c310fd180637349abbde5977c664fad"
      },
      "timestamp": "2024-06-22T04:22:34Z",
      "maturityHeight": 346,
      "type": "v2ContractResolution",
      "data": {
        "parent": {
          "id": "h:ee4c82247b462b875f7036b2076b1a525c97889a542c36b9e9ef1166fe74e781",
          "leafIndex": 397,
          "merkleProof": [
            "h:f58e964cf335ac0a4f055755aa210e0f3e1d7c6de35711f09a3e2a8fd54470ba",
            "h:36841292b0e182ddaf8c761ffd9b71f9463cf4530a134fdf60d08ea9a084ce57",
            "h:155c83d210d64c97a0bd0310630748c7fa2226ef6e514d37079cd25f797d4162",
            "h:abb482c19f1a14b21033b0b7b8304f685857a4f10d06fb20f172b253657e425b",
            "h:5dba3a456ed101f794a36e3396e375a88f8050e1a0b28bc2a15f105fbc44762a"
          ],
          "v2FileContract": {
            "filesize": 0,
            "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
            "proofHeight": 200,
            "expirationHeight": 210,
            "renterOutput": {
              "value": "10000000000000000000000000000",
              "address": "addr:b60ae577113147c4f68d2daa18dfba4af26a4a8f41a6e9d2a208c1afafe56997588cb25a5192"
            },
            "hostOutput": {
              "value": "0",
              "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            },
            "missedHostValue": "0",
            "totalCollateral": "0",
            "renterPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "hostPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "revisionNumber": 0,
            "renterSignature": "sig:97385f262a2f8db3bd29b072b0ab7cc6dbe01843af09c9010675b3ec7db8a96dd199b3ede4df4ada81d41ca3b5ccb2ad6bfaa01071438ec6fce72e5f18bcd40a",
            "hostSignature": "sig:97385f262a2f8db3bd29b072b0ab7cc6dbe01843af09c9010675b3ec7db8a96dd199b3ede4df4ada81d41ca3b5ccb2ad6bfaa01071438ec6fce72e5f18bcd40a"
          }
        },
        "type": "storage proof",
        "resolution": {
          "proofIndex": {
            "id": "h:3c95abbf4ee22cf09468ffd5d39ea74c9775dae57c34b45d91f3f7f753c18ed4",
            "leafIndex": 416,
            "merkleProof": [],
            "chainIndex": {
              "height": 200,
              "id": "bid:3c95abbf4ee22cf09468ffd5d39ea74c9775dae57c34b45d91f3f7f753c18ed4"
            }
          },
          "leaf": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "proof": []
        }
      }
    });

    let _event = serde_json::from_value::<Event>(j).unwrap();

    // FIXME this should deserialize from a JSON object generated from walletd and recalcuate the txid to check encoding/serde
}

#[test]
fn test_serde_event_v2_contract_resolution_renewal() {
    let j = json!(  {
      "id": "h:4712cf57e90de093a8ed52ec8831f376aac7c739847ec64f324525bf51d7bfc3",
      "index": {
        "height": 203,
        "id": "bid:6d37359564b7c36fb55c50f48aab4c2ae7545ce9b93ff1ab2f9511d1f20865b7"
      },
      "timestamp": "2024-06-22T04:22:34Z",
      "maturityHeight": 348,
      "type": "v2ContractResolution",
      "data": {
        "parent": {
          "id": "h:e773d79ce8ed3b5edf11572c3d56cc3908e6c0766479f09d21420df22ca416be",
          "leafIndex": 423,
          "merkleProof": [
            "h:dec7cb8813aa21ebaec3da1d3a521903305079c382b2e37b1cc8e3c53e66c2db",
            "h:55bd6fb6bae8bc5063f20f67100dbee711e9fa75b5b0b50fc01d7e15e76b69a3",
            "h:14b049a779a996ef3c771669d30517798ef026c95ab5be146cab98dc3854e8cf",
            "h:d9d42af0c7eed9f89c605738f667e6b4248bfb93aa73c98d7c37b40bc9ec8f28"
          ],
          "v2FileContract": {
            "filesize": 0,
            "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
            "proofHeight": 211,
            "expirationHeight": 221,
            "renterOutput": {
              "value": "10000000000000000000000000000",
              "address": "addr:b60ae577113147c4f68d2daa18dfba4af26a4a8f41a6e9d2a208c1afafe56997588cb25a5192"
            },
            "hostOutput": {
              "value": "0",
              "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            },
            "missedHostValue": "0",
            "totalCollateral": "0",
            "renterPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "hostPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "revisionNumber": 0,
            "renterSignature": "sig:db264235ecadc89e63221e4e96347d560754d1f93939120c6d02c96e5207578e64067bd6a4313d9d84de019412d028ba98e182cde342f0cb4ffe1ec3f4783e03",
            "hostSignature": "sig:db264235ecadc89e63221e4e96347d560754d1f93939120c6d02c96e5207578e64067bd6a4313d9d84de019412d028ba98e182cde342f0cb4ffe1ec3f4783e03"
          }
        },
        "type": "renewal",
        "resolution": {
          "finalRevision": {
            "filesize": 0,
            "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
            "proofHeight": 211,
            "expirationHeight": 221,
            "renterOutput": {
              "value": "10000000000000000000000000000",
              "address": "addr:b60ae577113147c4f68d2daa18dfba4af26a4a8f41a6e9d2a208c1afafe56997588cb25a5192"
            },
            "hostOutput": {
              "value": "0",
              "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            },
            "missedHostValue": "0",
            "totalCollateral": "0",
            "renterPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "hostPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "revisionNumber": 18446744073709551615u64,
            "renterSignature": "sig:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "hostSignature": "sig:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          },
          "newContract": {
            "filesize": 0,
            "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
            "proofHeight": 221,
            "expirationHeight": 231,
            "renterOutput": {
              "value": "10000000000000000000000000000",
              "address": "addr:b60ae577113147c4f68d2daa18dfba4af26a4a8f41a6e9d2a208c1afafe56997588cb25a5192"
            },
            "hostOutput": {
              "value": "0",
              "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            },
            "missedHostValue": "0",
            "totalCollateral": "0",
            "renterPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "hostPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "revisionNumber": 0,
            "renterSignature": "sig:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "hostSignature": "sig:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          },
          "renterRollover": "0",
          "hostRollover": "0",
          "renterSignature": "sig:984dea37a3897f6287fd04630e0878df5518e4ae95ff1cba7fa72a87b74cc85774306bba8ff563353b2d6bbca50e331f3dcf54eca3b36f14eb01dfdd7c07d00e",
          "hostSignature": "sig:984dea37a3897f6287fd04630e0878df5518e4ae95ff1cba7fa72a87b74cc85774306bba8ff563353b2d6bbca50e331f3dcf54eca3b36f14eb01dfdd7c07d00e"
        }
      }
    });

    let _event = serde_json::from_value::<Event>(j).unwrap();

    // FIXME this should deserialize from a JSON object generated from walletd and recalcuate the txid to check encoding/serde
}

#[test]
fn test_serde_event_v2_contract_resolution_expiration() {
    let j = json!(  {
      "id": "h:66c8978661a560bfd4497e7b10f99b32edee6f5c64f89376b0502bc07172b59b",
      "index": {
        "height": 190,
        "id": "bid:f3e8fc9091217ba6d8c369342c980138a56e514cfc78bf4dc698cb5095c05902"
      },
      "timestamp": "2024-06-22T04:22:34Z",
      "maturityHeight": 335,
      "type": "v2ContractResolution",
      "data": {
        "parent": {
          "id": "h:b48817a1efc249109eb54202fcfb4b8e0a14368b98c0f9e6fe2519a8e1cbffd8",
          "leafIndex": 351,
          "merkleProof": [
            "h:8509a73f82036fc4fd3ed652ff0f49db15ffaa2fef8d1010e9a2110026bb81b3",
            "h:cf179de3e7d390a4e85e784d7330daf1e925e47960bd0b06e68a1f00406b01da",
            "h:e46b612429e205b58843ad398b1f2dd31b11aebdd2aa0caac40d277905d4ca11",
            "h:a07408549e147d52e48b112a05bc632a19abc9f57fe2fea30efd945fdd01c49c",
            "h:56359fa49114d1ffdc14904cfdf9aff1e6f989ba8bc64d6f44218c73932688ec",
            "h:adffd0f07779af480239a099bcdbee317b3eb38796bbf43db061809d330379ad",
            "h:14815951f3861d371083dc342435d2017fe360d94b265fd6d9a8c6c4d6e2d048"
          ],
          "v2FileContract": {
            "filesize": 0,
            "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
            "proofHeight": 179,
            "expirationHeight": 189,
            "renterOutput": {
              "value": "10000000000000000000000000000",
              "address": "addr:b60ae577113147c4f68d2daa18dfba4af26a4a8f41a6e9d2a208c1afafe56997588cb25a5192"
            },
            "hostOutput": {
              "value": "0",
              "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            },
            "missedHostValue": "0",
            "totalCollateral": "0",
            "renterPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "hostPublicKey": "ed25519:999594db47cc792d408d26bb05f193b23ad020cb019113c0084a732673752a40",
            "revisionNumber": 0,
            "renterSignature": "sig:a51f56c532f331b8ee9fd9bd3a76c89bed8643f2a60be2d820f168d19c7dae73a737c0eef532b992845af2a4a3bfd4993f01a4b66f42f87366c9e50afa2a820f",
            "hostSignature": "sig:a51f56c532f331b8ee9fd9bd3a76c89bed8643f2a60be2d820f168d19c7dae73a737c0eef532b992845af2a4a3bfd4993f01a4b66f42f87366c9e50afa2a820f"
          }
        },
        "type": "expiration",
        "resolution": {}
      }
    });

    let _event = serde_json::from_value::<Event>(j).unwrap();

    // FIXME this should deserialize from a JSON object generated from walletd and recalcuate the txid to check encoding/serde
}

#[test]
fn test_serde_event_v2_contract_resolution_finalization() {
    let j = json!(
      {
        "id": "h:4057e021e1d6dec8d4e4ef9d6e9fa2e4491c559144848b9af5765e03b39bb69d",
        "index": {
          "height": 0,
          "id": "bid:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "timestamp": "2024-07-12T10:04:18.564506-07:00",
        "maturityHeight": 0,
        "type": "v2ContractResolution",
        "data": {
          "parent": {
            "id": "h:ee87ab83f9d16c9377d6154c477ac40d2ee70619de2ba146fcfe36fd0de86bf5",
            "leafIndex": 6680213938505633000u64,
            "merkleProof": [
              "h:0000000000000000000000000000000000000000000000000000000000000000",
              "h:0000000000000000000000000000000000000000000000000000000000000000",
              "h:0000000000000000000000000000000000000000000000000000000000000000",
              "h:0000000000000000000000000000000000000000000000000000000000000000",
              "h:0000000000000000000000000000000000000000000000000000000000000000"
            ],
            "v2FileContract": {
              "filesize": 0,
              "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
              "proofHeight": 10,
              "expirationHeight": 20,
              "renterOutput": {
                "value": "10000000000000000000000000000",
                "address": "addr:c899f7795bb20c94e57c764f06699e09e6ad071ad95539eef4fb505e79ab22e8be4d64067ccc"
              },
              "hostOutput": {
                "value": "0",
                "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
              },
              "missedHostValue": "0",
              "totalCollateral": "0",
              "renterPublicKey": "ed25519:65ea9701c409d4457a830b6fe7a2513d6f466ab4e424b3941de9f34a4a2d6170",
              "hostPublicKey": "ed25519:65ea9701c409d4457a830b6fe7a2513d6f466ab4e424b3941de9f34a4a2d6170",
              "revisionNumber": 0,
              "renterSignature": "sig:bd1794b9266fa0de94aea0f0ffb6550efd7e8874133963022413c8ccfe1a0e31c14690d3a5bbd343b160ed59219bd67f79103c45aee07f519d72b5ab4319440f",
              "hostSignature": "sig:bd1794b9266fa0de94aea0f0ffb6550efd7e8874133963022413c8ccfe1a0e31c14690d3a5bbd343b160ed59219bd67f79103c45aee07f519d72b5ab4319440f"
            }
          },
          "type": "finalization",
          "resolution": {
            "filesize": 0,
            "fileMerkleRoot": "h:0000000000000000000000000000000000000000000000000000000000000000",
            "proofHeight": 10,
            "expirationHeight": 20,
            "renterOutput": {
              "value": "10000000000000000000000000000",
              "address": "addr:c899f7795bb20c94e57c764f06699e09e6ad071ad95539eef4fb505e79ab22e8be4d64067ccc"
            },
            "hostOutput": {
              "value": "0",
              "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            },
            "missedHostValue": "0",
            "totalCollateral": "0",
            "renterPublicKey": "ed25519:65ea9701c409d4457a830b6fe7a2513d6f466ab4e424b3941de9f34a4a2d6170",
            "hostPublicKey": "ed25519:65ea9701c409d4457a830b6fe7a2513d6f466ab4e424b3941de9f34a4a2d6170",
            "revisionNumber": 1,
            "renterSignature": "sig:bd1794b9266fa0de94aea0f0ffb6550efd7e8874133963022413c8ccfe1a0e31c14690d3a5bbd343b160ed59219bd67f79103c45aee07f519d72b5ab4319440f",
            "hostSignature": "sig:bd1794b9266fa0de94aea0f0ffb6550efd7e8874133963022413c8ccfe1a0e31c14690d3a5bbd343b160ed59219bd67f79103c45aee07f519d72b5ab4319440f"
          }
        }
      }
    );

    let _event = serde_json::from_value::<Event>(j).unwrap();

    // FIXME this should deserialize from a JSON object generated from walletd and recalcuate the txid to check encoding/serde
}

#[test]
fn test_v2_transaction_serde_basic_send() {
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

    let j2 = serde_json::to_value(&tx).unwrap().to_string();
    let tx2 = serde_json::from_str::<V2Transaction>(&j2).unwrap();
    assert_eq!(tx, tx2);
}