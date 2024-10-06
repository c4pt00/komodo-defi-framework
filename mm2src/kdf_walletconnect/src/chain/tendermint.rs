use crate::{error::WalletConnectCtxError, WalletConnectCtx};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use common::log::info;
use futures::StreamExt;
use mm2_err_handle::prelude::{MmError, MmResult};
use relay_rpc::rpc::params::{session_request::{Request as SessionRequest, SessionRequestRequest},
                             RequestParams, ResponseParamsSuccess};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::WcRequestMethods;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CosmosAccountAlgo {
    #[serde(rename = "secp256k1")]
    Secp256k1,
    #[serde(rename = "tendermint/PubKeySecp256k1")]
    TendermintSecp256k1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmosAccount {
    pub address: String,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub pubkey: Vec<u8>,
    pub algo: CosmosAccountAlgo,
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Object(map) => {
            let mut vec = Vec::new();
            for i in 0..map.len() {
                if let Some(Value::Number(num)) = map.get(&i.to_string()) {
                    if let Some(byte) = num.as_u64() {
                        vec.push(byte as u8);
                    } else {
                        return Err(serde::de::Error::custom("Invalid byte value"));
                    }
                } else {
                    return Err(serde::de::Error::custom("Invalid pubkey format"));
                }
            }
            Ok(vec)
        },
        Value::Array(arr) => arr
            .into_iter()
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| serde::de::Error::custom("Invalid byte value"))
                    .map(|n| n as u8)
            })
            .collect(),
        Value::String(data) => {
            let data = general_purpose::STANDARD
                .decode(data)
                .map_err(|err| serde::de::Error::custom(err.to_string()))?;
            Ok(data)
        },
        _ => Err(serde::de::Error::custom("Pubkey must be an string, object or array")),
    }
}

pub async fn cosmos_get_accounts_impl(
    ctx: &WalletConnectCtx,
    chain_id: &str,
) -> MmResult<Vec<CosmosAccount>, WalletConnectCtxError> {
    let account = ctx.get_account_for_chain_id(chain_id).await?;

    let session_topic = {
        let session = ctx.session.lock().await;
        session.as_ref().map(|s| s.topic.clone())
    };

    if let Some(topic) = session_topic {
        let request = SessionRequest {
            method: WcRequestMethods::CosmosGetAccounts.as_ref().to_owned(),
            expiry: Some(Utc::now().timestamp() as u64 + 300),
            params: serde_json::to_value(&account).unwrap(),
        };
        let request = SessionRequestRequest {
            request,
            chain_id: format!("cosmos:{chain_id}"),
        };

        {
            let session_request = RequestParams::SessionRequest(request);
            ctx.publish_request(&topic, session_request).await?;
        };

        let mut session_handler = ctx.session_request_handler.lock().await;
        if let Some((message_id, data)) = session_handler.next().await {
            info!("Got cosmos account: {data:?}");
            let result = serde_json::from_value::<Vec<CosmosAccount>>(data)?;
            let response = ResponseParamsSuccess::SessionEvent(true);
            ctx.publish_response_ok(&topic, response, &message_id).await?;

            return Ok(result);
        }
    }

    MmError::err(WalletConnectCtxError::InvalidRequest)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CosmosTxSignedData {
    pub signature: CosmosTxSignature,
    pub signed: CosmosSignData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CosmosTxSignature {
    pub pub_key: CosmosTxPublicKey,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CosmosTxPublicKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosSignData {
    pub chain_id: String,
    pub account_number: String,
    pub auth_info_bytes: String,
    pub body_bytes: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosTxSignParams {
    pub signer_address: String,
    pub sign_doc: CosmosSignData,
}

pub async fn cosmos_sign_tx_direct_impl(
    ctx: &WalletConnectCtx,
    sign_doc: Value,
    chain_id: &str,
) -> MmResult<CosmosTxSignedData, WalletConnectCtxError> {
    let session_topic = {
        let session = ctx.session.lock().await;
        session.as_ref().map(|s| s.topic.clone())
    };

    // return not NotInitialized error if no session is found.
    if session_topic.is_none() {
        return MmError::err(WalletConnectCtxError::NotInitialized);
    }

    let request = SessionRequest {
        method: WcRequestMethods::CosmosSignDirect.as_ref().to_owned(),
        expiry: Some(Utc::now().timestamp() as u64 + 300),
        params: sign_doc,
    };
    let request = SessionRequestRequest {
        request,
        chain_id: format!("cosmos:{chain_id}"),
    };

    let topic = session_topic.unwrap();
    {
        let session_request = RequestParams::SessionRequest(request);
        ctx.publish_request(&topic, session_request).await?;
    }

    let mut session_handler = ctx.session_request_handler.lock().await;
    if let Some((message_id, data)) = session_handler.next().await {
        info!("Got cosmos sign response: {data:?}");
        let result = serde_json::from_value::<CosmosTxSignedData>(data)?;
        let response = ResponseParamsSuccess::SessionEvent(true);
        ctx.publish_response_ok(&topic, response, &message_id).await?;

        return Ok(result);
    }

    MmError::err(WalletConnectCtxError::InternalError(
        "No response from wallet".to_string(),
    ))
}

//{
//    "id": 1,
//    "jsonrpc": "2.0",
//    "method": "cosmos_signDirect",
//    "params": {
//        "signerAddress": "cosmos1sguafvgmel6f880ryvq8efh9522p8zvmrzlcrq",
//        "signDoc":  {
//            "chainId": "cosmoshub-4",
//            "accountNumber": "1"
//            "authInfoBytes": "CgoKABIECgIIARgBEhMKDQoFdWNvc20SBDIwMDAQwJoM",
//            "bodyBytes": "CpABChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEnAKLWNvc21vczFwa3B0cmU3ZmRrbDZnZnJ6bGVzamp2aHhobGMzcjRnbW1rOHJzNhItY29zbW9zMXF5cHF4cHE5cWNyc3N6ZzJwdnhxNnJzMHpxZzN5eWM1bHp2N3h1GhAKBXVjb3NtEgcxMjM0NTY3"
//        }
//    }
// }
