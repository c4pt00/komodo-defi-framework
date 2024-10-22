use std::str::FromStr;

use async_std::stream::StreamExt;
use chrono::Utc;
use derive_more::Display;
use ethereum_types::{Address, Public, H160, H256};
use ethkey::{public_to_address, recover, Message, Signature};
use kdf_walletconnect::{chain::{WcRequestMethods, ETH_CHAIN_ID},
                        error::WalletConnectError,
                        WalletConnectCtx};
use mm2_err_handle::prelude::*;
use relay_rpc::rpc::params::session_request::SessionRequestRequest;
use relay_rpc::rpc::params::{session_request::Request as SessionRequest, RequestParams, ResponseParamsSuccess};
use web3::helpers;

#[derive(Display, Debug)]
pub enum EthWalletConnectError {
    InvalidSignature(String),
    AccoountMisMatch(String),
}

pub async fn eth_request_wc_personal(
    ctx: &WalletConnectCtx,
    chain_id: &str,
) -> MmResult<(Public, Address), WalletConnectError> {
    let topic = ctx
        .session
        .get_session_active()
        .await
        .map(|session| session.topic.clone())
        .ok_or(WalletConnectError::NotInitialized)?;

    let full_chain_id = format!("{ETH_CHAIN_ID}:{chain_id}");

    let account_str = ctx.get_account_for_chain_id(&full_chain_id).await?;
    let account = helpers::serialize(&account_str);
    let message_str = "KDF: Verify that this account is yours";
    let message = helpers::serialize(&message_str);

    let params = json!(&[&account, &message]);

    let request = SessionRequestRequest {
        request: SessionRequest {
            method: WcRequestMethods::PersonalSign.as_ref().to_owned(),
            expiry: Some(Utc::now().timestamp() as u64 + 300),
            params,
        },
        chain_id: full_chain_id,
    };
    {
        let session_request = RequestParams::SessionRequest(request);
        ctx.publish_request(&topic, session_request).await?;
    }

    let mut session_handler = ctx.session_request_handler.lock().await;
    if let Some((message_id, data)) = session_handler.next().await {
        let result = serde_json::from_value::<String>(data)?;
        let response = ResponseParamsSuccess::SessionEvent(true);
        ctx.publish_response_ok(&topic, response, &message_id).await?;

        let hash = Message::from_str(&hex::encode(message_str)).expect("valid message hash");

        return get_pubkey_from_signature(&result, &hash, &account_str)
            .mm_err(|err| WalletConnectError::PayloadError(err.to_string()));
    }

    MmError::err(WalletConnectError::InternalError("No response from wallet".to_string()))
}

fn get_pubkey_from_signature(
    signature: &str,
    hash: &H256,
    account: &str,
) -> MmResult<(Public, Address), EthWalletConnectError> {
    let account = H160::from_str(account).expect("valid eth account");
    let signature = signature.strip_prefix("0x").unwrap_or(signature);
    let signature =
        Signature::from_str(signature).map_to_mm(|err| EthWalletConnectError::InvalidSignature(err.to_string()))?;

    let pubkey = recover(&signature, hash).map_to_mm(|_| {
        let error = format!("Couldn't recover a public key from the signature: '{signature:?}'");
        EthWalletConnectError::InvalidSignature(error)
    })?;

    let recovered_address = public_to_address(&pubkey);

    if account != recovered_address {
        let error = format!("Recovered address '{recovered_address:?}' should be the same as '{account:?}'");
        return MmError::err(EthWalletConnectError::AccoountMisMatch(error));
    }

    Ok((pubkey, recovered_address))
}
