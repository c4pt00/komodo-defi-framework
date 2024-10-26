use crate::{BytesJson, H256};

use chrono::Utc;
use derive_more::Display;
use ethcore_transaction::SignedTransaction;
use ethereum_types::{Address, Public, H160, U256};
use ethkey::{public_to_address, Message, Signature};
use kdf_walletconnect::{chain::{WcChain, WcRequestMethods},
                        error::WalletConnectError,
                        WalletConnectCtx};
use mm2_err_handle::prelude::*;
use relay_rpc::rpc::params::session_request::SessionRequestRequest;
use relay_rpc::rpc::params::{session_request::Request as SessionRequest, RequestParams};
use secp256k1::{recovery::{RecoverableSignature, RecoveryId},
                Secp256k1};
use std::{collections::HashMap, str::FromStr};
use web3::signing::hash_message;

#[derive(Display, Debug)]
pub enum EthWalletConnectError {
    InvalidSignature(String),
    AccoountMisMatch(String),
    TxDecodingFailed(String),
    InternalError(String),
    WalletConnectError(WalletConnectError),
}

impl From<WalletConnectError> for EthWalletConnectError {
    fn from(value: WalletConnectError) -> Self { Self::WalletConnectError(value) }
}

impl From<EthWalletConnectError> for WalletConnectError {
    fn from(value: EthWalletConnectError) -> Self { Self::SessionError(value.to_string()) }
}

impl From<rlp::DecoderError> for EthWalletConnectError {
    fn from(value: rlp::DecoderError) -> Self { Self::TxDecodingFailed(value.to_string()) }
}

impl From<ethkey::Error> for EthWalletConnectError {
    fn from(value: ethkey::Error) -> Self { Self::InternalError(value.to_string()) }
}

impl From<hex::FromHexError> for EthWalletConnectError {
    fn from(value: hex::FromHexError) -> Self { Self::TxDecodingFailed(value.to_string()) }
}

pub async fn wc_sign_eth_transaction(
    ctx: &WalletConnectCtx,
    chain_id: u64,
    tx_json: serde_json::Value,
) -> MmResult<(H256, BytesJson), EthWalletConnectError> {
    let chain_id = chain_id.to_string();
    let topic = ctx
        .session
        .get_session_active()
        .await
        .map(|session| session.topic.clone())
        .ok_or(WalletConnectError::NotInitialized)?;

    {
        let request = SessionRequestRequest {
            chain_id: WcChain::Eip155.to_chain_id(&chain_id),
            request: SessionRequest {
                method: WcRequestMethods::EthSignTransaction.as_ref().to_string(),
                expiry: Some(Utc::now().timestamp() as u64 + 300),
                params: tx_json.clone(),
            },
        };
        ctx.publish_request(&topic, RequestParams::SessionRequest(request))
            .await?;
    };

    let bytes = {
        let tx_hex: String = ctx.on_wc_session_response(Ok).await?;
        // First 4 bytes from WalletConnect represents Protoc info
        hex::decode(&tx_hex[4..])?
    };
    let unverified = rlp::decode(&bytes)?;
    let signed = SignedTransaction::new(unverified)?;
    let bytes = rlp::encode(&signed);

    Ok((signed.tx_hash(), BytesJson::from(bytes.to_vec())))
}

pub async fn eth_request_wc_personal_sign(
    ctx: &WalletConnectCtx,
    chain_id: u64,
) -> MmResult<(Public, Address), WalletConnectError> {
    let topic = ctx
        .session
        .get_session_active()
        .await
        .map(|session| session.topic.clone())
        .ok_or(WalletConnectError::NotInitialized)?;

    let account_str = ctx.get_account_for_chain_id(&chain_id.to_string()).await?;
    let message = "Authenticate with Komodefi";
    let message_hex = format!("0x{}", hex::encode(message));
    let params = json!(&[&message_hex, &account_str]);

    let request = SessionRequestRequest {
        request: SessionRequest {
            method: WcRequestMethods::PersonalSign.as_ref().to_owned(),
            expiry: Some(Utc::now().timestamp() as u64 + 300),
            params,
        },
        chain_id: format!("{}:{chain_id}", WcChain::Eip155.as_ref()),
    };
    {
        let session_request = RequestParams::SessionRequest(request);
        ctx.publish_request(&topic, session_request).await?;
    }

    ctx.on_wc_session_response(|data: String| Ok(extract_pubkey_from_signature(&data, message, &account_str)?))
        .await
}

fn extract_pubkey_from_signature(
    signature_str: &str,
    message: impl ToString,
    account: &str,
) -> MmResult<(Public, Address), EthWalletConnectError> {
    let message_hash = hash_message(message.to_string());
    let account = H160::from_str(&account[2..]).expect("valid eth account");
    let signature = Signature::from_str(&signature_str[2..])
        .map_to_mm(|err| EthWalletConnectError::InvalidSignature(err.to_string()))?;
    let pubkey = recover(&signature, &message_hash).map_to_mm(|err| {
        let error = format!("Couldn't recover a public key from the signature: '{signature:?}, error: {err:?}'");
        EthWalletConnectError::InvalidSignature(error)
    })?;

    let recovered_address = public_to_address(&pubkey);

    if account != recovered_address {
        let error = format!("Recovered address '{recovered_address:?}' should be the same as '{account:?}'");
        return MmError::err(EthWalletConnectError::AccoountMisMatch(error));
    }

    Ok((pubkey, recovered_address))
}

pub fn recover(signature: &Signature, message: &Message) -> Result<Public, ethkey::Error> {
    let recovery_id = signature[64] as i32 - 27;
    let recovery_id = RecoveryId::from_i32(recovery_id)?;
    let sig = RecoverableSignature::from_compact(&signature[0..64], recovery_id)?;
    let pubkey = Secp256k1::new().recover(&secp256k1::Message::from_slice(&message[..])?, &sig)?;
    let serialized = pubkey.serialize_uncompressed();

    let mut public = Public::default();
    public.as_mut().copy_from_slice(&serialized[1..65]);
    Ok(public)
}

pub fn wc_prepare_eth_tx_data(
    gas: U256,
    nonce: U256,
    data: &[u8],
    my_address: H160,
    to_addr: H160,
    value: U256,
    gas_price: Option<U256>,
) -> MmResult<serde_json::Value, String> {
    fn u256_to_hex(value: U256) -> String { format!("0x{:x}", value) }

    let mut mapped_data = HashMap::from([
        ("nonce", u256_to_hex(nonce)),
        ("to", format!("0x{}", hex::encode(to_addr.as_bytes()))),
        ("from", format!("0x{}", hex::encode(my_address.as_bytes()))),
        ("gas", u256_to_hex(gas)),
        ("value", u256_to_hex(value)),
        ("data", format!("0x{}", hex::encode(data))),
    ]);

    if let Some(gas_price) = gas_price {
        mapped_data.insert("gasPrice", u256_to_hex(gas_price));
    }

    serde_json::to_value(vec![mapped_data]).map_to_mm(|err| err.to_string())
}
