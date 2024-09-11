use crate::{error::WalletConnectCtxError, session::WcRequestResult, WalletConnectCtx};

use relay_rpc::rpc::params::RelayProtocolMetadata;
use relay_rpc::{domain::Topic,
                rpc::params::{pairing_delete::PairingDeleteRequest, pairing_extend::PairingExtendRequest,
                              ResponseParamsSuccess}};

pub(crate) async fn process_pairing_ping_response() -> WcRequestResult {
    let response = ResponseParamsSuccess::PairingPing(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

    Ok((value, irn_metadata))
}

pub(crate) async fn process_pairing_extend_response(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    extend: PairingExtendRequest,
) -> WcRequestResult {
    {
        let mut pairings = ctx.pairing.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic.as_ref()) {
            pairing.pairing.expiry = extend.expiry;
            pairing.pairing.active = true;
        };
    }

    let response = ResponseParamsSuccess::PairingPing(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

    Ok((value, irn_metadata))
}

pub(crate) async fn process_pairing_delete_response(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    _delete: PairingDeleteRequest,
) -> WcRequestResult {
    {
        ctx.pairing.disconnect(topic.as_ref(), &ctx.client).await?;
    }

    let response = ResponseParamsSuccess::PairingDelete(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

    Ok((value, irn_metadata))
}
