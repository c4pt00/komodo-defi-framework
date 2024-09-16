use crate::session::{WcRequestResponseResult, THIRTY_DAYS};
use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use chrono::Utc;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::domain::MessageId;
use relay_rpc::rpc::params::pairing_ping::PairingPingRequest;
use relay_rpc::rpc::params::{RelayProtocolMetadata, RequestParams};
use relay_rpc::{domain::Topic,
                rpc::params::{pairing_delete::PairingDeleteRequest, pairing_extend::PairingExtendRequest,
                              ResponseParamsSuccess}};

pub(crate) async fn process_pairing_ping_response(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
) -> MmResult<(), WalletConnectCtxError> {
    let response = ResponseParamsSuccess::PairingPing(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub(crate) async fn process_pairing_extend_response(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    extend: PairingExtendRequest,
) -> MmResult<(), WalletConnectCtxError> {
    {
        let mut pairings = ctx.pairing.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic.as_ref()) {
            pairing.pairing.expiry = extend.expiry;
            pairing.pairing.active = true;
        };
    }

    let response = ResponseParamsSuccess::PairingPing(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub(crate) async fn process_pairing_delete_response(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    _delete: PairingDeleteRequest,
) -> MmResult<(), WalletConnectCtxError> {
    {
        ctx.pairing.disconnect(topic.as_ref(), &ctx.client).await?;
    }

    let response = ResponseParamsSuccess::PairingDelete(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub(crate) async fn pairing_ping_request() -> WcRequestResponseResult {
    let request = RequestParams::PairingPing(PairingPingRequest {});
    let irn_metadata = request.irn_metadata();
    let value = serde_json::to_value(request)?;

    Ok((value, irn_metadata))
}

pub(crate) async fn pairing_delete_request() -> WcRequestResponseResult {
    let request = RequestParams::PairingDelete(PairingDeleteRequest {
        code: 6000,
        message: "Delete my pairing".to_string(),
    });
    let irn_metadata = request.irn_metadata();
    let value = serde_json::to_value(request)?;

    Ok((value, irn_metadata))
}

pub(crate) async fn pairing_extend_request() -> WcRequestResponseResult {
    let request = RequestParams::PairingExtend(PairingExtendRequest {
        expiry: Utc::now().timestamp() as u64 + THIRTY_DAYS,
    });
    let irn_metadata = request.irn_metadata();
    let value = serde_json::to_value(request)?;

    Ok((value, irn_metadata))
}
