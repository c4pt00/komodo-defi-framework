use common::log::info;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::rpc::params::RelayProtocolMetadata;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_extend::SessionExtendRequest, ResponseParamsSuccess}};

use crate::{error::WalletConnectCtxError, WalletConnectCtx};

/// Process session extend request.
pub(crate) async fn process_session_extend_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    extend: SessionExtendRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let mut sessions = ctx.sessions.lock().await;
    if let Some(session) = sessions.get_mut(topic) {
        session.expiry = extend.expiry;
        info!("Updated extended, info: {:?}", session);
    }

    let response = ResponseParamsSuccess::SessionExtend(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}
