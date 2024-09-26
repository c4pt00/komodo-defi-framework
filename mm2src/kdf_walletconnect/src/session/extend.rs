use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use common::log::info;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_extend::SessionExtendRequest, ResponseParamsSuccess}};

/// Process session extend request.
pub(crate) async fn reply_session_extend_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    extend: SessionExtendRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let mut session = ctx.session.lock().await;
    if let Some(session) = session.as_mut() {
        session.expiry = extend.expiry;
        info!("Updated extended, info: {:?}", session);
    }

    let param = ResponseParamsSuccess::SessionExtend(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}
