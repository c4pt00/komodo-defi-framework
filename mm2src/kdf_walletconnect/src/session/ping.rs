use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::ResponseParamsSuccess};

pub(crate) async fn process_session_ping_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
) -> MmResult<(), WalletConnectCtxError> {
    let param = ResponseParamsSuccess::SessionPing(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}
