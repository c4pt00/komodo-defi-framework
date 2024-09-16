use mm2_err_handle::prelude::MmResult;
use relay_rpc::rpc::params::RelayProtocolMetadata;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::ResponseParamsSuccess};

use crate::{error::WalletConnectCtxError, WalletConnectCtx};

pub(crate) async fn process_session_ping_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
) -> MmResult<(), WalletConnectCtxError> {
    let response = ResponseParamsSuccess::SessionPing(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}
