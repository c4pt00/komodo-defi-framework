use crate::{error::WalletConnectCtxError, WalletConnectCtx};
use common::log::info;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::rpc::params::RelayProtocolMetadata;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_update::SessionUpdateRequest, ResponseParamsSuccess}};

pub(crate) async fn process_session_update_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    update: SessionUpdateRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let mut sessions = ctx.sessions.lock().await;
    if let Some(session) = sessions.get_mut(topic) {
        session.namespaces = update.namespaces.0.clone();
        info!("Updated extended, info: {:?}", session);
    }

    let response = ResponseParamsSuccess::SessionUpdate(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    info!("published response");
    Ok(())
}
