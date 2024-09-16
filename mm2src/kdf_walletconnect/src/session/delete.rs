use std::sync::Arc;

use common::log::info;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::rpc::params::RelayProtocolMetadata;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_delete::SessionDeleteRequest, ResponseParamsSuccess}};

use crate::{error::WalletConnectCtxError, WalletConnectCtx};

pub(crate) async fn process_session_delete_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    delete_params: SessionDeleteRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let response = ResponseParamsSuccess::SessionDelete(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub(crate) async fn session_delete_cleanup(
    ctx: Arc<WalletConnectCtx>,
    topic: &Topic,
) -> MmResult<(), WalletConnectCtxError> {
    let mut sessions = ctx.sessions.lock().await;
    sessions
        .remove(topic)
        .ok_or_else(|| WalletConnectCtxError::InternalError("Attempt to remove non-existing session".to_string()))?;

    ctx.client.unsubscribe(topic.clone()).await?;

    // Check if there are no active sessions remaining
    if sessions.is_empty() {
        info!("\nNo active sessions left, disconnecting the pairing");

        // Attempt to disconnect and remove the pairing associated with the topic
        ctx.pairing
            .disconnect(topic.as_ref(), &ctx.client)
            .await
            .map_err(|e| WalletConnectCtxError::InternalError(format!("Failed to disconnect pairing: {}", e)))?;
    }

    Ok(())
}
