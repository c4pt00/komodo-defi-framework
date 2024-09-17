use std::sync::Arc;

use common::log::{debug, info};
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

    session_delete_cleanup(ctx, topic).await?;

    Ok(())
}

async fn session_delete_cleanup(ctx: &WalletConnectCtx, topic: &Topic) -> MmResult<(), WalletConnectCtxError> {
    let (session_count, pairing_topic) = {
        let mut sessions = ctx.sessions.lock().await;
        let session = sessions.remove(topic).ok_or_else(|| {
            WalletConnectCtxError::InternalError("Attempt to remove non-existing session".to_string())
        })?;

        ctx.client.unsubscribe(topic.clone()).await?;

        // Get the pairing topic
        let pairing_topic = session.pairing_topic.clone();
        // Check if there are no more sessions for this pairing
        let session_count = sessions.values().filter(|s| s.pairing_topic == pairing_topic).count();

        (session_count, pairing_topic)
    };

    if session_count == 0 {
        debug!("No active sessions left for pairing {}, disconnecting", pairing_topic);
        // Attempt to disconnect the pairing
        ctx.pairing.disconnect(pairing_topic.as_ref(), &ctx.client).await?;
    }

    Ok(())
}
