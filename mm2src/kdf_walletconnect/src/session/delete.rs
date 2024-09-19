use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use common::log::debug;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_delete::SessionDeleteRequest, ResponseParamsSuccess}};

pub(crate) async fn process_session_delete_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    _delete_params: SessionDeleteRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let param = ResponseParamsSuccess::SessionDelete(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    session_delete_cleanup(ctx, topic).await?;

    Ok(())
}

async fn session_delete_cleanup(ctx: &WalletConnectCtx, topic: &Topic) -> MmResult<(), WalletConnectCtxError> {
    {
        ctx.client.unsubscribe(topic.clone()).await?;
    };

    if let Some(session) = ctx.session.lock().await.as_mut().take() {
        debug!(
            "No active sessions left for pairing {}, disconnecting",
            session.pairing_topic
        );
        // Attempt to disconnect the pairing
        ctx.pairing
            .disconnect(session.pairing_topic.as_ref(), &ctx.client)
            .await?;
    }

    Ok(())
}
