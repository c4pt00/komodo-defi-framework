use crate::{error::{WalletConnectCtxError, USER_REQUESTED},
            WalletConnectCtx};

use common::log::debug;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_delete::SessionDeleteRequest, RequestParams, ResponseParamsSuccess}};

pub(crate) async fn reply_session_delete_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    _delete_params: SessionDeleteRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let param = ResponseParamsSuccess::SessionDelete(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    session_delete_cleanup(ctx, topic).await
}

pub(crate) async fn send_session_delete_request(
    ctx: &WalletConnectCtx,
    session_topic: &Topic,
) -> MmResult<(), WalletConnectCtxError> {
    let delete_request = SessionDeleteRequest {
        code: USER_REQUESTED,
        message: "User Disconnected".to_owned(),
    };
    let param = RequestParams::SessionDelete(delete_request);

    ctx.publish_request(session_topic, param).await?;

    session_delete_cleanup(ctx, session_topic).await
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
