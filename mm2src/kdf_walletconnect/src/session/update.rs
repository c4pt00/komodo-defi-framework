use crate::storage::WalletConnectStorageOps;
use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use mm2_err_handle::prelude::*;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_update::SessionUpdateRequest, ResponseParamsSuccess}};

// TODO: Handle properly when multi chain is supported.
// Hanlding for only cosmos support.
pub(crate) async fn reply_session_update_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    update: SessionUpdateRequest,
) -> MmResult<(), WalletConnectCtxError> {
    {
        let mut session = ctx.session.lock().await;
        if let Some(session) = session.as_mut() {
            session.namespaces = update.namespaces.0.clone();

            // Update storage session.
            ctx.storage
                .db
                .update_session(session)
                .await
                .mm_err(|err| WalletConnectCtxError::StorageError(err.to_string()))?;
        };
    }

    let param = ResponseParamsSuccess::SessionUpdate(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}
