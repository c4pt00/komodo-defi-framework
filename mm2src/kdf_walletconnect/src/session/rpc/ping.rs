use std::time::Duration;

use crate::{error::WalletConnectError, WalletConnectCtx};

use common::custom_futures::timeout::FutureTimerExt;
use futures::StreamExt;
use mm2_err_handle::prelude::*;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{RequestParams, ResponseParamsSuccess}};

pub(crate) async fn reply_session_ping_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
) -> MmResult<(), WalletConnectError> {
    let param = ResponseParamsSuccess::SessionPing(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}

pub async fn send_session_ping_request(ctx: &WalletConnectCtx, topic: &Topic) -> MmResult<(), WalletConnectError> {
    let param = RequestParams::SessionPing(());
    ctx.publish_request(topic, param).await?;

    let wait_duration = Duration::from_secs(30);
    if let Ok(Some(resp)) = ctx.message_rx.lock().await.next().timeout(wait_duration).await {
        resp.mm_err(WalletConnectError::InternalError)?;
        return Ok(());
    }

    MmError::err(WalletConnectError::PayloadError("Session Ping Error".to_owned()))
}
