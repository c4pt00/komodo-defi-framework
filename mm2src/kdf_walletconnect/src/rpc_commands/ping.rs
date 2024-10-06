use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::domain::Topic;
use serde::{Deserialize, Serialize};

use crate::{error::WalletConnectCtxError, session::ping::send_session_ping_request, WalletConnectCtx};

#[derive(Debug, PartialEq, Serialize)]
pub struct SessionPingResponse {
    pub successful: bool,
}

#[derive(Deserialize)]
pub struct SessionPingRequest {
    topic: Topic,
}

/// `ping session` RPC command implementation.
pub async fn ping_session(ctx: MmArc, req: SessionPingRequest) -> MmResult<SessionPingResponse, WalletConnectCtxError> {
    let ctx = WalletConnectCtx::from_ctx(&ctx)?;
    send_session_ping_request(&ctx, &req.topic).await?;

    Ok(SessionPingResponse { successful: true })
}
