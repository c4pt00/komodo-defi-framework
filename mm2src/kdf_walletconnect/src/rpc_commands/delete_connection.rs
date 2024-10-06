use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::domain::Topic;
use serde::{Deserialize, Serialize};

use crate::{error::WalletConnectCtxError, session::delete::send_session_delete_request, WalletConnectCtx};

#[derive(Debug, PartialEq, Serialize)]
pub struct DeleteConnectionResponse {
    pub successful: bool,
}

#[derive(Deserialize)]
pub struct DeleteConnectionRequest {
    topic: Topic,
}

/// `delete connection` RPC command implementation.
pub async fn delete_connection(
    ctx: MmArc,
    req: DeleteConnectionRequest,
) -> MmResult<DeleteConnectionResponse, WalletConnectCtxError> {
    let ctx = WalletConnectCtx::from_ctx(&ctx)?;
    send_session_delete_request(&ctx, &req.topic).await?;

    Ok(DeleteConnectionResponse { successful: true })
}
