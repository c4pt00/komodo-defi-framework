use kdf_walletconnect::{session::delete::send_session_delete_request, WalletConnectCtx};
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use serde::{Deserialize, Serialize};

use super::WalletConnectRpcError;

#[derive(Debug, PartialEq, Serialize)]
pub struct DeleteConnectionResponse {
    pub successful: bool,
}

#[derive(Deserialize)]
pub struct DeleteConnectionRequest {
    topic: String,
}

/// `delete connection` RPC command implementation.
pub async fn delete_connection(
    ctx: MmArc,
    req: DeleteConnectionRequest,
) -> MmResult<DeleteConnectionResponse, WalletConnectRpcError> {
    let ctx = WalletConnectCtx::try_from_ctx_or_initialize(&ctx)
        .mm_err(|err| WalletConnectRpcError::InitializationError(err.to_string()))?;
    send_session_delete_request(&ctx, &req.topic.into())
        .await
        .mm_err(|err| WalletConnectRpcError::SessionRequestError(err.to_string()))?;

    Ok(DeleteConnectionResponse { successful: true })
}
