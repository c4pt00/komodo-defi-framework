use kdf_walletconnect::{session::Session, WalletConnectCtx};
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use serde::Serialize;

use super::{EmptyRpcRequst, WalletConnectRpcError};

#[derive(Debug, PartialEq, Serialize)]
pub struct GetSessionResponse {
    pub session: Option<Session>,
}

/// `delete connection` RPC command implementation.
pub async fn get_session(ctx: MmArc, _req: EmptyRpcRequst) -> MmResult<GetSessionResponse, WalletConnectRpcError> {
    let ctx =
        WalletConnectCtx::from_ctx(&ctx).mm_err(|err| WalletConnectRpcError::InitializationError(err.to_string()))?;
    let session = ctx.session.get_session_active().await;

    Ok(GetSessionResponse { session })
}
