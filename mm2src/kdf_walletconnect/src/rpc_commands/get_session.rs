use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmResult;
use serde::Serialize;

use super::EmptyRpcRequst;
use crate::{error::WalletConnectCtxError, session::Session, WalletConnectCtx};

#[derive(Debug, PartialEq, Serialize)]
pub struct GetSessionResponse {
    pub session: Option<Session>,
}

/// `delete connection` RPC command implementation.
pub async fn get_session(ctx: MmArc, _req: EmptyRpcRequst) -> MmResult<GetSessionResponse, WalletConnectCtxError> {
    let ctx = WalletConnectCtx::try_from_ctx_or_initialize(&ctx)?;
    let session = ctx.get_session().await;

    Ok(GetSessionResponse { session })
}
