use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmResult;
use serde::Serialize;

use super::EmptyRpcRequst;
use crate::{error::WalletConnectCtxError, WalletConnectCtx};

#[derive(Debug, PartialEq, Serialize)]
pub struct CreateConnectionResponse {
    pub url: String,
}

/// `new_connection` RPC command implementation.
pub async fn new_connection(
    ctx: MmArc,
    _req: EmptyRpcRequst,
) -> MmResult<CreateConnectionResponse, WalletConnectCtxError> {
    let ctx = WalletConnectCtx::try_from_ctx_or_initialize(&ctx)?;
    let url = ctx.new_connection(None).await?;

    Ok(CreateConnectionResponse { url })
}
