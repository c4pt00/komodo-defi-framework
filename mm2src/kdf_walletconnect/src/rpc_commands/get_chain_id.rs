use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmResult;
use serde::Serialize;

use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use super::EmptyRpcRequst;

#[derive(Debug, PartialEq, Serialize)]
pub struct GetChainIdResponse {
    pub chain_id: String,
}

/// `delete connection` RPC command implementation.
pub async fn get_chain_id(ctx: MmArc, _req: EmptyRpcRequst) -> MmResult<GetChainIdResponse, WalletConnectCtxError> {
    let ctx = WalletConnectCtx::try_from_ctx_or_initialize(&ctx)?;
    let chain_id = ctx.get_active_chain_id().await;

    Ok(GetChainIdResponse { chain_id })
}
