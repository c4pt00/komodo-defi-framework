use common::HttpStatusCode;
use derive_more::Display;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::PeerId;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::p2p::P2PContext;

#[derive(Clone, Deserialize)]
pub struct RequestPayload {
    peer_id: String,
}

#[derive(Clone, Debug, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum QueryError {}

impl HttpStatusCode for QueryError {
    fn status_code(&self) -> common::StatusCode { todo!() }
}

pub async fn peer_connection_healthcheck_rpc(ctx: MmArc, req: RequestPayload) -> Result<bool, MmError<QueryError>> {
    let peer_id = PeerId::from_str(&req.peer_id).unwrap();
    let ctx = P2PContext::fetch_from_mm_arc(&ctx);
    let cmd_tx = ctx.cmd_tx.lock().clone();
    Ok(mm2_libp2p::peer_connection_healthcheck(cmd_tx, peer_id).await)
}
