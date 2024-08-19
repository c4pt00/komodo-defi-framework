use common::HttpStatusCode;
use derive_more::Display;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::PeerId;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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

pub async fn is_peer_connected(_ctx: MmArc, req: RequestPayload) -> Result<bool, MmError<QueryError>> {
    let _peer_id = PeerId::from_str(&req.peer_id).unwrap();
    todo!()
}
