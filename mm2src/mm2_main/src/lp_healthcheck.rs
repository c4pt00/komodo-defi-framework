use common::HttpStatusCode;
use derive_more::Display;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::{pub_sub_topic, PeerId, TopicPrefix};
use mm2_net::p2p::P2PContext;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::lp_network::broadcast_p2p_msg;

pub const PEER_HEALTHCHECK_PREFIX: TopicPrefix = "hcheck";

#[inline]
pub fn peer_healthcheck_topic(peer_id: &PeerId) -> String {
    pub_sub_topic(PEER_HEALTHCHECK_PREFIX, &peer_id.to_string())
}

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
    let p2p_ctx = P2PContext::fetch_from_mm_arc(&ctx);
    let cmd_tx = p2p_ctx.cmd_tx.lock().clone();

    broadcast_p2p_msg(&ctx, peer_healthcheck_topic(&peer_id), vec![], Some(p2p_ctx.peer_id()));
    // TODO: wait (timeout is 5 seconds) for peer's answer.

    todo!()
}
