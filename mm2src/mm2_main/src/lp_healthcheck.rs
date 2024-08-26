use common::HttpStatusCode;
use crypto::CryptoCtx;
use derive_more::Display;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::{encode_and_sign, pub_sub_topic, PeerId, TopicPrefix};
use mm2_net::p2p::P2PContext;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::lp_network::broadcast_p2p_msg;

pub const PEER_HEALTHCHECK_PREFIX: TopicPrefix = "hcheck";

struct HealtCheckMsg {
    peer_id: String,
    public_key_encoded: Vec<u8>,
    signature_bytes: Vec<u8>,
}

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
    let target_peer_id = PeerId::from_str(&req.peer_id).unwrap();
    let p2p_ctx = P2PContext::fetch_from_mm_arc(&ctx);
    let crypto_ctx = CryptoCtx::from_ctx(&ctx).expect("CryptoCtx must be initialized already");
    let my_peer_id = p2p_ctx.peer_id();

    let secret = crypto_ctx.mm2_internal_privkey_secret().take();
    let msg = encode_and_sign(&my_peer_id.to_bytes(), &secret).expect("TODO");

    println!("0000000000 SENDING FROM {:?}", my_peer_id.to_string());
    broadcast_p2p_msg(&ctx, peer_healthcheck_topic(&target_peer_id), msg, None);
    // TODO: wait (timeout is 5 seconds) for peer's answer.

    todo!()
}
