use chrono::Utc;
use common::HttpStatusCode;
use crypto::CryptoCtx;
use derive_more::Display;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::{encode_and_sign, pub_sub_topic, Libp2pPublic, PeerId, SigningError, TopicPrefix};
use mm2_net::p2p::P2PContext;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::lp_network::broadcast_p2p_msg;

pub const PEER_HEALTHCHECK_PREFIX: TopicPrefix = "hcheck";

struct HealthCheckMessage {
    signature: Vec<u8>,
    data: HealthCheckData,
}

impl HealthCheckMessage {
    pub fn generate_message(ctx: &MmArc, target_peer: PeerId, expires_in_seconds: i64) -> Result<Self, SigningError> {
        let p2p_ctx = P2PContext::fetch_from_mm_arc(ctx);
        let sender_peer = p2p_ctx.peer_id().to_string();
        let keypair = p2p_ctx.keypair();
        let sender_public_key = keypair.public().encode_protobuf();
        let target_peer = target_peer.to_string();

        let data = HealthCheckData {
            sender_peer,
            sender_public_key,
            target_peer,
            expires_at: Utc::now().timestamp() + expires_in_seconds,
        };

        let signature = keypair.sign(&data.encode())?;

        Ok(Self { signature, data })
    }

    fn is_received_message_valid(&self, my_peer_id: PeerId) -> bool {
        if Utc::now().timestamp() > self.data.expires_at {
            return false;
        }

        if self.data.target_peer != my_peer_id.to_string() {
            return false;
        }

        let Ok(public_key) = Libp2pPublic::try_decode_protobuf(&self.data.sender_public_key) else { return false };

        if self.data.sender_peer != public_key.to_peer_id().to_string() {
            return false;
        }

        public_key.verify(&self.data.encode(), &self.signature)
    }
}

struct HealthCheckData {
    sender_peer: String,
    sender_public_key: Vec<u8>,
    target_peer: String,
    expires_at: i64,
}

impl HealthCheckData {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.sender_peer.as_bytes());
        bytes.extend(&self.sender_public_key);
        bytes.extend(self.target_peer.as_bytes());
        bytes.extend(self.expires_at.to_ne_bytes());

        bytes
    }
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
