use async_std::prelude::FutureExt;
use chrono::Utc;
use common::HttpStatusCode;
use derive_more::Display;
use futures::channel::oneshot::{self, Receiver, Sender};
use instant::Duration;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::{decode_message, encode_message, pub_sub_topic, Libp2pPublic, PeerId, SigningError, TopicPrefix};
use mm2_net::p2p::P2PContext;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::lp_network::broadcast_p2p_msg;

pub(crate) const PEER_HEALTHCHECK_PREFIX: TopicPrefix = "hcheck";

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HealthcheckMessage {
    signature: Vec<u8>,
    data: HealthCheckData,
}

impl HealthcheckMessage {
    pub(crate) fn generate_message(
        ctx: &MmArc,
        target_peer: PeerId,
        is_a_reply: bool,
        expires_in_seconds: i64,
    ) -> Result<Self, SigningError> {
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
            is_a_reply,
        };

        let signature = keypair.sign(&data.encode().unwrap())?;

        Ok(Self { signature, data })
    }

    pub(crate) fn is_received_message_valid(&self, my_peer_id: PeerId) -> bool {
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

        public_key.verify(&self.data.encode().unwrap(), &self.signature)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> { encode_message(self) }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> { decode_message(bytes) }

    pub(crate) fn should_reply(&self) -> bool { !self.data.is_a_reply }

    pub(crate) fn sender_peer(&self) -> &str { &self.data.sender_peer }
}

#[derive(Debug, Deserialize, Serialize)]
struct HealthCheckData {
    sender_peer: String,
    sender_public_key: Vec<u8>,
    target_peer: String,
    expires_at: i64,
    is_a_reply: bool,
}

impl HealthCheckData {
    fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> { encode_message(self) }
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
    /// When things go awry, we want records to clear themselves to keep the memory clean of unused data.
    /// This is unrelated to the timeout logic.
    const ADDRESS_RECORD_EXPIRATION: Duration = Duration::from_secs(60);

    const RESULT_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

    let target_peer_id = PeerId::from_str(&req.peer_id).unwrap();
    let msg = HealthcheckMessage::generate_message(&ctx, target_peer_id, false, 10).unwrap();

    let (tx, rx): (Sender<()>, Receiver<()>) = oneshot::channel();
    {
        let mut book = ctx.healthcheck_book.lock().await;
        book.clear_expired_entries();
        book.insert(target_peer_id.to_string(), tx, ADDRESS_RECORD_EXPIRATION);
    }

    broadcast_p2p_msg(
        &ctx,
        peer_healthcheck_topic(&target_peer_id),
        msg.encode().unwrap(),
        None,
    );

    Ok(rx.timeout(RESULT_CHANNEL_TIMEOUT).await == Ok(Ok(())))
}
