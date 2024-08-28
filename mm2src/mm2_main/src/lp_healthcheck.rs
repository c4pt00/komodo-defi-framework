use async_std::prelude::FutureExt;
use chrono::Utc;
use common::{log, HttpStatusCode, StatusCode};
use derive_more::Display;
use futures::channel::oneshot::{self, Receiver, Sender};
use instant::Duration;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmError;
use mm2_libp2p::{decode_message, encode_message, pub_sub_topic, Libp2pPublic, PeerId, TopicPrefix};
use mm2_net::p2p::P2PContext;
use ser_error_derive::SerializeErrorType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::lp_network::broadcast_p2p_msg;

pub(crate) const PEER_HEALTHCHECK_PREFIX: TopicPrefix = "hcheck";

/// The default duration required to wait before sending another healthcheck
/// request to the same peer.
pub(crate) const HEALTHCHECK_BLOCKING_DURATION: Duration = Duration::from_millis(750);

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HealthcheckMessage {
    signature: Vec<u8>,
    data: HealthcheckData,
}

impl HealthcheckMessage {
    pub(crate) fn generate_message(
        ctx: &MmArc,
        target_peer: PeerId,
        is_a_reply: bool,
        expires_in_seconds: i64,
    ) -> Result<Self, String> {
        let p2p_ctx = P2PContext::fetch_from_mm_arc(ctx);
        let sender_peer = p2p_ctx.peer_id().to_string();
        let keypair = p2p_ctx.keypair();
        let sender_public_key = keypair.public().encode_protobuf();
        let target_peer = target_peer.to_string();

        let data = HealthcheckData {
            sender_peer,
            sender_public_key,
            target_peer,
            expires_at: Utc::now().timestamp() + expires_in_seconds,
            is_a_reply,
        };

        let signature = try_s!(keypair.sign(&try_s!(data.encode())));

        Ok(Self { signature, data })
    }

    pub(crate) fn is_received_message_valid(&self, my_peer_id: PeerId) -> bool {
        let now = Utc::now().timestamp();
        if now > self.data.expires_at {
            log::debug!(
                "Healthcheck message is expired. Current time in UTC: {now}, healthcheck `expires_at` in UTC: {}",
                self.data.expires_at
            );
            return false;
        }

        if self.data.target_peer != my_peer_id.to_string() {
            log::debug!(
                "`target_peer` doesn't match with our peer address. Our address: '{}', healthcheck `target_peer`: '{}'.",
                my_peer_id,
                self.data.target_peer
            );
            return false;
        }

        let Ok(public_key) = Libp2pPublic::try_decode_protobuf(&self.data.sender_public_key) else {
            log::debug!("Couldn't decode public key from the healthcheck message.");

            return false
        };

        if self.data.sender_peer != public_key.to_peer_id().to_string() {
            log::debug!("`sender_peer` and `sender_public_key` doesn't belong each other.");

            return false;
        }

        let Ok(encoded_message) = self.data.encode() else {
            log::debug!("Couldn't encode healthcheck data.");
            return false
        };

        let res = public_key.verify(&encoded_message, &self.signature);

        if !res {
            log::debug!("Healthcheck isn't signed correctly.");
        }

        res
    }

    #[inline]
    pub(crate) fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> { encode_message(self) }

    #[inline]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> { decode_message(bytes) }

    #[inline]
    pub(crate) fn should_reply(&self) -> bool { !self.data.is_a_reply }

    #[inline]
    pub(crate) fn sender_peer(&self) -> &str { &self.data.sender_peer }
}

#[derive(Debug, Deserialize, Serialize)]
struct HealthcheckData {
    sender_peer: String,
    sender_public_key: Vec<u8>,
    target_peer: String,
    expires_at: i64,
    is_a_reply: bool,
}

impl HealthcheckData {
    #[inline]
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
pub enum HealthcheckRpcError {
    InvalidPeerAddress { reason: String },
    MessageGenerationFailed { reason: String },
    MessageEncodingFailed { reason: String },
}

impl HttpStatusCode for HealthcheckRpcError {
    fn status_code(&self) -> common::StatusCode {
        match self {
            HealthcheckRpcError::InvalidPeerAddress { .. } => StatusCode::BAD_REQUEST,
            HealthcheckRpcError::MessageGenerationFailed { .. } | HealthcheckRpcError::MessageEncodingFailed { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

pub async fn peer_connection_healthcheck_rpc(
    ctx: MmArc,
    req: RequestPayload,
) -> Result<bool, MmError<HealthcheckRpcError>> {
    /// When things go awry, we want records to clear themselves to keep the memory clean of unused data.
    /// This is unrelated to the timeout logic.
    const ADDRESS_RECORD_EXPIRATION: Duration = Duration::from_secs(60);

    const RESULT_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

    const HEALTHCHECK_MESSAGE_EXPIRATION: i64 = 10;

    let target_peer_id = PeerId::from_str(&req.peer_id)
        .map_err(|e| HealthcheckRpcError::InvalidPeerAddress { reason: e.to_string() })?;

    let message = HealthcheckMessage::generate_message(&ctx, target_peer_id, false, HEALTHCHECK_MESSAGE_EXPIRATION)
        .map_err(|reason| HealthcheckRpcError::MessageGenerationFailed { reason })?;

    let encoded_message = message
        .encode()
        .map_err(|e| HealthcheckRpcError::MessageEncodingFailed { reason: e.to_string() })?;

    let (tx, rx): (Sender<()>, Receiver<()>) = oneshot::channel();

    let mut book = ctx.healthcheck_response_handler.lock().await;
    book.clear_expired_entries();
    book.insert(target_peer_id.to_string(), tx, ADDRESS_RECORD_EXPIRATION);
    drop(book);

    broadcast_p2p_msg(&ctx, peer_healthcheck_topic(&target_peer_id), encoded_message, None);

    Ok(rx.timeout(RESULT_CHANNEL_TIMEOUT).await == Ok(Ok(())))
}
