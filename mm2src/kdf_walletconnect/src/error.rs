use enum_derives::EnumFromStringify;
use pairing_api::PairingClientError;
use relay_client::error::{ClientError, Error};
use relay_rpc::rpc::{PublishError, SubscriptionError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, EnumFromStringify, thiserror::Error)]
pub enum WalletConnectCtxError {
    #[error("Pairing Error: {0}")]
    #[from_stringify("PairingClientError")]
    PairingError(String),
    #[error("Publish Error: {0}")]
    PublishError(String),
    #[error("Client Error: {0}")]
    #[from_stringify("ClientError")]
    ClientError(String),
    #[error("Subscription Error: {0}")]
    SubscriptionError(String),
    #[error("Internal Error: {0}")]
    InternalError(String),
    #[error("Serde Error: {0}")]
    #[from_stringify("serde_json::Error")]
    SerdeError(String),
    #[error("UnSuccessfulResponse Error: {0}")]
    UnSuccessfulResponse(String),
    #[error("Session Error: {0}")]
    #[from_stringify("SessionError")]
    SessionError(String),
    #[error("Unknown params")]
    InvalidRequest,
    #[error("Request is not yet implemented")]
    NotImplemented,
    #[error("Hex Error: {0}")]
    #[from_stringify("hex::FromHexError")]
    HexError(String),
    #[error("Payload Error: {0}")]
    #[from_stringify("wc_common::PayloadError")]
    PayloadError(String),
}

impl From<Error<PublishError>> for WalletConnectCtxError {
    fn from(error: Error<PublishError>) -> Self { WalletConnectCtxError::PublishError(format!("{error:?}")) }
}

impl From<Error<SubscriptionError>> for WalletConnectCtxError {
    fn from(error: Error<SubscriptionError>) -> Self { WalletConnectCtxError::SubscriptionError(format!("{error:?}")) }
}

/// Session key and topic derivation errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SessionError {
    #[error("Failed to generate symmetric session key: {0}")]
    SymKeyGeneration(String),
}
