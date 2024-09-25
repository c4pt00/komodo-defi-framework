use enum_derives::EnumFromStringify;
use pairing_api::PairingClientError;
use relay_client::error::{ClientError, Error};
use relay_rpc::rpc::{PublishError, SubscriptionError};
use serde::{Deserialize, Serialize};

// Error codes for various cases
pub(crate) const INVALID_METHOD: i32 = 1001;
pub(crate) const INVALID_EVENT: i32 = 1002;
pub(crate) const INVALID_UPDATE_REQUEST: i32 = 1003;
pub(crate) const INVALID_EXTEND_REQUEST: i32 = 1004;
pub(crate) const INVALID_SESSION_SETTLE_REQUEST: i32 = 1005;

// Unauthorized error codes
pub(crate) const UNAUTHORIZED_METHOD: i32 = 3001;
pub(crate) const UNAUTHORIZED_EVENT: i32 = 3002;
pub(crate) const UNAUTHORIZED_UPDATE_REQUEST: i32 = 3003;
pub(crate) const UNAUTHORIZED_EXTEND_REQUEST: i32 = 3004;
pub(crate) const UNAUTHORIZED_CHAIN: i32 = 3005;

// EIP-1193 error code
pub(crate) const USER_REJECTED_REQUEST: i32 = 4001;

// Rejected (CAIP-25) error codes
pub(crate) const USER_REJECTED: i32 = 5000;
pub(crate) const USER_REJECTED_CHAINS: i32 = 5001;
pub(crate) const USER_REJECTED_METHODS: i32 = 5002;
pub(crate) const USER_REJECTED_EVENTS: i32 = 5003;

// Unsupported error codes
pub(crate) const UNSUPPORTED_CHAINS: i32 = 5100;
pub(crate) const UNSUPPORTED_METHODS: i32 = 5101;
pub(crate) const UNSUPPORTED_EVENTS: i32 = 5102;
pub(crate) const UNSUPPORTED_ACCOUNTS: i32 = 5103;
pub(crate) const UNSUPPORTED_NAMESPACE_KEY: i32 = 5104;

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
    #[error("Account not found for chain_id: {0}")]
    NoAccountFound(String),
    #[error("Account not found for index: {0}")]
    NoAccountFoundForIndex(u8),
    #[error("Empty account approved for chain_id: {0}")]
    EmptyAccount(String),
    #[error("WalletConnect is not initaliazed yet!")]
    NotInitialized,
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
