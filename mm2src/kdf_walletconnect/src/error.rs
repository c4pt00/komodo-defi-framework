use derive_more::Display;
use pairing_api::PairingClientError;
use relay_client::error::{ClientError, Error};
use relay_rpc::rpc::{PublishError, SubscriptionError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Display, Serialize, Deserialize)]
pub enum WalletConnectCtxError {
    PairingError(String),
    EncodeError(String),
    PublishError(String),
    ClientError(String),
    PairingNotFound(String),
    SubscriptionError(String),
    InternalError(String),
    SerdeError(String),
    UnsuccessfulResponse(String),
}

impl From<PairingClientError> for WalletConnectCtxError {
    fn from(error: PairingClientError) -> Self { WalletConnectCtxError::PairingError(error.to_string()) }
}

impl From<ClientError> for WalletConnectCtxError {
    fn from(error: ClientError) -> Self { WalletConnectCtxError::ClientError(error.to_string()) }
}

impl From<Error<PublishError>> for WalletConnectCtxError {
    fn from(error: Error<PublishError>) -> Self { WalletConnectCtxError::PublishError(format!("{error:?}")) }
}

impl From<Error<SubscriptionError>> for WalletConnectCtxError {
    fn from(error: Error<SubscriptionError>) -> Self { WalletConnectCtxError::SubscriptionError(format!("{error:?}")) }
}

impl From<serde_json::Error> for WalletConnectCtxError {
    fn from(value: serde_json::Error) -> Self { WalletConnectCtxError::SerdeError(value.to_string()) }
}
