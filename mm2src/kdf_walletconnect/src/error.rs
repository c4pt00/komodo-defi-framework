use derive_more::Display;
use pairing_api::PairingClientError;
use relay_client::error::{ClientError, Error};
use relay_rpc::rpc::PublishError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Display, Serialize, Deserialize)]
pub enum WalletConnectClientError {
    PairingError(String),
    EncodeError(String),
    PublishError(String),
    ClientError(String),
    PairingNotFound(String),
}

impl From<PairingClientError> for WalletConnectClientError {
    fn from(error: PairingClientError) -> Self { WalletConnectClientError::PairingError(error.to_string()) }
}

impl From<ClientError> for WalletConnectClientError {
    fn from(error: ClientError) -> Self { WalletConnectClientError::ClientError(error.to_string()) }
}

impl From<Error<PublishError>> for WalletConnectClientError {
    fn from(error: Error<PublishError>) -> Self { WalletConnectClientError::PublishError(format!("{error:?}")) }
}
