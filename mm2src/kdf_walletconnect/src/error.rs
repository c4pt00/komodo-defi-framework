use derive_more::Display;
use pairing_api::PairingClientError;
use relay_client::error::{ClientError, Error};
use relay_rpc::rpc::PublishError;

#[derive(Debug, Display)]
pub enum WalletConnectClientError {
    PairingError(PairingClientError),
    EncodeError(String),
    PublishError(Error<PublishError>),
    ClientError(ClientError),
    PairingNotFound(String)
}

impl From<PairingClientError> for WalletConnectClientError {
    fn from(value: PairingClientError) -> Self {
        WalletConnectClientError::PairingError(value)
    }
}

impl From<ClientError> for WalletConnectClientError {
    fn from(value: ClientError) -> Self {
        WalletConnectClientError::ClientError(value)
    }
}
