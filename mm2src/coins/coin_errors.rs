use crate::{eth::Web3RpcError, my_tx_history_v2::MyTxHistoryErrorV2, utxo::rpc_clients::UtxoRpcError, DelegationError,
            NumConversError, TxHistoryError, UnexpectedDerivationMethod, WithdrawError};
use enum_derives::EnumFromStringify;
use futures01::Future;
use mm2_err_handle::prelude::MmError;
use spv_validation::helpers_validation::SPVError;
use std::num::TryFromIntError;

/// Helper type used as result for swap payment validation function(s)
pub type ValidatePaymentFut<T> = Box<dyn Future<Item = T, Error = MmError<ValidatePaymentError>> + Send>;
/// Helper type used as result for swap payment validation function(s)
pub type ValidatePaymentResult<T> = Result<T, MmError<ValidatePaymentError>>;

/// Enum covering possible error cases of swap payment validation
#[derive(Debug, Display, EnumFromStringify)]
pub enum ValidatePaymentError {
    /// Should be used to indicate internal MM2 state problems (e.g., DB errors, etc.).
    #[from_stringify("NumConversError", "UnexpectedDerivationMethod", "keys::Error")]
    InternalError(String),
    /// Problem with deserializing the transaction, or one of the transaction parts is invalid.
    #[from_stringify("rlp::DecoderError", "serialization::Error")]
    TxDeserializationError(String),
    /// One of the input parameters is invalid.
    InvalidParameter(String),
    /// Coin's RPC returned unexpected/invalid response during payment validation.
    InvalidRpcResponse(String),
    /// Payment transaction doesn't exist on-chain.
    TxDoesNotExist(String),
    /// SPV client error.
    #[from_stringify("SPVError")]
    SPVError(SPVError),
    /// Payment transaction is in unexpected state. E.g., `Uninitialized` instead of `Sent` for ETH payment.
    UnexpectedPaymentState(String),
    /// Transport (RPC) error.
    #[from_stringify("web3::Error")]
    Transport(String),
    /// Transaction has wrong properties, for example, it has been sent to a wrong address.
    WrongPaymentTx(String),
    /// Indicates error during watcher reward calculation.
    WatcherRewardError(String),
    /// Input payment timelock overflows the type used by specific coin.
    TimelockOverflow(TryFromIntError),
    #[display(fmt = "Nft Protocol is not supported yet!")]
    NftProtocolNotSupported,
}

impl From<UtxoRpcError> for ValidatePaymentError {
    fn from(err: UtxoRpcError) -> Self {
        match err {
            UtxoRpcError::Transport(e) => Self::Transport(e.to_string()),
            UtxoRpcError::Internal(e) => Self::InternalError(e),
            _ => Self::InvalidRpcResponse(err.to_string()),
        }
    }
}

impl From<Web3RpcError> for ValidatePaymentError {
    fn from(e: Web3RpcError) -> Self {
        match e {
            Web3RpcError::Transport(tr) => ValidatePaymentError::Transport(tr),
            Web3RpcError::InvalidResponse(resp) => ValidatePaymentError::InvalidRpcResponse(resp),
            Web3RpcError::Internal(internal) | Web3RpcError::Timeout(internal) => {
                ValidatePaymentError::InternalError(internal)
            },
            Web3RpcError::NftProtocolNotSupported => ValidatePaymentError::NftProtocolNotSupported,
        }
    }
}

#[derive(Debug, Display, EnumFromStringify)]
pub enum MyAddressError {
    #[from_stringify("UnexpectedDerivationMethod")]
    UnexpectedDerivationMethod(String),
    InternalError(String),
}

impl From<MyAddressError> for WithdrawError {
    fn from(err: MyAddressError) -> Self { Self::InternalError(err.to_string()) }
}

impl From<MyAddressError> for UtxoRpcError {
    fn from(err: MyAddressError) -> Self { Self::Internal(err.to_string()) }
}

impl From<MyAddressError> for DelegationError {
    fn from(err: MyAddressError) -> Self { Self::InternalError(err.to_string()) }
}

impl From<MyAddressError> for TxHistoryError {
    fn from(err: MyAddressError) -> Self { Self::InternalError(err.to_string()) }
}

impl From<MyAddressError> for MyTxHistoryErrorV2 {
    fn from(err: MyAddressError) -> Self { Self::Internal(err.to_string()) }
}
