use async_trait::async_trait;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::Topic, rpc::params::session::SettleNamespaces};

use crate::session::Session;

pub(crate) mod sqlite;
pub(crate) mod wasm;

pub(crate) const SESSION_STORAGE_TABLE_NAME: &str = "kdf_wc_session_storage";

#[derive(Debug, thiserror::Error)]
pub(crate) enum WalletConnectStorageError {
    #[error("Table Error: {0}")]
    TableError(String),
}

#[async_trait]
pub(crate) trait WalletConnectStorageOps {
    fn init(&self) -> MmResult<(), WalletConnectStorageError>;
    fn save_session(&self, session: &Session) -> MmResult<(), WalletConnectStorageError>;
    fn get_all_sessions(&self) -> MmResult<Vec<Session>, WalletConnectStorageError>;
    fn delete_session(&self, topic: &Topic) -> MmResult<(), WalletConnectStorageError>;
    fn update_namespace(&self, topic: &Topic, namespace: SettleNamespaces) -> MmResult<(), WalletConnectStorageError>;
    fn update_expiry(&self, expiry: u64) -> MmResult<(), WalletConnectStorageError>;
}
