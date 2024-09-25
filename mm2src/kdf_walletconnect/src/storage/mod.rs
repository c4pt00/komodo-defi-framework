use async_trait::async_trait;
use mm2_err_handle::prelude::MmResult;
use mm2_err_handle::prelude::*;
use relay_rpc::{domain::Topic, rpc::params::session::SettleNamespaces};

use crate::session::Session;

#[cfg(not(target_arch = "wasm32"))] pub(crate) mod sqlite;
#[cfg(target_arch = "wasm32")] pub(crate) mod wasm;

pub(crate) const SESSION_STORAGE_TABLE_NAME: &str = "kdf_wc_session_storage";

#[async_trait]
pub(crate) trait WalletConnectStorageOps {
    type Error: std::fmt::Debug + NotMmError + NotEqual + Send;

    async fn init(&self) -> MmResult<(), Self::Error>;
    async fn is_initialized(&self) -> MmResult<bool, Self::Error>;
    async fn save_session(&self, session: Session) -> MmResult<(), Self::Error>;
    async fn get_sessions(&self) -> MmResult<Vec<Session>, Self::Error>;
    async fn delete_session(&self, topic: &Topic) -> MmResult<(), Self::Error>;
    async fn update_namespace(&self, topic: &Topic, namespace: SettleNamespaces) -> MmResult<(), Self::Error>;
    async fn update_expiry(&self, expiry: u64) -> MmResult<(), Self::Error>;
}
