use async_trait::async_trait;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::MmResult;
use mm2_err_handle::prelude::*;
use relay_rpc::domain::Topic;

use crate::{error::WalletConnectCtxError, session::Session};

#[cfg(target_arch = "wasm32")] pub(crate) mod indexed_db;
#[cfg(not(target_arch = "wasm32"))] pub(crate) mod sqlite;

#[async_trait]
pub(crate) trait WalletConnectStorageOps {
    type Error: std::fmt::Debug + NotMmError + NotEqual + Send;

    async fn init(&self) -> MmResult<(), Self::Error>;
    async fn is_initialized(&self) -> MmResult<bool, Self::Error>;
    async fn save_session(&self, session: &Session) -> MmResult<(), Self::Error>;
    async fn get_session(&self, topic: &Topic) -> MmResult<Option<Session>, Self::Error>;
    async fn get_all_sessions(&self) -> MmResult<Vec<Session>, Self::Error>;
    async fn delete_session(&self, topic: &Topic) -> MmResult<(), Self::Error>;
    async fn update_session(&self, session: &Session) -> MmResult<(), Self::Error>;
}

pub(crate) struct SessionStorageDb {
    #[cfg(target_arch = "wasm32")]
    pub(crate) db: indexed_db::IDBSessionStorage,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) db: sqlite::SqliteSessionStorage,
}

impl SessionStorageDb {
    pub(crate) fn init(ctx: &MmArc) -> MmResult<Self, WalletConnectCtxError> {
        let selfi = SessionStorageDb {
            #[cfg(target_arch = "wasm32")]
            db: indexed_db::IDBSessionStorage::new(ctx)
                .mm_err(|err| WalletConnectCtxError::StorageError(err.to_string()))?,
            #[cfg(not(target_arch = "wasm32"))]
            db: sqlite::SqliteSessionStorage::new(ctx).mm_err(WalletConnectCtxError::StorageError)?,
        };

        Ok(selfi)
    }
}

#[cfg(ignore)]
#[cfg(test)]
pub(crate) mod session_storage_tests {

    #[cfg(target_arch = "wasm32")]
    common::cfg_wasm32! {
        use wasm_bindgen_test::*;
        wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
    }
    use common::cross_test;
    use mm2_test_helpers::for_tests::mm_ctx_with_custom_async_db;
    use relay_rpc::{domain::{SubscriptionId, Topic},
                    rpc::params::Metadata};

    use crate::{session::key::SessionKey,
                session::{Session, SessionType},
                WalletConnectCtx};

    use super::WalletConnectStorageOps;

    cross_test!(save_session_impl, {
        let mm_ctx = mm_ctx_with_custom_async_db().await;
        let wc_ctx = WalletConnectCtx::try_init(&mm_ctx).unwrap();
        let session_key = SessionKey {
            sym_key: [
                115, 159, 247, 31, 199, 84, 88, 59, 158, 252, 98, 225, 51, 125, 201, 239, 142, 34, 9, 201, 128, 114,
                144, 166, 102, 131, 87, 191, 33, 24, 153, 7,
            ],
            public_key: [
                115, 159, 247, 31, 199, 84, 88, 59, 158, 252, 98, 225, 51, 125, 201, 239, 142, 34, 9, 201, 128, 114,
                144, 166, 102, 131, 87, 191, 33, 24, 153, 7,
            ],
        };

        let session = Session::new(
            &wc_ctx,
            Topic::generate(),
            SubscriptionId::generate(),
            session_key,
            Topic::generate(),
            Metadata::default(),
            SessionType::Controller,
        );

        // try save session
        wc_ctx.storage.db.save_session(&session).await.unwrap();

        // try get session
        let db_session = wc_ctx.storage.db.get_session(&session.topic).await.unwrap();
        assert_eq!(session, db_session.unwrap());
    });
}
