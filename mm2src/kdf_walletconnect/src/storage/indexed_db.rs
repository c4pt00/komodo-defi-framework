use super::WalletConnectStorageOps;
use crate::error::WcIndexedDbError;
use crate::session::Session;
use async_trait::async_trait;
use mm2_core::mm_ctx::MmArc;
use mm2_db::indexed_db::{ConstructibleDb, DbIdentifier, DbInstance, DbLocked, DbUpgrader, IndexedDb, IndexedDbBuilder,
                         InitDbResult, OnUpgradeResult, SharedDb, TableSignature};
use mm2_err_handle::prelude::MmResult;
use mm2_err_handle::prelude::*;
use relay_rpc::domain::Topic;

const DB_VERSION: u32 = 1;

pub type IDBSessionStorageLocked<'a> = DbLocked<'a, IDBSessionStorageInner>;

impl TableSignature for Session {
    const TABLE_NAME: &'static str = "sessions";

    fn on_upgrade_needed(upgrader: &DbUpgrader, old_version: u32, new_version: u32) -> OnUpgradeResult<()> {
        if let (0, 1) = (old_version, new_version) {
            let table = upgrader.create_table(Self::TABLE_NAME)?;
            table.create_index("topic", false)?;
        }
        Ok(())
    }
}

pub struct IDBSessionStorageInner(IndexedDb);

#[async_trait]
impl DbInstance for IDBSessionStorageInner {
    const DB_NAME: &'static str = "wc_session_storage";

    async fn init(db_id: DbIdentifier) -> InitDbResult<Self> {
        let inner = IndexedDbBuilder::new(db_id)
            .with_version(DB_VERSION)
            .with_table::<Session>()
            .build()
            .await?;

        Ok(Self(inner))
    }
}

impl IDBSessionStorageInner {
    pub(crate) fn get_inner(&self) -> &IndexedDb { &self.0 }
}

#[derive(Clone)]
pub struct IDBSessionStorage(SharedDb<IDBSessionStorageInner>);

impl IDBSessionStorage {
    pub(crate) fn new(ctx: &MmArc) -> MmResult<Self, WcIndexedDbError> {
        Ok(Self(ConstructibleDb::new(ctx).into_shared()))
    }

    async fn lock_db(&self) -> MmResult<IDBSessionStorageLocked<'_>, WcIndexedDbError> {
        Ok(self
            .0
            .get_or_initialize()
            .await
            .mm_err(|err| WcIndexedDbError::InternalError(err.to_string()))?)
    }
}

#[async_trait::async_trait]
impl WalletConnectStorageOps for IDBSessionStorage {
    type Error = WcIndexedDbError;

    async fn init(&self) -> MmResult<(), Self::Error> { Ok(()) }

    async fn is_initialized(&self) -> MmResult<bool, Self::Error> { Ok(true) }

    async fn save_session(&self, session: &Session) -> MmResult<(), Self::Error> {
        let lock_db = self.lock_db().await?;
        let transaction = lock_db.get_inner().transaction().await?;
        let session_table = transaction.table::<Session>().await?;
        session_table
            .replace_item_by_unique_index("topic", session.topic.clone(), &session)
            .await?;

        Ok(())
    }

    async fn get_session(&self, topic: &Topic) -> MmResult<Option<Session>, Self::Error> {
        let lock_db = self.lock_db().await?;
        let transaction = lock_db.get_inner().transaction().await?;
        let session_table = transaction.table::<Session>().await?;

        Ok(session_table
            .get_item_by_unique_index("topic", topic)
            .await?
            .map(|s| s.1))
    }

    async fn get_all_sessions(&self) -> MmResult<Vec<Session>, Self::Error> {
        let lock_db = self.lock_db().await?;
        let transaction = lock_db.get_inner().transaction().await?;
        let session_table = transaction.table::<Session>().await?;

        Ok(session_table
            .get_all_items()
            .await?
            .into_iter()
            .map(|s| s.1)
            .collect::<Vec<_>>())
    }

    async fn delete_session(&self, topic: &Topic) -> MmResult<(), Self::Error> {
        let lock_db = self.lock_db().await?;
        let transaction = lock_db.get_inner().transaction().await?;
        let session_table = transaction.table::<Session>().await?;

        session_table.delete_item_by_unique_index("topic", topic).await?;
        Ok(())
    }

    async fn update_session(&self, session: &Session) -> MmResult<(), Self::Error> { self.save_session(&session).await }
}

pub(crate) mod crypto {
    use js_sys::{JsString, Object, Reflect, Uint8Array};

    fn rsa_oaep_params() -> Object {
        // Create a new empty JavaScript object
        let rsa_oaep_params = Object::new();

        // "name": "RSA-OAEP"
        let _ = Reflect::set(&rsa_oaep_params, &JsString::from("name"), &JsString::from("RSA-OAEP"));

        // "modulusLength": 2048
        let _ = Reflect::set(&rsa_oaep_params, &JsString::from("modulusLength"), &2048.into());

        // "publicExponent": new Uint8Array([0x01, 0x00, 0x01])
        let public_exponent = Uint8Array::new_with_length(3);
        public_exponent.copy_from(&[0x01, 0x00, 0x01]);

        let _ = Reflect::set(&rsa_oaep_params, &JsString::from("publicExponent"), &public_exponent);

        // Create the "hash" sub-object
        let hash_obj = Object::new();
        let _ = Reflect::set(&hash_obj, &JsString::from("name"), &JsString::from("SHA-256"));

        // "hash": {"name": "SHA-256"}
        let _ = Reflect::set(&rsa_oaep_params, &JsString::from("hash"), &hash_obj);

        rsa_oaep_params
    }
}