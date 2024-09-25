use async_trait::async_trait;
use mm2_db::indexed_db::{DbIdentifier, DbInstance, DbLocked, IndexedDb, IndexedDbBuilder, InitDbResult};

const DB_VERSION: u32 = 1;

pub type SessionStorageIDBLocked<'a> = DbLocked<'a, SessionStorageIDB>;

pub struct SessionStorageIDB {
    inner: IndexedDb,
}

#[async_trait]
impl DbInstance for SessionStorageIDB {
    const DB_NAME: &'static str = "nft_cache";

    async fn init(db_id: DbIdentifier) -> InitDbResult<Self> {
        let inner = IndexedDbBuilder::new(db_id)
            .with_version(DB_VERSION)
            //.with_table::<LastScannedBlockTable>()
            .build()
            .await?;
        Ok(SessionStorageIDB { inner })
    }
}

impl SessionStorageIDB {
    pub(crate) fn get_inner(&self) -> &IndexedDb { &self.inner }
}
