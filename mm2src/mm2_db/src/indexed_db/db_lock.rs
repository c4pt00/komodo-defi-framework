use super::{DbIdentifier, DbInstance, InitDbResult};
use futures::lock::{MappedMutexGuard as AsyncMappedMutexGuard, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use mm2_core::{mm_ctx::MmArc, DbNamespaceId};
use std::sync::{Arc, Weak};

/// The mapped mutex guard.
/// This implements `Deref<Db>`.
pub type DbLocked<'a, Db> = AsyncMappedMutexGuard<'a, Option<Db>, Db>;
pub type SharedDb<Db> = Arc<ConstructibleDb<Db>>;
pub type WeakDb<Db> = Weak<ConstructibleDb<Db>>;

pub struct ConstructibleDb<Db> {
    /// It's better to use something like [`Constructible`], but it doesn't provide a method to get the inner value by the mutable reference.
    mutex: AsyncMutex<Option<Db>>,
    db_namespace: DbNamespaceId,
    db_id: AsyncMutex<Option<String>>,
    default_db_id: String,
}

impl<Db: DbInstance> ConstructibleDb<Db> {
    pub fn into_shared(self) -> SharedDb<Db> { Arc::new(self) }

    /// Creates a new uninitialized `Db` instance from other Iguana and/or HD accounts.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new(ctx: &MmArc, db_id: Option<&str>) -> Self {
        let rmd = hex::encode(ctx.rmd160().as_slice());
        let db_id = db_id.unwrap_or(&rmd);
        ConstructibleDb {
            mutex: AsyncMutex::new(None),
            db_namespace: ctx.db_namespace,
            db_id: AsyncMutex::new(Some(db_id.to_string())),
            default_db_id: rmd,
        }
    }

    /// Creates a new uninitialized `Db` instance shared between Iguana and all HD accounts
    /// derived from the same passphrase.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new_shared_db(ctx: &MmArc) -> Self {
        let db_id = hex::encode(ctx.shared_db_id().as_slice());
        ConstructibleDb {
            mutex: AsyncMutex::new(None),
            db_namespace: ctx.db_namespace,
            db_id: AsyncMutex::new(Some(db_id.to_string())),
            default_db_id: db_id,
        }
    }

    /// Creates a new uninitialized `Db` instance shared between all wallets/seed.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new_global_db(ctx: &MmArc) -> Self {
        ConstructibleDb {
            mutex: AsyncMutex::new(None),
            db_namespace: ctx.db_namespace,
            db_id: AsyncMutex::new(None),
            default_db_id: ctx.rmd160_hex(),
        }
    }

    /// Locks the given mutex and checks if the inner database is initialized already or not,
    /// initializes it if it's required, and returns the locked instance.
    pub async fn get_or_initialize(&self, db_id: Option<&str>) -> InitDbResult<DbLocked<'_, Db>> {
        let mut locked_db = self.mutex.lock().await;
        let locked_db_id = self.db_id.lock().await;

        // Check if the database is initialized and if the db_id matches
        if let Some(current_db_id) = &*locked_db_id {
            if locked_db.is_some() && (db_id.map(|id| id.to_string()) == Some(current_db_id.clone())) {
                // If the database is initialized and the db_id matches, return the existing instance
                return Ok(unwrap_db_instance(locked_db));
            }
        }

        // Check if there is already an initialized database instance (`locked_db`)
        // and if no specific db_id is provided. It then verifies whether
        // the current db_id matches the default default_db_id.
        // If these conditions are met, the function returns the existing database instance.
        if locked_db.is_some() && db_id.is_none() && Some(self.default_db_id.as_str()) == locked_db_id.as_deref() {
            return Ok(unwrap_db_instance(locked_db));
        }

        // Initialize the new DB instance as the db_id is different or no DB was initialized before
        let db = Db::init(DbIdentifier::new::<Db>(self.db_namespace, locked_db_id.clone())).await?;
        *locked_db = Some(db);

        Ok(unwrap_db_instance(locked_db))
    }
}

/// # Panics
///
/// This function will `panic!()` if the inner value of the `guard` is `None`.
fn unwrap_db_instance<Db>(guard: AsyncMutexGuard<'_, Option<Db>>) -> DbLocked<'_, Db> {
    AsyncMutexGuard::map(guard, |wrapped_db| {
        wrapped_db
            .as_mut()
            .expect("The locked 'Option<Db>' must contain a value")
    })
}
