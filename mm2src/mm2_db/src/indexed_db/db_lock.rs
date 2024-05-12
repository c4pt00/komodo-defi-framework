use super::{DbIdentifier, DbInstance, InitDbResult};
use mm2_core::{mm_ctx::MmArc, DbNamespaceId};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex as AsyncMutex, OwnedMappedMutexGuard, OwnedMutexGuard};

/// The mapped mutex guard.
/// This implements `Deref<Db>`.
pub type DbLocked<Db> = OwnedMappedMutexGuard<Option<Db>, Db>;
pub type SharedDb<Db> = Arc<ConstructibleDb<Db>>;
pub type WeakDb<Db> = Weak<ConstructibleDb<Db>>;

#[allow(clippy::type_complexity)]
pub struct ConstructibleDb<Db> {
    /// It's better to use something like [`Constructible`], but it doesn't provide a method to get the inner value by the mutable reference.
    mutexes: Arc<AsyncMutex<HashMap<String, Arc<AsyncMutex<Option<Db>>>>>>,
    db_namespace: DbNamespaceId,
    // Default mm2 d_id derive from passphrase rmd160
    db_id: String,
    // Default mm2 shared_db_id derive from passphrase
    shared_db_id: String,
}

impl<Db: DbInstance> ConstructibleDb<Db> {
    pub fn into_shared(self) -> SharedDb<Db> { Arc::new(self) }

    /// Creates a new uninitialized `Db` instance from other Iguana and/or HD accounts.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new(ctx: &MmArc, db_id: Option<&str>) -> Self {
        let db_id_ = hex::encode(ctx.rmd160().as_slice());
        let shared_db_id = hex::encode(ctx.shared_db_id().as_slice());

        let db_id = db_id.unwrap_or(&db_id_);
        let conns = HashMap::from([(db_id.to_owned(), Arc::new(AsyncMutex::new(None)))]);

        ConstructibleDb {
            mutexes: Arc::new(AsyncMutex::new(conns)),
            db_namespace: ctx.db_namespace,
            db_id: db_id.to_string(),
            shared_db_id,
        }
    }

    /// Creates a new uninitialized `Db` instance shared between Iguana and all HD accounts
    /// derived from the same passphrase.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new_shared_db(ctx: &MmArc) -> Self {
        let db_id = hex::encode(ctx.rmd160().as_slice());
        let shared_db_id = hex::encode(ctx.shared_db_id().as_slice());
        let conns = HashMap::from([(shared_db_id.clone(), Arc::new(AsyncMutex::new(None)))]);
        ConstructibleDb {
            mutexes: Arc::new(AsyncMutex::new(conns)),
            db_namespace: ctx.db_namespace,
            db_id,
            shared_db_id,
        }
    }

    /// Creates a new uninitialized `Db` instance shared between all wallets/seed.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new_global_db(ctx: &MmArc) -> Self {
        let db_id = hex::encode(ctx.rmd160().as_slice());
        let shared_db_id = hex::encode(ctx.shared_db_id().as_slice());
        ConstructibleDb {
            mutexes: Arc::new(AsyncMutex::new(HashMap::default())),
            db_namespace: ctx.db_namespace,
            db_id,
            shared_db_id,
        }
    }

    // handle to get or initialize db
    pub async fn get_or_initialize(&self, db_id: Option<&str>) -> InitDbResult<DbLocked<Db>> {
        self.get_or_initialize_impl(db_id, false).await
    }

    // handle to get or initialize shared db
    pub async fn get_or_initialize_shared(&self, db_id: Option<&str>) -> InitDbResult<DbLocked<Db>> {
        self.get_or_initialize_impl(db_id, true).await
    }

    /// Locks the given mutex and checks if the inner database is initialized already or not,
    /// initializes it if it's required, and returns the locked instance.
    async fn get_or_initialize_impl(&self, db_id: Option<&str>, is_shared: bool) -> InitDbResult<DbLocked<Db>> {
        let db_id = match is_shared {
            true => db_id.map(|id| id.to_owned()).unwrap_or_else(|| self.shared_db_id.to_owned()),
            false => db_id.map(|id| id.to_owned()).unwrap_or_else(|| self.db_id.to_owned()),
        };

        let mut connections = self.mutexes.lock().await;
        if let Some(connection) = connections.get_mut(&db_id) {
            let mut locked_db = connection.clone().lock_owned().await;
            // check and return found connection if already initialized.
            if locked_db.is_some() {
                return Ok(unwrap_db_instance(locked_db));
            };

            // existing connection found but not initialized, hence, we initialize and return this connection.
            let db = Db::init(DbIdentifier::new::<Db>(self.db_namespace, Some(db_id.clone()))).await?;
            *locked_db = Some(db);
            return Ok(unwrap_db_instance(locked_db));
        }

        // No connection found so we create a new connection with immediate initialization
        let db = Db::init(DbIdentifier::new::<Db>(self.db_namespace, Some(db_id.clone()))).await?;
        let db = Arc::new(AsyncMutex::new(Some(db)));
        connections.insert(db_id, db.clone());

        let locked_db = db.lock_owned().await;
        Ok(unwrap_db_instance(locked_db))
    }
}

/// # Panics
///
/// This function will `panic!()` if the inner value of the `guard` is `None`.
fn unwrap_db_instance<Db>(guard: OwnedMutexGuard<Option<Db>>) -> DbLocked<Db> {
    OwnedMutexGuard::map(guard, |wrapped_db| {
        wrapped_db
            .as_mut()
            .expect("The locked 'Option<Db>' must contain a value")
    })
}
