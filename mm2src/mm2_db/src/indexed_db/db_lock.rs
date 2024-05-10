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

pub struct ConstructibleDb<Db> {
    /// It's better to use something like [`Constructible`], but it doesn't provide a method to get the inner value by the mutable reference.
    mutexes: Arc<AsyncMutex<HashMap<String, Arc<AsyncMutex<Option<Db>>>>>>,
    db_namespace: DbNamespaceId,
    ctx: MmArc,
}

impl<Db: DbInstance> ConstructibleDb<Db> {
    pub fn into_shared(self) -> SharedDb<Db> { Arc::new(self) }

    /// Creates a new uninitialized `Db` instance from other Iguana and/or HD accounts.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new(ctx: &MmArc, db_id: Option<&str>) -> Self {
        let rmd = hex::encode(ctx.rmd160().as_slice());
        let db_id = db_id.unwrap_or(&rmd);

        let conns = HashMap::from([(db_id.to_owned(), Arc::new(AsyncMutex::new(None)))]);

        ConstructibleDb {
            mutexes: Arc::new(AsyncMutex::new(conns)),
            db_namespace: ctx.db_namespace,
            ctx: ctx.clone(),
        }
    }

    /// Creates a new uninitialized `Db` instance shared between Iguana and all HD accounts
    /// derived from the same passphrase.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new_shared_db(ctx: &MmArc) -> Self {
        let db_id = hex::encode(ctx.shared_db_id().as_slice());
        let conns = HashMap::from([(db_id.to_owned(), Arc::new(AsyncMutex::new(None)))]);
        ConstructibleDb {
            mutexes: Arc::new(AsyncMutex::new(conns)),
            db_namespace: ctx.db_namespace,
            ctx: ctx.clone(),
        }
    }

    /// Creates a new uninitialized `Db` instance shared between all wallets/seed.
    /// This can be initialized later using [`ConstructibleDb::get_or_initialize`].
    pub fn new_global_db(ctx: &MmArc) -> Self {
        ConstructibleDb {
            mutexes: Arc::new(AsyncMutex::new(HashMap::default())),
            db_namespace: ctx.db_namespace,
            ctx: ctx.clone(),
        }
    }

    /// Locks the given mutex and checks if the inner database is initialized already or not,
    /// initializes it if it's required, and returns the locked instance.
    pub async fn get_or_initialize(&self, db_id: Option<&str>) -> InitDbResult<DbLocked<Db>> {
        // TODO: caller might be calling for shared_db instead so handle default case, shouldn't be elf.ctx.rmd160_hex() but ctx.shared_db_id() instead
        let db_id = db_id.map(|id| id.to_owned()).unwrap_or_else(|| self.ctx.rmd160_hex());

        let mut connections = self.mutexes.lock().await;
        if let Some(connection) = connections.get_mut(&db_id) {
            let mut locked_db = connection.clone().lock_owned().await;
            // check and return found connection if already initialized.
            if &*locked_db.is_some() {
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
