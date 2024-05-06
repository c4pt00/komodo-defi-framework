use crate::mm_ctx::{log_sqlite_file_open_attempt, MmCtx};
use db_common::sqlite::rusqlite::Connection;
use gstuff::try_s;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const ASYNC_SQLITE_DB_ID: &str = "KOMODEFI.db";
const SYNC_SQLITE_DB_ID: &str = "MM2.db";

/// Represents the kind of database connection ID: either shared or single-user.
enum DbIdConnKind {
    Shared,
    Single,
}

/// A pool for managing SQLite connections, where each connection is keyed by a unique string identifier.
#[derive(Clone)]
pub struct SqliteConnPool(Arc<Mutex<HashMap<String, Arc<Mutex<Connection>>>>>);

impl SqliteConnPool {
    /// Initializes a single-user database connection.
    pub fn init(ctx: &MmCtx, db_id: Option<&str>) -> Result<(), String> {
        Self::init_impl(ctx, db_id, DbIdConnKind::Single)
    }

    /// Initializes a shared database connection.
    pub fn init_shared(ctx: &MmCtx, db_id: Option<&str>) -> Result<(), String> {
        Self::init_impl(ctx, db_id, DbIdConnKind::Shared)
    }

    /// Internal implementation to initialize a database connection.
    fn init_impl(ctx: &MmCtx, db_id: Option<&str>, db_id_conn_kind: DbIdConnKind) -> Result<(), String> {
        let db_id = Self::db_id(ctx, db_id, &db_id_conn_kind);

        match ctx.sqlite_conn_pool.as_option() {
            // if connection pool is not already initialized, create new connection pool.
            None => {
                let conn = Self::open_connection(ctx, &db_id, &db_id_conn_kind);
                let store = Arc::new(Mutex::new(HashMap::from([(db_id, conn)])));
                try_s!(ctx.sqlite_conn_pool.pin(Self(store)));
            },
            // if connection pool is already initialized, insert new connection.
            Some(pool) => {
                let conn = Self::open_connection(ctx, &db_id, &db_id_conn_kind);
                let mut pool = pool.0.lock().unwrap();
                pool.insert(db_id, conn);
            },
        };

        Ok(())
    }

    /// Test method for initializing a single-user database connection in-memory.
    pub fn init_test(ctx: &MmCtx) -> Result<(), String> { Self::init_impl_test(ctx, None, DbIdConnKind::Single) }

    /// Test method for initializing a shared database connection in-memory.
    pub fn init_shared_test(ctx: &MmCtx) -> Result<(), String> { Self::init_impl_test(ctx, None, DbIdConnKind::Shared) }

    /// Internal test implementation to initialize a database connection in-memory.
    fn init_impl_test(ctx: &MmCtx, db_id: Option<&str>, db_id_conn_kind: DbIdConnKind) -> Result<(), String> {
        let db_id = Self::db_id(ctx, db_id, &db_id_conn_kind);

        match ctx.sqlite_conn_pool.as_option() {
            None => {
                let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
                let store = Arc::new(Mutex::new(HashMap::from([(db_id, connection)])));
                try_s!(ctx.sqlite_conn_pool.pin(Self(store)));
            },
            Some(pool) => {
                let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
                let mut pool = pool.0.lock().unwrap();
                pool.insert(db_id, connection);
            },
        }
        Ok(())
    }

    /// Retrieves a single-user connection from the pool.
    pub fn sqlite_conn(&self, ctx: &MmCtx, db_id: Option<&str>) -> Arc<Mutex<Connection>> {
        Self::sqlite_conn_impl(ctx, db_id, DbIdConnKind::Single)
    }

    /// Retrieves a shared connection from the pool.
    pub fn sqlite_conn_shared(&self, ctx: &MmCtx, db_id: Option<&str>) -> Arc<Mutex<Connection>> {
        Self::sqlite_conn_impl(ctx, db_id, DbIdConnKind::Shared)
    }

    /// Optionally retrieves a single-user connection from the pool if available.
    pub fn sqlite_conn_opt(&self, ctx: &MmCtx, db_id: Option<&str>) -> Option<Arc<Mutex<Connection>>> {
        Self::sqlite_conn_opt_impl(ctx, db_id, DbIdConnKind::Single)
    }

    /// Optionally retrieves a shared connection from the pool if available.
    pub fn shared_sqlite_conn_opt(&self, ctx: &MmCtx, db_id: Option<&str>) -> Option<Arc<Mutex<Connection>>> {
        Self::sqlite_conn_opt_impl(ctx, db_id, DbIdConnKind::Shared)
    }

    /// Internal implementation to retrieve or create a connection optionally.
    fn sqlite_conn_opt_impl(
        ctx: &MmCtx,
        db_id: Option<&str>,
        db_id_conn_kind: DbIdConnKind,
    ) -> Option<Arc<Mutex<Connection>>> {
        if let Some(connections) = ctx.sqlite_conn_pool.as_option() {
            let db_id = Self::db_id(ctx, db_id, &db_id_conn_kind);
            let mut connections = connections.0.lock().unwrap();
            return if let Some(connection) = connections.get(&db_id) {
                Some(connection.clone())
            } else {
                let conn = Self::open_connection(ctx, &db_id, &db_id_conn_kind);
                connections.insert(db_id, conn.clone());
                // TODO: run migration and fix directions
                Some(conn)
            };
        };
        None
    }

    /// Internal implementation to retrieve or create a connection.
    fn sqlite_conn_impl(ctx: &MmCtx, db_id: Option<&str>, db_id_conn_kind: DbIdConnKind) -> Arc<Mutex<Connection>> {
        let mut connections = ctx
            .sqlite_conn_pool
            .or(&|| panic!("sqlite_conn_pool is not initialized"))
            .0
            .lock()
            .unwrap();

        let db_id = Self::db_id(ctx, db_id, &db_id_conn_kind);
        return if let Some(connection) = connections.get(&db_id) {
            connection.clone()
        } else {
            let conn = Self::open_connection(ctx, &db_id, &db_id_conn_kind);
            connections.insert(db_id, conn.clone());
            // TODO: run migration and fix directions
            conn
        };
    }

    /// Generates a database ID based on the connection kind and optional database ID.
    fn db_id(ctx: &MmCtx, db_id: Option<&str>, db_id_conn_kind: &DbIdConnKind) -> String {
        let db_id_default = match db_id_conn_kind {
            DbIdConnKind::Shared => hex::encode(ctx.shared_db_id().as_slice()),
            DbIdConnKind::Single => ctx.rmd160_hex(),
        };

        db_id.map(|e| e.to_owned()).unwrap_or_else(|| db_id_default)
    }

    /// Opens a database connection based on the database ID and connection kind.
    fn open_connection(ctx: &MmCtx, db_id: &str, db_id_conn_kind: &DbIdConnKind) -> Arc<Mutex<Connection>> {
        let sqlite_file_path = match db_id_conn_kind {
            DbIdConnKind::Shared => ctx.shared_dbdir(Some(db_id)).join("MM2-shared.db"),
            DbIdConnKind::Single => ctx.dbdir(Some(db_id)).join(SYNC_SQLITE_DB_ID),
        };

        log_sqlite_file_open_attempt(&sqlite_file_path);
        Arc::new(Mutex::new(
            Connection::open(sqlite_file_path).expect("failed to open db"),
        ))
    }
}
