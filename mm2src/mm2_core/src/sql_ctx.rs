use std::{collections::HashMap,
          sync::{Arc, Mutex}};

use db_common::{async_sql_conn::AsyncConnection, sqlite::rusqlite::Connection};
use futures::lock::Mutex as AsyncMutex;
use gstuff::try_s;

use crate::mm_ctx::{from_ctx, log_sqlite_file_open_attempt, MmArc};

pub struct AsyncSqlConnectionCtx {
    connections: Arc<AsyncMutex<HashMap<String, Arc<AsyncMutex<AsyncConnection>>>>>,
    ctx: MmArc,
}

impl AsyncSqlConnectionCtx {
    pub fn from_ctx(ctx: &MmArc) -> Result<Arc<Self>, String> {
        let res = try_s!(from_ctx(&ctx.async_sqlite_connection_ctx, move || Ok(Self {
            connections: Arc::new(AsyncMutex::new(HashMap::new())),
            ctx: ctx.clone()
        })));

        Ok(res)
    }

    pub async fn init(&self, db_id: Option<&str>) -> Result<(), String> {
        let sqlite_file_path = self.ctx.dbdir(db_id).join("KOMODEFI.db");
        log_sqlite_file_open_attempt(&sqlite_file_path);
        let async_conn = try_s!(AsyncConnection::open(sqlite_file_path).await);

        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let mut connections = self.connections.lock().await;
        connections.insert(db_id, Arc::new(AsyncMutex::new(async_conn)));

        Ok(())
    }
}

pub struct SyncSqlConnectionCtx {
    connections: Arc<Mutex<HashMap<String, Arc<Mutex<Connection>>>>>,
    ctx: MmArc,
}

impl SyncSqlConnectionCtx {
    pub fn from_ctx(ctx: &MmArc) -> Result<Arc<Self>, String> {
        let res = try_s!(from_ctx(&ctx.sqlite_connection_ctx, move || Ok(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            ctx: ctx.clone()
        })));

        Ok(res)
    }

    pub fn init(&self, db_id: Option<&str>) -> Result<(), String> {
        let sqlite_file_path = self.ctx.dbdir(db_id).join("KOMODEFI.db");
        log_sqlite_file_open_attempt(&sqlite_file_path);
        let connection = try_s!(Connection::open(sqlite_file_path));

        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let mut connections = self.connections.lock().unwrap();
        connections.insert(db_id, Arc::new(Mutex::new(connection)));

        Ok(())
    }

    pub fn sqlite_conn_opt(&self, db_id: Option<&str>) -> Option<Arc<Mutex<Connection>>> {
        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        if let Ok(connections) = self.connections.lock() {
            return connections.get(&db_id).cloned();
        };

        None
    }

    pub fn connection(&self, db_id: Option<&str>) -> Arc<Mutex<Connection>> {
        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let connection = self.connections.lock().unwrap();

        connection
            .get(&db_id)
            .cloned()
            .expect("sqlite_connection is not initialized")
    }
}

pub struct SharedSqlConnectionCtx {
    connections: Arc<Mutex<HashMap<String, Arc<Mutex<Connection>>>>>,
    ctx: MmArc,
}

impl SharedSqlConnectionCtx {
    pub fn from_ctx(ctx: &MmArc) -> Result<Arc<Self>, String> {
        let res = try_s!(from_ctx(&ctx.shared_sqlite_connection_ctx, move || Ok(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            ctx: ctx.clone()
        })));

        Ok(res)
    }

    pub fn init(&self, db_id: Option<&str>) -> Result<(), String> {
        let sqlite_file_path = self.ctx.dbdir(db_id).join("MM2-shared.db");
        log_sqlite_file_open_attempt(&sqlite_file_path);
        let connection = try_s!(Connection::open(sqlite_file_path));

        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let mut connections = self.connections.lock().unwrap();
        connections.insert(db_id, Arc::new(Mutex::new(connection)));

        Ok(())
    }

    pub fn connection(&self, db_id: Option<&str>) -> Arc<Mutex<Connection>> {
        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let connection = self.connections.lock().unwrap();

        connection
            .get(&db_id)
            .cloned()
            .expect("sqlite_connection is not initialized")
    }
}
