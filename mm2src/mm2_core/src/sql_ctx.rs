use std::{collections::HashMap, sync::Arc};

use db_common::async_sql_conn::AsyncConnection;
use futures::lock::Mutex as AsyncMutex;
use gstuff::try_s;
use common::log::error;

use crate::mm_ctx::{from_ctx, log_sqlite_file_open_attempt, MmArc};

pub struct AsyncSqlConnectionCtx {
    pub connections: Arc<AsyncMutex<HashMap<String, Arc<AsyncMutex<AsyncConnection>>>>>,
    ctx: MmArc,
}

impl AsyncSqlConnectionCtx {
    pub async fn from_ctx(ctx: &MmArc) -> Result<Arc<Self>, String> {
        let res = try_s!(from_ctx(&ctx.async_sqlite_connection_ctx, move || {
            Ok(Self {
                connections: Arc::new(AsyncMutex::new(HashMap::new())),
                ctx: ctx.clone(),
            })
        }));

        Ok(res)
    }

    pub async fn init(&self, db_id: Option<&str>) -> Result<Arc<AsyncMutex<AsyncConnection>>, String> {
        let sqlite_file_path = self.ctx.dbdir(db_id).join("KOMODEFI.db");
        log_sqlite_file_open_attempt(&sqlite_file_path);
        let async_conn = Arc::new(AsyncMutex::new(try_s!(AsyncConnection::open(sqlite_file_path).await)));

        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let mut connections = self.connections.lock().await;
        connections.insert(db_id, async_conn.clone());

        Ok(async_conn)
    }

    pub async fn get_or_init(&self, db_id: Option<&str>) -> Result<Arc<AsyncMutex<AsyncConnection>>, String> {
        let db_id_str = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let connections = self.connections.lock().await;
        if let Some(connection) = connections.get(&db_id_str) {
            return Ok(connection.clone());
        };

        self.init(db_id)
    }

    pub async fn connection(&self, db_id: Option<&str>) -> Arc<AsyncMutex<AsyncConnection>> {
        let db_id = db_id.map(|e| e.to_string()).unwrap_or_else(|| self.ctx.rmd160_hex());
        let connection = self.connections.lock().await;

        connection
            .get(&db_id)
            .cloned()
            .expect("sqlite_connection is not initialized")
    }

    pub async fn close_connectionsn(&self, ctx: &MmArc) {
        let mut connections = self.connections.lock().await;
        for connection in connections.values_mut() {
            if let Err(err) = connection.lock().await.close() {
                error!("Error stopping AsyncConnection: {}", e);
            };
        }
    }
}
