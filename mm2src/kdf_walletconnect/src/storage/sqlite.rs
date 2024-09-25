use async_trait::async_trait;
use db_common::sqlite::rusqlite::{Connection, Result as SqlResult};
use db_common::sqlite::{query_single_row, string_from_row, CHECK_TABLE_EXISTS_SQL};
use db_common::{async_sql_conn::{AsyncConnError, AsyncConnection},
                sqlite::validate_table_name};
use futures::lock::{Mutex, MutexGuard};
use mm2_err_handle::prelude::*;
use relay_rpc::{domain::Topic, rpc::params::session::SettleNamespaces};
use std::sync::Arc;

use super::WalletConnectStorageOps;
use crate::session::Session;

const SESSION_TBALE_NAME: &str = "session";

/// Sessions table
fn create_sessions_table() -> SqlResult<String> {
    validate_table_name(SESSION_TBALE_NAME)?;
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {SESSION_TBALE_NAME} (
        topic VARCHAR(255) PRIMARY KEY,
        subscription_id VARCHAR(255) NOT NULL,
        session_key TEXT NOT NULL,
        expiry BIGINT NOT NULL,
        pairing_topic VARCHAR(255) NOT NULL,
        session_type VARCHAR(50) NOT NULL,
        proposer TEXT NOT NULL,
        controller TEXT NOT NULL,
        relay TEXT NOT NULL,
        namespaces TEXT,
        proposed_namespace TEXT
    );"
    ))
}

#[derive(Clone, Debug)]
pub struct SqliteSessionStorage {
    pub conn: Arc<Mutex<Connection>>,
}

#[async_trait]
impl WalletConnectStorageOps for MutexGuard<'_, AsyncConnection> {
    type Error = AsyncConnError;

    async fn init(&self) -> MmResult<(), Self::Error> {
        self.call(move |conn| {
            conn.execute(&create_sessions_table()?, []).map(|_| ())?;
            Ok(())
        })
        .await
        .map_to_mm(AsyncConnError::from)
    }

    async fn is_initialized(&self) -> MmResult<bool, Self::Error> {
        validate_table_name(SESSION_TBALE_NAME).map_err(AsyncConnError::from)?;
        self.call(move |conn| {
            let initialized = query_single_row(conn, CHECK_TABLE_EXISTS_SQL, [SESSION_TBALE_NAME], string_from_row)?;
            Ok(initialized.is_some())
        })
        .await
        .map_to_mm(AsyncConnError::from)
    }

    async fn save_session(&self, session: Session) -> MmResult<(), Self::Error> {
        validate_table_name(SESSION_TBALE_NAME).map_err(AsyncConnError::from)?;
        let sql = format!(
            "INSERT INTO {} (
            topic, subscription_id, session_key, expiry, pairing_topic, session_type, proposer, controller, relay, namespace, propose_namespaces
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
        );",
            SESSION_TBALE_NAME
        );

        self.call(move |conn| {
            let transaction = conn.transaction()?;

            //let session_key =
            //    serde_json::to_string(&session.session_key).map_err(|err| AsyncConnError::from(err.to_string()))?;
            let relay = serde_json::to_string(&session.relay).map_err(|err| AsyncConnError::from(err.to_string()))?;
            let proposer =
                serde_json::to_string(&session.proposer).map_err(|err| AsyncConnError::from(err.to_string()))?;
            let controller =
                serde_json::to_string(&session.controller).map_err(|err| AsyncConnError::from(err.to_string()))?;
            let namespaces =
                serde_json::to_string(&session.namespaces).map_err(|err| AsyncConnError::from(err.to_string()))?;
            let propose_namespaces = serde_json::to_string(&session.propose_namespaces)
                .map_err(|err| AsyncConnError::from(err.to_string()))?;

            let params = [
                session.topic.to_string(),
                session.subscription_id.to_string(),
                "session_key".to_string(),
                session.expiry.to_string(),
                session.pairing_topic.to_string(),
                session.session_type.to_string(),
                proposer,
                controller,
                relay,
                namespaces,
                propose_namespaces,
            ];
            transaction.execute(&sql, params)?;
            transaction.commit()?;

            Ok(())
        })
        .await
        .map_to_mm(AsyncConnError::from)
    }

    async fn get_sessions(&self) -> MmResult<Vec<Session>, Self::Error> { todo!() }

    async fn update_expiry(&self, expiry: u64) -> MmResult<(), Self::Error> { todo!() }

    async fn delete_session(&self, topic: &Topic) -> MmResult<(), Self::Error> { todo!() }

    async fn update_namespace(&self, topic: &Topic, namespace: SettleNamespaces) -> MmResult<(), Self::Error> {
        todo!()
    }
}
