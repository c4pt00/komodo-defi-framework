use super::{Session, THIRTY_DAYS};
use crate::chain::{SUPPORTED_CHAINS, SUPPORTED_EVENTS, SUPPORTED_METHODS};
use crate::storage::WalletConnectStorageOps;
use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use chrono::Utc;
use common::log::info;
use mm2_err_handle::prelude::{MapMmError, MmResult};
use relay_rpc::rpc::params::session::{Namespace, SettleNamespaces};
use relay_rpc::rpc::params::RequestParams;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_settle::SessionSettleRequest, ResponseParamsSuccess}};
use std::collections::BTreeMap;

pub(crate) async fn send_session_settle_request(
    ctx: &WalletConnectCtx,
    session_info: &Session,
) -> MmResult<(), WalletConnectCtxError> {
    let mut settled_namespaces = BTreeMap::<String, Namespace>::new();
    settled_namespaces.insert("eip155".to_string(), Namespace {
        chains: Some(SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect()),
        methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
        accounts: None,
    });

    let request = RequestParams::SessionSettle(SessionSettleRequest {
        relay: session_info.relay.clone(),
        controller: session_info.controller.clone(),
        namespaces: SettleNamespaces(settled_namespaces),
        expiry: Utc::now().timestamp() as u64 + THIRTY_DAYS,
    });

    ctx.publish_request(&session_info.topic, request).await?;

    Ok(())
}

/// Process session settle request.
pub(crate) async fn reply_session_settle_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    settle: SessionSettleRequest,
) -> MmResult<(), WalletConnectCtxError> {
    {
        let session = ctx.session.get_session_mut(topic).await;
        if let Some(mut session) = session {
            session.namespaces = settle.namespaces.0.clone();
            session.controller = settle.controller.clone();
            session.relay = settle.relay.clone();
            session.expiry = settle.expiry;

            // Update storage session.
            ctx.storage
                .db
                .update_session(&session)
                .await
                .mm_err(|err| WalletConnectCtxError::StorageError(err.to_string()))?;

            info!("Session successfully settled for topic: {:?}", topic);
        }
    }

    let param = ResponseParamsSuccess::SessionSettle(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}
