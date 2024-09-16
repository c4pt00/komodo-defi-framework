use std::collections::BTreeMap;

use crate::{error::WalletConnectCtxError, WalletConnectCtx};
use crate::{SUPPORTED_ACCOUNTS, SUPPORTED_EVENTS, SUPPORTED_METHODS};

use chrono::Utc;
use common::log::info;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::rpc::params::session::{Namespace, SettleNamespaces};
use relay_rpc::rpc::params::session_settle::Controller;
use relay_rpc::rpc::params::{Relay, RelayProtocolMetadata, RequestParams};
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_settle::SessionSettleRequest, ResponseParamsSuccess}};

use super::{SessionInfo, THIRTY_DAYS};

pub(crate) async fn send_session_settle_request(
    ctx: &WalletConnectCtx,
    session_info: SessionInfo,
    session_topic: Topic,
) -> MmResult<(), WalletConnectCtxError> {
    let mut settled_namespaces = BTreeMap::<String, Namespace>::new();
    settled_namespaces.insert("eip155".to_string(), Namespace {
        accounts: Some(SUPPORTED_ACCOUNTS.iter().map(|a| a.to_string()).collect()),
        methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
        chains: None,
    });

    let request = RequestParams::SessionSettle(SessionSettleRequest {
        relay: session_info.relay.clone(),
        controller: session_info.controller.clone(),
        namespaces: SettleNamespaces(settled_namespaces),
        expiry: Utc::now().timestamp() as u64 + THIRTY_DAYS,
    });
    let irn_metadata = request.irn_metadata();

    ctx.publish_request(&session_topic, request.into(), irn_metadata)
        .await?;

    Ok(())
}

/// Process session settle request.
pub(crate) async fn process_session_settle_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    settle: SessionSettleRequest,
) -> MmResult<(), WalletConnectCtxError> {
    {
        let mut sessions = ctx.sessions.lock().await;
        if let Some(session) = sessions.get_mut(topic) {
            session.namespaces = settle.namespaces.0.clone();
            session.controller = settle.controller.clone();
            session.relay = settle.relay.clone();
            session.expiry = settle.expiry;

            info!("Session successfully settled for topic: {:?}", topic);
            info!("Updated session info: {:?}", session);
        }
    }

    let response = ResponseParamsSuccess::SessionSettle(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}
