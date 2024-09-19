use super::{Session, THIRTY_DAYS};
use crate::{error::WalletConnectCtxError, WalletConnectCtx};
use crate::{SUPPORTED_ACCOUNTS, SUPPORTED_EVENTS, SUPPORTED_METHODS};

use chrono::Utc;
use common::log::info;
use mm2_err_handle::prelude::MmResult;
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

    ctx.publish_request(&session_info.topic, request).await?;

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
        let mut session = ctx.session.lock().await;
        if let Some(session) = session.as_mut() {
            session.namespaces = settle.namespaces.0.clone();
            session.controller = settle.controller.clone();
            session.relay = settle.relay.clone();
            session.expiry = settle.expiry;

            info!("Session successfully settled for topic: {:?}", topic);
        }
    }

    let param = ResponseParamsSuccess::SessionSettle(true);
    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}
