use std::collections::BTreeSet;

use chrono::Utc;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session_event::SessionEventRequest, RelayProtocolMetadata, ResponseParamsSuccess}};

use crate::{error::WalletConnectCtxError, WalletConnectCtx};

pub enum SessionEvents {
    ChainChanged(String),
    AccountsChanged(String, Vec<String>),
    Unknown,
}

impl SessionEvents {
    pub fn from_events(event: SessionEventRequest) -> MmResult<Self, WalletConnectCtxError> {
        match event.event.name.as_str() {
            "chainChanged" => Ok(SessionEvents::ChainChanged(event.chain_id)),
            "accountsChanged" => {
                let data = serde_json::from_value::<Vec<String>>(event.event.data)?;
                Ok(SessionEvents::AccountsChanged(event.chain_id, data))
            },
            _ => Ok(SessionEvents::Unknown),
        }
    }

    pub async fn handle_session_event(
        &self,
        ctx: &WalletConnectCtx,
        topic: &Topic,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        match &self {
            SessionEvents::ChainChanged(chain_id) => {
                Self::handle_chain_changed_event(ctx, chain_id, topic, message_id).await
            },
            SessionEvents::AccountsChanged(chain_id, data) => {
                Self::handle_account_changed_event(ctx, chain_id, data, topic, message_id).await
            },
            SessionEvents::Unknown => todo!(),
        }
    }

    async fn handle_chain_changed_event(
        ctx: &WalletConnectCtx,
        chain_id: &str,
        topic: &Topic,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        {
            *ctx.active_chain_id.lock().await = chain_id.clone().to_owned();

            {
                let mut sessions = ctx.sessions.lock().await;
                let current_time = Utc::now().timestamp() as u64;
                sessions.retain(|_, session| session.expiry > current_time);
            };

            let mut sessions = ctx.sessions.lock().await;
            for session in sessions.values_mut() {
                if let Some((namespace, chain)) = parse_chain_and_chain_id(chain_id) {
                    if let Some(ns) = session.namespaces.get_mut(&namespace) {
                        ns.chains.get_or_insert_with(BTreeSet::new).insert(chain_id.to_owned());
                    }
                }
            }
        }

        //TODO: Notify about chain changed.

        let params = ResponseParamsSuccess::SessionEvent(true);
        let irn_metadata = params.irn_metadata();

        let value = serde_json::to_value(params)?;
        ctx.publish_response(topic, value, irn_metadata, message_id).await?;

        Ok(())
    }

    async fn handle_account_changed_event(
        ctx: &WalletConnectCtx,
        chain_id: &str,
        data: &[String],
        topic: &Topic,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        // TODO: Handle account change logic.
        //TODO: Notify about account changed.

        let params = ResponseParamsSuccess::SessionEvent(true);
        let irn_metadata = params.irn_metadata();

        let value = serde_json::to_value(params)?;
        ctx.publish_response(topic, value, irn_metadata, message_id).await?;

        Ok(())
    }
}

fn parse_chain_and_chain_id(chain: &str) -> Option<(String, String)> {
    let sp = chain.split(':').collect::<Vec<_>>();
    if sp.len() == 2 {
        return None;
    };

    Some((sp[0].to_owned(), sp[1].to_owned()))
}
