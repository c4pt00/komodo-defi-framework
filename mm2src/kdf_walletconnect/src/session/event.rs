use crate::{error::{WalletConnectCtxError, INVALID_EVENT, UNSUPPORTED_CHAINS},
            WalletConnectCtx};

use mm2_err_handle::prelude::{MmError, MmResult};
use relay_rpc::{domain::{MessageId, Topic},
                rpc::{params::{session_event::SessionEventRequest, ResponseParamsError, ResponseParamsSuccess},
                      ErrorData}};

pub enum SessionEvents {
    ChainChanged(String),
    AccountsChanged(String, Vec<String>),
    Unknown(String),
}

impl SessionEvents {
    pub fn from_events(event: SessionEventRequest) -> MmResult<Self, WalletConnectCtxError> {
        match event.event.name.as_str() {
            "chainChanged" => Ok(SessionEvents::ChainChanged(event.chain_id)),
            "accountsChanged" => {
                let data = serde_json::from_value::<Vec<String>>(event.event.data)?;
                Ok(SessionEvents::AccountsChanged(event.chain_id, data))
            },
            _ => Ok(SessionEvents::Unknown(event.event.name)),
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
                Self::handle_accounts_changed_event(ctx, chain_id, data, topic, message_id).await
            },
            SessionEvents::Unknown(name) => {
                let error_data = ErrorData {
                    code: INVALID_EVENT,
                    message: format!("Received an invalid/unsupported session event: {name}"),
                    data: None,
                };
                ctx.publish_response_err(topic, ResponseParamsError::SessionEvent(error_data), message_id)
                    .await?;

                MmError::err(WalletConnectCtxError::SessionError(format!(
                    "Unsupported session event"
                )))
            },
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

            // TODO: validate session expiration.
            //
            if let Some((namespace, _chain)) = parse_chain_and_chain_id(chain_id) {
                if ctx.namespaces.get(&namespace).is_none() {
                    let error_data = ErrorData {
                        code: UNSUPPORTED_CHAINS,
                        message: "Chain_Id was changed to an unsupported chain".to_string(),
                        data: None,
                    };

                    ctx.publish_response_err(topic, ResponseParamsError::SessionEvent(error_data), message_id)
                        .await?;

                    return MmError::err(WalletConnectCtxError::SessionError(format!(
                        "Unsupported chainChanged chain_id from session request: {chain_id}",
                    )));
                }

                let mut session = ctx.session.lock().await;
                if let Some(session) = session.as_mut() {
                    if let Some(ns) = session.namespaces.get_mut(&namespace) {
                        if let Some(chains) = ns.chains.as_mut() {
                            chains.insert(chain_id.to_owned());
                        }
                    }
                }
            }
        }

        //TODO: Notify about chain changed.

        let params = ResponseParamsSuccess::SessionEvent(true);
        ctx.publish_response_ok(topic, params, message_id).await?;

        Ok(())
    }

    async fn handle_accounts_changed_event(
        ctx: &WalletConnectCtx,
        _chain_id: &str,
        _data: &[String],
        topic: &Topic,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        // TODO: Handle account change logic.
        //TODO: Notify about account changed.

        let param = ResponseParamsSuccess::SessionEvent(true);
        ctx.publish_response_ok(topic, param, message_id).await?;

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
