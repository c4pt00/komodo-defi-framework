use crate::{chain::WcChainId,
            error::{WalletConnectError, INVALID_EVENT, UNSUPPORTED_CHAINS},
            WalletConnectCtx};

use common::log::info;
use mm2_err_handle::prelude::*;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::{params::{session::Namespace, session_event::SessionEventRequest, ResponseParamsError,
                               ResponseParamsSuccess},
                      ErrorData}};

pub async fn handle_session_event(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    event: SessionEventRequest,
) -> MmResult<(), WalletConnectError> {
    let chain_id = WcChainId::try_from_str(&event.chain_id)?;
    let event_name = event.event.name.as_str();

    match event_name {
        "chainChanged" => {
            // check if chain_id is supported.
            let chain_id_new = serde_json::from_value::<u32>(event.event.data)?;
            if !ctx.is_chain_supported(&chain_id).await {
                return MmError::err(WalletConnectError::InternalError(format!(
                    "chain_id not supported: {}",
                    event.chain_id
                )));
            };

            if let Some(session) = ctx.session.get_session_active().await {
                if let Some(Namespace {
                    chains: Some(chains), ..
                }) = session.namespaces.get(chain_id.chain.as_ref())
                {
                    if chains.contains(&chain_id.to_string()) {
                        let chain_id = chain_id.chain_id_from_id(chain_id_new.to_string().as_str());
                        ctx.session.set_active_chain_id(chain_id).await;

                        let params = ResponseParamsSuccess::SessionEvent(true);
                        ctx.publish_response_ok(topic, params, message_id).await?;

                        return Ok(());
                    };
                }
            };

            println!("Chain ID not supported");
            let error_data = ErrorData {
                code: UNSUPPORTED_CHAINS,
                message: "Chain_Id was changed to an unsupported chain".to_string(),
                data: None,
            };

            ctx.publish_response_err(topic, ResponseParamsError::SessionEvent(error_data), message_id)
                .await?;
        },
        "accountsChanged" => {
            // TODO: Handle account change logic.

            info!("accountsChanged session event received: {event:?}");
            // let data = serde_json::from_value::<Vec<String>>(event.event.data)?;
            let param = ResponseParamsSuccess::SessionEvent(true);
            ctx.publish_response_ok(topic, param, message_id).await?;
        },
        _ => {
            let error_data = ErrorData {
                code: INVALID_EVENT,
                message: format!("Received an invalid/unsupported session event: {}", event.event.name),
                data: None,
            };
            ctx.publish_response_err(topic, ResponseParamsError::SessionEvent(error_data), message_id)
                .await?;
        },
    };

    Ok(())
}
