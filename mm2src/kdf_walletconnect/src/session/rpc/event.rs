use crate::{chain::{WcChain, WcChainId},
            error::{WalletConnectError, UNSUPPORTED_CHAINS},
            WalletConnectCtx};

use common::log::{error, info};
use mm2_err_handle::prelude::*;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::{params::{session_event::SessionEventRequest, ResponseParamsError},
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
            let session = ctx
                .session
                .get_session(topic)
                .ok_or(MmError::new(WalletConnectError::SessionError(
                    "No active WalletConnect session found".to_string(),
                )))?;

            if WcChain::Eip155 != chain_id.chain {
                return Ok(());
            };

            ctx.validate_chain_id(&session, &chain_id).await?;

            if let Some(active_chain_id) = session.get_active_chain_id().await {
                if &chain_id == active_chain_id {
                    return Ok(());
                }
            };

            // check if chain_id is supported.
            let id_string = serde_json::from_value::<u32>(event.event.data)?;
            let new_chain = chain_id.chain.derive_chain_id(id_string.to_string());
            if let Err(err) = ctx.validate_chain_id(&session, &new_chain).await {
                error!("{err:?}");
                let error_data = ErrorData {
                    code: UNSUPPORTED_CHAINS,
                    message: "Unsupported chain id".to_string(),
                    data: None,
                };
                let params = ResponseParamsError::SessionEvent(error_data);
                ctx.publish_response_err(topic, params, message_id).await?;
            } else {
                {
                    ctx.session
                        .get_session_mut(topic)
                        .ok_or(MmError::new(WalletConnectError::SessionError(
                            "No active WalletConnect session found".to_string(),
                        )))?
                        .set_active_chain_id(chain_id.clone())
                        .await;
                }
            };
        },
        "accountsChanged" => {
            // TODO: Handle accountsChanged event logic.
        },
        _ => {
            // TODO: Handle other event logic.},
        },
    };

    info!("chainChanged event handled successfully");
    Ok(())
}
