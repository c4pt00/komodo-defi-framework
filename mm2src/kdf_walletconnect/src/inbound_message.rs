use std::sync::Arc;

use mm2_err_handle::prelude::{MmError, MmResult};
use relay_rpc::{domain::Topic,
                rpc::{params::ResponseParamsSuccess, Params, Request, Response}};

use crate::{error::WalletConnectCtxError,
            pairing::{process_pairing_delete_response, process_pairing_extend_response, process_pairing_ping_response},
            session::handle_session_event,
            WalletConnectCtx};

pub(crate) async fn process_inbound_request(
    ctx: Arc<WalletConnectCtx>,
    request: Request,
    topic: &Topic,
) -> MmResult<(), WalletConnectCtxError> {
    match request.params {
        Params::SessionPropose(proposal) => {
            let response = ctx
                .sessions
                .process_proposal_request(&ctx, proposal, topic.clone())
                .await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::SessionExtend(param) => {
            let response = ctx.sessions.process_session_extend_request(topic, param).await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::SessionDelete(param) => {
            let response = ctx.sessions.process_session_delete_request(param)?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::SessionPing(()) => {
            let response = ctx.sessions.process_session_ping_request()?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::SessionSettle(param) => {
            let response = ctx.sessions.process_session_settle_request(topic, param).await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::SessionUpdate(param) => {
            let response = ctx.sessions.process_session_update_request(topic, param).await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::SessionRequest(_) => todo!(),
        Params::SessionEvent(param) => handle_session_event(&ctx, param).await?,

        Params::PairingPing(_param) => {
            let response = process_pairing_ping_response().await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::PairingDelete(param) => {
            let response = process_pairing_delete_response(&ctx, topic, param).await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        Params::PairingExtend(param) => {
            let response = process_pairing_extend_response(&ctx, topic, param).await?;
            ctx.publish_response(topic, response.0, response.1, request.id).await?;
        },
        _ => todo!(),
    };

    // ctx.session.session_delete_cleanup(ctx.clone(), topic).await?

    Ok(())
}

pub(crate) async fn process_inbound_response(
    ctx: Arc<WalletConnectCtx>,
    response: Response,
    topic: &Topic,
) -> MmResult<(), WalletConnectCtxError> {
    match response {
        Response::Success(value) => {
            let params = serde_json::from_value::<ResponseParamsSuccess>(value.result)?;
            match params {
                ResponseParamsSuccess::SessionPropose(param) => {
                    ctx.sessions.handle_session_propose_response(topic, param).await;
                    Ok(())
                },
                ResponseParamsSuccess::SessionSettle(success)
                | ResponseParamsSuccess::SessionUpdate(success)
                | ResponseParamsSuccess::SessionExtend(success)
                | ResponseParamsSuccess::SessionRequest(success)
                | ResponseParamsSuccess::SessionEvent(success)
                | ResponseParamsSuccess::SessionDelete(success)
                | ResponseParamsSuccess::SessionPing(success)
                | ResponseParamsSuccess::PairingExtend(success)
                | ResponseParamsSuccess::PairingDelete(success)
                | ResponseParamsSuccess::PairingPing(success) => {
                    if !success {
                        return MmError::err(WalletConnectCtxError::UnsuccessfulResponse(format!(
                            "Unsuccessful response={params:?}"
                        )));
                    }

                    Ok(())
                },
            }
        },
        Response::Error(err) => {
            println!("Error: {err:?}");
            todo!()
        },
    }
}
