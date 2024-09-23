use super::{settle::send_session_settle_request, Session};
use crate::{error::WalletConnectCtxError,
            session::{SessionKey, SessionType, THIRTY_DAYS},
            WalletConnectCtx};

use chrono::Utc;
use mm2_err_handle::map_to_mm::MapToMmResult;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session::ProposeNamespaces,
                              session_propose::{Proposer, SessionProposeRequest, SessionProposeResponse},
                              Metadata, RequestParams, ResponseParamsSuccess}};

/// Creates a new session proposal form topic and metadata.
pub(crate) async fn send_proposal(
    ctx: &WalletConnectCtx,
    topic: Topic,
    required_namespaces: Option<ProposeNamespaces>,
) -> MmResult<(), WalletConnectCtxError> {
    let proposer = Proposer {
        metadata: ctx.metadata.clone(),
        public_key: hex::encode(ctx.key_pair.public_key.as_bytes()),
    };
    let session_proposal = RequestParams::SessionPropose(SessionProposeRequest {
        relays: vec![ctx.relay.clone()],
        proposer,
        required_namespaces: required_namespaces.unwrap_or(ctx.namespaces.clone()),
    });

    ctx.publish_request(&topic, session_proposal).await?;

    Ok(())
}

/// Process session proposal request
/// https://specs.walletconnect.com/2.0/specs/clients/sign/session-proposal
pub async fn process_proposal_request(
    ctx: &WalletConnectCtx,
    proposal: SessionProposeRequest,
    topic: &Topic,
    message_id: &MessageId,
) -> MmResult<(), WalletConnectCtxError> {
    let sender_public_key = hex::decode(&proposal.proposer.public_key)?
        .as_slice()
        .try_into()
        .unwrap();

    let session_key = SessionKey::from_osrng(&sender_public_key)?;
    let session_topic: Topic = session_key.generate_topic().into();
    let subscription_id = ctx
        .client
        .subscribe(session_topic.clone())
        .await
        .map_to_mm(|err| WalletConnectCtxError::SubscriptionError(err.to_string()))?;

    let session = Session::new(
        ctx,
        session_topic.clone(),
        subscription_id,
        session_key,
        topic.clone(),
        proposal.proposer.metadata,
        SessionType::Controller,
    );
    session
        .propose_namespaces
        .supported(&proposal.required_namespaces)
        .map_to_mm(|err| WalletConnectCtxError::InternalError(err.to_string()))?;

    {
        let mut old_session = ctx.session.lock().await;
        *old_session = Some(session.clone());
        let mut subs = ctx.subscriptions.lock().await;
        subs.push(session_topic.clone());
    }

    {
        send_session_settle_request(ctx, &session).await?;
    };

    // Respond to incoming session propose.
    let param = ResponseParamsSuccess::SessionPropose(SessionProposeResponse {
        relay: ctx.relay.clone(),
        responder_public_key: proposal.proposer.public_key,
    });

    ctx.publish_response_ok(topic, param, message_id).await?;

    Ok(())
}

/// Process session propose reponse.
pub(crate) async fn process_session_propose_response(
    ctx: &WalletConnectCtx,
    pairing_topic: &Topic,
    response: SessionProposeResponse,
) -> MmResult<(), WalletConnectCtxError> {
    let other_public_key = hex::decode(&response.responder_public_key)?
        .as_slice()
        .try_into()
        .unwrap();

    let mut session_key = SessionKey::new(ctx.key_pair.public_key);
    session_key.generate_symmetric_key(&ctx.key_pair.secret, &other_public_key)?;

    let session_topic: Topic = session_key.generate_topic().into();
    let subscription_id = ctx
        .client
        .subscribe(session_topic.clone())
        .await
        .map_to_mm(|err| WalletConnectCtxError::SubscriptionError(err.to_string()))?;

    let mut session = Session::new(
        ctx,
        session_topic.clone(),
        subscription_id,
        session_key,
        pairing_topic.clone(),
        Metadata::default(),
        SessionType::Controller,
    );
    session.relay = response.relay;
    session.expiry = Utc::now().timestamp() as u64 + THIRTY_DAYS;
    session.controller.public_key = response.responder_public_key;

    {
        let mut old_session = ctx.session.lock().await;
        *old_session = Some(session);
        let mut subs = ctx.subscriptions.lock().await;
        subs.push(session_topic.clone());
    };

    // Activate pairing_topic
    ctx.pairing.activate(pairing_topic.as_ref()).await?;

    Ok(())
}
