use std::{collections::BTreeMap, ops::Deref};

use chrono::Utc;
use mm2_err_handle::prelude::MmResult;
use relay_rpc::{domain::{MessageId, Topic},
                rpc::params::{session::{Namespace, ProposeNamespace, ProposeNamespaces},
                              session_propose::{Proposer, SessionProposeRequest, SessionProposeResponse},
                              Metadata, Relay, RequestParams, ResponseParamsSuccess}};

use super::{settle::send_session_settle_request, SessionInfo};
use crate::{error::WalletConnectCtxError,
            metadata::generate_metadata,
            session::{SessionKey, SessionType, THIRTY_DAYS},
            WalletConnectCtx, SUPPORTED_CHAINS, SUPPORTED_EVENTS, SUPPORTED_METHODS, SUPPORTED_PROTOCOL};
use mm2_err_handle::map_to_mm::MapToMmResult;
use relay_rpc::rpc::params::RelayProtocolMetadata;

/// Creates a new session proposal form topic and metadata.
pub(crate) async fn create_proposal_session(
    ctx: &WalletConnectCtx,
    topic: Topic,
    metadata: Metadata,
    required_namespaces: Option<ProposeNamespaces>,
) -> MmResult<(), WalletConnectCtxError> {
    let proposer = Proposer {
        metadata: generate_metadata(),
        public_key: hex::encode(ctx.sessions.public_key.as_bytes()),
    };
    let mut namespaces = BTreeMap::<String, ProposeNamespace>::new();
    namespaces.insert("eip155".to_string(), ProposeNamespace {
        chains: SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
        methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
    });

    let relays = Relay {
        protocol: SUPPORTED_PROTOCOL.to_string(),
        data: None,
    };

    let session_proposal = RequestParams::SessionPropose(SessionProposeRequest {
        relays: vec![relays],
        proposer,
        required_namespaces: required_namespaces.unwrap_or(ProposeNamespaces(namespaces)),
    });
    let irn_metadata = session_proposal.irn_metadata();

    ctx.publish_request(&topic, session_proposal.into(), irn_metadata)
        .await?;

    Ok(())
}

async fn send_proposal_request_response(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    responder_public_key: String,
) -> MmResult<(), WalletConnectCtxError> {
    let relay = Relay {
        protocol: SUPPORTED_PROTOCOL.to_string(),
        data: None,
    };
    let response = ResponseParamsSuccess::SessionPropose(SessionProposeResponse {
        relay,
        responder_public_key,
    });
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

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
    let sender_public_key = hex::decode(&proposal.proposer.public_key)
        .map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?
        .as_slice()
        .try_into()
        .unwrap();

    let session_key = SessionKey::from_osrng(&sender_public_key)
        .map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;
    let session_topic: Topic = session_key.generate_topic().into();
    let subscription_id = ctx
        .client
        .subscribe(session_topic.clone())
        .await
        .map_to_mm(|err| WalletConnectCtxError::SubscriptionError(err.to_string()))?;

    let session = SessionInfo::new(
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
        let mut sessions = ctx.sessions.deref().lock().await;
        _ = sessions.insert(session_topic.clone(), session.clone());
    }

    {
        send_session_settle_request(ctx, session, session_topic).await?;
    };

    send_proposal_request_response(ctx, topic, message_id, proposal.proposer.public_key).await
}

/// Process session propose reponse.
pub(crate) async fn process_session_propose_response(
    ctx: &WalletConnectCtx,
    pairing_topic: &Topic,
    response: SessionProposeResponse,
) -> MmResult<(), WalletConnectCtxError> {
    let other_public_key = hex::decode(&response.responder_public_key)
        .map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?
        .as_slice()
        .try_into()
        .unwrap();

    let mut session_key = SessionKey::new(ctx.sessions.public_key);
    session_key.generate_symmetric_key(ctx.sessions.keypair.clone(), &other_public_key)?;

    let session_topic: Topic = session_key.generate_topic().into();
    let subscription_id = ctx
        .client
        .subscribe(session_topic.clone())
        .await
        .map_to_mm(|err| WalletConnectCtxError::SubscriptionError(err.to_string()))?;

    let mut session = SessionInfo::new(
        subscription_id,
        session_key,
        pairing_topic.clone(),
        Metadata::default(),
        SessionType::Controller,
    );
    session.relay = response.relay;
    session.expiry = Utc::now().timestamp() as u64 + THIRTY_DAYS;
    session.controller.public_key = response.responder_public_key;

    let mut sessions = ctx.sessions.lock().await;
    sessions.insert(session_topic.clone(), session.clone());

    // Activate pairing_topic
    ctx.pairing.activate(pairing_topic.as_ref()).await?;

    Ok(())
}
