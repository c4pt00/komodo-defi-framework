use crate::{error::WalletConnectCtxError, session_key::SessionKey, WalletConnectCtx, SUPPORTED_ACCOUNTS,
            SUPPORTED_CHAINS, SUPPORTED_EVENTS, SUPPORTED_METHODS, SUPPORTED_PROTOCOL};
use chrono::Utc;
use common::log::info;
use futures::lock::Mutex;
use mm2_err_handle::prelude::{MapToMmResult, MmResult};
use rand::rngs::OsRng;
use relay_rpc::auth::ed25519_dalek::SigningKey;
use relay_rpc::rpc::params::session_delete::SessionDeleteRequest;
use relay_rpc::rpc::params::session_extend::SessionExtendRequest;
use relay_rpc::rpc::params::session_propose::Proposer;
use relay_rpc::rpc::params::session_update::SessionUpdateRequest;
use relay_rpc::rpc::params::{IrnMetadata, RelayProtocolMetadata};
use relay_rpc::{domain::{SubscriptionId, Topic},
                rpc::params::{session::{ProposeNamespace, ProposeNamespaces, SettleNamespace, SettleNamespaces},
                              session_propose::{SessionProposeRequest, SessionProposeResponse},
                              session_settle::{Controller, SessionSettleRequest},
                              Metadata, Relay, RequestParams, ResponseParamsSuccess}};
use serde_json::Value;
use std::collections::HashMap;
use std::ops::Deref;
use std::{collections::BTreeMap, sync::Arc};

const FIVE_MINUTES: u64 = 300;
pub(crate) const THIRTY_DAYS: u64 = 60 * 60 * 30;

pub(crate) type WcRequestResponseResult = MmResult<(Value, IrnMetadata), WalletConnectCtxError>;

#[derive(Debug, Clone)]
pub enum SessionType {
    Controller,
    Proposer,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Pairing subscription id.
    pub subscription_id: SubscriptionId,
    /// Session symmetric key
    pub session_key: SessionKey,
    pub controller: Controller,
    pub proposer: Proposer,
    pub relay: Relay,
    pub namespaces: ProposeNamespaces,
    pub settled_namespaces: SettleNamespaces,
    pub expiry: u64,
    pub pairing_topic: Topic,
    pub session_type: SessionType,
}

impl SessionInfo {
    pub fn new(
        subscription_id: SubscriptionId,
        session_key: SessionKey,
        pairing_topic: Topic,
        metadata: Metadata,
        session_type: SessionType,
    ) -> Self {
        // Initialize the namespaces for both proposer and controller
        let mut namespaces = BTreeMap::<String, ProposeNamespace>::new();
        namespaces.insert("eip155".to_string(), ProposeNamespace {
            chains: SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
            methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
            events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
        });

        let mut settled_namespaces = BTreeMap::<String, SettleNamespace>::new();
        settled_namespaces.insert("eip155".to_string(), SettleNamespace {
            accounts: SUPPORTED_ACCOUNTS.iter().map(|a| a.to_string()).collect(),
            methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
            events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
        });

        let relay = Relay {
            protocol: SUPPORTED_PROTOCOL.to_string(),
            data: None,
        };

        // handle proposer or controller
        let (proposer, controller) = match session_type {
            SessionType::Proposer => (
                Proposer {
                    public_key: hex::encode(session_key.diffie_public_key()),
                    metadata,
                },
                Controller::default(),
            ),
            SessionType::Controller => (Proposer::default(), Controller {
                public_key: hex::encode(session_key.diffie_public_key()),
                metadata,
            }),
        };

        Self {
            subscription_id,
            session_key,
            controller,
            proposer,
            namespaces: ProposeNamespaces(namespaces),
            settled_namespaces: SettleNamespaces(settled_namespaces),
            relay,
            expiry: Utc::now().timestamp() as u64 + FIVE_MINUTES,
            pairing_topic,
            session_type,
        }
    }

    fn supported_propose_namespaces(&self) -> &ProposeNamespaces { &self.namespaces }

    fn supported_settle_namespaces(&self) -> &SettleNamespaces { &self.settled_namespaces }

    fn create_settle_request(&self) -> RequestParams {
        RequestParams::SessionSettle(SessionSettleRequest {
            relay: self.relay.clone(),
            controller: self.controller.clone(),
            namespaces: self.supported_settle_namespaces().clone(),
            expiry: Utc::now().timestamp() as u64 + FIVE_MINUTES,
        })
    }

    fn create_proposal_response(&self) -> Result<(Value, IrnMetadata), WalletConnectCtxError> {
        let response = ResponseParamsSuccess::SessionPropose(SessionProposeResponse {
            relay: self.relay.clone(),
            responder_public_key: self.controller.public_key.clone(),
        });
        let irn_metadata = response.irn_metadata();
        let value =
            serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

        Ok((value, irn_metadata))
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    session: Arc<Mutex<HashMap<Topic, SessionInfo>>>,
}

impl Deref for Session {
    type Target = Arc<Mutex<HashMap<Topic, SessionInfo>>>;
    fn deref(&self) -> &Self::Target { &self.session }
}

impl Default for Session {
    fn default() -> Self { Self::new() }
}

impl Session {
    pub fn new() -> Self {
        Self {
            session: Default::default(),
        }
    }

    pub fn from_session_info(topic: Topic, session_info: SessionInfo) -> Self {
        Self {
            session: Arc::new(Mutex::new(HashMap::from([(topic, session_info)]))),
        }
    }

    pub(crate) async fn create_proposal_session(
        ctx: &WalletConnectCtx,
        topic: Topic,
        metadata: Metadata,
    ) -> MmResult<(), WalletConnectCtxError> {
        let (session, session_topic) = {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key();
            let session_key = SessionKey::from_osrng(public_key.as_bytes())?;
            let session_topic: Topic = session_key.generate_topic().into();
            let subscription_id = ctx
                .client
                .subscribe(session_topic.clone())
                .await
                .map_to_mm(|err| WalletConnectCtxError::SubscriptionError(err.to_string()))?;

            (
                SessionInfo::new(
                    subscription_id,
                    session_key,
                    topic.clone(),
                    metadata,
                    SessionType::Proposer,
                ),
                session_topic,
            )
        };

        {
            let mut sessions = ctx.session.lock().await;
            sessions.insert(session_topic.clone(), session.clone());
        }

        let session_proposal = RequestParams::SessionPropose(SessionProposeRequest {
            relays: vec![session.relay],
            proposer: session.proposer,
            required_namespaces: session.namespaces,
        });
        let irn_metadata = session_proposal.irn_metadata();

        ctx.publish_request(&topic, session_proposal.into(), irn_metadata)
            .await?;

        Ok(())
    }

    pub(crate) async fn handle_session_propose_response(
        &self,
        session_topic: &Topic,
        response: SessionProposeResponse,
    ) {
        let mut sessions = self.lock().await;
        if let Some(session) = sessions.get_mut(session_topic) {
            info!("session found!");
            session.proposer.public_key = response.responder_public_key;
            session.relay = response.relay;
            session.expiry = Utc::now().timestamp() as u64 + THIRTY_DAYS;
        };
    }

    pub(crate) async fn process_session_extend_request(
        &self,
        topic: &Topic,
        extend: SessionExtendRequest,
    ) -> WcRequestResponseResult {
        let mut sessions = self.session.lock().await;
        if let Some(session) = sessions.get_mut(topic) {
            session.expiry = extend.expiry;
            info!("Updated extended, info: {:?}", session);
        }

        let response = ResponseParamsSuccess::SessionExtend(true);
        let irn_metadata = response.irn_metadata();
        let value =
            serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

        Ok((value, irn_metadata))
    }

    /// https://specs.walletconnect.com/2.0/specs/clients/sign/session-proposal
    pub async fn process_proposal_request(
        &self,
        ctx: &WalletConnectCtx,
        proposal: SessionProposeRequest,
        pairing_topic: Topic,
    ) -> WcRequestResponseResult {
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
            pairing_topic,
            proposal.proposer.metadata,
            SessionType::Controller,
        );
        session
            .supported_propose_namespaces()
            .supported(&proposal.required_namespaces)
            .map_to_mm(|err| WalletConnectCtxError::InternalError(err.to_string()))?;

        {
            let mut sessions = ctx.session.deref().lock().await;
            _ = sessions.insert(session_topic.clone(), session.clone());
        }

        let settle_params = session.create_settle_request();
        let irn_metadata = settle_params.irn_metadata();
        ctx.publish_request(&session_topic, settle_params.into(), irn_metadata)
            .await?;

        Ok(session.create_proposal_response()?)
    }

    pub(crate) async fn process_session_settle_request(
        &self,
        topic: &Topic,
        settle: SessionSettleRequest,
    ) -> WcRequestResponseResult {
        {
            let mut sessions = self.session.lock().await;
            if let Some(session) = sessions.get_mut(topic) {
                session.settled_namespaces = settle.namespaces.clone();
                session.controller = settle.controller.clone();
                session.relay = settle.relay.clone();
                session.expiry = settle.expiry;

                info!("Session successfully settled for topic: {:?}", topic);
                info!("Updated session info: {:?}", session);
            }
        }

        let response = ResponseParamsSuccess::SessionSettle(true);
        let irn_metadata = response.irn_metadata();
        let value =
            serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

        Ok((value, irn_metadata))
    }

    pub(crate) fn process_session_ping_request(&self) -> WcRequestResponseResult {
        let response = ResponseParamsSuccess::SessionPing(true);
        let irn_metadata = response.irn_metadata();
        let value =
            serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

        Ok((value, irn_metadata))
    }

    pub(crate) fn process_session_delete_request(
        &self,
        delete_params: SessionDeleteRequest,
    ) -> WcRequestResponseResult {
        info!(
            "\nSession is being terminated reason={}, code={}",
            delete_params.message, delete_params.code,
        );

        let response = ResponseParamsSuccess::SessionDelete(true);
        let irn_metadata = response.irn_metadata();
        let value =
            serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

        Ok((value, irn_metadata))
    }

    pub(crate) async fn session_delete_cleanup(
        &self,
        ctx: Arc<WalletConnectCtx>,
        topic: &Topic,
    ) -> MmResult<(), WalletConnectCtxError> {
        let mut sessions = ctx.session.lock().await;
        sessions.remove(topic).ok_or_else(|| {
            WalletConnectCtxError::InternalError("Attempt to remove non-existing session".to_string())
        })?;

        ctx.client.unsubscribe(topic.clone()).await?;

        // Check if there are no active sessions remaining
        if sessions.is_empty() {
            info!("\nNo active sessions left, disconnecting the pairing");

            // Attempt to disconnect and remove the pairing associated with the topic
            ctx.pairing
                .disconnect(topic.as_ref(), &ctx.client)
                .await
                .map_err(|e| WalletConnectCtxError::InternalError(format!("Failed to disconnect pairing: {}", e)))?;
        }

        Ok(())
    }

    pub(crate) async fn process_session_update_request(
        &self,
        topic: &Topic,
        update: SessionUpdateRequest,
    ) -> WcRequestResponseResult {
        let mut sessions = self.session.lock().await;
        if let Some(session) = sessions.get_mut(topic) {
            session.settled_namespaces = update.namespaces.clone();
            info!("Updated extended, info: {:?}", session);
        }

        let response = ResponseParamsSuccess::SessionUpdate(true);
        let irn_metadata = response.irn_metadata();
        let value =
            serde_json::to_value(response).map_err(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;

        Ok((value, irn_metadata))
    }
}
