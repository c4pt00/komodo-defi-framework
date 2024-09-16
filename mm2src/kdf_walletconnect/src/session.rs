use crate::error::SessionError;
use crate::{error::WalletConnectCtxError, WalletConnectCtx, SUPPORTED_ACCOUNTS, SUPPORTED_CHAINS, SUPPORTED_EVENTS,
            SUPPORTED_METHODS, SUPPORTED_PROTOCOL};
use chrono::naive::serde;
use chrono::Utc;
use common::log::info;
use futures::lock::Mutex;
use mm2_err_handle::prelude::{MapToMmResult, MmResult};
use relay_rpc::auth::ed25519_dalek::SigningKey;
use relay_rpc::domain::MessageId;
use relay_rpc::rpc::params::session::Namespace;
use relay_rpc::rpc::params::session_delete::SessionDeleteRequest;
use relay_rpc::rpc::params::session_event::SessionEventRequest;
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
use std::collections::{BTreeSet, HashMap};
use std::ops::Deref;
use std::{collections::BTreeMap, sync::Arc};
use {hkdf::Hkdf,
     rand::{rngs::OsRng, CryptoRng, RngCore},
     sha2::{Digest, Sha256},
     std::fmt::Debug,
     x25519_dalek::{EphemeralSecret, PublicKey}};

const FIVE_MINUTES: u64 = 300;
pub(crate) const THIRTY_DAYS: u64 = 60 * 60 * 30;

pub(crate) type WcRequestResponseResult = MmResult<(Value, IrnMetadata), WalletConnectCtxError>;

#[derive(Clone)]
pub struct SessionKey {
    sym_key: [u8; 32],
    public_key: PublicKey,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("sym_key", &"*******")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl SessionKey {
    /// Creates new session key from `osrng`.
    pub fn from_osrng(sender_public_key: &[u8; 32]) -> Result<Self, SessionError> {
        SessionKey::diffie_hellman(OsRng, sender_public_key)
    }

    /// Performs Diffie-Hellman symmetric key derivation.
    pub fn diffie_hellman<T>(csprng: T, sender_public_key: &[u8; 32]) -> Result<Self, SessionError>
    where
        T: RngCore + CryptoRng,
    {
        let single_use_private_key = EphemeralSecret::random_from_rng(csprng);
        let public_key = PublicKey::from(&single_use_private_key);

        let ikm = single_use_private_key.diffie_hellman(&PublicKey::from(*sender_public_key));

        let mut session_sym_key = Self {
            sym_key: [0u8; 32],
            public_key,
        };
        let hk = Hkdf::<Sha256>::new(None, ikm.as_bytes());
        hk.expand(&[], &mut session_sym_key.sym_key)
            .map_err(|e| SessionError::SymKeyGeneration(e.to_string()))?;

        Ok(session_sym_key)
    }

    /// Gets symmetic key reference.
    pub fn symmetric_key(&self) -> &[u8; 32] { &self.sym_key }

    /// Gets "our" public key used in symmetric key derivation.
    pub fn diffie_public_key(&self) -> &[u8; 32] { self.public_key.as_bytes() }

    /// Generates new session topic.
    pub fn generate_topic(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sym_key);
        hex::encode(hasher.finalize())
    }
}

/// In the WalletConnect protocol, a session involves two parties: a controller
/// (typically a wallet) and a proposer (typically a dApp). This enum is used
/// to distinguish between these two roles.
#[derive(Debug, Clone)]
pub enum SessionType {
    /// Represents the controlling party in a session, typically a wallet.
    Controller,
    /// Represents the proposing party in a session, typically a dApp.
    Proposer,
}

/// This struct is typically used in the core session management logic of a WalletConnect
/// implementation. It's used to store, retrieve, and update session information throughout
/// the lifecycle of a WalletConnect connection.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Pairing subscription id.
    pub subscription_id: SubscriptionId,
    /// Session symmetric key
    pub session_key: SessionKey,
    /// Information about the controlling party (typically a wallet).
    pub controller: Controller,
    /// Information about the proposing party (typically a dApp).
    pub proposer: Proposer,
    /// Details about the relay used for communication.
    pub relay: Relay,
    /// Agreed-upon namespaces for the session, mapping namespace strings to their definitions.
    pub namespaces: BTreeMap<String, Namespace>,
    /// Namespaces proposed for the session, may differ from agreed namespaces.
    pub propose_namespaces: ProposeNamespaces,
    /// Unix timestamp (in seconds) when the session expires.
    pub expiry: u64,
    /// Topic used for the initial pairing process.
    pub pairing_topic: Topic,
    /// Indicates whether this session info represents a Controller or Proposer perspective.
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
            namespaces: BTreeMap::new(),
            proposer,
            propose_namespaces: ProposeNamespaces(namespaces),
            relay,
            expiry: Utc::now().timestamp() as u64 + FIVE_MINUTES,
            pairing_topic,
            session_type,
        }
    }

    fn supported_propose_namespaces(&self) -> &ProposeNamespaces { &self.propose_namespaces }

    fn create_settle_request(&self) -> RequestParams {
        let mut settled_namespaces = BTreeMap::<String, Namespace>::new();
        settled_namespaces.insert("eip155".to_string(), Namespace {
            accounts: Some(SUPPORTED_ACCOUNTS.iter().map(|a| a.to_string()).collect()),
            methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
            events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
            chains: None,
        });

        RequestParams::SessionSettle(SessionSettleRequest {
            relay: self.relay.clone(),
            controller: self.controller.clone(),
            namespaces: SettleNamespaces(settled_namespaces),
            expiry: Utc::now().timestamp() as u64 + FIVE_MINUTES,
        })
    }

    async fn proposal_response(
        &self,
        ctx: &WalletConnectCtx,
        topic: &Topic,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        let response = ResponseParamsSuccess::SessionPropose(SessionProposeResponse {
            relay: self.relay.clone(),
            responder_public_key: self.controller.public_key.clone(),
        });
        let irn_metadata = response.irn_metadata();
        let value = serde_json::to_value(response)?;

        ctx.publish_response(topic, value, irn_metadata, message_id).await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    sessions: Arc<Mutex<HashMap<Topic, SessionInfo>>>,
}

impl Deref for Session {
    type Target = Arc<Mutex<HashMap<Topic, SessionInfo>>>;
    fn deref(&self) -> &Self::Target { &self.sessions }
}

impl Default for Session {
    fn default() -> Self { Self::new() }
}

impl Session {
    pub fn new() -> Self {
        Self {
            sessions: Default::default(),
        }
    }
}

/// Creates a new session proposal form topic and metadata.
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

        info!("Session topic: {session_topic:?}");
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
        let mut sessions = ctx.sessions.lock().await;
        sessions.insert(session_topic.clone(), session.clone());
    }

    let session_proposal = RequestParams::SessionPropose(SessionProposeRequest {
        relays: vec![session.relay],
        proposer: session.proposer,
        required_namespaces: session.propose_namespaces,
    });
    let irn_metadata = session_proposal.irn_metadata();

    ctx.publish_request(&topic, session_proposal.into(), irn_metadata)
        .await?;

    Ok(())
}

/// Process session propose reponse.
pub(crate) async fn process_session_propose_response(
    ctx: &WalletConnectCtx,
    session_topic: &Topic,
    response: SessionProposeResponse,
) {
    let mut sessions = ctx.sessions.lock().await;
    if let Some(session) = sessions.get_mut(session_topic) {
        info!("session found!");
        session.proposer.public_key = response.responder_public_key;
        session.relay = response.relay;
        session.expiry = Utc::now().timestamp() as u64 + THIRTY_DAYS;
    };
}

/// Process session extend request.
pub(crate) async fn process_session_extend_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    extend: SessionExtendRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let mut sessions = ctx.sessions.lock().await;
    if let Some(session) = sessions.get_mut(topic) {
        session.expiry = extend.expiry;
        info!("Updated extended, info: {:?}", session);
    }

    let response = ResponseParamsSuccess::SessionExtend(true);
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
        .supported_propose_namespaces()
        .supported(&proposal.required_namespaces)
        .map_to_mm(|err| WalletConnectCtxError::InternalError(err.to_string()))?;

    {
        let mut sessions = ctx.sessions.deref().lock().await;
        _ = sessions.insert(session_topic.clone(), session.clone());
    }

    let settle_params = session.create_settle_request();
    let irn_metadata = settle_params.irn_metadata();

    ctx.publish_request(&session_topic, settle_params.into(), irn_metadata)
        .await?;

    session.proposal_response(ctx, topic, message_id).await
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

pub(crate) async fn process_session_ping_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
) -> MmResult<(), WalletConnectCtxError> {
    let response = ResponseParamsSuccess::SessionPing(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub(crate) async fn process_session_delete_request(
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    delete_params: SessionDeleteRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let response = ResponseParamsSuccess::SessionDelete(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub(crate) async fn session_delete_cleanup(
    ctx: Arc<WalletConnectCtx>,
    topic: &Topic,
) -> MmResult<(), WalletConnectCtxError> {
    let mut sessions = ctx.sessions.lock().await;
    sessions
        .remove(topic)
        .ok_or_else(|| WalletConnectCtxError::InternalError("Attempt to remove non-existing session".to_string()))?;

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
    ctx: &WalletConnectCtx,
    topic: &Topic,
    message_id: &MessageId,
    update: SessionUpdateRequest,
) -> MmResult<(), WalletConnectCtxError> {
    let mut sessions = ctx.sessions.lock().await;
    if let Some(session) = sessions.get_mut(topic) {
        session.namespaces = update.namespaces.0.clone();
        info!("Updated extended, info: {:?}", session);
    }

    let response = ResponseParamsSuccess::SessionUpdate(true);
    let irn_metadata = response.irn_metadata();
    let value = serde_json::to_value(response)?;

    ctx.publish_response(topic, value, irn_metadata, message_id).await?;

    Ok(())
}

pub enum SessionEvents {
    ChainCHanged(String, Vec<String>),
    AccountsChanged(String, Vec<String>),
    Unknown,
}

impl SessionEvents {
    pub fn from_events(event: SessionEventRequest) -> MmResult<Self, WalletConnectCtxError> {
        match event.event.name.as_str() {
            "chainCHanged" => {
                let data = serde_json::from_value::<Vec<String>>(event.event.data)?;
                Ok(SessionEvents::ChainCHanged(event.chain_id, data))
            },
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
            SessionEvents::ChainCHanged(chain_id, data) => {
                Self::handle_chain_changed_event(ctx, chain_id, data, topic, message_id).await
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
        data: &Vec<String>,
        topic: &Topic,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        *ctx.active_chain_id.lock().await = chain_id.clone().to_owned();

        {
            let mut sessions = ctx.sessions.lock().await;
            let current_time = Utc::now().timestamp() as u64;
            sessions.retain(|_, session| session.expiry > current_time);
        };

        let mut sessions = ctx.sessions.lock().await;
        for session in sessions.values_mut() {
            for id in data {
                if let Some((namespace, chain)) = parse_chain_and_chain_id(chain_id) {
                    if let Some(ns) = session.namespaces.get_mut(&namespace) {
                        ns.chains
                            .get_or_insert_with(BTreeSet::new)
                            .insert(format!("{namespace}:{id}"));
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
        data: &Vec<String>,
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
