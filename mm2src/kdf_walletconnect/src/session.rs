pub mod delete;
pub(crate) mod event;
pub(crate) mod extend;
pub mod ping;
pub(crate) mod propose;
pub(crate) mod settle;
pub(crate) mod update;

use crate::error::SessionError;
use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use chrono::Utc;
use dashmap::mapref::one::RefMut;
use dashmap::DashMap;
use futures::lock::Mutex;
use mm2_err_handle::prelude::{MmError, MmResult};
use relay_rpc::rpc::params::session::Namespace;
use relay_rpc::rpc::params::session_propose::Proposer;
use relay_rpc::rpc::params::IrnMetadata;
use relay_rpc::{domain::{SubscriptionId, Topic},
                rpc::params::{session::ProposeNamespaces, session_settle::Controller, Metadata, Relay}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use x25519_dalek::{SharedSecret, StaticSecret};
use {hkdf::Hkdf,
     rand::{rngs::OsRng, CryptoRng, RngCore},
     sha2::{Digest, Sha256},
     std::fmt::Debug,
     x25519_dalek::PublicKey};

pub(crate) const FIVE_MINUTES: u64 = 300;
pub(crate) const THIRTY_DAYS: u64 = 60 * 60 * 30;

pub(crate) type WcRequestResponseResult = MmResult<(Value, IrnMetadata), WalletConnectCtxError>;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionKey {
    pub(crate) sym_key: [u8; 32],
    pub(crate) public_key: [u8; 32],
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
    /// Creates a new SessionKey with a given public key and empty symmetric key.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            sym_key: [0u8; 32],
            public_key: public_key.to_bytes(),
        }
    }

    /// Creates new session key from `osrng`.
    pub fn from_osrng(other_public_key: &[u8; 32]) -> Result<Self, SessionError> {
        SessionKey::diffie_hellman(OsRng, other_public_key)
    }
    /// Performs Diffie-Hellman symmetric key derivation.
    pub fn diffie_hellman<T>(csprng: T, other_public_key: &[u8; 32]) -> Result<Self, SessionError>
    where
        T: RngCore + CryptoRng,
    {
        let static_private_key = StaticSecret::random_from_rng(csprng);
        let public_key = PublicKey::from(&static_private_key);
        let shared_secret = static_private_key.diffie_hellman(&PublicKey::from(*other_public_key));

        let mut session_key = Self {
            sym_key: [0u8; 32],
            public_key: public_key.to_bytes(),
        };
        session_key.derive_symmetric_key(&shared_secret)?;

        Ok(session_key)
    }

    /// Generates the symmetric key given the ephemeral secret and the peer's public key.
    pub fn generate_symmetric_key(
        &mut self,
        static_secret: &StaticSecret,
        peer_public_key: &[u8; 32],
    ) -> Result<(), SessionError> {
        let shared_secret = static_secret.diffie_hellman(&PublicKey::from(*peer_public_key));
        self.derive_symmetric_key(&shared_secret)
    }

    /// Derives the symmetric key from a shared secret.
    fn derive_symmetric_key(&mut self, shared_secret: &SharedSecret) -> Result<(), SessionError> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        hk.expand(&[], &mut self.sym_key)
            .map_err(|e| SessionError::SymKeyGeneration(e.to_string()))
    }

    /// Gets symmetic key reference.
    pub fn symmetric_key(&self) -> &[u8; 32] { &self.sym_key }

    /// Gets "our" public key used in symmetric key derivation.
    pub fn diffie_public_key(&self) -> &[u8; 32] { &self.public_key }

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionType {
    /// Represents the controlling party in a session, typically a wallet.
    Controller,
    /// Represents the proposing party in a session, typically a dApp.
    Proposer,
}

impl ToString for SessionType {
    fn to_string(&self) -> String {
        match self {
            Self::Controller => "Controller".to_string(),
            Self::Proposer => "Proposer".to_string(),
        }
    }
}

/// This struct is typically used in the core session management logic of a WalletConnect
/// implementation. It's used to store, retrieve, and update session information throughout
/// the lifecycle of a WalletConnect connection.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Session {
    /// Session topic
    pub topic: Topic,
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

impl Session {
    pub fn new(
        ctx: &WalletConnectCtx,
        session_topic: Topic,
        subscription_id: SubscriptionId,
        session_key: SessionKey,
        pairing_topic: Topic,
        metadata: Metadata,
        session_type: SessionType,
    ) -> Self {
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
            propose_namespaces: ctx.required_namespaces.clone(),
            relay: ctx.relay.clone(),
            expiry: Utc::now().timestamp() as u64 + FIVE_MINUTES,
            pairing_topic,
            session_type,
            topic: session_topic,
        }
    }

    pub(crate) fn extend(&mut self, till: u64) { self.expiry = till; }
}

pub(crate) struct SymKeyPair {
    pub(crate) secret: StaticSecret,
    pub(crate) public_key: PublicKey,
}

impl SymKeyPair {
    pub(crate) fn new() -> Self {
        let static_secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&static_secret);
        Self {
            secret: static_secret,
            public_key,
        }
    }
}

struct SessionManagementImpl {
    active_topic: Mutex<Option<Topic>>,
    sessions: DashMap<Topic, Session>,
}

pub struct SessionManagement(Arc<SessionManagementImpl>);

impl Default for SessionManagement {
    fn default() -> Self { Self::new() }
}

#[allow(unused)]
impl SessionManagement {
    pub fn new() -> Self {
        let impl_ = SessionManagementImpl {
            active_topic: Default::default(),
            sessions: Default::default(),
        };

        Self(Arc::new(impl_))
    }

    pub(crate) async fn add_session(&self, session: Session) {
        // set active session topic.
        *self.0.active_topic.lock().await = Some(session.topic.clone());

        // insert session
        self.0.sessions.insert(session.topic.clone(), session);
    }

    pub(crate) async fn delete_session(&self, topic: &Topic) -> Option<Session> {
        let mut active_topic = self.0.active_topic.lock().await;

        if let Some(ref topic_) = *active_topic {
            if topic_ == topic {
                *active_topic = None;
            };
        };

        self.0.sessions.remove(topic).map(|(_, session)| session)
    }

    pub(crate) fn get_session(&self, topic: &Topic) -> Option<Session> {
        self.0.sessions.get(topic).map(|session| session.clone())
    }

    pub(crate) async fn get_session_mut(&self, topic: &Topic) -> Option<RefMut<'_, Topic, Session>> {
        self.0.sessions.get_mut(topic)
    }

    pub async fn get_session_active(&self) -> Option<Session> {
        let active_topic = self.0.active_topic.lock().await;
        if let Some(ref topic) = *active_topic {
            self.get_session(topic)
        } else {
            None
        }
    }

    pub(crate) fn get_sessions(&self) -> Vec<Session> {
        self.0
            .sessions
            .clone()
            .into_iter()
            .map(|(_, session)| session)
            .collect()
    }

    pub(crate) fn extend_session(&self, topic: &Topic, till: u64) {
        if let Some(mut session) = self.0.sessions.get_mut(topic) {
            session.extend(till);
        }
    }

    pub(crate) async fn extend_active_session(&self, till: u64) {
        let active_topic = self.0.active_topic.lock().await;
        if let Some(ref topic) = *active_topic {
            self.extend_session(topic, till);
        }
    }

    pub(crate) async fn delete_expired_sessions(&self) -> Vec<Session> {
        let now = Utc::now().timestamp() as u64;
        let mut expired_sessions = Vec::new();

        // Collect session arcs for processing
        for session in self.0.sessions.iter() {
            if session.expiry <= now {
                // Remove the session from the map
                if let Some(session) = self.delete_session(&session.topic).await {
                    expired_sessions.push(session);
                }
            }
        }

        expired_sessions
    }

    pub(crate) fn sym_key(&self, topic: &Topic) -> Option<Vec<u8>> {
        self.get_session(topic).map(|k| k.session_key.symmetric_key().to_vec())
    }
}
