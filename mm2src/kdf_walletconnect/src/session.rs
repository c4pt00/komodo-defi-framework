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
use mm2_err_handle::prelude::MmResult;
use relay_rpc::rpc::params::session::Namespace;
use relay_rpc::rpc::params::session_propose::Proposer;
use relay_rpc::rpc::params::IrnMetadata;
use relay_rpc::{domain::{SubscriptionId, Topic},
                rpc::params::{session::ProposeNamespaces, session_settle::Controller, Metadata, Relay}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
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
            propose_namespaces: ctx.namespaces.clone(),
            relay: ctx.relay.clone(),
            expiry: Utc::now().timestamp() as u64 + FIVE_MINUTES,
            pairing_topic,
            session_type,
            topic: session_topic,
        }
    }
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
