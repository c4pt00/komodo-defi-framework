pub(crate) mod key;
pub mod rpc;

use crate::{error::WalletConnectCtxError, WalletConnectCtx};

use chrono::Utc;
use common::log::debug;
use dashmap::mapref::one::RefMut;
use dashmap::DashMap;
use futures::lock::Mutex;
use key::SessionKey;
use mm2_err_handle::prelude::MmResult;
use relay_client::websocket::Client;
use relay_rpc::domain::Topic;
use relay_rpc::rpc::params::session::Namespace;
use relay_rpc::rpc::params::session_propose::Proposer;
use relay_rpc::rpc::params::IrnMetadata;
use relay_rpc::{domain::SubscriptionId,
                rpc::params::{session::ProposeNamespaces, session_settle::Controller, Metadata, Relay}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

pub(crate) const FIVE_MINUTES: u64 = 300;
pub(crate) const THIRTY_DAYS: u64 = 60 * 60 * 30;

pub(crate) type WcRequestResponseResult = MmResult<(Value, IrnMetadata), WalletConnectCtxError>;

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionRpcInfo {
    pub topic: String,
    pub metadata: Metadata,
    pub peer_pubkey: String,
    pub pairing_topic: String,
    pub namespaces: BTreeMap<String, Namespace>,
    pub subscription_id: SubscriptionId,
}

/// This struct is typically used in the core session management logic of a WalletConnect
/// implementation. It's used to store, retrieve, and update session information throughout
/// the lifecycle of a WalletConnect connection.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Session {
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

/// Internal implementation of session management.
#[derive(Default, Debug)]
struct SessionManagementImpl {
    /// The currently active session topic.
    active_topic: Mutex<Option<Topic>>,
    /// A thread-safe map of sessions indexed by topic.
    sessions: DashMap<Topic, Session>,
}

pub struct SessionManagement(Arc<SessionManagementImpl>);

impl Default for SessionManagement {
    fn default() -> Self { Self::new() }
}

#[allow(unused)]
impl SessionManagement {
    pub fn new() -> Self { Self(Default::default()) }

    /// Inserts the provided `Session` into the session store, associated with the specified topic.
    /// If a session with the same topic already exists, it will be overwritten.
    pub(crate) async fn add_session(&self, session: Session) {
        // set active session topic.
        *self.0.active_topic.lock().await = Some(session.topic.clone());

        // insert session
        self.0.sessions.insert(session.topic.clone(), session);
    }

    /// Removes the session corresponding to the specified topic from the session store.
    /// If the session does not exist, this method does nothing.
    pub(crate) async fn delete_session(&self, topic: &Topic) -> Option<Session> {
        debug!("Deleting session with topic: {topic}");
        let mut active_topic = self.0.active_topic.lock().await;

        if let Some(ref topic_) = *active_topic {
            if topic_ == topic {
                *active_topic = None;
            };
        };

        let removed_session = self.0.sessions.remove(topic).map(|(_, session)| session);

        // Update active session
        if active_topic.is_none() {}
        if let Some(session) = self.0.sessions.iter().next() {
            debug!("New session with topic: {} activated!", session.topic);
            *active_topic = Some(session.topic.clone());
        }

        removed_session
    }

    /// Retrieves a cloned session associated with a given topic.
    pub fn get_session(&self, topic: &Topic) -> Option<SessionRpcInfo> {
        self.0.sessions.get(topic).map(|(session)| SessionRpcInfo {
            topic: topic.to_string(),
            metadata: session.controller.metadata.clone(),
            peer_pubkey: session.controller.public_key.clone(),
            pairing_topic: session.pairing_topic.to_string(),
            namespaces: session.namespaces.clone(),
            subscription_id: session.subscription_id.clone(),
        })
    }

    /// Retrieves a mutable reference to the session associated with a given topic.
    pub(crate) async fn get_session_mut(&self, topic: &Topic) -> Option<RefMut<'_, Topic, Session>> {
        self.0.sessions.get_mut(topic)
    }

    /// Returns an `Option<Session>` containing the active session if it exists; otherwise, returns `None`.
    pub async fn get_session_active(&self) -> Option<SessionRpcInfo> {
        let active_topic = self.0.active_topic.lock().await;
        if let Some(ref topic) = *active_topic {
            self.get_session(topic)
        } else {
            None
        }
    }

    /// Retrieves all sessions(active and inactive)
    pub fn get_sessions(&self) -> Vec<SessionRpcInfo> {
        self.0
            .sessions
            .clone()
            .into_iter()
            .map(|(topic, session)| SessionRpcInfo {
                topic: topic.to_string(),
                metadata: session.controller.metadata.clone(),
                peer_pubkey: session.controller.public_key.clone(),
                pairing_topic: session.pairing_topic.to_string(),
                namespaces: session.namespaces.clone(),
                subscription_id: session.subscription_id,
            })
            .collect()
    }

    /// Updates the expiry time of the session associated with the given topic to the specified timestamp.
    /// If the session does not exist, this method does nothing.
    pub(crate) fn extend_session(&self, topic: &Topic, till: u64) {
        debug!("Extending session with topic: {topic}");
        if let Some(mut session) = self.0.sessions.get_mut(topic) {
            session.extend(till);
        }
    }

    /// This method checks all sessions for expiration based on the current time.
    /// Expired sessions are removed from the session store and returned.
    /// If the active session is expired, it is also removed, and the active session is set to `None`.
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

    /// Retrieves the symmetric key associated with a given topic.
    pub(crate) fn sym_key(&self, topic: &Topic) -> Option<Vec<u8>> {
        self.0
            .sessions
            .get(topic)
            .map(|k| k.session_key.symmetric_key().to_vec())
    }

    pub async fn disconnect_session(&self, topic: &Topic, client: &Client) -> MmResult<(), WalletConnectCtxError> {
        client.unsubscribe(topic.clone()).await?;
        self.delete_session(topic).await;

        Ok(())
    }
}
