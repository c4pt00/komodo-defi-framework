pub mod chain;
mod connection_handler;
#[allow(unused)] pub mod error;
pub mod inbound_message;
mod metadata;
#[allow(unused)] mod pairing;
pub mod session;
mod storage;

use crate::connection_handler::keep_session_alive_ping;
use crate::session::rpc::propose::send_proposal_request;

use chain::{WcChainId, WcRequestMethods, SUPPORTED_PROTOCOL};
use chrono::Utc;
use common::custom_futures::timeout::FutureTimerExt;
use common::log::{debug, info};
use common::{executor::SpawnFuture, log::error};
use connection_handler::Handler;
use error::WalletConnectError;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::lock::Mutex;
use futures::StreamExt;
use inbound_message::{process_inbound_request, process_inbound_response, SessionMessageType};
use metadata::{generate_metadata, AUTH_TOKEN_SUB, PROJECT_ID, RELAY_ADDRESS};
use mm2_core::mm_ctx::{from_ctx, MmArc};
use mm2_err_handle::prelude::*;
use pairing_api::PairingClient;
use relay_client::websocket::{connection_event_loop as client_event_loop, Client, PublishedMessage};
use relay_client::{ConnectionOptions, MessageIdGenerator};
use relay_rpc::auth::{ed25519_dalek::SigningKey, AuthToken};
use relay_rpc::domain::{MessageId, Topic};
use relay_rpc::rpc::params::session::Namespace;
use relay_rpc::rpc::params::session_event::{Event, SessionEventRequest};
use relay_rpc::rpc::params::session_request::SessionRequestRequest;
use relay_rpc::rpc::params::{session_request::Request as SessionRequest, IrnMetadata, Metadata, Relay,
                             RelayProtocolMetadata, RequestParams, ResponseParamsError, ResponseParamsSuccess};
use relay_rpc::rpc::{ErrorResponse, Payload, Request, Response, SuccessfulResponse};
use serde::de::DeserializeOwned;
use session::{key::SymKeyPair, SessionManager};
use std::collections::BTreeSet;
use std::{sync::Arc, time::Duration};
use storage::SessionStorageDb;
use storage::WalletConnectStorageOps;
use wc_common::{decode_and_decrypt_type0, encrypt_and_encode, EnvelopeType};

#[async_trait::async_trait]
pub trait WalletConnectOps {
    type Error;
    type Params<'a>;
    type SignTxData;
    type SendTxData;

    async fn wc_chain_id(&self, ctx: &WalletConnectCtx) -> Result<WcChainId, Self::Error>;

    async fn wc_sign_tx<'a>(
        &self,
        ctx: &WalletConnectCtx,
        params: Self::Params<'a>,
    ) -> Result<Self::SignTxData, Self::Error>;

    async fn wc_send_tx<'a>(
        &self,
        ctx: &WalletConnectCtx,
        params: Self::Params<'a>,
    ) -> Result<Self::SendTxData, Self::Error>;
}

pub struct WalletConnectCtx {
    pub client: Arc<Client>,
    pub pairing: PairingClient,
    pub session: SessionManager,

    pub(crate) key_pair: SymKeyPair,
    pub(crate) storage: SessionStorageDb,

    relay: Relay,
    metadata: Metadata,
    subscriptions: Arc<Mutex<Vec<Topic>>>,
    inbound_message_rx: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>,
    connection_live_rx: Arc<Mutex<UnboundedReceiver<()>>>,
    message_tx: UnboundedSender<SessionMessageType>,
    message_rx: Arc<Mutex<UnboundedReceiver<SessionMessageType>>>,
}

impl WalletConnectCtx {
    pub fn try_init(ctx: &MmArc) -> MmResult<Self, WalletConnectError> {
        let (msg_sender, msg_receiver) = unbounded();
        let (conn_live_sender, conn_live_receiver) = unbounded();
        let (message_tx, session_request_receiver) = unbounded();

        let pairing = PairingClient::new();
        let relay = Relay {
            protocol: SUPPORTED_PROTOCOL.to_string(),
            data: None,
        };

        let storage = SessionStorageDb::init(ctx)?;

        let client = Arc::new(Client::new_unmanaged());
        ctx.spawner().spawn(client_event_loop(
            client.control_rx().expect("client controller should never fail!"),
            Handler::new("Komodefi", msg_sender, conn_live_sender),
        ));

        Ok(Self {
            client,
            pairing,
            relay,
            storage,
            metadata: generate_metadata(),
            key_pair: SymKeyPair::new(),
            session: SessionManager::new(),
            subscriptions: Default::default(),

            inbound_message_rx: Arc::new(msg_receiver.into()),
            connection_live_rx: Arc::new(conn_live_receiver.into()),
            message_rx: Arc::new(session_request_receiver.into()),
            message_tx,
        })
    }

    pub fn from_ctx(ctx: &MmArc) -> MmResult<Arc<WalletConnectCtx>, WalletConnectError> {
        from_ctx(&ctx.wallet_connect, move || {
            Self::try_init(ctx).map_err(|err| err.to_string())
        })
        .map_to_mm(WalletConnectError::InternalError)
    }

    pub async fn connect_client(&self) -> MmResult<(), WalletConnectError> {
        let auth = {
            let key = SigningKey::generate(&mut rand::thread_rng());
            AuthToken::new(AUTH_TOKEN_SUB)
                .aud(RELAY_ADDRESS)
                .ttl(Duration::from_secs(8 * 60 * 60))
                .as_jwt(&key)
                .unwrap()
        };
        let opts = ConnectionOptions::new(PROJECT_ID, auth).with_address(RELAY_ADDRESS);

        self.client.connect(&opts).await?;

        Ok(())
    }

    /// Create a WalletConnect pairing connection url.
    pub async fn new_connection(&self, namespaces: Option<serde_json::Value>) -> MmResult<String, WalletConnectError> {
        let namespaces = match namespaces {
            Some(value) => Some(serde_json::from_value(value)?),
            None => None,
        };
        let (topic, url) = self.pairing.create(self.metadata.clone(), None).await?;

        info!("Subscribing to topic: {topic:?}");

        self.client.subscribe(topic.clone()).await?;

        info!("Subscribed to topic: {topic:?}");

        send_proposal_request(self, &topic, namespaces).await?;

        {
            let mut subs = self.subscriptions.lock().await;
            subs.push(topic);
        };

        Ok(url)
    }

    /// Retrieves the symmetric key associated with a given `topic`.
    async fn sym_key(&self, topic: &Topic) -> MmResult<Vec<u8>, WalletConnectError> {
        {
            if let Some(key) = self.session.sym_key(topic) {
                return Ok(key);
            }
        }

        {
            let pairings = self.pairing.pairings.lock().await;
            if let Some(pairing) = pairings.get(topic.as_ref()) {
                let key = hex::decode(pairing.sym_key.clone())?;
                return Ok(key);
            }
        }

        MmError::err(WalletConnectError::InternalError(format!("Topic not found:{topic}")))
    }

    /// Handles an inbound published message by decrypting, decoding, and processing it.
    async fn handle_published_message(&self, msg: PublishedMessage) -> MmResult<(), WalletConnectError> {
        let message = {
            let key = self.sym_key(&msg.topic).await?;
            decode_and_decrypt_type0(msg.message.as_bytes(), &key)?
        };

        debug!("Inbound message payload={message}");

        match serde_json::from_str(&message)? {
            Payload::Request(request) => process_inbound_request(self, request, &msg.topic).await?,
            Payload::Response(response) => process_inbound_response(self, response, &msg.topic).await,
        }

        debug!("Inbound message was handled successfully");

        Ok(())
    }

    /// Loads sessions from storage, activates valid ones, and deletes expired ones.
    async fn load_session_from_storage(&self) -> MmResult<(), WalletConnectError> {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut sessions = self
            .storage
            .get_all_sessions()
            .await
            .mm_err(|err| WalletConnectError::StorageError(err.to_string()))?;

        // bring last session to the back.
        sessions.sort_by(|a, b| a.expiry.cmp(&b.expiry));

        for session in sessions {
            // delete expired session
            if now > session.expiry {
                debug!("Session {} expired, trying to delete from storage", session.topic);
                if let Err(err) = self.storage.delete_session(&session.topic).await {
                    error!("Unable to delete session: {:?} from storage", err);
                }
                continue;
            };

            let topic = session.topic.clone();
            let pairing_topic = session.pairing_topic.clone();

            debug!("Session found! activating :{}", topic);
            self.session.add_session(session).await;

            self.client.batch_subscribe(vec![topic.clone(), pairing_topic]).await?;
        }

        Ok(())
    }

    /// function to publish a request.
    pub(crate) async fn publish_request(
        &self,
        topic: &Topic,
        param: RequestParams,
    ) -> MmResult<(), WalletConnectError> {
        debug!("Outbound request message payload={param:?}");

        let irn_metadata = param.irn_metadata();
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, param.into());

        self.publish_payload(topic, irn_metadata, Payload::Request(request))
            .await?;

        debug!("Outbound request sent!");

        Ok(())
    }

    /// Private function to publish a success request response.
    pub(crate) async fn publish_response_ok(
        &self,
        topic: &Topic,
        result: ResponseParamsSuccess,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectError> {
        let irn_metadata = result.irn_metadata();
        let value = serde_json::to_value(result)?;
        let response = Response::Success(SuccessfulResponse::new(*message_id, value));

        self.publish_payload(topic, irn_metadata, Payload::Response(response))
            .await?;

        Ok(())
    }

    /// Private function to publish an error request response.
    pub(crate) async fn publish_response_err(
        &self,
        topic: &Topic,
        error_data: ResponseParamsError,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectError> {
        let error = error_data.error();
        let irn_metadata = error_data.irn_metadata();
        let response = Response::Error(ErrorResponse::new(*message_id, error));

        self.publish_payload(topic, irn_metadata, Payload::Response(response))
            .await?;

        Ok(())
    }

    /// Private function to publish a payload.
    pub(crate) async fn publish_payload(
        &self,
        topic: &Topic,
        irn_metadata: IrnMetadata,
        payload: Payload,
    ) -> MmResult<(), WalletConnectError> {
        let message = {
            let sym_key = self.sym_key(topic).await?;
            let payload = serde_json::to_string(&payload)?;
            encrypt_and_encode(EnvelopeType::Type0, payload, &sym_key)?
        };

        self.client
            .publish(
                topic.clone(),
                message,
                None,
                irn_metadata.tag,
                Duration::from_secs(irn_metadata.ttl),
                irn_metadata.prompt,
            )
            .await?;

        Ok(())
    }

    /// Checks if the current session is connected to a Ledger device.
    /// NOTE: for COSMOS chains only.
    pub async fn is_ledger_connection(&self) -> bool {
        self.session
            .get_session_active()
            .await
            .and_then(|session| session.session_properties.clone())
            .and_then(|props| props.keys.as_ref().cloned())
            .and_then(|keys| keys.first().cloned())
            .map(|key| key.is_nano_ledger)
            .unwrap_or(false)
    }

    /// Checks if a given chain ID is supported.
    pub async fn is_chain_supported(&self, chain_id: &WcChainId) -> bool {
        if let Some(session) = self.session.get_session_active().await {
            if let Some(ns) = session.namespaces.get(chain_id.chain.as_ref()) {
                if let Some(chains) = &ns.chains {
                    return chains.contains(&chain_id.to_string());
                }
            }

            // https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces
            // #13-chains-might-be-omitted-if-the-caip-2-is-defined-in-the-index
            if session.namespaces.contains_key(&chain_id.to_string()) {
                return true;
            }
        }

        false
    }

    pub async fn validate_or_update_active_chain_id(&self, chain_id: &WcChainId) -> MmResult<(), WalletConnectError> {
        if !self.is_chain_supported(chain_id).await {
            return MmError::err(WalletConnectError::InvalidChainId(chain_id.to_string()));
        };

        {
            if let Some(active_chain_id) = self.session.get_active_chain_id().await {
                if chain_id.to_string() == active_chain_id {
                    return Ok(());
                }
            };

            let event = SessionEventRequest {
                event: Event {
                    name: "chainChanged".to_string(),
                    data: serde_json::to_value(&chain_id.id)?,
                },
                chain_id: chain_id.to_string(),
            };
            let param = RequestParams::SessionEvent(event);

            let active_topic = self.session.get_active_topic_or_err().await?;
            self.publish_request(&active_topic, param).await?;
        }

        self.session.set_active_chain_id(chain_id.id.clone()).await;

        Ok(())
    }

    /// TODO: accept WcChainId
    /// Retrieves the available account for a given chain ID.
    pub async fn get_account_for_chain_id(&self, chain_id: &WcChainId) -> MmResult<String, WalletConnectError> {
        let namespaces = &self
            .session
            .get_session_active()
            .await
            .ok_or(MmError::new(WalletConnectError::SessionError(
                "No active WalletConnect session found".to_string(),
            )))?
            .namespaces;

        if let Some(Namespace {
            accounts: Some(accounts),
            ..
        }) = namespaces.get(chain_id.chain.as_ref())
        {
            if let Some(account) = find_account_in_namespace(accounts, &chain_id.id) {
                return Ok(account);
            }
        };

        MmError::err(WalletConnectError::NoAccountFound(chain_id.to_string()))
    }

    /// Waits for and handles a WalletConnect session response with arbitrary data.
    pub async fn send_session_request_and_wait<T, R, F>(
        &self,
        chain_id: &WcChainId,
        method: WcRequestMethods,
        params: serde_json::Value,
        response_handler: F,
    ) -> MmResult<R, WalletConnectError>
    where
        T: DeserializeOwned,
        F: Fn(T) -> MmResult<R, WalletConnectError>,
    {
        // Send request
        let active_topic = self.session.get_active_topic_or_err().await?;
        let request = SessionRequestRequest {
            chain_id: chain_id.to_string(),
            request: SessionRequest {
                method: method.as_ref().to_string(),
                expiry: Some(Utc::now().timestamp() as u64 + 300),
                params,
            },
        };
        self.publish_request(&active_topic, RequestParams::SessionRequest(request))
            .await?;

        // Wait for response
        let wait_duration = Duration::from_secs(300);
        if let Ok(Some(resp)) = self.message_rx.lock().await.next().timeout(wait_duration).await {
            let result = resp.mm_err(WalletConnectError::InternalError)?;
            if let ResponseParamsSuccess::Arbitrary(data) = result.data {
                let data = serde_json::from_value::<T>(data)?;
                let response = ResponseParamsSuccess::SessionEvent(true);
                self.publish_response_ok(&result.topic, response, &result.message_id)
                    .await?;
                return response_handler(data);
            }
        }

        // Handle timeout/error
        self.client.disconnect().await?;
        MmError::err(WalletConnectError::NoWalletFeedback)
    }

    pub async fn drop_session(&self, topic: &Topic) -> MmResult<(), WalletConnectError> {
        self.client.unsubscribe(topic.clone()).await?;
        self.session.delete_session(topic).await;
        self.storage
            .delete_session(topic)
            .await
            .mm_err(|err| WalletConnectError::StorageError(err.to_string()))?;

        Ok(())
    }
}

/// This function spwans related WalletConnect related tasks and needed initialization before
/// WalletConnect can be usable in KDF.
pub async fn initialize_walletconnect(ctx: &MmArc) -> MmResult<(), WalletConnectError> {
    // Initialized WalletConnectCtx
    let wallet_connect = WalletConnectCtx::from_ctx(ctx)?;
    // Intialize storage.
    wallet_connect.storage.init().await.unwrap();
    // WalletConnectCtx is initialized, now we can connect to relayer client and spawn a watcher
    // loop for disconnection.
    ctx.spawner().spawn({
        let this = wallet_connect.clone();
        async move {
            info!("Initializing WalletConnect connection");
            connection_handler::initial_connection(&this).await;
            connection_handler::handle_disconnections(&this).await;
        }
    });

    ctx.spawner().spawn(keep_session_alive_ping(wallet_connect.clone()));

    // spawn message handler event loop
    ctx.spawner().spawn(async move {
        let mut recv = wallet_connect.inbound_message_rx.lock().await;
        while let Some(msg) = recv.next().await {
            if let Err(e) = wallet_connect.clone().handle_published_message(msg).await {
                info!("Error processing message: {:?}", e);
            }
        }
    });

    Ok(())
}

fn find_account_in_namespace<'a>(accounts: &'a BTreeSet<String>, chain_id: &'a str) -> Option<String> {
    accounts.iter().find_map(move |account_name| {
        let parts: Vec<&str> = account_name.split(':').collect();
        if parts.len() >= 3 && parts[1] == chain_id {
            Some(parts[2].to_string())
        } else {
            None
        }
    })
}
