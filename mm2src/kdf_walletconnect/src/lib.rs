pub mod chain;
#[allow(unused)] pub mod error;
mod handler;
mod inbound_message;
mod metadata;
#[allow(unused)] mod pairing;
pub mod rpc_commands;
pub mod session;
mod storage;

use chain::{build_required_namespaces,
            cosmos::{cosmos_get_accounts_impl, CosmosAccount},
            SUPPORTED_CHAINS};
use common::executor::SpawnFuture;
use common::{executor::Timer,
             log::{error, info}};
use error::WalletConnectCtxError;
use futures::{channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
              lock::Mutex,
              StreamExt};
use handler::Handler;
use inbound_message::{process_inbound_request, process_inbound_response};
use metadata::{generate_metadata, AUTH_TOKEN_SUB, PROJECT_ID, RELAY_ADDRESS};
use mm2_core::mm_ctx::{from_ctx, MmArc};
use mm2_err_handle::prelude::MmResult;
use mm2_err_handle::prelude::*;
use pairing_api::PairingClient;
use relay_client::{websocket::{Client, PublishedMessage},
                   ConnectionOptions, MessageIdGenerator};
use relay_rpc::rpc::params::{RelayProtocolMetadata, RequestParams};
use relay_rpc::{auth::{ed25519_dalek::SigningKey, AuthToken},
                domain::{MessageId, Topic},
                rpc::{params::{session::ProposeNamespaces, IrnMetadata, Metadata, Relay, ResponseParamsError,
                               ResponseParamsSuccess},
                      ErrorResponse, Payload, Request, Response, SuccessfulResponse}};
use serde_json::Value;
use session::{propose::send_proposal_request, Session, SymKeyPair};
use std::{sync::Arc, time::Duration};
use storage::{SessionStorageDb, WalletConnectStorageOps};
use wc_common::{decode_and_decrypt_type0, encrypt_and_encode, EnvelopeType};

pub(crate) const SUPPORTED_PROTOCOL: &str = "irn";
const DEFAULT_CHAIN_ID: &str = "cosmoshub-4"; // tendermint e.g ATOM

type SessionEventMessage = (MessageId, Value);

pub struct WalletConnectCtx {
    pub client: Client,
    pub pairing: PairingClient,
    pub session: Arc<Mutex<Option<Session>>>,
    pub active_chain_id: Arc<Mutex<String>>,

    pub(crate) key_pair: SymKeyPair,
    pub(crate) storage: SessionStorageDb,

    relay: Relay,
    metadata: Metadata,
    namespaces: ProposeNamespaces,
    subscriptions: Arc<Mutex<Vec<Topic>>>,
    inbound_message_handler: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>,
    connection_live_handler: Arc<Mutex<UnboundedReceiver<()>>>,
    session_request_sender: Arc<Mutex<UnboundedSender<SessionEventMessage>>>,
    session_request_handler: Arc<Mutex<UnboundedReceiver<SessionEventMessage>>>,
}

impl WalletConnectCtx {
    pub fn try_init(ctx: &MmArc) -> MmResult<Self, WalletConnectCtxError> {
        let (msg_sender, msg_receiver) = unbounded();
        let (conn_live_sender, conn_live_receiver) = unbounded();
        let (session_request_sender, session_request_receiver) = unbounded();

        let pairing = PairingClient::new();
        let client = Client::new(Handler::new("Komodefi", msg_sender, conn_live_sender));

        let required = build_required_namespaces();

        let relay = Relay {
            protocol: SUPPORTED_PROTOCOL.to_string(),
            data: None,
        };

        let storage = SessionStorageDb::init(ctx)?;

        Ok(Self {
            client,
            pairing,
            session: Default::default(),
            active_chain_id: Arc::new(Mutex::new(DEFAULT_CHAIN_ID.to_string())),
            relay,
            namespaces: required,
            metadata: generate_metadata(),
            key_pair: SymKeyPair::new(),
            storage,
            inbound_message_handler: Arc::new(Mutex::new(msg_receiver)),
            connection_live_handler: Arc::new(Mutex::new(conn_live_receiver)),
            session_request_handler: Arc::new(Mutex::new(session_request_receiver)),
            session_request_sender: Arc::new(Mutex::new(session_request_sender)),
            subscriptions: Default::default(),
        })
    }

    pub fn try_from_ctx_or_initialize(ctx: &MmArc) -> MmResult<Arc<WalletConnectCtx>, WalletConnectCtxError> {
        from_ctx(&ctx.wallet_connect, move || {
            Self::try_init(ctx).map_err(|err| err.to_string())
        })
        .map_to_mm(WalletConnectCtxError::InternalError)
    }

    pub async fn connect_client(&self) -> MmResult<(), WalletConnectCtxError> {
        let auth = {
            let key = SigningKey::generate(&mut rand::thread_rng());
            AuthToken::new(AUTH_TOKEN_SUB)
                .aud(RELAY_ADDRESS)
                .ttl(Duration::from_secs(60 * 60))
                .as_jwt(&key)
                .unwrap()
        };
        let opts = ConnectionOptions::new(PROJECT_ID, auth).with_address(RELAY_ADDRESS);

        self.client.connect(&opts).await?;

        info!("WC connected");

        Ok(())
    }

    /// Create a WalletConnect pairing connection url.
    pub async fn new_connection(
        &self,
        required_namespaces: Option<ProposeNamespaces>,
    ) -> MmResult<String, WalletConnectCtxError> {
        let (topic, url) = self.pairing.create(self.metadata.clone(), None).await?;

        info!("Subscribing to topic: {topic:?}");

        self.client.subscribe(topic.clone()).await?;

        info!("Subscribed to topic: {topic:?}");

        send_proposal_request(self, topic.clone(), required_namespaces).await?;

        {
            let mut subs = self.subscriptions.lock().await;
            subs.push(topic);
        };

        Ok(url)
    }

    /// Connect to a WalletConnect pairing url.
    pub async fn connect_to_pairing(&self, url: &str, activate: bool) -> MmResult<Topic, WalletConnectCtxError> {
        let topic = self.pairing.pair(url, activate).await?;

        info!("Subscribing to topic: {topic:?}");
        self.client.subscribe(topic.clone()).await?;
        info!("Subscribed to topic: {topic:?}");

        {
            let mut subs = self.subscriptions.lock().await;
            subs.push(topic.clone());
        };

        Ok(topic)
    }

    pub fn is_chain_supported(&self, chain_id: &str) -> bool { SUPPORTED_CHAINS.iter().any(|chain| chain == &chain_id) }

    /// Set active chain.
    pub async fn set_active_chain(&self, chain_id: &str) {
        let mut active_chain = self.active_chain_id.lock().await;
        *active_chain = chain_id.to_owned();
    }

    /// Get current active chain id.
    pub async fn get_active_chain_id(&self) -> String { self.active_chain_id.lock().await.clone() }

    pub async fn get_session(&self) -> Option<Session> { self.session.lock().await.clone() }

    /// Get available accounts for a given chain_id.
    pub async fn get_account_for_chain_id(&self, chain_id: &str) -> MmResult<String, WalletConnectCtxError> {
        let active_chain_id = self.active_chain_id.lock().await;
        if *active_chain_id == chain_id {
            let session = self.session.lock().await;
            if let Some(session) = session.as_ref() {
                // Iterate through namespaces to find the matching chain_id
                for (namespace_key, namespace) in &session.namespaces {
                    if let Some(chains) = &namespace.chains {
                        let key = format!("{namespace_key}:{chain_id}");
                        // Check if the chain_id exists within the namespace chains
                        if chains.contains(&key) {
                            if let Some(accounts) = &namespace.accounts {
                                // Loop through the accounts and extract the account for the correct chain
                                for account_name in accounts {
                                    // "cosmos:cosmoshub-4:cosmos1fg2nemunucn496fewakqfe0mllcqfulrmjnj77"
                                    let account_vec = account_name.split(':').collect::<Vec<_>>();
                                    if account_vec.len() >= 3 {
                                        return Ok(account_vec[2].to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If the chain doesn't match, or no valid account is found, return an error
        MmError::err(WalletConnectCtxError::NoAccountFound(chain_id.to_string()))
    }

    pub async fn cosmos_get_account(
        &self,
        account_index: u8,
        chain: &str,
        chain_id: &str,
    ) -> MmResult<CosmosAccount, WalletConnectCtxError> {
        let accounts = cosmos_get_accounts_impl(self, chain, chain_id).await?;

        if accounts.is_empty() {
            return MmError::err(WalletConnectCtxError::EmptyAccount(chain_id.to_string()));
        };

        if accounts.len() < account_index as usize + 1 {
            return MmError::err(WalletConnectCtxError::NoAccountFoundForIndex(account_index));
        };

        Ok(accounts[account_index as usize].clone())
    }

    async fn sym_key(&self, topic: &Topic) -> MmResult<Vec<u8>, WalletConnectCtxError> {
        {
            let session = self.session.lock().await;
            if let Some(session) = session.as_ref() {
                if &session.topic == topic {
                    return Ok(session.session_key.symmetric_key().to_vec());
                }
            }
        }

        {
            let pairings = self.pairing.pairings.lock().await;
            if let Some(pairing) = pairings.get(topic.as_ref()) {
                let key = hex::decode(pairing.sym_key.clone())?;
                return Ok(key);
            }
        }

        MmError::err(WalletConnectCtxError::PairingError(format!("Topic not found:{topic}")))
    }

    /// Private function to publish a request.
    async fn publish_request(&self, topic: &Topic, param: RequestParams) -> MmResult<(), WalletConnectCtxError> {
        let irn_metadata = param.irn_metadata();
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, param.into());
        self.publish_payload(topic, irn_metadata, Payload::Request(request))
            .await?;

        info!("Otbound request sent!\n");

        Ok(())
    }

    /// Private function to publish a success request response.
    async fn publish_response_ok(
        &self,
        topic: &Topic,
        result: ResponseParamsSuccess,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        let irn_metadata = result.irn_metadata();
        let value = serde_json::to_value(result)?;
        let response = Response::Success(SuccessfulResponse::new(*message_id, value));
        self.publish_payload(topic, irn_metadata, Payload::Response(response))
            .await?;

        Ok(())
    }

    /// Private function to publish an error request response.
    async fn publish_response_err(
        &self,
        topic: &Topic,
        error_data: ResponseParamsError,
        message_id: &MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        let error = error_data.error();
        let irn_metadata = error_data.irn_metadata();
        let response = Response::Error(ErrorResponse::new(*message_id, error));
        self.publish_payload(topic, irn_metadata, Payload::Response(response))
            .await?;

        Ok(())
    }

    /// Private function to publish a payload.
    async fn publish_payload(
        &self,
        topic: &Topic,
        irn_metadata: IrnMetadata,
        payload: Payload,
    ) -> MmResult<(), WalletConnectCtxError> {
        let sym_key = self.sym_key(topic).await?;
        let payload = serde_json::to_string(&payload)?;

        info!("\n Sending Outbound request: {payload}!");

        let message = encrypt_and_encode(EnvelopeType::Type0, payload, &sym_key)?;
        {
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
        };

        Ok(())
    }

    pub async fn message_handler_event_loop(self: Arc<Self>) {
        let selfi = self.clone();
        let mut recv = self.inbound_message_handler.lock().await;
        while let Some(msg) = recv.next().await {
            info!("received message");
            if let Err(e) = selfi.handle_published_message(msg).await {
                info!("Error processing message: {:?}", e);
            }
        }
    }

    async fn handle_published_message(&self, msg: PublishedMessage) -> MmResult<(), WalletConnectCtxError> {
        let message = {
            let key = self.sym_key(&msg.topic).await?;
            decode_and_decrypt_type0(msg.message.as_bytes(), &key).unwrap()
        };

        info!("Inbound message payload={message}");

        let payload: Payload = serde_json::from_str(&message)?;

        match payload {
            Payload::Request(request) => process_inbound_request(self, request, &msg.topic).await?,
            Payload::Response(response) => process_inbound_response(self, response, &msg.topic).await?,
        }

        info!("Inbound message was handled successfully");
        Ok(())
    }

    async fn load_session_from_storage(&self) -> MmResult<(), WalletConnectCtxError> {
        let sessions = self
            .storage
            .db
            .get_all_sessions()
            .await
            .mm_err(|err| WalletConnectCtxError::StorageError(err.to_string()))?;
        if let Some(session) = sessions.first() {
            info!("Session found! activating :{}", session.topic);

            let mut ctx_session = self.session.lock().await;
            *ctx_session = Some(session.clone());

            // subcribe to session topics
            self.client.subscribe(session.topic.clone()).await?;
            self.client.subscribe(session.pairing_topic.clone()).await?;
        }

        Ok(())
    }

    async fn connection_live_watcher(self: Arc<Self>) {
        let mut recv = self.connection_live_handler.lock().await;
        let mut retry_count = 0;

        while let Some(_msg) = recv.next().await {
            info!("Connection disconnected. Attempting to reconnect...");

            // Try reconnecting
            match self.connect_client().await {
                Ok(_) => {
                    info!(
                        "Successfully reconnected to client after {} attempt(s).",
                        retry_count + 1
                    );
                    retry_count = 0;
                },
                Err(err) => {
                    retry_count += 1;
                    common::log::error!(
                        "Error while reconnecting to client (attempt {}): {:?}. Retrying in 5 seconds...",
                        retry_count,
                        err
                    );
                    Timer::sleep(5.).await;
                    continue;
                },
            }

            // Subscribe to existing topics again after reconnecting
            let subs = self.subscriptions.lock().await;
            for topic in &*subs {
                match self.client.subscribe(topic.clone()).await {
                    Ok(_) => info!("Successfully reconnected to topic: {:?}", topic),
                    Err(err) => error!("Failed to subscribe to topic: {:?}. Error: {:?}", topic, err),
                }
            }

            info!("Reconnection process complete.");
        }
    }
}

/// This function spwans related WalletConnect related tasks and needed initialization before
/// WalletConnect can be usable in KDF.
pub async fn initialize_walletconnect(ctx: &MmArc) -> MmResult<(), WalletConnectCtxError> {
    // Initialized WalletConnectCtx
    let wallet_connect = WalletConnectCtx::try_from_ctx_or_initialize(ctx)?;

    // WalletConnectCtx is initialized, now we can connect to relayer client.
    wallet_connect.connect_client().await?;

    // spawn message handler event loop
    ctx.spawner().spawn(wallet_connect.clone().message_handler_event_loop());

    // spawn WalletConnect client disconnect task
    ctx.spawner().spawn(wallet_connect.clone().connection_live_watcher());

    // load session from storage
    wallet_connect.load_session_from_storage().await?;

    Ok(())
}
