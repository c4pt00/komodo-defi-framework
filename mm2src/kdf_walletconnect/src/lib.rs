mod chain;
#[allow(unused)] mod error;
mod handler;
mod inbound_message;
mod metadata;
#[allow(unused)] mod pairing;
mod session;

use async_trait::async_trait;
use chain::build_required_namespaces;
use common::{executor::Timer, log::info};
use error::WalletConnectCtxError;
use futures::{channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
              lock::Mutex,
              StreamExt};
use handler::Handler;
use inbound_message::{process_inbound_request, process_inbound_response};
use metadata::{generate_metadata, AUTH_TOKEN_SUB, PROJECT_ID, RELAY_ADDRESS};
use mm2_err_handle::prelude::MmResult;
use mm2_err_handle::prelude::*;
use pairing_api::PairingClient;
use relay_client::{websocket::{Client, PublishedMessage},
                   ConnectionOptions, MessageIdGenerator};
use relay_rpc::rpc::params::{session_request::SessionRequestRequest, RelayProtocolMetadata, RequestParams};
use relay_rpc::{auth::{ed25519_dalek::SigningKey, AuthToken},
                domain::{MessageId, Topic},
                rpc::{params::{session::ProposeNamespaces, IrnMetadata, Metadata, Relay, ResponseParamsError,
                               ResponseParamsSuccess},
                      ErrorResponse, Payload, Request, Response, SuccessfulResponse}};
use session::{propose::new_proposal, Session, SymKeyPair};
use std::{sync::Arc, time::Duration};
use wc_common::{decode_and_decrypt_type0, encrypt_and_encode, EnvelopeType};

pub(crate) const SUPPORTED_PROTOCOL: &str = "irn";
const DEFAULT_CHAIN_ID: &str = "1"; // eth mainnet.

pub struct WalletConnectCtx {
    pub client: Client,
    pub pairing: PairingClient,
    pub session: Arc<Mutex<Option<Session>>>,
    pub active_chain_id: Arc<Mutex<String>>,
    pub(crate) key_pair: SymKeyPair,
    relay: Relay,
    namespaces: ProposeNamespaces,
    metadata: Metadata,
    inbound_message_handler: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>,
    connection_live_handler: Arc<Mutex<UnboundedReceiver<()>>>,

    session_request_sender: Arc<Mutex<UnboundedSender<SessionRequestRequest>>>,
    session_request_handler: Arc<Mutex<UnboundedReceiver<SessionRequestRequest>>>,
}

impl Default for WalletConnectCtx {
    fn default() -> Self { Self::new() }
}

impl WalletConnectCtx {
    pub fn new() -> Self {
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

        Self {
            client,
            pairing,
            session: Arc::new(Mutex::new(None)),
            active_chain_id: Arc::new(Mutex::new(DEFAULT_CHAIN_ID.to_string())),
            relay,
            namespaces: required,
            metadata: generate_metadata(),
            key_pair: SymKeyPair::new(),
            inbound_message_handler: Arc::new(Mutex::new(msg_receiver)),
            connection_live_handler: Arc::new(Mutex::new(conn_live_receiver)),
            session_request_handler: Arc::new(Mutex::new(session_request_receiver)),
            session_request_sender: Arc::new(Mutex::new(session_request_sender)),
        }
    }

    pub async fn create_pairing(
        &self,
        required_namespaces: Option<ProposeNamespaces>,
    ) -> MmResult<String, WalletConnectCtxError> {
        let (topic, url) = self.pairing.create(self.metadata.clone(), None).await?;

        info!("Subscribing to topic: {topic:?}");
        self.client.subscribe(topic.clone()).await?;
        info!("Subscribed to topic: {topic:?}");

        new_proposal(self, topic, required_namespaces).await?;

        Ok(url)
    }

    pub async fn connect_to_pairing(&self, url: &str, activate: bool) -> MmResult<Topic, WalletConnectCtxError> {
        let topic = self.pairing.pair(url, activate).await?;

        info!("Subscribing to topic: {topic:?}");
        self.client.subscribe(topic.clone()).await?;
        info!("Subscribed to topic: {topic:?}");

        Ok(topic)
    }

    pub async fn get_active_chain_id(&self) -> String { self.active_chain_id.lock().await.clone() }

    pub async fn get_session(&self) -> Option<Session> {
        let session = self.session.lock().await;
        session.clone()
    }

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
                                    let account_vec = account_name.split(':').collect::<Vec<_>>();
                                    if account_vec.len() >= 3 && account_vec[1] == chain_id {
                                        let account = account_vec[2].to_owned();
                                        return Ok(account);
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

    pub async fn published_message_event_loop(self: Arc<Self>) {
        let self_clone = self.clone();
        let mut recv = self.inbound_message_handler.lock().await;
        while let Some(msg) = recv.next().await {
            info!("received message");
            if let Err(e) = self_clone.handle_single_message(msg).await {
                info!("Error processing message: {:?}", e);
            }
        }
    }

    async fn handle_single_message(&self, msg: PublishedMessage) -> MmResult<(), WalletConnectCtxError> {
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
    pub async fn spawn_connection_live_watcher(self: Arc<Self>) {
        let mut recv = self.connection_live_handler.lock().await;
        while let Some(_msg) = recv.next().await {
            info!("connection disconnected, reconnecting");
            if let Err(err) = self.connect_client().await {
                common::log::error!("{err:?}");
                Timer::sleep(5.).await;
                continue;
            };
            info!("reconnecting success!");
        }
    }
}

#[async_trait]
pub trait WcCoinOps {
    /// Returns the coin's namespace identifier (e.g., "eip155" for Ethereum).
    fn chain(&self) -> String;

    /// Returns the list of supported chains for the coin.
    fn chain_id(&self) -> Vec<String>;

    /// Returns a boolean indicating whether WalletConnect should be used for this coin.
    fn use_walletconnect(&self) -> bool;
}
