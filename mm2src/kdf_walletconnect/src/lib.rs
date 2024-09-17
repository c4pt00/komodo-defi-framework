#[allow(unused)] mod error;
mod handler;
mod inbound_message;
mod metadata;
#[allow(unused)] mod pairing;
mod session;

use chrono::Utc;
use common::{executor::Timer, log::info};
use error::WalletConnectCtxError;
use futures::{channel::mpsc::{unbounded, UnboundedReceiver},
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
use relay_rpc::rpc::params::{RelayProtocolMetadata, RequestParams};
use relay_rpc::{auth::{ed25519_dalek::SigningKey, AuthToken},
                domain::{MessageId, Topic},
                rpc::{params::{session::{ProposeNamespace, ProposeNamespaces},
                               IrnMetadata, Metadata, Relay, ResponseParamsError, ResponseParamsSuccess},
                      ErrorResponse, Payload, Request, Response, SuccessfulResponse}};
use session::{propose::create_proposal_session, Session};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use wc_common::{decode_and_decrypt_type0, encrypt_and_encode, EnvelopeType};

pub(crate) const SUPPORTED_PROTOCOL: &str = "irn";
const SUPPORTED_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
    "eth_signTypedData_v4",
];
const SUPPORTED_CHAINS: &[&str] = &["eip155:1", "eip155:5"];
const SUPPORTED_EVENTS: &[&str] = &["chainChanged", "accountsChanged"];
const SUPPORTED_ACCOUNTS: &[&str] = &["eip155:5:0xBA5BA3955463ADcc7aa3E33bbdfb8A68e0933dD8"];
const DEFAULT_CHAIN_ID: &str = "1"; // eth mainnet.

pub struct WalletConnectCtx {
    pub client: Client,
    pub pairing: PairingClient,
    pub sessions: Session,
    pub msg_handler: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>,
    pub connection_live_handler: Arc<Mutex<UnboundedReceiver<()>>>,
    pub active_chain_id: Arc<Mutex<String>>,
    pub relay: Relay,
    pub namespaces: ProposeNamespaces,
    pub metadata: Metadata,
}

impl Default for WalletConnectCtx {
    fn default() -> Self { Self::new() }
}

impl WalletConnectCtx {
    pub fn new() -> Self {
        let (msg_sender, msg_receiver) = unbounded();
        let (conn_live_sender, conn_live_receiver) = unbounded();

        let pairing = PairingClient::new();
        let client = Client::new(Handler::new("Komodefi", msg_sender, conn_live_sender));

        let mut required = BTreeMap::new();
        required.insert("eip155".to_string(), ProposeNamespace {
            chains: SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
            methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
            events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
        });

        let relay = Relay {
            protocol: SUPPORTED_PROTOCOL.to_string(),
            data: None,
        };

        Self {
            client,
            pairing,
            sessions: Session::new(),
            msg_handler: Arc::new(Mutex::new(msg_receiver)),
            connection_live_handler: Arc::new(Mutex::new(conn_live_receiver)),
            active_chain_id: Arc::new(Mutex::new(DEFAULT_CHAIN_ID.to_string())),
            relay,
            namespaces: ProposeNamespaces(required),
            metadata: generate_metadata(),
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

        create_proposal_session(self, topic, required_namespaces).await?;

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

    pub async fn get_active_sessions(&self) -> impl IntoIterator {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .filter_map(|session| {
                if session.expiry > Utc::now().timestamp() as u64 {
                    Some(session.pairing_topic.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    pub async fn get_inactive_sessions(&self) -> impl IntoIterator {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .filter_map(|session| {
                if session.expiry <= Utc::now().timestamp() as u64 {
                    Some(session.pairing_topic.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
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
            let sessions = self.sessions.lock().await;
            if let Some(sesssion) = sessions.get(topic) {
                return Ok(sesssion.session_key.symmetric_key().to_vec());
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
        let mut recv = self.msg_handler.lock().await;
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
