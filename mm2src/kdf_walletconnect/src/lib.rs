mod error;
mod handler;
mod inbound_message;
mod metadata;
mod pairing;
mod session;
mod session_key;

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
use pairing_api::{Methods, PairingClient};
use rand::rngs::OsRng;
use relay_client::{websocket::{Client, PublishedMessage},
                   ConnectionOptions, MessageIdGenerator};
use relay_rpc::rpc::params::RelayProtocolMetadata;
use relay_rpc::{auth::{ed25519_dalek::SigningKey, AuthToken},
                domain::{MessageId, Topic},
                rpc::{params::{session_propose::SessionProposeRequest, IrnMetadata, RequestParams},
                      Params, Payload, Request, Response, SuccessfulResponse, JSON_RPC_VERSION_STR}};
use session::{Session, SessionInfo, SessionType};
use session_key::SessionKey;
use std::{sync::Arc, time::Duration};
use wc_common::{decode_and_decrypt_type0, encrypt_and_encode, EnvelopeType};

const SUPPORTED_PROTOCOL: &str = "irn";
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

pub struct WalletConnectCtx {
    pub client: Client,
    pub pairing: PairingClient,
    pub session: Session,
    pub msg_handler: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>,
    pub connection_live_handler: Arc<Mutex<UnboundedReceiver<()>>>,
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

        Self {
            client,
            pairing,
            session: Session::new(),
            msg_handler: Arc::new(Mutex::new(msg_receiver)),
            connection_live_handler: Arc::new(Mutex::new(conn_live_receiver)),
        }
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
            let sessions = self.session.lock().await;
            if let Some(sesssion) = sessions.get(topic) {
                return Ok(sesssion.session_key.symmetric_key().to_vec());
            }
        }

        {
            let pairings = self.pairing.pairings.lock().await;
            if let Some(pairing) = pairings.get(topic.as_ref()) {
                let key = hex::decode(pairing.sym_key.clone())
                    .map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;
                return Ok(key);
            }
        }

        MmError::err(WalletConnectCtxError::PairingNotFound(format!(
            "Topic not found:{topic}"
        )))
    }

    pub async fn create_pairing(&self) -> MmResult<String, WalletConnectCtxError> {
        let metadata = generate_metadata();
        let methods = Methods(vec![SUPPORTED_METHODS
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()]);

        let (topic, url) = self
            .pairing
            .create(metadata.clone(), Some(methods), &self.client)
            .await?;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let session_key = SessionKey::from_osrng(public_key.as_bytes())
            .map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;
        let session_topic: Topic = session_key.generate_topic().into();
        let subscription_id = self
            .client
            .subscribe(session_topic.clone())
            .await
            .map_to_mm(|err| WalletConnectCtxError::SubscriptionError(err.to_string()))?;
        let session = SessionInfo::new(
            subscription_id,
            session_key,
            topic.clone(),
            metadata,
            SessionType::Proposer,
        );

        let session_proposal = RequestParams::SessionPropose(SessionProposeRequest {
            relays: vec![session.relay.clone()],
            proposer: session.proposer.clone(),
            required_namespaces: session.namespaces.clone(),
        });

        {
            let mut sessions = self.session.lock().await;
            sessions.insert(session_topic.clone(), session);
        }

        let irn_metadata = session_proposal.irn_metadata();
        self.publish_request(&topic, session_proposal.into(), irn_metadata)
            .await?;

        let clean_url = url.replace("&amp;", "&");
        Ok(clean_url)
    }

    pub async fn connect_to_pairing(&self, url: &str, activate: bool) -> MmResult<Topic, WalletConnectCtxError> {
        Ok(self.pairing.pair(url, activate, &self.client).await?)
    }

    /// Private function to publish a request.
    async fn publish_request(
        &self,
        topic: &Topic,
        params: Params,
        irn_metadata: IrnMetadata,
    ) -> MmResult<(), WalletConnectCtxError> {
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, params);
        self.publish_payload(topic, irn_metadata, Payload::Request(request))
            .await?;

        info!("Otbound request sent!\n");

        Ok(())
    }

    /// Private function to publish a request response.
    async fn publish_response(
        &self,
        topic: &Topic,
        params: serde_json::Value,
        irn_metadata: IrnMetadata,
        message_id: MessageId,
    ) -> MmResult<(), WalletConnectCtxError> {
        let response = Response::Success(SuccessfulResponse {
            id: message_id,
            jsonrpc: JSON_RPC_VERSION_STR.into(),
            result: params,
        });

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

        let payload =
            serde_json::to_string(&payload).map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;
        info!("\n Sending Outbound request: {payload}!");

        let message = encrypt_and_encode(EnvelopeType::Type0, payload, &sym_key)
            .map_to_mm(|err| WalletConnectCtxError::EncodeError(err.to_string()))?;
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
        let mut recv = self.msg_handler.lock().await;
        while let Some(msg) = recv.next().await {
            let message = {
                let key = self.sym_key(&msg.topic).await.unwrap();
                decode_and_decrypt_type0(msg.message.as_bytes(), &key).unwrap()
            };

            info!("\nInbound message payload={message}");

            let response = serde_json::from_str::<Payload>(&message).unwrap();
            let result = match response {
                Payload::Request(request) => process_inbound_request(self.clone(), request, &msg.topic).await,
                Payload::Response(response) => process_inbound_response(self.clone(), response, &msg.topic).await,
            };

            match result {
                Ok(()) => info!("Inbound message was handled succesfully"),
                Err(err) => info!("Error while handling inbound message: {err:?}"),
            };
        }
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
