mod error;
mod handler;
mod pairing;
mod session;
mod session_key;

use common::log::info;
use error::WalletConnectCtxError;
use futures::{channel::mpsc::{unbounded, UnboundedReceiver},
              lock::Mutex,
              StreamExt};
use handler::Handler;
use mm2_err_handle::prelude::MmResult;
use mm2_err_handle::prelude::*;
use pairing::{process_pairing_delete_response, process_pairing_extend_response, process_pairing_ping_response};
use pairing_api::{Methods, PairingClient};
use relay_client::{websocket::{Client, PublishedMessage},
                   ConnectionOptions, MessageIdGenerator};
use relay_rpc::{auth::{ed25519_dalek::SigningKey, AuthToken},
                domain::{MessageId, Topic},
                rpc::{params::{IrnMetadata, Metadata, ResponseParamsSuccess},
                      Params, Payload, Request, Response, SuccessfulResponse, JSON_RPC_VERSION_STR}};
use session::{Session, APP_DESCRIPTION, APP_NAME};
use std::{sync::Arc, time::Duration};
use wc_common::{decode_and_decrypt_type0, encrypt_and_encode, EnvelopeType};

const RELAY_ADDRESS: &str = "wss://relay.walletconnect.com";
const PROJECT_ID: &str = "86e916bcbacee7f98225dde86b697f5b";
const AUTH_TOKEN_SUB: &str = "http://127.0.0.1:8000";

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
    pub handler: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>,
}

impl Default for WalletConnectCtx {
    fn default() -> Self { Self::new() }
}

impl WalletConnectCtx {
    pub fn new() -> Self {
        let (msg_sender, msg_receiver) = unbounded();

        let pairing = PairingClient::new();
        let client = Client::new(Handler::new("Komodefi", msg_sender));

        Self {
            client,
            pairing,
            session: Session::new(),
            handler: Arc::new(Mutex::new(msg_receiver)),
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

    // todo: return slice
    async fn sym_key(&self, topic: &Topic) -> MmResult<Vec<u8>, WalletConnectCtxError> {
        println!("sym topic: {topic:?}");
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

        MmError::err(WalletConnectCtxError::PairingNotFound("Topic not found".to_owned()))
    }

    pub async fn create_pairing(&self) -> MmResult<(Topic, String), WalletConnectCtxError> {
        let metadata = Metadata {
            description: APP_DESCRIPTION.to_owned(),
            url: "127.0.0.1:3000".to_owned(),
            icons: vec![],
            name: APP_NAME.to_owned(),
        };
        let methods = Methods(vec![SUPPORTED_METHODS
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()]);

        Ok(self.pairing.create(metadata, Some(methods), &self.client).await?)
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
        let mut recv = self.handler.lock().await;
        while let Some(msg) = recv.next().await {
            let message = {
                let key = self.sym_key(&msg.topic).await.unwrap();
                decode_and_decrypt_type0(msg.message.as_bytes(), &key).unwrap()
            };

            println!("\nInbound message payload={message}");

            let response = serde_json::from_str::<Payload>(&message).unwrap();
            let result = match response {
                Payload::Request(request) => process_inbound_request(self.clone(), request, &msg.topic).await,
                Payload::Response(response) => process_inbound_response(self.clone(), response).await,
            };

            match result {
                Ok(()) => info!("Inbound message was handled succesfully"),
                Err(err) => info!("Error while handling inbound message: {err:?}"),
            };
        }
    }
}

async fn process_inbound_request(
    ctx: Arc<WalletConnectCtx>,
    request: Request,
    topic: &Topic,
) -> MmResult<(), WalletConnectCtxError> {
    let response = match request.params {
        Params::SessionPropose(proposal) => ctx.session.process_proposal_request(&ctx, proposal).await,
        Params::SessionExtend(param) => ctx.session.process_session_extend_request(topic, param).await,
        Params::SessionDelete(param) => ctx.session.process_session_delete_request(param),
        Params::SessionPing(()) => ctx.session.process_session_ping_request(),
        Params::SessionSettle(param) => ctx.session.process_session_settle_request(topic, param).await,
        Params::SessionUpdate(param) => ctx.session.process_session_update_request(topic, param).await,
        Params::SessionRequest(_) => todo!(),
        Params::SessionEvent(_) => todo!(),

        Params::PairingPing(_param) => process_pairing_ping_response().await,
        Params::PairingDelete(param) => process_pairing_delete_response(&ctx, topic, param).await,
        Params::PairingExtend(param) => process_pairing_extend_response(&ctx, topic, param).await,
        _ => todo!(),
    }?;

    info!("Publishing reponse");
    ctx.publish_response(topic, response.0, response.1, request.id).await?;

    // todo
    // ctx.session.session_delete_cleanup(ctx.clone(), topic).await?

    Ok(())
}

async fn process_inbound_response(
    _ctx: Arc<WalletConnectCtx>,
    response: Response,
) -> MmResult<(), WalletConnectCtxError> {
    match response {
        Response::Success(value) => {
            let params = serde_json::from_value::<ResponseParamsSuccess>(value.result)?;
            match params {
                ResponseParamsSuccess::SessionPropose(param) => {
                    info!("Session Propose Response: {param:?}");
                    todo!()
                },
                ResponseParamsSuccess::SessionSettle(success) | ResponseParamsSuccess::SessionUpdate(success) |ResponseParamsSuccess::SessionExtend(success)
                | ResponseParamsSuccess::SessionRequest(success)
                | ResponseParamsSuccess::SessionEvent(success)
                | ResponseParamsSuccess::SessionDelete(success)
                | ResponseParamsSuccess::SessionPing(success)
                | ResponseParamsSuccess::PairingExtend(success)
                | ResponseParamsSuccess::PairingDelete(success)
                | ResponseParamsSuccess::PairingPing(success) => {
                    if !success {
                       return MmError::err(WalletConnectCtxError::UnsuccessfulResponse(format!("Unsuccessful response={params:?}")));
                    }

                    Ok(())
                },
            }
        },
        Response::Error(err) => {
            println!("Error: {err:?}");
            todo!()
        },
    }
}
