use std::{collections::HashMap, sync::Arc, time::Duration};

use error::WalletConnectClientError;
use futures::{channel::mpsc::{unbounded, UnboundedReceiver}, lock::Mutex, StreamExt};
use handler::Handler;
use mm2_err_handle::prelude::MmResult;
use pairing_api::{Methods, PairingClient};
use relay_client::{websocket::{Client, PublishedMessage}, ConnectionOptions, MessageIdGenerator};
use relay_rpc::{domain::{MessageId, SubscriptionId, Topic}, rpc::{params::{IrnMetadata, Metadata}, Params, Payload, Request, Response, SuccessfulResponse, JSON_RPC_VERSION_STR}};
use session_key::SessionKey;
use mm2_err_handle::prelude::*;
use wc_common::{encrypt_and_encode, EnvelopeType};
use common::log::info;


mod session_key;
mod handler;
mod error;

pub const RELAY_ADDRESS: &str = "wss://relay.walletconnect.com";
pub const PROJECT_ID: &str = "86e916bcbacee7f98225dde86b697f5b";

#[derive(Debug)]
pub struct Session {
    /// Pairing subscription id.
    pub subscription_id: SubscriptionId,
    /// Session symmetric key.
    pub session_key: SessionKey,
}

#[derive(Debug)]
pub struct WalletConnectClient {
   pub client: Arc<Client>,
   pub pairing: Arc<PairingClient>,
   pub sessions: HashMap<Topic, Session>,
   pub handler: Arc<Mutex<UnboundedReceiver<PublishedMessage>>>
}

impl Default for WalletConnectClient {
    fn default() -> Self {
         Self::new()
    }
}

impl WalletConnectClient {
    pub fn new() -> Self {
        let (msg_sender, msg_receiver) = unbounded();

        let pairing = PairingClient::new();
        let client = Arc::new(Client::new(Handler::new("Komodefi", msg_sender)));

        Self {
            client,
            pairing,
            sessions: HashMap::new(),
            handler: Arc::new(Mutex::new(msg_receiver))
        }
    }

    pub async fn create_pairing(&self, metadata: Metadata, methods: Option<Methods>) ->  MmResult<(Topic, String), WalletConnectClientError> {
      Ok(self.pairing.create(metadata, methods, &self.client).await?)
    }

    pub async fn connect_to_pairing(&self, url: &str, activate: bool) -> MmResult<Topic, WalletConnectClientError> {
       Ok(self.pairing.pair(url, activate, &self.client).await?)
    }

    pub async fn connect(&self, opts: &ConnectionOptions) -> MmResult<(), WalletConnectClientError> {
        Ok(self.client.connect(opts).await?)
    }


    /// Private function to publish a request.
       async fn publish_request(
           &self,
           topic: &str,
           params: Params,
           irn_metadata: IrnMetadata
       ) -> MmResult<(), WalletConnectClientError> {
           let message_id = MessageIdGenerator::new().next();
           let request = Request::new(message_id, params);
           // Publish the encrypted message
           self.publish_payload(topic, irn_metadata, Payload::Request(request))
               .await?;

           info!("Otbound request sent!\n");

           Ok(())
       }

       /// Private function to publish a request response.
       async fn publish_response(
           &self,
           topic: &str,
           params: Params,
           irn_metadata: IrnMetadata,
           message_id: MessageId,
       ) -> MmResult<(), WalletConnectClientError> {
           let response = Response::Success(SuccessfulResponse {
               id: message_id,
               jsonrpc: JSON_RPC_VERSION_STR.into(),
               result: serde_json::to_value(params)
                   .map_to_mm(|err| WalletConnectClientError::EncodeError(err.to_string()))?,
           });

           // Publish the encrypted message
           self.publish_payload(topic, irn_metadata, Payload::Response(response))
               .await?;

           println!("\nOutbound request sent!");

           Ok(())
       }


       /// Private function to publish a payload.
       async fn publish_payload(
           &self,
           topic: &str,
           irn_metadata: IrnMetadata,
           payload: Payload,
       ) -> MmResult<(), WalletConnectClientError> {
           // try to extend session before updating local store.
           let sym_key = {
               let pairings = self.pairing.pairings.lock().await;
               let pairing = pairings
                   .get(topic)
                   .ok_or_else(|| WalletConnectClientError::PairingNotFound(format!("Pariring not found for topic:{topic}")))?;
               hex::decode(pairing.sym_key.clone()).map_to_mm(|err| {
                    WalletConnectClientError::EncodeError(format!("Failed to decode sym_key: {:?}", err))
                })?
            };

           let payload = serde_json::to_string(&payload)
               .map_to_mm(|err| WalletConnectClientError::EncodeError(err.to_string()))?;
           let message = encrypt_and_encode(EnvelopeType::Type0, payload, &sym_key)
               .map_to_mm(|err| WalletConnectClientError::EncodeError(err.to_string()))?;

           // Publish the encrypted message
           {
               self.client
                   .publish(
                       topic.into(),
                       message,
                       None,
                       irn_metadata.tag,
                       Duration::from_secs(irn_metadata.ttl),
                       irn_metadata.prompt,
                   )
                   .await
                   .map_to_mm(WalletConnectClientError::PublishError)?;
            };

            Ok(())
        }
}

pub async fn published_message_event_loop(client: Arc<WalletConnectClient>) {
    let mut recv = client.handler.lock().await;
    while let Some(data) = recv.next().await {
        todo!()
    }
}
