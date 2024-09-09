use std::{collections::HashMap, sync::Arc};

use futures::{channel::mpsc::{unbounded, UnboundedReceiver}, lock::Mutex};
use handler::Handler;
use mm2_err_handle::prelude::MmResult;
use pairing_api::PairingClient;
use relay_client::{error::ClientError, websocket::{Client, PublishedMessage}, ConnectionOptions};
use relay_rpc::domain::{SubscriptionId, Topic};
use session_key::SessionKey;
use mm2_err_handle::prelude::*;

mod session_key;
mod handler;

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
        let (sender, receiver) = unbounded();

        let pairing = PairingClient::new();
        let client = Arc::new(Client::new(Handler::new("Komodefi", sender)));

        Self {
            client,
            pairing,
            sessions: HashMap::new(),
            handler: Arc::new(Mutex::new(receiver))
        }
    }

    pub async fn connect(&self, opts: &ConnectionOptions) -> MmResult<(), ClientError>{
        self.client.connect(opts).await.map_to_mm(|err|err)
    }


}
