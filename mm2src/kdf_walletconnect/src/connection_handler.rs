use std::sync::Arc;

use crate::storage::WalletConnectStorageOps;
use crate::{WalletConnectCtx, WalletConnectError};

use common::executor::Timer;
use common::log::{error, info};
use futures::channel::mpsc::UnboundedSender;
use futures::StreamExt;
use mm2_err_handle::prelude::*;
use relay_client::error::ClientError;
use relay_client::websocket::{CloseFrame, ConnectionHandler, PublishedMessage};
use relay_rpc::domain::Topic;

const INITIAL_RETRY_SECS: f64 = 5.0;
const MAX_BACKOFF: u64 = 60;
const RETRY_INCREMENT: f64 = 5.0;

pub struct Handler {
    name: &'static str,
    msg_sender: UnboundedSender<PublishedMessage>,
    conn_live_sender: UnboundedSender<Option<String>>,
}

impl Handler {
    pub fn new(
        name: &'static str,
        msg_sender: UnboundedSender<PublishedMessage>,
        conn_live_sender: UnboundedSender<Option<String>>,
    ) -> Self {
        Self {
            name,
            msg_sender,
            conn_live_sender,
        }
    }
}

impl ConnectionHandler for Handler {
    fn connected(&mut self) {
        info!("\n[{}] connection to WalletConnect relay server successful", self.name);
    }

    fn disconnected(&mut self, frame: Option<CloseFrame<'static>>) {
        info!("\n[{}] connection closed: frame={frame:?}", self.name);

        if let Err(e) = self.conn_live_sender.start_send(None) {
            error!("\n[{}] failed to send to the receiver: {e}", self.name);
        }
    }

    fn message_received(&mut self, message: PublishedMessage) {
        info!(
            "\n[{}] inbound message: message_id={} topic={} tag={} message={}",
            self.name, message.message_id, message.topic, message.tag, message.message,
        );

        if let Err(e) = self.msg_sender.start_send(message) {
            error!("\n[{}] failed to send to the receiver: {e}", self.name);
        }
    }

    fn inbound_error(&mut self, error: ClientError) {
        info!("\n[{}] inbound error: {error}", self.name);
        if let Err(e) = self.conn_live_sender.start_send(Some(error.to_string())) {
            error!("\n[{}] failed to send to the receiver: {e}", self.name);
        }
    }

    fn outbound_error(&mut self, error: ClientError) {
        info!("\n[{}] outbound error: {error}", self.name);
        if let Err(e) = self.conn_live_sender.start_send(Some(error.to_string())) {
            error!("\n[{}] failed to send to the receiver: {e}", self.name);
        }
    }
}

/// Establishes initial connection to WalletConnect relay server with linear retry mechanism.
/// Uses increasing delay between retry attempts starting from INITIAL_RETRY_SECS.
/// After successful connection, attempts to restore previous session state from storage.
pub(crate) async fn initialize_connection(this: Arc<WalletConnectCtx>) {
    info!("Initializing WalletConnect connection");
    let mut retry_count = 0;
    let mut retry_secs = INITIAL_RETRY_SECS;

    while let Err(err) = this.connect_client().await {
        retry_count += 1;
        error!(
            "Error during initial connection attempt {}: {:?}. Retrying in {retry_secs} seconds...",
            retry_count, err
        );
        Timer::sleep(retry_secs).await;
        retry_secs += RETRY_INCREMENT;
    }

    // Initialize storage
    if let Err(err) = this.storage.init().await {
        error!("Unable to initialize WalletConnect persistent storage: {err:?}. Only inmemory storage will be utilized for this Session.");
    };

    // load session from storage
    if let Err(err) = this.load_session_from_storage().await {
        error!("Unable to load session from storage: {err:?}");
    };

    // Spawn session disconnection watcher.
    handle_disconnections(&this).await;
}

/// Handles unexpected disconnections from WalletConnect relay server.
/// Implements exponential backoff retry mechanism for reconnection attempts.
/// After successful reconnection, resubscribes to previous topics to restore full functionality.
pub(crate) async fn handle_disconnections(this: &WalletConnectCtx) {
    let mut recv = this.connection_live_rx.lock().await;
    let mut backoff = 1;

    while let Some(msg) = recv.next().await {
        info!("Connection disconnected. Attempting to reconnect...");
        // In some rare occasion, WalletConnect websocket client returns
        // `Websocket transport error: IO error: unexpected end of file`
        // probably a problem with the relay server.
        let msg = msg.map_or("".to_string(), |m| m);
        if msg.contains("unexpected end of file") {
            this.client.disconnect().await.ok();
        }

        loop {
            match this.connect_client().await {
                Ok(_) => {
                    if let Err(e) = resubscribe_to_topics(this, None).await {
                        error!("Failed to resubscribe after reconnection: {:?}", e);
                    }
                    info!("Reconnection process complete.");
                    backoff = 1;
                    break;
                },
                Err(e) => {
                    error!("Reconnection attempt failed: {:?}. Retrying in {:?}...", e, backoff);
                    Timer::sleep(backoff as f64).await;
                    backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                },
            }
        }
    }
}

/// Resubscribes to previously active topics after reconnection.
/// Called by handle_disconnections to restore subscription state.
async fn resubscribe_to_topics(this: &WalletConnectCtx, topic: Option<&Topic>) -> MmResult<(), WalletConnectError> {
    if let Some(topic) = topic {
        if let Some(session) = this.session.get_session(topic) {
            this.client
                .batch_subscribe(vec![session.topic.clone(), session.pairing_topic.clone()])
                .await?;
            return Ok(());
        }
    }
    let sessions = this.session.get_sessions();
    for session in sessions {
        this.client
            .batch_subscribe(vec![session.topic.into(), session.pairing_topic.into()])
            .await?;
    }

    Ok(())
}
