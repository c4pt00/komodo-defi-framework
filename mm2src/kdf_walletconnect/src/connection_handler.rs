use crate::{WalletConnectCtx, WalletConnectError};

use common::executor::Timer;
use common::log::{debug, error, info};
use futures::channel::mpsc::UnboundedSender;
use futures::StreamExt;
use mm2_err_handle::prelude::*;
use relay_client::error::ClientError;
use relay_client::websocket::{CloseFrame, ConnectionHandler, PublishedMessage};
use relay_rpc::rpc::params::RequestParams;
use std::sync::Arc;
use tokio::time::interval;
use tokio::time::Duration;

const INITIAL_RETRY_SECS: f64 = 5.0;
const RETRY_INCREMENT: f64 = 5.0;
const MAX_BACKOFF: u64 = 60;
const PING_INTERVAL: u64 = 140;
const PING_TIMEOUT: f64 = 60.;

pub struct Handler {
    name: &'static str,
    msg_sender: UnboundedSender<PublishedMessage>,
    conn_live_sender: UnboundedSender<()>,
}

impl Handler {
    pub fn new(
        name: &'static str,
        msg_sender: UnboundedSender<PublishedMessage>,
        conn_live_sender: UnboundedSender<()>,
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

        if let Err(e) = self.conn_live_sender.start_send(()) {
            info!("\n[{}] failed to send to the receiver: {e}", self.name);
        }
    }

    fn message_received(&mut self, message: PublishedMessage) {
        info!(
            "\n[{}] inbound message: message_id={} topic={} tag={} message={}",
            self.name, message.message_id, message.topic, message.tag, message.message,
        );

        if let Err(e) = self.msg_sender.start_send(message) {
            info!("\n[{}] failed to send to the receiver: {e}", self.name);
        }
    }

    fn inbound_error(&mut self, error: ClientError) {
        info!("\n[{}] inbound error: {error}", self.name);
    }

    fn outbound_error(&mut self, error: ClientError) {
        info!("\n[{}] outbound error: {error}", self.name);
    }
}

/// Establishes initial connection to WalletConnect relay server with linear retry mechanism.
/// Uses increasing delay between retry attempts starting from INITIAL_RETRY_SECS.
/// After successful connection, attempts to restore previous session state from storage.
pub(crate) async fn initial_connection(this: &WalletConnectCtx) {
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

    debug!("Successfully connected to client after {} attempt(s).", retry_count + 1);

    // load session from storage
    if let Err(err) = this.load_session_from_storage().await {
        error!("Unable to load session from storage: {err:?}");
    };
}

/// Handles unexpected disconnections from WalletConnect relay server.
/// Implements exponential backoff retry mechanism for reconnection attempts.
/// After successful reconnection, resubscribes to previous topics to restore full functionality.
pub(crate) async fn handle_disconnections(this: &WalletConnectCtx) {
    let mut recv = this.connection_live_rx.lock().await;
    let mut backoff = 1;

    while let Some(_msg) = recv.next().await {
        debug!("Connection disconnected. Attempting to reconnect...");

        loop {
            match this.connect_client().await {
                Ok(_) => {
                    if let Err(e) = resubscribe_to_topics(this).await {
                        error!("Failed to resubscribe after reconnection: {:?}", e);
                    }
                    debug!("Reconnection process complete.");
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

/// Maintains connection health with WalletConnect relay server through periodic pings.
/// Sends a ping every 4 minutes to proactively detect disconnections and automatically reconnects if needed.
/// This helps prevent connection drops as the relay server tends to disconnect inactive connections after 5 minutes.
/// The ping interval is designed to catch potential disconnections before the server timeout while minimizing
/// unnecessary network traffic.
pub(crate) async fn keep_alive_ping(ctx: Arc<WalletConnectCtx>) {
    let mut interval = interval(Duration::from_secs(PING_INTERVAL));
    let mut backoff = 1.;

    // Skip the first tick which happens immediately
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match try_ping(&ctx).await {
                    Ok(_) => {
                        backoff = 1.;
                        continue;
                    }
                    Err(e) => {
                        error!("WalletConnect ping failed: {:?}. Attempting reconnect...", e);
                        // Attempt reconnection with backoff
                        if let Err(reconnect_err) = handle_ping_failure(&ctx).await {
                            error!("Reconnection failed: {:?}", reconnect_err);
                            // Increase backoff for next attempt
                            backoff = std::cmp::min(backoff as u64 * 2, MAX_BACKOFF ) as f64;
                            Timer::sleep(backoff).await;
                            continue;
                        }
                        // Reset backoff after successful reconnection
                        backoff = 1.;
                        debug!("Successfully reconnected after ping failure");
                    }
                }
            }
        }
    }
}

/// Attempts to verify connection health with WalletConnect relay server by sending a ping message.
/// Waits for a pong response with a specified timeout period.
async fn try_ping(ctx: &WalletConnectCtx) -> MmResult<(), WalletConnectError> {
    let active_topic = ctx.session.get_active_topic_or_err().await?;
    let param = RequestParams::SessionPing(());
    ctx.publish_request(&active_topic, param).await?;

    let timeout = Timer::sleep(PING_TIMEOUT);
    tokio::pin!(timeout);

    let mut recv = ctx.message_rx.lock().await;
    tokio::select! {
        msg = recv.next() => {
            match msg {
                Some(Ok(_)) => {
                    debug!("WalletConnect Session Is Alive");
                    Ok(())
                },
                Some(Err(err)) => {
                    MmError::err(WalletConnectError::InternalError(
                        format!("WalletConnect Ping Error: {err:?}")
                    ))
                },
                None => {
                    error!("WalletConnect Ping timeout");
                    MmError::err(WalletConnectError::InternalError(
                        "WalletConnect Ping timeout".into()
                    ))
                }
            }
        },
        _ = timeout => {
            error!("WalletConnect Ping timeout");
            MmError::err(WalletConnectError::InternalError(
                "WalletConnect Ping timeout".into()
            ))
        }
    }
}

// Handle reconnection after ping failure
async fn handle_ping_failure(ctx: &WalletConnectCtx) -> MmResult<(), WalletConnectError> {
    // Attempt to disconnect client
    ctx.client.disconnect().await?;
    // Attempt to reconnect
    ctx.connect_client().await?;
    // Resubscribe to topics if needed
    resubscribe_to_topics(ctx).await?;
    // Verify connection with a new ping
    try_ping(ctx).await
}

/// Resubscribes to previously active topics after reconnection.
/// Called by handle_disconnections to restore subscription state.
async fn resubscribe_to_topics(this: &WalletConnectCtx) -> MmResult<(), WalletConnectError> {
    let subs = this.subscriptions.lock().await;
    this.client.batch_subscribe(&**subs).await?;

    Ok(())
}
