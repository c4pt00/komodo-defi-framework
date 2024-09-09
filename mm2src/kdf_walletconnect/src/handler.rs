use std::time::Duration;

use common::log::info;
use futures::channel::mpsc::UnboundedSender;
use relay_client::{error::ClientError,
                   websocket::{CloseFrame, ConnectionHandler, PublishedMessage},
                   ConnectionOptions};
use relay_rpc::auth::{ed25519_dalek::SigningKey, AuthToken};

pub struct Handler {
    name: &'static str,
    sender: UnboundedSender<PublishedMessage>,
}

impl Handler {
    pub fn new(name: &'static str, sender: UnboundedSender<PublishedMessage>) -> Self { Self { name, sender } }
}

impl ConnectionHandler for Handler {
    fn connected(&mut self) {
        info!("\n[{}] connection open", self.name);
    }

    fn disconnected(&mut self, frame: Option<CloseFrame<'static>>) {
        info!("\n[{}] connection closed: frame={frame:?}", self.name);
    }

    fn message_received(&mut self, message: PublishedMessage) {
        info!(
            "\n[{}] inbound message: message_id={} topic={} tag={} message={}",
            self.name, message.message_id, message.topic, message.tag, message.message,
        );

        if let Err(e) = self.sender.start_send(message) {
            info!("\n[{}] failed to send the to the receiver: {e}", self.name);
        }
    }

    fn inbound_error(&mut self, error: ClientError) {
        info!("\n[{}] inbound error: {error}", self.name);
    }

    fn outbound_error(&mut self, error: ClientError) {
        info!("\n[{}] outbound error: {error}", self.name);
    }
}

fn create_conn_opts(relay_address: &str, project_id: &str) -> ConnectionOptions {
    let key = SigningKey::generate(&mut rand::thread_rng());

    let auth = AuthToken::new("https://komodefi.com")
        .aud(relay_address)
        .ttl(Duration::from_secs(60 * 60))
        .as_jwt(&key)
        .unwrap();

    ConnectionOptions::new(project_id, auth).with_address(relay_address)
}
