use common::log::info;
use futures::channel::mpsc::UnboundedSender;
use relay_client::{error::ClientError,
                   websocket::{CloseFrame, ConnectionHandler, PublishedMessage}};

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
        info!("\n[{}] connection open", self.name);
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
