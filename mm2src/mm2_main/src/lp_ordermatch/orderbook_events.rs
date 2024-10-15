use super::OrderbookP2PItem;
use mm2_event_stream::{Broadcaster, Event, EventStreamer, StreamHandlerInput};

use async_trait::async_trait;
use futures::channel::oneshot;
use futures::StreamExt;
use uuid::Uuid;

pub struct OrderbookStreamer {
    base: String,
    rel: String,
}

impl OrderbookStreamer {
    pub fn new(base: String, rel: String) -> Self { Self { base, rel } }

    pub fn derive_streamer_id(base: &str, rel: &str) -> String { format!("ORDERBOOK_UPDATE/{base}:{rel}") }
}

#[derive(Serialize)]
#[serde(tag = "order_type", content = "order_data")]
pub enum OrderbookItemChangeEvent {
    // NOTE(clippy): This is box-ed due to in-balance of the size of enum variants.
    /// New or updated orderbook item.
    NewOrUpdatedItem(Box<OrderbookP2PItem>),
    /// Removed orderbook item (only UUID is relevant in this case).
    RemovedItem(Uuid),
}

#[async_trait]
impl EventStreamer for OrderbookStreamer {
    type DataInType = OrderbookItemChangeEvent;

    fn streamer_id(&self) -> String { Self::derive_streamer_id(&self.base, &self.rel) }

    async fn handle(
        self,
        broadcaster: Broadcaster,
        ready_tx: oneshot::Sender<Result<(), String>>,
        mut data_rx: impl StreamHandlerInput<Self::DataInType>,
    ) {
        ready_tx
            .send(Ok(()))
            .expect("Receiver is dropped, which should never happen.");

        while let Some(orderbook_update) = data_rx.next().await {
            let event_data = serde_json::to_value(orderbook_update).expect("Serialization shouldn't fail.");
            let event = Event::new(self.streamer_id(), event_data);
            broadcaster.broadcast(event);
        }
    }
}
