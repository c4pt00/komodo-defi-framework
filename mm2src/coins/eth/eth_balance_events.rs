use async_trait::async_trait;
use common::{executor::{AbortSettings, SpawnAbortable, Timer},
             log};
use futures::channel::oneshot::{self, Receiver, Sender};
use futures_util::StreamExt;
use mm2_core::mm_ctx::MmArc;
use mm2_event_stream::{behaviour::{EventBehaviour, EventInitStatus},
                       EventStreamConfiguration};

use super::EthCoin;
use crate::MmCoin;

#[async_trait]
impl EventBehaviour for EthCoin {
    const EVENT_NAME: &'static str = "COIN_BALANCE";

    async fn handle(self, interval: f64, tx: oneshot::Sender<EventInitStatus>) {
        const RECEIVER_DROPPED_MSG: &str = "Receiver is dropped, which should never happen.";

        // TODO
        async fn with_socket() {}
        async fn with_polling() {}

        let ctx = match MmArc::from_weak(&self.ctx) {
            Some(ctx) => ctx,
            None => {
                let msg = "MM context must have been initialized already.";
                tx.send(EventInitStatus::Failed(msg.to_owned()))
                    .expect(RECEIVER_DROPPED_MSG);
                panic!("{}", msg);
            },
        };
    }

    async fn spawn_if_active(self, config: &EventStreamConfiguration) -> EventInitStatus {
        if let Some(event) = config.get_event(Self::EVENT_NAME) {
            log::info!("{} event is activated for {}", Self::EVENT_NAME, self.ticker,);

            let (tx, rx): (Sender<EventInitStatus>, Receiver<EventInitStatus>) = oneshot::channel();
            let fut = self.clone().handle(event.stream_interval_seconds, tx);
            let settings =
                AbortSettings::info_on_abort(format!("{} event is stopped for {}.", Self::EVENT_NAME, self.ticker));
            self.spawner().spawn_with_settings(fut, settings);

            rx.await.unwrap_or_else(|e| {
                EventInitStatus::Failed(format!("Event initialization status must be received: {}", e))
            })
        } else {
            EventInitStatus::Inactive
        }
    }
}
