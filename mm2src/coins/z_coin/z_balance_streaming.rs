use crate::common::Future01CompatExt;
use crate::streaming_events_config::{BalanceEventConfig, EmptySubConfig};
use crate::z_coin::ZCoin;
use crate::MarketCoinOps;

use async_trait::async_trait;
use common::log::error;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::channel::oneshot;
use futures::lock::Mutex as AsyncMutex;
use futures_util::StreamExt;
use mm2_event_stream::{Controller, Event, EventStreamer, StreamHandlerInput};
use serde_json::Value as Json;
use std::sync::Arc;

pub type ZBalanceEventSender = UnboundedSender<()>;
pub type ZBalanceEventHandler = Arc<AsyncMutex<UnboundedReceiver<()>>>;

pub struct ZCoinBalanceEventStreamer {
    /// Whether the event is enabled for this coin.
    enabled: bool,
    coin: ZCoin,
}

impl ZCoinBalanceEventStreamer {
    pub fn try_new(config: Json, coin: ZCoin) -> serde_json::Result<Self> {
        let config: BalanceEventConfig = serde_json::from_value(config)?;
        let enabled = match config.find_coin(coin.ticker()) {
            // This is just an extra check to make sure the config is correct (no config)
            Some(c) => serde_json::from_value::<EmptySubConfig>(c).map(|_| true)?,
            None => false,
        };
        Ok(Self { enabled, coin })
    }
}

#[async_trait]
impl EventStreamer for ZCoinBalanceEventStreamer {
    type DataInType = ();

    fn streamer_id(&self) -> String { format!("BALANCE:{}", self.coin.ticker()) }

    async fn handle(
        self,
        broadcaster: Controller<Event>,
        ready_tx: oneshot::Sender<Result<(), String>>,
        mut data_rx: impl StreamHandlerInput<()>,
    ) {
        let streamer_id = self.streamer_id();
        let coin = self.coin;

        ready_tx
            .send(Ok(()))
            .expect("Receiver is dropped, which should never happen.");

        // Iterates through received events, and updates balance changes accordingly.
        while (data_rx.next().await).is_some() {
            match coin.my_balance().compat().await {
                Ok(balance) => {
                    let payload = json!({
                        "ticker": coin.ticker(),
                        "address": coin.my_z_address_encoded(),
                        "balance": { "spendable": balance.spendable, "unspendable": balance.unspendable }
                    });

                    broadcaster
                        .broadcast(Event::new(streamer_id.clone(), payload, None))
                        .await;
                },
                Err(err) => {
                    let ticker = coin.ticker();
                    error!("Failed getting balance for '{ticker}'. Error: {err}");
                    let e = serde_json::to_value(err).expect("Serialization should't fail.");
                    return broadcaster.broadcast(Event::err(streamer_id.clone(), e, None)).await;
                },
            };
        }
    }
}
