use async_trait::async_trait;
use common::{executor::{AbortSettings, SpawnAbortable, Timer},
             log, Future01CompatExt};
use ethereum_types::Address;
use futures::channel::oneshot::{self, Receiver, Sender};
use futures_util::StreamExt;
use mm2_core::mm_ctx::MmArc;
use mm2_event_stream::{behaviour::{EventBehaviour, EventInitStatus},
                       EventStreamConfiguration};
use mm2_number::BigDecimal;

use super::EthCoin;
use crate::{eth::u256_to_big_decimal, MmCoin};

/// Type map for list of (ticker, address, decimals) values
type AddressList = Vec<(String, Address, u8)>;

#[async_trait]
impl EventBehaviour for EthCoin {
    const EVENT_NAME: &'static str = "COIN_BALANCE";

    async fn handle(self, interval: f64, tx: oneshot::Sender<EventInitStatus>) {
        const RECEIVER_DROPPED_MSG: &str = "Receiver is dropped, which should never happen.";

        async fn with_socket(_coin: EthCoin, _ctx: MmArc) { todo!() }

        async fn with_polling(coin: EthCoin, ctx: MmArc, interval: f64) {
            loop {
                // TODO:
                // Do not re-compute this over and over
                let mut addresses_info: AddressList = coin
                    .get_erc_tokens_infos()
                    .into_iter()
                    .map(|(ticker, info)| (ticker, info.token_address, info.decimals))
                    .collect();

                addresses_info.push((coin.ticker.clone(), coin.my_address, coin.decimals));

                for (ticker, address, decimals) in addresses_info {
                    let balance = coin.address_balance(address).compat().await.unwrap();
                    let balance = u256_to_big_decimal(balance, decimals).unwrap();

                    let _ = json!({
                        "ticker": ticker,
                        "balance": { "spendable": balance, "unspendable": BigDecimal::default() }
                    });
                }

                // TODO: subtract the time complexity
                Timer::sleep(interval).await;
            }
        }

        let ctx = match MmArc::from_weak(&self.ctx) {
            Some(ctx) => ctx,
            None => {
                let msg = "MM context must have been initialized already.";
                tx.send(EventInitStatus::Failed(msg.to_owned()))
                    .expect(RECEIVER_DROPPED_MSG);
                panic!("{}", msg);
            },
        };

        with_polling(self, ctx, interval).await
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
