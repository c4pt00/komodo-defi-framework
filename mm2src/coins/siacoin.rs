use super::{BalanceError, CoinBalance, CoinsContext, HistorySyncState, MarketCoinOps, MmCoin, RawTransactionFut,
            RawTransactionRequest, SwapOps, TradeFee, TransactionData, TransactionDetails, TransactionEnum,
            TransactionErr, TransactionFut, TransactionType};
use crate::siacoin::sia_withdraw::SiaWithdrawBuilder;
use crate::{coin_errors::MyAddressError, now_sec, BalanceFut, CanRefundHtlc, CheckIfMyPaymentSentArgs, CoinFutSpawner,
            ConfirmPaymentInput, DexFee, FeeApproxStage, FoundSwapTxSpend, MakerSwapTakerCoin,
            NegotiateSwapContractAddrErr, PaymentInstructionArgs, PaymentInstructions, PaymentInstructionsErr,
            PrivKeyBuildPolicy, PrivKeyPolicy, RefundPaymentArgs, RefundResult, SearchForSwapTxSpendInput,
            SendPaymentArgs, SignatureResult, SpendPaymentArgs, TakerSwapMakerCoin, TradePreimageFut,
            TradePreimageResult, TradePreimageValue, Transaction, TransactionResult, TxMarshalingErr,
            UnexpectedDerivationMethod, ValidateAddressResult, ValidateFeeArgs, ValidateInstructionsErr,
            ValidateOtherPubKeyErr, ValidatePaymentError, ValidatePaymentInput, ValidatePaymentResult,
            VerificationResult, WaitForHTLCTxSpendArgs, WatcherOps, WithdrawFut, WithdrawRequest};
use async_trait::async_trait;
use common::executor::abortable_queue::AbortableQueue;
use common::executor::{AbortableSystem, AbortedError, Timer};
use common::log::info;
use common::DEX_FEE_PUBKEY_ED25510;
use derive_more::{From, Into};
use futures::compat::Future01CompatExt;
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use hex;
use keys::KeyPair;
use mm2_core::mm_ctx::MmArc;
use mm2_number::num_bigint::ToBigInt;
use mm2_number::{BigDecimal, BigInt, MmNumber};
use num_traits::ToPrimitive;
use rpc::v1::types::{Bytes as BytesJson, H256 as H256Json};
use serde_json::Value as Json;
pub use sia_rust::transport::client::{ApiClient as SiaApiClient, ApiClientError as SiaApiClientError,
                                      ApiClientHelpers, ApiClientHelpersError};
pub use sia_rust::transport::endpoints::{AddressesEventsRequest, GetAddressUtxosRequest, GetEventRequest,
                                         TxpoolBroadcastRequest};
pub use sia_rust::types::{Address, Currency, Event, EventDataWrapper, EventPayout, EventType, Hash256,
                          Keypair as SiaKeypair, PrivateKeyError, PublicKey, PublicKeyError, SiacoinElement,
                          SiacoinOutput, SpendPolicy, V1Transaction, V2Transaction, V2TransactionBuilder};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

// TODO this is not well documented, and we should work toward removing this entire module.
// It serves no purpose if we follow thiserror patterns and uniformly use the Error trait.
use mm2_err_handle::prelude::*;

lazy_static! {
    pub static ref FEE_PUBLIC_KEY_BYTES: Vec<u8> =
        hex::decode(DEX_FEE_PUBKEY_ED25510).expect("DEX_FEE_PUBKEY_ED25510 is a valid hex string");
    pub static ref FEE_PUBLIC_KEY: PublicKey =
        PublicKey::from_bytes(&FEE_PUBLIC_KEY_BYTES).expect("DEX_FEE_PUBKEY_ED25510 is a valid PublicKey");
    pub static ref FEE_ADDR: Address = Address::from_public_key(&FEE_PUBLIC_KEY);
}

// TODO consider if this is the best way to handle wasm vs native
#[cfg(not(target_arch = "wasm32"))]
use sia_rust::transport::client::native::Conf as SiaClientConf;
#[cfg(not(target_arch = "wasm32"))]
use sia_rust::transport::client::native::NativeClient as SiaClientType;

#[cfg(target_arch = "wasm32")]
use sia_rust::transport::client::wasm::Client as SiaClientType;
#[cfg(target_arch = "wasm32")]
use sia_rust::transport::client::wasm::Conf as SiaClientConf;

pub mod sia_hd_wallet;
mod sia_withdraw;

// TODO see https://github.com/KomodoPlatform/komodo-defi-framework/pull/2086#discussion_r1521668313
// for additional fields needed
#[derive(Clone)]
pub struct SiaCoinGeneric<T: SiaApiClient + ApiClientHelpers> {
    /// SIA coin config
    pub conf: SiaCoinConf,
    pub priv_key_policy: Arc<PrivKeyPolicy<SiaKeypair>>,
    /// Client used to interact with the blockchain, most likely a HTTP(s) client
    pub client: Arc<T>,
    /// State of the transaction history loop (enabled, started, in progress, etc.)
    pub history_sync_state: Arc<Mutex<HistorySyncState>>,
    /// This abortable system is used to spawn coin's related futures that should be aborted on coin deactivation
    /// and on [`MmArc::stop`].
    pub abortable_system: Arc<AbortableQueue>,
    required_confirmations: Arc<AtomicU64>,
}

pub type SiaCoin = SiaCoinGeneric<SiaClientType>;

impl WatcherOps for SiaCoin {}

/// The JSON configuration loaded from `coins` file
#[derive(Clone, Debug, Deserialize)]
pub struct SiaCoinConf {
    #[serde(rename = "coin")]
    pub ticker: String,
    pub required_confirmations: u64,
}

// TODO see https://github.com/KomodoPlatform/komodo-defi-framework/pull/2086#discussion_r1521660384
// for additional fields needed
#[derive(Clone, Debug, Deserialize)]
pub struct SiaCoinActivationRequest {
    #[serde(default)]
    pub tx_history: bool,
    pub required_confirmations: Option<u64>,
    pub gap_limit: Option<u32>,
    pub client_conf: SiaClientConf,
}

pub async fn sia_coin_from_conf_and_request(
    ctx: &MmArc,
    json_conf: Json,
    request: &SiaCoinActivationRequest,
    priv_key_policy: PrivKeyBuildPolicy,
) -> Result<SiaCoin, MmError<SiaCoinError>> {
    let priv_key = match priv_key_policy {
        PrivKeyBuildPolicy::IguanaPrivKey(priv_key) => priv_key,
        _ => return Err(FrameworkError::UnsupportedPrivKeyPolicy.into()),
    };
    let key_pair = SiaKeypair::from_private_bytes(priv_key.as_slice()).map_err(SiaCoinError::InvalidPrivateKey)?;
    let conf: SiaCoinConf = serde_json::from_value(json_conf).map_err(SiaCoinError::InvalidConf)?;
    SiaCoinBuilder::new(ctx, conf, key_pair, request).build().await
}

pub struct SiaCoinBuilder<'a> {
    ctx: &'a MmArc,
    conf: SiaCoinConf,
    key_pair: SiaKeypair,
    request: &'a SiaCoinActivationRequest,
}

impl<'a> SiaCoinBuilder<'a> {
    pub fn new(ctx: &'a MmArc, conf: SiaCoinConf, key_pair: SiaKeypair, request: &'a SiaCoinActivationRequest) -> Self {
        SiaCoinBuilder {
            ctx,
            conf,
            key_pair,
            request,
        }
    }

    async fn build(self) -> MmResult<SiaCoin, SiaCoinError> {
        let abortable_queue: AbortableQueue = self
            .ctx
            .abortable_system
            .create_subsystem()
            .map_err(FrameworkError::AbortableSystem)?;
        let abortable_system = Arc::new(abortable_queue);
        let history_sync_state = if self.request.tx_history {
            HistorySyncState::NotStarted
        } else {
            HistorySyncState::NotEnabled
        };

        // Use required_confirmations from activation request if it's set, otherwise use the value from coins conf
        let required_confirmations: AtomicU64 = self
            .request
            .required_confirmations
            .unwrap_or(self.conf.required_confirmations)
            .into();

        Ok(SiaCoin {
            conf: self.conf,
            client: Arc::new(
                SiaClientType::new(self.request.client_conf.clone())
                    .await
                    .map_to_mm(SiaCoinError::ClientError)?,
            ),
            priv_key_policy: PrivKeyPolicy::Iguana(self.key_pair).into(),
            history_sync_state: Mutex::new(history_sync_state).into(),
            abortable_system,
            required_confirmations: required_confirmations.into(),
        })
    }
}

/// Convert hastings representation to "coin" amount
/// BigDecimal(1) == 1 SC == 10^24 hastings
/// 1 H == 0.000000000000000000000001 SC
fn hastings_to_siacoin(hastings: Currency) -> BigDecimal {
    let hastings: u128 = hastings.into();
    BigDecimal::new(BigInt::from(hastings), 24)
}

#[derive(Debug, Error)]
pub enum CoinToHastingsError {
    #[error("Sia Failed to convert BigDecimal:{0} to BigInt")]
    BigDecimalToBigInt(BigDecimal),
    #[error("Sia Failed to convert BigDecimal:{0} to u128")]
    BigIntToU128(BigDecimal),
}

/// Convert "coin" representation to hastings amount
/// BigDecimal(1) == 1 SC == 10^24 hastings
// it's not ideal that we require these standalone helpers, but a newtype of Currency is even messier
// TODO Alright - MmCoin trait should have an associated type "Currency" with a trait bound like
// "IsCurrency" implementing methods for conversion to and from BigDecimal/MmNumber
fn siacoin_to_hastings(siacoin: BigDecimal) -> Result<Currency, CoinToHastingsError> {
    // Shift the decimal place to the right by 24 places (10^24)
    let decimals = BigInt::from(10u128.pow(24));
    let hastings = siacoin.clone() * BigDecimal::from(decimals);
    hastings
        .to_bigint()
        .ok_or(CoinToHastingsError::BigDecimalToBigInt(siacoin.clone()))?
        .to_u128()
        .ok_or(CoinToHastingsError::BigIntToU128(siacoin))
        .map(|int| Currency(int))
}

#[derive(Debug, Error)]
pub enum SiaCoinError {
    #[error("Sia Invalid conf, JSON deserialization failed {}", _0)]
    InvalidConf(#[from] serde_json::Error),
    #[error("Sia Client Error: {}", _0)]
    ClientError(#[from] SiaApiClientError),
    #[error("Sia Client Helpers Error: {}", _0)]
    ClientHelpersError(#[from] ApiClientHelpersError),
    #[error("Sia Invalid Secret Key: {}", _0)]
    InvalidPrivateKey(#[from] PrivateKeyError),
    #[error("Sia Invalid Secret Key: {}", _0)]
    InvalidPublicKey(#[from] PublicKeyError),
    #[error("Sia Internal KDf error: {}", _0)]
    KdfError(#[from] FrameworkError),
}

impl NotMmError for SiaCoinError {}

#[derive(Debug, Error)]
pub enum FrameworkError {
    #[error("Sia Failed to create abortable system {}", _0)]
    AbortableSystem(AbortedError),
    #[error(
        "Sia select_outputs insufficent amount, available: {:?} required: {:?}",
        available,
        required
    )]
    SelectOutputsInsufficientAmount { available: Currency, required: Currency },
    #[error("Sia TransactionErr {:?}", _0)]
    MmTransactionErr(TransactionErr),
    #[error("Sia UnexpectedDerivationMethod {}", _0)]
    UnexpectedDerivationMethod(MmError<UnexpectedDerivationMethod>),
    #[error("Sia Invalid Private Key Policy, must use iguana seed")]
    UnsupportedPrivKeyPolicy,
    #[error("Sia MyAddressError: `{0}`")]
    MyAddressError(MyAddressError),
}

impl NotMmError for FrameworkError {}

// This is required because AbortedError doesn't impl Error
impl From<AbortedError> for FrameworkError {
    fn from(e: AbortedError) -> Self { FrameworkError::AbortableSystem(e) }
}

impl From<TransactionErr> for FrameworkError {
    fn from(e: TransactionErr) -> Self { FrameworkError::MmTransactionErr(e) }
}

impl From<MyAddressError> for FrameworkError {
    fn from(e: MyAddressError) -> Self { FrameworkError::MyAddressError(e) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiaCoinProtocolInfo;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum SiaFeePolicy {
    Fixed,
    HastingsPerByte(Currency),
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SiaFeeDetails {
    pub coin: String,
    pub policy: SiaFeePolicy,
    pub total_amount: BigDecimal,
}

#[async_trait]
impl MmCoin for SiaCoin {
    fn spawner(&self) -> CoinFutSpawner { CoinFutSpawner::new(&self.abortable_system) }

    fn get_raw_transaction(&self, _req: RawTransactionRequest) -> RawTransactionFut { unimplemented!() }

    fn get_tx_hex_by_hash(&self, _tx_hash: Vec<u8>) -> RawTransactionFut { unimplemented!() }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut {
        let coin = self.clone();
        let fut = async move {
            let builder = SiaWithdrawBuilder::new(&coin, req)?;
            builder.build().await
        };
        Box::new(fut.boxed().compat())
    }

    fn decimals(&self) -> u8 { 24 }

    fn convert_to_address(&self, _from: &str, _to_address_format: Json) -> Result<String, String> { unimplemented!() }

    fn validate_address(&self, address: &str) -> ValidateAddressResult {
        match Address::from_str(address) {
            Ok(_) => ValidateAddressResult {
                is_valid: true,
                reason: None,
            },
            Err(e) => ValidateAddressResult {
                is_valid: false,
                reason: Some(e.to_string()),
            },
        }
    }

    // Todo: deprecate this due to the use of attempts once tx_history_v2 is implemented
    fn process_history_loop(&self, ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        if self.history_sync_status() == HistorySyncState::NotEnabled {
            return Box::new(futures01::future::ok(()));
        }

        let mut my_balance: Option<CoinBalance> = None;
        let coin = self.clone();

        let fut = async move {
            let history = match coin.load_history_from_file(&ctx).compat().await {
                Ok(history) => history,
                Err(e) => {
                    log_tag!(
                        ctx,
                        "",
                        "tx_history",
                        "coin" => coin.conf.ticker;
                        fmt = "Error {} on 'load_history_from_file', stop the history loop", e
                    );
                    return;
                },
            };

            let mut history_map: HashMap<H256Json, TransactionDetails> = history
                .into_iter()
                .filter_map(|tx| {
                    let tx_hash = H256Json::from_str(tx.tx.tx_hash()?).ok()?;
                    Some((tx_hash, tx))
                })
                .collect();

            let mut success_iteration = 0i32;
            let mut attempts = 0;
            loop {
                if ctx.is_stopping() {
                    break;
                };
                {
                    let coins_ctx = CoinsContext::from_ctx(&ctx).unwrap();
                    let coins = coins_ctx.coins.lock().await;
                    if !coins.contains_key(&coin.conf.ticker) {
                        log_tag!(ctx, "", "tx_history", "coin" => coin.conf.ticker; fmt = "Loop stopped");
                        attempts += 1;
                        if attempts > 6 {
                            log_tag!(
                                ctx,
                                "",
                                "tx_history",
                                "coin" => coin.conf.ticker;
                                fmt = "Loop stopped after 6 attempts to find coin in coins context"
                            );
                            break;
                        }
                        Timer::sleep(10.).await;
                        continue;
                    };
                }

                let actual_balance = match coin.my_balance().compat().await {
                    Ok(actual_balance) => Some(actual_balance),
                    Err(err) => {
                        log_tag!(
                            ctx,
                            "",
                            "tx_history",
                            "coin" => coin.conf.ticker;
                            fmt = "Error {:?} on getting balance", err
                        );
                        None
                    },
                };

                let need_update = history_map.iter().any(|(_, tx)| tx.should_update());
                match (&my_balance, &actual_balance) {
                    (Some(prev_balance), Some(actual_balance)) if prev_balance == actual_balance && !need_update => {
                        // my balance hasn't been changed, there is no need to reload tx_history
                        Timer::sleep(30.).await;
                        continue;
                    },
                    _ => (),
                }

                // Todo: get mempool transactions and update them once they have confirmations
                let filtered_events: Vec<Event> = match coin.request_events_history().await {
                    Ok(events) => events
                        .into_iter()
                        .filter(|event| {
                            event.event_type == EventType::V2Transaction
                                || event.event_type == EventType::V1Transaction
                                || event.event_type == EventType::Miner
                                || event.event_type == EventType::Foundation
                        })
                        .collect(),
                    Err(e) => {
                        log_tag!(
                            ctx,
                            "",
                            "tx_history",
                            "coin" => coin.conf.ticker;
                            fmt = "Error {} on 'request_events_history', stop the history loop", e
                        );

                        Timer::sleep(10.).await;
                        continue;
                    },
                };

                // Remove transactions in the history_map that are not in the requested transaction list anymore
                let history_length = history_map.len();
                let requested_ids: HashSet<H256Json> = filtered_events.iter().map(|x| H256Json(x.id.0)).collect();
                history_map.retain(|hash, _| requested_ids.contains(hash));

                if history_map.len() < history_length {
                    let to_write: Vec<TransactionDetails> = history_map.values().cloned().collect();
                    if let Err(e) = coin.save_history_to_file(&ctx, to_write).compat().await {
                        log_tag!(
                            ctx,
                            "",
                            "tx_history",
                            "coin" => coin.conf.ticker;
                            fmt = "Error {} on 'save_history_to_file', stop the history loop", e
                        );
                        return;
                    };
                }

                let mut transactions_left = if requested_ids.len() > history_map.len() {
                    *coin.history_sync_state.lock().unwrap() = HistorySyncState::InProgress(json!({
                        "transactions_left": requested_ids.len() - history_map.len()
                    }));
                    requested_ids.len() - history_map.len()
                } else {
                    *coin.history_sync_state.lock().unwrap() = HistorySyncState::InProgress(json!({
                        "transactions_left": 0
                    }));
                    0
                };

                for txid in requested_ids {
                    let mut updated = false;
                    match history_map.entry(txid) {
                        Entry::Vacant(e) => match filtered_events.iter().find(|event| H256Json(event.id.0) == txid) {
                            Some(event) => {
                                let tx_details = match coin.tx_details_from_event(event) {
                                    Ok(tx_details) => tx_details,
                                    Err(e) => {
                                        log_tag!(
                                            ctx,
                                            "",
                                            "tx_history",
                                            "coin" => coin.conf.ticker;
                                            fmt = "Error {} on 'tx_details_from_event', stop the history loop", e
                                        );
                                        return;
                                    },
                                };
                                e.insert(tx_details);
                                if transactions_left > 0 {
                                    transactions_left -= 1;
                                    *coin.history_sync_state.lock().unwrap() =
                                        HistorySyncState::InProgress(json!({ "transactions_left": transactions_left }));
                                }
                                updated = true;
                            },
                            None => log_tag!(
                                ctx,
                                "",
                                "tx_history",
                                "coin" => coin.conf.ticker;
                                fmt = "Transaction with id {} not found in the events list", txid
                            ),
                        },
                        Entry::Occupied(_) => {},
                    }
                    if updated {
                        let to_write: Vec<TransactionDetails> = history_map.values().cloned().collect();
                        if let Err(e) = coin.save_history_to_file(&ctx, to_write).compat().await {
                            log_tag!(
                                ctx,
                                "",
                                "tx_history",
                                "coin" => coin.conf.ticker;
                                fmt = "Error {} on 'save_history_to_file', stop the history loop", e
                            );
                            return;
                        };
                    }
                }
                *coin.history_sync_state.lock().unwrap() = HistorySyncState::Finished;

                if success_iteration == 0 {
                    log_tag!(
                        ctx,
                        "😅",
                        "tx_history",
                        "coin" => coin.conf.ticker;
                        fmt = "history has been loaded successfully"
                    );
                }

                my_balance = actual_balance;
                success_iteration += 1;
                Timer::sleep(30.).await;
            }
        };

        Box::new(fut.map(|_| Ok(())).boxed().compat())
    }

    fn history_sync_status(&self) -> HistorySyncState { self.history_sync_state.lock().unwrap().clone() }

    /// Get fee to be paid per 1 swap transaction
    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> { unimplemented!() }

    // Todo: Implement this method when working on swaps
    async fn get_sender_trade_fee(
        &self,
        _value: TradePreimageValue,
        _stage: FeeApproxStage,
        _include_refund_fee: bool,
    ) -> TradePreimageResult<TradeFee> {
        Ok(TradeFee {
            coin: self.conf.ticker.clone(),
            amount: Default::default(),
            paid_from_trading_vol: false,
        })
    }

    /// Get the transaction fee required to spend the HTLC output
    // TODO Dummy value for now
    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        let ticker = self.conf.ticker.clone();
        let fut = async move {
            Ok(TradeFee {
                coin: ticker,
                amount: Default::default(),
                paid_from_trading_vol: false,
            })
        };
        Box::new(fut.boxed().compat())
    }

    async fn get_fee_to_send_taker_fee(
        &self,
        _dex_fee_amount: DexFee,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 { self.required_confirmations.load(AtomicOrdering::Relaxed) }

    fn requires_notarization(&self) -> bool { false }

    fn set_required_confirmations(&self, confirmations: u64) {
        self.required_confirmations
            .store(confirmations, AtomicOrdering::Relaxed);
    }

    fn set_requires_notarization(&self, _requires_nota: bool) { unimplemented!() }

    fn swap_contract_address(&self) -> Option<BytesJson> { unimplemented!() }

    fn fallback_swap_contract(&self) -> Option<BytesJson> { unimplemented!() }

    fn mature_confirmations(&self) -> Option<u32> { unimplemented!() }

    fn coin_protocol_info(&self, _amount_to_receive: Option<MmNumber>) -> Vec<u8> { Vec::new() }

    fn is_coin_protocol_supported(
        &self,
        _info: &Option<Vec<u8>>,
        _amount_to_send: Option<MmNumber>,
        _locktime: u64,
        _is_maker: bool,
    ) -> bool {
        true
    }

    fn on_disabled(&self) -> Result<(), AbortedError> { Ok(()) }

    fn on_token_deactivated(&self, _ticker: &str) {}
}

// TODO Alright - Dummy values for these functions allow minimal functionality to produce signatures
#[async_trait]
impl MarketCoinOps for SiaCoin {
    fn ticker(&self) -> &str { &self.conf.ticker }

    // needs test coverage FIXME COME BACK
    fn my_address(&self) -> MmResult<String, MyAddressError> {
        let key_pair = match &*self.priv_key_policy {
            PrivKeyPolicy::Iguana(key_pair) => key_pair,
            PrivKeyPolicy::Trezor => {
                return Err(MyAddressError::UnexpectedDerivationMethod(
                    "Trezor not yet supported. Must use iguana seed.".to_string(),
                )
                .into());
            },
            PrivKeyPolicy::HDWallet { .. } => {
                return Err(MyAddressError::UnexpectedDerivationMethod(
                    "HDWallet not yet supported. Must use iguana seed.".to_string(),
                )
                .into());
            },
            #[cfg(target_arch = "wasm32")]
            PrivKeyPolicy::Metamask(_) => {
                return Err(MyAddressError::UnexpectedDerivationMethod(
                    "Metamask not supported. Must use iguana seed.".to_string(),
                )
                .into());
            },
        };
        let address = key_pair.public().address();
        Ok(address.to_string())
    }

    async fn get_public_key(&self) -> Result<String, MmError<UnexpectedDerivationMethod>> {
        let public_key = match &*self.priv_key_policy {
            PrivKeyPolicy::Iguana(key_pair) => key_pair.public(),
            PrivKeyPolicy::Trezor => {
                return MmError::err(UnexpectedDerivationMethod::ExpectedSingleAddress);
            },
            PrivKeyPolicy::HDWallet { .. } => {
                return MmError::err(UnexpectedDerivationMethod::ExpectedSingleAddress);
            },
            #[cfg(target_arch = "wasm32")]
            PrivKeyPolicy::Metamask(_) => {
                return MmError::err(UnexpectedDerivationMethod::ExpectedSingleAddress);
            },
        };
        Ok(public_key.to_string())
    }

    fn sign_message_hash(&self, _message: &str) -> Option<[u8; 32]> { unimplemented!() }

    fn sign_message(&self, _message: &str) -> SignatureResult<String> { unimplemented!() }

    fn verify_message(&self, _signature: &str, _message: &str, _address: &str) -> VerificationResult<bool> {
        unimplemented!()
    }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let coin = self.clone();
        let fut = async move {
            let my_address = match &*coin.priv_key_policy {
                PrivKeyPolicy::Iguana(key_pair) => key_pair.public().address(),
                _ => {
                    return MmError::err(BalanceError::UnexpectedDerivationMethod(
                        UnexpectedDerivationMethod::ExpectedSingleAddress,
                    ))
                },
            };
            let balance = coin
                .client
                .address_balance(my_address)
                .await
                .map_to_mm(|e| BalanceError::Transport(e.to_string()))?;
            Ok(CoinBalance {
                spendable: hastings_to_siacoin(balance.siacoins),
                unspendable: hastings_to_siacoin(balance.immature_siacoins),
            })
        };
        Box::new(fut.boxed().compat())
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { Box::new(self.my_balance().map(|res| res.spendable)) }

    fn platform_ticker(&self) -> &str { "TSIA" }

    /// Receives raw transaction bytes in hexadecimal format as input and returns tx hash in hexadecimal format
    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        let client = self.client.clone();
        let tx = tx.to_owned();

        let fut = async move {
            let tx: Json = serde_json::from_str(&tx).map_err(|e| e.to_string())?;
            let transaction = serde_json::from_str::<V2Transaction>(&tx.to_string()).map_err(|e| e.to_string())?;
            let txid = transaction.txid().to_string();
            let request = TxpoolBroadcastRequest {
                transactions: vec![],
                v2transactions: vec![transaction],
            };

            client.dispatcher(request).await.map_err(|e| e.to_string())?;
            Ok(txid)
        };
        Box::new(fut.boxed().compat())
    }

    fn send_raw_tx_bytes(&self, _tx: &[u8]) -> Box<dyn Future<Item = String, Error = String> + Send> {
        unimplemented!()
    }

    fn wait_for_confirmations(&self, input: ConfirmPaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let tx: SiaTransaction = try_fus!(serde_json::from_slice(&input.payment_tx).map_err(|e| format!(
            "siacoin wait_for_confirmations payment_tx deser failed: {}",
            e
        )
        .to_string()));
        let txid = tx.txid();
        let client = self.client.clone();
        let tx_request = GetEventRequest { txid: txid.clone() };

        let fut = async move {
            loop {
                if now_sec() > input.wait_until {
                    return ERR!(
                        "Waited too long until {} for payment {} to be received",
                        input.wait_until,
                        tx.txid()
                    );
                }

                match client.dispatcher(tx_request.clone()).await {
                    Ok(event) => {
                        // if event.confirmations >= input.confirmations {
                        if event.index.height > 0 {
                            return Ok(()); // Transaction is confirmed at least once
                        }
                    },
                    Err(e) => info!("Waiting for confirmation of Sia txid {}: {}", txid, e),
                }
                // TODO Alright above is a placeholder to allow swaps to progress after 1 confirmation.
                // Sia team will add a "confirmations" field in GetEventResponse for us to use here.

                Timer::sleep(input.check_every as f64).await;
            }
        };

        Box::new(fut.boxed().compat())
    }

    fn wait_for_htlc_tx_spend(&self, _args: WaitForHTLCTxSpendArgs<'_>) -> TransactionFut { unimplemented!() }

    fn tx_enum_from_bytes(&self, _bytes: &[u8]) -> Result<TransactionEnum, MmError<TxMarshalingErr>> {
        MmError::err(TxMarshalingErr::NotSupported(
            "tx_enum_from_bytes is not supported for Sia coin yet.".to_string(),
        ))
    }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> {
        let client = self.client.clone(); // Clone the client

        let height_fut = async move { client.current_height().await.map_err(|e| e.to_string()) }
            .boxed() // Make the future 'static by boxing
            .compat(); // Convert to a futures 0.1-compatible future

        Box::new(height_fut)
    }

    fn display_priv_key(&self) -> Result<String, String> { unimplemented!() }

    // Todo: revise this when working on swaps
    fn min_tx_amount(&self) -> BigDecimal { hastings_to_siacoin(1u64.into()) }

    // TODO Alright: research a sensible value for this. It represents the minimum amount of coins that can be traded
    fn min_trading_vol(&self) -> MmNumber { hastings_to_siacoin(1u64.into()).into() }

    fn is_trezor(&self) -> bool { self.priv_key_policy.is_trezor() }
}

#[derive(Debug, Error)]
pub enum SendTakerFeeError {
    #[error("sia send_taker_fee: failed to parse uuid from bytes {}", _0)]
    ParseUuid(#[from] uuid::Error),
    #[error("sia send_taker_fee: Unexpected Uuid version {}", _0)]
    UuidVersion(usize),
    #[error("sia send_taker_fee: failed to convert trade_fee_amount to u128")]
    SiacoinToHastings(#[from] CoinToHastingsError),
    #[error("sia send_taker_fee: unexpected DexFee variant")]
    DexFeeVariant,
    #[error("sia send_taker_fee: siacoin internal error {}", _0)]
    SiaCoinInternal(#[from] SiaCoinError),
}

#[derive(Debug, Error)]
pub enum SendMakerFeeError {
    #[error("sia send_maker_payment failed to foo {}", _0)]
    Foo(bool),
}

// contains futures-0.3.x implementations of the SwapOps trait and various helpers
impl SiaCoin {
    fn my_keypair(&self) -> Result<&SiaKeypair, FrameworkError> {
        match &*self.priv_key_policy {
            PrivKeyPolicy::Iguana(keypair) => Ok(keypair),
            _ => Err(FrameworkError::UnsupportedPrivKeyPolicy),
        }
    }

    /// Create a new transaction to send the taker fee to the fee address
    // this was abtracted away from the SwapOps trait method to provide cleaner error handling
    // TODO Alright : refactor error types of SwapOps methods to use associated types
    async fn new_send_taker_fee(
        &self,
        _fee_addr: &[u8],
        dex_fee: DexFee,
        uuid: &[u8],
        _expire_at: u64,
    ) -> Result<TransactionEnum, SendTakerFeeError> {
        // Check the Uuid provided is valid v4 as we will encode it into the transaction
        let uuid_type_check = Uuid::from_slice(uuid).map_err(SendTakerFeeError::ParseUuid)?;

        match uuid_type_check.get_version_num() {
            4 => (),
            version => return Err(SendTakerFeeError::UuidVersion(version)),
        }

        // Convert the DexFee to a Currency amount
        let trade_fee_amount = if let DexFee::Standard(mm_num) = dex_fee {
            siacoin_to_hastings(BigDecimal::from(mm_num)).map_err(SendTakerFeeError::SiacoinToHastings)?
        } else {
            return Err(SendTakerFeeError::DexFeeVariant);
        };

        let my_keypair = self
            .my_keypair()
            .map_err(SiaCoinError::KdfError)
            .map_err(SendTakerFeeError::SiaCoinInternal)?;

        // Calculate the miner fee amount
        let tx_fee_amount = Currency::ZERO; // FIXME Alright: calculate tx fee amount after we know TX size

        // Create a new transaction builder
        let mut tx_builder = V2TransactionBuilder::new();

        // Add the trade fee output
        tx_builder.add_siacoin_output((FEE_ADDR.clone(), trade_fee_amount).into());

        // Fund the transaction
        self.client
            .fund_tx_single_source(&mut tx_builder, &my_keypair.public(), tx_fee_amount)
            .await
            .map_err(SiaCoinError::ClientHelpersError)
            .map_err(SendTakerFeeError::SiaCoinInternal)?;

        // FIXME Alright determine whether to embed uuid via `tx_builder.arbitary_data`

        // Sign inputs and finalize the transaction
        let tx = tx_builder.sign_simple(vec![my_keypair]).build();

        Ok(TransactionEnum::SiaTransaction(tx.into()))
    }
}

#[async_trait]
impl SwapOps for SiaCoin {
    /* TODO Alright - refactor SwapOps to use associated types for error handling
    TransactionErr is a very suboptimal structure for error handling, so we route to
    new_send_taker_fee to allow for cleaner code patterns. The error is then converted to a
    TransactionErr::Plain(String) for compatibility with the SwapOps trait
    This may lose verbosity such as the full error chain/trace. */
    async fn send_taker_fee(&self, fee_addr: &[u8], dex_fee: DexFee, uuid: &[u8], expire_at: u64) -> TransactionResult {
        self.new_send_taker_fee(fee_addr, dex_fee, uuid, expire_at)
            .await
            .map_err(|e| e.to_string().into())
    }

    async fn send_maker_payment(&self, _maker_payment_args: SendPaymentArgs<'_>) -> TransactionResult {
        unimplemented!()
    }

    async fn send_taker_payment(&self, _taker_payment_args: SendPaymentArgs<'_>) -> TransactionResult {
        unimplemented!()
    }

    async fn send_maker_spends_taker_payment(
        &self,
        _maker_spends_payment_args: SpendPaymentArgs<'_>,
    ) -> TransactionResult {
        unimplemented!()
    }

    async fn send_taker_spends_maker_payment(
        &self,
        _taker_spends_payment_args: SpendPaymentArgs<'_>,
    ) -> TransactionResult {
        unimplemented!()
    }

    async fn send_taker_refunds_payment(
        &self,
        _taker_refunds_payment_args: RefundPaymentArgs<'_>,
    ) -> TransactionResult {
        unimplemented!()
    }

    async fn send_maker_refunds_payment(
        &self,
        _maker_refunds_payment_args: RefundPaymentArgs<'_>,
    ) -> TransactionResult {
        unimplemented!()
    }

    async fn validate_fee(&self, _validate_fee_args: ValidateFeeArgs<'_>) -> ValidatePaymentResult<()> {
        unimplemented!()
    }

    async fn validate_maker_payment(&self, _input: ValidatePaymentInput) -> ValidatePaymentResult<()> {
        unimplemented!()
    }

    async fn validate_taker_payment(&self, _input: ValidatePaymentInput) -> ValidatePaymentResult<()> {
        unimplemented!()
    }

    async fn check_if_my_payment_sent(
        &self,
        _if_my_payment_sent_args: CheckIfMyPaymentSentArgs<'_>,
    ) -> Result<Option<TransactionEnum>, String> {
        unimplemented!()
    }

    async fn search_for_swap_tx_spend_my(
        &self,
        _: SearchForSwapTxSpendInput<'_>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    async fn search_for_swap_tx_spend_other(
        &self,
        _: SearchForSwapTxSpendInput<'_>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    fn check_tx_signed_by_pub(&self, _tx: &[u8], _expected_pub: &[u8]) -> Result<bool, MmError<ValidatePaymentError>> {
        unimplemented!();
    }

    async fn extract_secret(
        &self,
        _secret_hash: &[u8],
        _spend_tx: &[u8],
        _watcher_reward: bool,
    ) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn is_auto_refundable(&self) -> bool { false }

    async fn wait_for_htlc_refund(&self, _tx: &[u8], _locktime: u64) -> RefundResult<()> { unimplemented!() }

    fn negotiate_swap_contract_addr(
        &self,
        _other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        unimplemented!()
    }

    fn derive_htlc_key_pair(&self, _swap_unique_data: &[u8]) -> KeyPair { unimplemented!() }

    fn derive_htlc_pubkey(&self, _swap_unique_data: &[u8]) -> Vec<u8> { unimplemented!() }

    async fn can_refund_htlc(&self, _locktime: u64) -> Result<CanRefundHtlc, String> { unimplemented!() }

    fn validate_other_pubkey(&self, _raw_pubkey: &[u8]) -> MmResult<(), ValidateOtherPubKeyErr> { unimplemented!() }

    async fn maker_payment_instructions(
        &self,
        _args: PaymentInstructionArgs<'_>,
    ) -> Result<Option<Vec<u8>>, MmError<PaymentInstructionsErr>> {
        unimplemented!()
    }

    async fn taker_payment_instructions(
        &self,
        _args: PaymentInstructionArgs<'_>,
    ) -> Result<Option<Vec<u8>>, MmError<PaymentInstructionsErr>> {
        unimplemented!()
    }

    fn validate_maker_payment_instructions(
        &self,
        _instructions: &[u8],
        _args: PaymentInstructionArgs,
    ) -> Result<PaymentInstructions, MmError<ValidateInstructionsErr>> {
        unimplemented!()
    }

    fn validate_taker_payment_instructions(
        &self,
        _instructions: &[u8],
        _args: PaymentInstructionArgs,
    ) -> Result<PaymentInstructions, MmError<ValidateInstructionsErr>> {
        unimplemented!()
    }
}

#[async_trait]
impl TakerSwapMakerCoin for SiaCoin {
    async fn on_taker_payment_refund_start(&self, _maker_payment: &[u8]) -> RefundResult<()> { Ok(()) }

    async fn on_taker_payment_refund_success(&self, _maker_payment: &[u8]) -> RefundResult<()> { Ok(()) }
}

#[async_trait]
impl MakerSwapTakerCoin for SiaCoin {
    async fn on_maker_payment_refund_start(&self, _taker_payment: &[u8]) -> RefundResult<()> { Ok(()) }

    async fn on_maker_payment_refund_success(&self, _taker_payment: &[u8]) -> RefundResult<()> { Ok(()) }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, From, Into)]
#[serde(transparent)]
pub struct SiaTransaction(pub V2Transaction);

impl SiaTransaction {
    pub fn txid(&self) -> Hash256 { self.0.txid() }
}

impl Transaction for SiaTransaction {
    // serde should always be succesful but write an empty vec just in case.
    // FIXME Alright this trait should be refactored to return a Result for this method
    fn tx_hex(&self) -> Vec<u8> { serde_json::ser::to_vec(self).unwrap_or_default() }

    fn tx_hash_as_bytes(&self) -> BytesJson { BytesJson(self.txid().0.to_vec()) }
}

/// Represents the different types of transactions that can be sent to a wallet.
/// This enum is generally only useful for displaying wallet history.
/// We do not support any operations for any type other than V2Transaction, but we want the ability
/// to display other event types within the wallet history.
/// Use SiaTransaction type instead.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SiaTransactionTypes {
    V1Transaction(V1Transaction),
    V2Transaction(V2Transaction),
    EventPayout(EventPayout),
}

impl SiaCoin {
    async fn get_unspent_outputs(&self, address: Address) -> Result<Vec<SiacoinElement>, MmError<SiaApiClientError>> {
        let request = GetAddressUtxosRequest {
            address,
            limit: None,
            offset: None,
        };
        let res = self.client.dispatcher(request).await?;
        Ok(res)
    }

    async fn get_address_events(&self, address: Address) -> Result<Vec<Event>, MmError<SiaApiClientError>> {
        let request = AddressesEventsRequest {
            address,
            limit: None,
            offset: None,
        };
        let res = self.client.dispatcher(request).await?;
        Ok(res)
    }

    pub async fn request_events_history(&self) -> Result<Vec<Event>, MmError<String>> {
        let my_address = match &*self.priv_key_policy {
            PrivKeyPolicy::Iguana(key_pair) => key_pair.public().address(),
            _ => {
                return MmError::err(ERRL!("Unexpected derivation method. Expected single address."));
            },
        };

        let address_events = self.get_address_events(my_address).await.map_err(|e| e.to_string())?;

        Ok(address_events)
    }

    // TODO this was written prior to Currency arithmetic traits being added; refactor to use those
    fn tx_details_from_event(&self, event: &Event) -> Result<TransactionDetails, MmError<String>> {
        match &event.data {
            EventDataWrapper::V2Transaction(tx) => {
                let txid = tx.txid().to_string();

                let from: Vec<String> = tx
                    .siacoin_inputs
                    .iter()
                    .map(|input| input.parent.siacoin_output.address.to_string())
                    .collect();

                let to: Vec<String> = tx
                    .siacoin_outputs
                    .iter()
                    .map(|output| output.address.to_string())
                    .collect();

                let total_input: u128 = tx
                    .siacoin_inputs
                    .iter()
                    .map(|input| *input.parent.siacoin_output.value)
                    .sum();

                let total_output: u128 = tx.siacoin_outputs.iter().map(|output| *output.value).sum();

                let fee = total_input - total_output;

                let my_address = self.my_address().mm_err(|e| e.to_string())?;

                let spent_by_me: u128 = tx
                    .siacoin_inputs
                    .iter()
                    .filter(|input| input.parent.siacoin_output.address.to_string() == my_address)
                    .map(|input| *input.parent.siacoin_output.value)
                    .sum();

                let received_by_me: u128 = tx
                    .siacoin_outputs
                    .iter()
                    .filter(|output| output.address.to_string() == my_address)
                    .map(|output| *output.value)
                    .sum();

                let my_balance_change = hastings_to_siacoin(received_by_me.into()) - hastings_to_siacoin(spent_by_me.into());

                Ok(TransactionDetails {
                    tx: TransactionData::Sia {
                        tx_json: SiaTransactionTypes::V2Transaction(tx.clone()),
                        tx_hash: txid,
                    },
                    from,
                    to,
                    total_amount: hastings_to_siacoin(total_input.into()),
                    spent_by_me: hastings_to_siacoin(spent_by_me.into()),
                    received_by_me: hastings_to_siacoin(received_by_me.into()),
                    my_balance_change,
                    block_height: event.index.height,
                    timestamp: event.timestamp.timestamp() as u64,
                    fee_details: Some(
                        SiaFeeDetails {
                            coin: self.ticker().to_string(),
                            policy: SiaFeePolicy::Unknown,
                            total_amount: hastings_to_siacoin(fee.into()),
                        }
                        .into(),
                    ),
                    coin: self.ticker().to_string(),
                    internal_id: vec![].into(),
                    kmd_rewards: None,
                    transaction_type: TransactionType::SiaV2Transaction,
                    memo: None,
                })
            },
            EventDataWrapper::V1Transaction(tx) => {
                let txid = tx.transaction.txid().to_string();

                let from: Vec<String> = tx
                    .spent_siacoin_elements
                    .iter()
                    .map(|element| element.siacoin_output.address.to_string())
                    .collect();

                let to: Vec<String> = tx
                    .transaction
                    .siacoin_outputs
                    .iter()
                    .map(|output| output.address.to_string())
                    .collect();

                let total_input: u128 = tx
                    .spent_siacoin_elements
                    .iter()
                    .map(|element| *element.siacoin_output.value)
                    .sum();

                let total_output: u128 = tx.transaction.siacoin_outputs.iter().map(|output| *output.value).sum();

                let fee = total_input - total_output;

                let my_address = self.my_address().mm_err(|e| e.to_string())?;

                let spent_by_me: u128 = tx
                    .spent_siacoin_elements
                    .iter()
                    .filter(|element| element.siacoin_output.address.to_string() == my_address)
                    .map(|element| *element.siacoin_output.value)
                    .sum();

                let received_by_me: u128 = tx
                    .transaction
                    .siacoin_outputs
                    .iter()
                    .filter(|output| output.address.to_string() == my_address)
                    .map(|output| *output.value)
                    .sum();

                let my_balance_change = hastings_to_siacoin(received_by_me.into()) - hastings_to_siacoin(spent_by_me.into());

                Ok(TransactionDetails {
                    tx: TransactionData::Sia {
                        tx_json: SiaTransactionTypes::V1Transaction(tx.transaction.clone()),
                        tx_hash: txid,
                    },
                    from,
                    to,
                    total_amount: hastings_to_siacoin(total_input.into()),
                    spent_by_me: hastings_to_siacoin(spent_by_me.into()),
                    received_by_me: hastings_to_siacoin(received_by_me.into()),
                    my_balance_change,
                    block_height: event.index.height,
                    timestamp: event.timestamp.timestamp() as u64,
                    fee_details: Some(
                        SiaFeeDetails {
                            coin: self.ticker().to_string(),
                            policy: SiaFeePolicy::Unknown,
                            total_amount: hastings_to_siacoin(fee.into()),
                        }
                        .into(),
                    ),
                    coin: self.ticker().to_string(),
                    internal_id: vec![].into(),
                    kmd_rewards: None,
                    transaction_type: TransactionType::SiaV1Transaction,
                    memo: None,
                })
            },
            EventDataWrapper::MinerPayout(event_payout) | EventDataWrapper::FoundationPayout(event_payout) => {
                let txid = event_payout.siacoin_element.state_element.id.to_string();

                let from: Vec<String> = vec![];

                let to: Vec<String> = vec![event_payout.siacoin_element.siacoin_output.address.to_string()];

                let total_output: u128 = event_payout.siacoin_element.siacoin_output.value.0;

                let my_address = self.my_address().mm_err(|e| e.to_string())?;

                let received_by_me: u128 =
                    if event_payout.siacoin_element.siacoin_output.address.to_string() == my_address {
                        total_output
                    } else {
                        0
                    };

                let my_balance_change = hastings_to_siacoin(received_by_me.into());

                Ok(TransactionDetails {
                    tx: TransactionData::Sia {
                        tx_json: SiaTransactionTypes::EventPayout(event_payout.clone()),
                        tx_hash: txid,
                    },
                    from,
                    to,
                    total_amount: hastings_to_siacoin(total_output.into()),
                    spent_by_me: BigDecimal::from(0),
                    received_by_me: hastings_to_siacoin(received_by_me.into()),
                    my_balance_change,
                    block_height: event.index.height,
                    timestamp: event.timestamp.timestamp() as u64,
                    fee_details: None,
                    coin: self.ticker().to_string(),
                    internal_id: vec![].into(),
                    kmd_rewards: None,
                    transaction_type: TransactionType::SiaMinerPayout,
                    memo: None,
                })
            },
            EventDataWrapper::ClaimPayout(_) // TODO this can be moved to the above case with Miner and Foundation payouts
            | EventDataWrapper::V2FileContractResolution(_)
            | EventDataWrapper::EventV1ContractResolution(_) => MmError::err(ERRL!("Unsupported event type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm2_number::BigDecimal;
    use std::str::FromStr;

    fn valid_transaction() -> SiaTransaction {
        let j = json!(
            {
                "siacoinInputs": [
                    {
                        "parent": {
                            "id": "h:f59e395dc5cbe3217ee80eff60585ffc9802e7ca580d55297782d4a9b4e08589",
                            "leafIndex": 3,
                            "merkleProof": [
                                "h:ab0e1726444c50e2c0f7325eb65e5bd262a97aad2647d2816c39d97958d9588a",
                                "h:467e2be4d8482eca1f99440b6efd531ab556d10a8371a98a05b00cb284620cf0",
                                "h:64d5766fce1ff78a13a4a4744795ad49a8f8d187c01f9f46544810049643a74a",
                                "h:31d5151875152bc25d1df18ca6bbda1bef5b351e8d53c277791ecf416fcbb8a8",
                                "h:12a92a1ba87c7b38f3c4e264c399abfa28fb46274cfa429605a6409bd6d0a779",
                                "h:eda1d58a9282dbf6c3f1beb4d6c7bdc036d14a1cfee8ab1e94fabefa9bd63865",
                                "h:e03dee6e27220386c906f19fec711647353a5f6d76633a191cbc2f6dce239e89",
                                "h:e70fcf0129c500f7afb49f4f2bb82950462e952b7cdebb2ad0aa1561dc6ea8eb"
                            ],
                            "siacoinOutput": {
                                "value": "300000000000000000000000000000",
                                "address": "addr:f7843ac265b037658b304468013da4fd0f304a1b73df0dc68c4273c867bfa38d01a7661a187f"
                            },
                            "maturityHeight": 145
                        },
                        "satisfiedPolicy": {
                            "policy": {
                                "type": "uc",
                                "policy": {
                                    "timelock": 0,
                                    "publicKeys": [
                                        "ed25519:cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc"
                                    ],
                                    "signaturesRequired": 1
                                }
                            },
                            "signatures": [
                                "sig:f0a29ba576eb0dbc3438877ac1d3a6da4f3c4cbafd9030709c8a83c2fffa64f4dd080d37444261f023af3bd7a10a9597c33616267d5371bf2c0ade5e25e61903"
                            ]
                        }
                    }
                ],
                "siacoinOutputs": [
                    {
                        "value": "1000000000000000000000000000",
                        "address": "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
                    },
                    {
                        "value": "299000000000000000000000000000",
                        "address": "addr:f7843ac265b037658b304468013da4fd0f304a1b73df0dc68c4273c867bfa38d01a7661a187f"
                    }
                ],
                "minerFee": "0"
            }
        );
        let tx = serde_json::from_value::<V2Transaction>(j).unwrap();
        SiaTransaction(tx)
    }

    #[test]
    fn test_siacoin_from_hastings_u128_max() {
        let hastings = u128::MAX;
        let siacoin = hastings_to_siacoin(hastings.into());
        assert_eq!(
            siacoin,
            BigDecimal::from_str("340282366920938.463463374607431768211455").unwrap()
        );
    }

    #[test]
    fn test_siacoin_from_hastings_total_supply() {
        // Total supply of Siacoin
        let hastings = 57769875000000000000000000000000000u128;
        let siacoin = hastings_to_siacoin(hastings.into());
        assert_eq!(siacoin, BigDecimal::from_str("57769875000").unwrap());
    }

    #[test]
    fn test_siacoin_to_hastings_supply() {
        // Total supply of Siacoin
        let siacoin = BigDecimal::from_str("57769875000").unwrap();
        let hastings = siacoin_to_hastings(siacoin).unwrap();
        assert_eq!(hastings, Currency(57769875000000000000000000000000000));
    }

    #[test]
    fn test_sia_transaction_serde_roundtrip() {
        let tx = valid_transaction();

        let vec = serde_json::ser::to_vec(&tx).unwrap();
        let tx2: SiaTransaction = serde_json::from_slice(&vec).unwrap();

        assert_eq!(tx, tx2);
    }

    /// Test the .expect()s used during lazy_static initialization of FEE_PUBLIC_KEY
    #[test]
    fn test_sia_fee_pubkey_init() {
        let pubkey_bytes: Vec<u8> = hex::decode(DEX_FEE_PUBKEY_ED25510).unwrap();
        let pubkey = PublicKey::from_bytes(&FEE_PUBLIC_KEY_BYTES).unwrap();
        assert_eq!(pubkey_bytes, *FEE_PUBLIC_KEY_BYTES);
        assert_eq!(pubkey, *FEE_PUBLIC_KEY);
    }

    #[test]
    fn test_siacoin_from_hastings_coin() {
        let coin = hastings_to_siacoin(Currency::COIN);
        assert_eq!(coin, BigDecimal::from(1));
    }

    #[test]
    fn test_siacoin_from_hastings_zero() {
        let coin = hastings_to_siacoin(Currency::ZERO);
        assert_eq!(coin, BigDecimal::from(0));
    }

    #[test]
    fn test_siacoin_to_hastings_coin() {
        let coin = BigDecimal::from(1);
        let hastings = siacoin_to_hastings(coin).unwrap();
        assert_eq!(hastings, Currency::COIN.into());
    }

    #[test]
    fn test_siacoin_to_hastings_zero() {
        let coin = BigDecimal::from(0);
        let hastings = siacoin_to_hastings(coin).unwrap();
        assert_eq!(hastings, Currency::ZERO.into());
    }

    #[test]
    fn test_siacoin_to_hastings_one() {
        let coin = serde_json::from_str::<BigDecimal>("0.000000000000000000000001").unwrap();
        println!("coin {:?}", coin);
        let hastings = siacoin_to_hastings(coin).unwrap();
        assert_eq!(hastings, Currency(1).into());
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use common::log::info;
    use common::log::wasm_log::register_wasm_log;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use url::Url;

    wasm_bindgen_test_configure!(run_in_browser);

    async fn init_client() -> SiaClientType {
        let conf = SiaClientConf {
            server_url: Url::parse("https://sia-walletd.komodo.earth/").unwrap(),
            headers: HashMap::new(),
        };
        SiaClientType::new(conf).await.unwrap()
    }

    #[wasm_bindgen_test]
    async fn test_endpoint_txpool_broadcast() {
        register_wasm_log();

        use sia_rust::transaction::V2Transaction;

        let client = init_client().await;

        let tx = serde_json::from_str::<V2Transaction>(
            r#"
            {
                "siacoinInputs": [
                    {
                        "parent": {
                            "id": "h:27248ab562cbbee260e07ccae87c74aae71c9358d7f91eee25837e2011ce36d3",
                            "leafIndex": 21867,
                            "merkleProof": [
                                "h:ac2fdcbed40f103e54b0b1a37c20a865f6f1f765950bc6ac358ff3a0e769da50",
                                "h:b25570eb5c106619d4eef5ad62482023df7a1c7461e9559248cb82659ebab069",
                                "h:baa78ec23a169d4e9d7f801e5cf25926bf8c29e939e0e94ba065b43941eb0af8",
                                "h:239857343f2997462bed6c253806cf578d252dbbfd5b662c203e5f75d897886d",
                                "h:ad727ef2112dc738a72644703177f730c634a0a00e0b405bd240b0da6cdfbc1c",
                                "h:4cfe0579eabafa25e98d83c3b5d07ae3835ce3ea176072064ea2b3be689e99aa",
                                "h:736af73aa1338f3bc28d1d8d3cf4f4d0393f15c3b005670f762709b6231951fc"
                            ],
                            "siacoinOutput": {
                                "value": "772999980000000000000000000",
                                "address": "addr:1599ea80d9af168ce823e58448fad305eac2faf260f7f0b56481c5ef18f0961057bf17030fb3"
                            },
                            "maturityHeight": 0
                        },
                        "satisfiedPolicy": {
                            "policy": {
                                "type": "pk",
                                "policy": "ed25519:968e286ef5df3954b7189c53a0b4b3d827664357ebc85d590299b199af46abad"
                            },
                            "signatures": [
                                "sig:7a2c332fef3958a0486ef5e55b70d2a68514ff46d9307a85c3c0e40b76a19eebf4371ab3dd38a668cefe94dbedff2c50cc67856fbf42dce2194b380e536c1500"
                            ]
                        }
                    }
                ],
                "siacoinOutputs": [
                    {
                        "value": "2000000000000000000000000",
                        "address": "addr:1d9a926b1e14b54242375c7899a60de883c8cad0a45a49a7ca2fdb6eb52f0f01dfe678918204"
                    },
                    {
                        "value": "770999970000000000000000000",
                        "address": "addr:1599ea80d9af168ce823e58448fad305eac2faf260f7f0b56481c5ef18f0961057bf17030fb3"
                    }
                ],
                "minerFee": "10000000000000000000"
            }
            "#).unwrap();

        let request = TxpoolBroadcastRequest {
            transactions: vec![],
            v2transactions: vec![tx],
        };
        let resp = client.dispatcher(request).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_helper_address_balance() {
        register_wasm_log();
        use sia_rust::http::endpoints::AddressBalanceRequest;
        use sia_rust::types::Address;

        let client = init_client().await;

        client
            .address_balance(
                Address::from_str("addr:1599ea80d9af168ce823e58448fad305eac2faf260f7f0b56481c5ef18f0961057bf17030fb3")
                    .unwrap(),
            )
            .await
            .unwrap();
    }
}
