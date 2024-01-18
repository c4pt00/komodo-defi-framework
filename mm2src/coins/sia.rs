use super::{CoinBalance, HistorySyncState, MarketCoinOps, MmCoin, RawTransactionFut, RawTransactionRequest, SwapOps,
            TradeFee, TransactionEnum, TransactionFut};
use crate::{coin_errors::MyAddressError, BalanceFut, CanRefundHtlc, CheckIfMyPaymentSentArgs, CoinFutSpawner,
            ConfirmPaymentInput, FeeApproxStage, FoundSwapTxSpend, MakerSwapTakerCoin, MmCoinEnum,
            NegotiateSwapContractAddrErr, PaymentInstructionArgs, PaymentInstructions, PaymentInstructionsErr,
            RawTransactionResult, RefundPaymentArgs, RefundResult, SearchForSwapTxSpendInput,
            SendMakerPaymentSpendPreimageInput, SendPaymentArgs, SignRawTransactionRequest, SignatureResult,
            SpendPaymentArgs, TakerSwapMakerCoin, TradePreimageFut, TradePreimageResult, TradePreimageValue,
            TransactionResult, TxMarshalingErr, UnexpectedDerivationMethod, ValidateAddressResult, ValidateFeeArgs,
            ValidateInstructionsErr, ValidateOtherPubKeyErr, ValidatePaymentError, ValidatePaymentFut,
            ValidatePaymentInput, VerificationResult, WaitForHTLCTxSpendArgs, WatcherOps, WatcherReward,
            WatcherRewardError, WatcherSearchForSwapTxSpendInput, WatcherValidatePaymentInput,
            WatcherValidateTakerFeeInput, WithdrawFut, WithdrawRequest};
use crate::{DexFee, ValidateWatcherSpendInput};
use async_trait::async_trait;
use common::executor::AbortedError;
use futures01::Future;
use keys::KeyPair;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use mm2_number::{BigDecimal, MmNumber};
use rpc::v1::types::Bytes as BytesJson;
use serde_json::Value as Json;
use std::ops::Deref;
use std::sync::Arc;

use mm2_core::mm_ctx::MmWeak;

#[derive(Clone)]
pub struct SiaCoin(SiaArc);
#[derive(Clone)]
pub struct SiaArc(Arc<SiaCoinFields>);

pub struct SiaCoinConf {
    ticker: String,
}

pub enum SiaRpcClientEnum {
    Native,
    Lite,
}

pub struct SiaCoinFields {
    /// SIA coin config
    pub conf: SiaCoinConf,
    /// Minimum transaction value at which the value is not less than fee
    pub dust_amount: u64,
    /// RPC client
    pub rpc_client: SiaRpcClientEnum,
    pub(crate) ctx: MmWeak,
}

pub async fn sia_coin_wo_policy(ctx: &MmArc, ticker: &str) -> Result<SiaCoin, String> {
    let coin = try_s!(SiaCoinBuilder::new(ctx, ticker).build().await);
    Ok(coin)
}
pub struct SiaCoinBuilder<'a> {
    ctx: &'a MmArc,
    ticker: &'a str,
}

impl<'a> SiaCoinBuilder<'a> {
    pub fn new(ctx: &'a MmArc, ticker: &'a str) -> Self { SiaCoinBuilder { ctx, ticker } }
}

#[derive(Debug, Display)]
struct SiaCoinBuildError;

impl<'a> SiaCoinBuilder<'a> {
    fn ctx(&self) -> &MmArc { self.ctx }

    async fn build(self) -> MmResult<SiaCoin, SiaCoinBuildError> {
        let sia_fields = SiaCoinFields {
            conf: SiaCoinConf {
                ticker: "FIXME".to_string(), // FIXME Alright
            },
            dust_amount: 0,
            rpc_client: SiaRpcClientEnum::Lite,
            ctx: self.ctx().weak(),
        };
        let sia_arc = SiaArc::new(sia_fields);

        Ok(SiaCoin::from(sia_arc))
    }
}

impl Deref for SiaArc {
    type Target = SiaCoinFields;
    fn deref(&self) -> &SiaCoinFields { &self.0 }
}

impl From<SiaCoinFields> for SiaArc {
    fn from(coin: SiaCoinFields) -> SiaArc { SiaArc::new(coin) }
}

impl From<Arc<SiaCoinFields>> for SiaArc {
    fn from(arc: Arc<SiaCoinFields>) -> SiaArc { SiaArc(arc) }
}

impl From<SiaArc> for SiaCoin {
    fn from(coin: SiaArc) -> SiaCoin { SiaCoin(coin) }
}

impl SiaArc {
    pub fn new(fields: SiaCoinFields) -> SiaArc { SiaArc(Arc::new(fields)) }

    pub fn with_arc(inner: Arc<SiaCoinFields>) -> SiaArc { SiaArc(inner) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiaCoinProtocolInfo {}

#[derive(Debug)]
pub struct SiaCoinImpl {
    pub ticker: String,
}

#[async_trait]
impl MmCoin for SiaCoin {
    fn is_asset_chain(&self) -> bool { unimplemented!() }

    fn spawner(&self) -> CoinFutSpawner { unimplemented!() }

    fn get_raw_transaction(&self, _req: RawTransactionRequest) -> RawTransactionFut { unimplemented!() }

    fn get_tx_hex_by_hash(&self, tx_hash: Vec<u8>) -> RawTransactionFut { unimplemented!() }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut { unimplemented!() }

    fn decimals(&self) -> u8 { unimplemented!() }

    fn convert_to_address(&self, from: &str, to_address_format: Json) -> Result<String, String> { unimplemented!() }

    fn validate_address(&self, address: &str) -> ValidateAddressResult { unimplemented!() }

    fn process_history_loop(&self, ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> { unimplemented!() }

    fn history_sync_status(&self) -> HistorySyncState { unimplemented!() }

    /// Get fee to be paid per 1 swap transaction
    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> { unimplemented!() }

    async fn get_sender_trade_fee(
        &self,
        _value: TradePreimageValue,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> { unimplemented!() }

    async fn get_fee_to_send_taker_fee(
        &self,
        _dex_fee_amount: DexFee,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 { 1 }

    fn requires_notarization(&self) -> bool { false }

    fn set_required_confirmations(&self, _confirmations: u64) { unimplemented!() }

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

    fn on_token_deactivated(&self, _ticker: &str) { () }
}

#[async_trait]
impl MarketCoinOps for SiaCoin {
    fn ticker(&self) -> &str { &self.0.conf.ticker }

    fn my_address(&self) -> MmResult<String, MyAddressError> { unimplemented!() }

    fn get_public_key(&self) -> Result<String, MmError<UnexpectedDerivationMethod>> { unimplemented!() }

    fn sign_message_hash(&self, _message: &str) -> Option<[u8; 32]> { unimplemented!() }

    fn sign_message(&self, _message: &str) -> SignatureResult<String> { unimplemented!() }

    fn verify_message(&self, _signature: &str, _message: &str, _address: &str) -> VerificationResult<bool> {
        unimplemented!()
    }

    fn my_balance(&self) -> BalanceFut<CoinBalance> { unimplemented!() }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { unimplemented!() }

    fn platform_ticker(&self) -> &str { "SIA" }

    /// Receives raw transaction bytes in hexadecimal format as input and returns tx hash in hexadecimal format
    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> { unimplemented!() }

    fn send_raw_tx_bytes(&self, tx: &[u8]) -> Box<dyn Future<Item = String, Error = String> + Send> { unimplemented!() }

    #[inline(always)]
    async fn sign_raw_tx(&self, _args: &SignRawTransactionRequest) -> RawTransactionResult { unimplemented!() }

    fn wait_for_confirmations(&self, _input: ConfirmPaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn wait_for_htlc_tx_spend(&self, args: WaitForHTLCTxSpendArgs<'_>) -> TransactionFut { unimplemented!() }

    fn tx_enum_from_bytes(&self, _bytes: &[u8]) -> Result<TransactionEnum, MmError<TxMarshalingErr>> {
        MmError::err(TxMarshalingErr::NotSupported(
            "tx_enum_from_bytes is not supported for Test coin yet.".to_string(),
        ))
    }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> { unimplemented!() }

    fn display_priv_key(&self) -> Result<String, String> { unimplemented!() }

    fn min_tx_amount(&self) -> BigDecimal { Default::default() }

    fn min_trading_vol(&self) -> MmNumber { MmNumber::from("0.00777") }
}

#[async_trait]
impl SwapOps for SiaCoin {
    fn send_taker_fee(&self, fee_addr: &[u8], dex_fee: DexFee, uuid: &[u8]) -> TransactionFut { unimplemented!() }

    fn send_maker_payment(&self, _maker_payment_args: SendPaymentArgs) -> TransactionFut { unimplemented!() }

    fn send_taker_payment(&self, _taker_payment_args: SendPaymentArgs) -> TransactionFut { unimplemented!() }

    fn send_maker_spends_taker_payment(&self, _maker_spends_payment_args: SpendPaymentArgs) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_spends_maker_payment(&self, _taker_spends_payment_args: SpendPaymentArgs) -> TransactionFut {
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

    fn validate_fee(&self, _validate_fee_args: ValidateFeeArgs) -> ValidatePaymentFut<()> { unimplemented!() }

    fn validate_maker_payment(&self, _input: ValidatePaymentInput) -> ValidatePaymentFut<()> { unimplemented!() }

    fn validate_taker_payment(&self, _input: ValidatePaymentInput) -> ValidatePaymentFut<()> { unimplemented!() }

    fn check_if_my_payment_sent(
        &self,
        _if_my_payment_sent_args: CheckIfMyPaymentSentArgs,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
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

    fn check_tx_signed_by_pub(&self, tx: &[u8], expected_pub: &[u8]) -> Result<bool, MmError<ValidatePaymentError>> {
        unimplemented!();
    }

    async fn extract_secret(
        &self,
        secret_hash: &[u8],
        spend_tx: &[u8],
        watcher_reward: bool,
    ) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn is_auto_refundable(&self) -> bool { false }

    async fn wait_for_htlc_refund(&self, _tx: &[u8], _locktime: u64) -> RefundResult<()> { unimplemented!() }

    fn negotiate_swap_contract_addr(
        &self,
        other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        unimplemented!()
    }

    fn derive_htlc_key_pair(&self, _swap_unique_data: &[u8]) -> KeyPair { unimplemented!() }

    fn derive_htlc_pubkey(&self, _swap_unique_data: &[u8]) -> Vec<u8> { unimplemented!() }

    fn can_refund_htlc(&self, locktime: u64) -> Box<dyn Future<Item = CanRefundHtlc, Error = String> + Send + '_> {
        unimplemented!()
    }

    fn validate_other_pubkey(&self, raw_pubkey: &[u8]) -> MmResult<(), ValidateOtherPubKeyErr> { unimplemented!() }

    async fn maker_payment_instructions(
        &self,
        _args: PaymentInstructionArgs<'_>,
    ) -> Result<Option<Vec<u8>>, MmError<PaymentInstructionsErr>> {
        unimplemented!()
    }

    async fn taker_payment_instructions(
        &self,
        args: PaymentInstructionArgs<'_>,
    ) -> Result<Option<Vec<u8>>, MmError<PaymentInstructionsErr>> {
        unimplemented!()
    }

    fn validate_maker_payment_instructions(
        &self,
        _instructions: &[u8],
        args: PaymentInstructionArgs,
    ) -> Result<PaymentInstructions, MmError<ValidateInstructionsErr>> {
        unimplemented!()
    }

    fn validate_taker_payment_instructions(
        &self,
        _instructions: &[u8],
        args: PaymentInstructionArgs,
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

#[async_trait]
impl WatcherOps for SiaCoin {
    fn send_maker_payment_spend_preimage(&self, _input: SendMakerPaymentSpendPreimageInput) -> TransactionFut {
        unimplemented!();
    }

    fn send_taker_payment_refund_preimage(&self, _watcher_refunds_payment_args: RefundPaymentArgs) -> TransactionFut {
        unimplemented!();
    }

    fn create_taker_payment_refund_preimage(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u64,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
        _swap_unique_data: &[u8],
    ) -> TransactionFut {
        unimplemented!();
    }

    fn create_maker_payment_spend_preimage(
        &self,
        _maker_payment_tx: &[u8],
        _time_lock: u64,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_unique_data: &[u8],
    ) -> TransactionFut {
        unimplemented!();
    }

    fn watcher_validate_taker_fee(&self, _input: WatcherValidateTakerFeeInput) -> ValidatePaymentFut<()> {
        unimplemented!();
    }

    fn watcher_validate_taker_payment(&self, _input: WatcherValidatePaymentInput) -> ValidatePaymentFut<()> {
        unimplemented!();
    }

    fn taker_validates_payment_spend_or_refund(&self, _input: ValidateWatcherSpendInput) -> ValidatePaymentFut<()> {
        unimplemented!()
    }

    async fn watcher_search_for_swap_tx_spend(
        &self,
        _input: WatcherSearchForSwapTxSpendInput<'_>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!();
    }

    async fn get_taker_watcher_reward(
        &self,
        _other_coin: &MmCoinEnum,
        _coin_amount: Option<BigDecimal>,
        _other_coin_amount: Option<BigDecimal>,
        _reward_amount: Option<BigDecimal>,
        _wait_until: u64,
    ) -> Result<WatcherReward, MmError<WatcherRewardError>> {
        unimplemented!()
    }

    async fn get_maker_watcher_reward(
        &self,
        _other_coin: &MmCoinEnum,
        _reward_amount: Option<BigDecimal>,
        _wait_until: u64,
    ) -> Result<Option<WatcherReward>, MmError<WatcherRewardError>> {
        unimplemented!()
    }
}
