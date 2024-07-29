use super::eth::{wei_from_big_decimal, EthCoin, EthCoinType, SignedEthTx, TAKER_SWAP_V2};
use super::{RefundFundingSecretArgs, RefundTakerPaymentArgs, SendTakerFundingArgs, SwapTxTypeWithSecretHash,
            TakerPaymentStateV2, Transaction, TransactionErr, ValidateSwapV2TxResult, ValidateTakerFundingArgs};
use crate::{ParseCoinAssocTypes, ValidateSwapV2TxError};
use enum_derives::EnumFromStringify;
use ethabi::{Contract, Token};
use ethcore_transaction::Action;
use ethereum_types::{Address, Public, U256};
use ethkey::public_to_address;
use futures::compat::Future01CompatExt;
use mm2_err_handle::map_to_mm::MapToMmResult;
use mm2_err_handle::mm_error::MmError;
use mm2_number::BigDecimal;
use std::convert::TryInto;
use std::num::TryFromIntError;

struct TakerFundingArgs {
    dex_fee: U256,
    payment_amount: U256,
    maker_address: Address,
    taker_secret_hash: [u8; 32],
    maker_secret_hash: [u8; 32],
    funding_time_lock: u32,
    payment_time_lock: u32,
}

struct TakerRefundSecretArgs {
    dex_fee: U256,
    payment_amount: U256,
    maker_address: Address,
    taker_secret: [u8; 32],
    maker_secret_hash: [u8; 32],
    payment_time_lock: u32,
    token_address: Address,
}

struct TakerRefundArgs {
    dex_fee: U256,
    payment_amount: U256,
    maker_address: Address,
    taker_secret_hash: [u8; 32],
    maker_secret_hash: [u8; 32],
    payment_time_lock: u32,
    token_address: Address,
}

impl EthCoin {
    pub(crate) async fn send_taker_funding_impl(
        &self,
        args: SendTakerFundingArgs<'_>,
    ) -> Result<SignedEthTx, TransactionErr> {
        let taker_swap_v2_contract = self
            .swap_v2_contracts
            .as_ref()
            .map(|contracts| contracts.taker_swap_v2_contract)
            .ok_or_else(|| TransactionErr::Plain(ERRL!("Expected swap_v2_contracts to be Some, but found None")))?;
        // TODO add burnFee support
        let dex_fee = try_tx_s!(wei_from_big_decimal(&args.dex_fee.fee_amount().into(), self.decimals));

        let payment_amount = try_tx_s!(wei_from_big_decimal(
            &(args.trading_amount.clone() + args.premium_amount.clone()),
            self.decimals
        ));
        // TODO add maker_pub created by legacy derive_htlc_pubkey support additionally?
        // as derive_htlc_pubkey_v2 function is used for swap_v2, we can call public_to_address
        let maker_address = public_to_address(&Public::from_slice(args.maker_pub));

        let funding_time_lock: u32 = try_tx_s!(args.funding_time_lock.try_into());
        let payment_time_lock: u32 = try_tx_s!(args.payment_time_lock.try_into());
        let funding_args = TakerFundingArgs {
            dex_fee,
            payment_amount,
            maker_address,
            taker_secret_hash: try_tx_s!(args.taker_secret_hash.try_into()),
            maker_secret_hash: try_tx_s!(args.maker_secret_hash.try_into()),
            funding_time_lock,
            payment_time_lock,
        };

        match &self.coin_type {
            EthCoinType::Eth => {
                let data = try_tx_s!(self.prepare_taker_eth_funding_data(&funding_args).await);
                let eth_total_payment = try_tx_s!(wei_from_big_decimal(
                    &(args.dex_fee.fee_amount().to_decimal() + args.trading_amount + args.premium_amount),
                    self.decimals
                ));
                self.sign_and_send_transaction(
                    eth_total_payment,
                    Action::Call(taker_swap_v2_contract),
                    data,
                    // TODO need new consts and params for v2 calls. now it uses v1
                    U256::from(self.gas_limit.eth_payment),
                )
                .compat()
                .await
            },
            EthCoinType::Erc20 {
                platform: _,
                token_addr,
            } => {
                let allowed = self
                    .allowance(taker_swap_v2_contract)
                    .compat()
                    .await
                    .map_err(|e| TransactionErr::Plain(ERRL!("{}", e)))?;
                let data = try_tx_s!(self.prepare_taker_erc20_funding_data(&funding_args, *token_addr).await);
                if allowed < payment_amount {
                    let approved_tx = self.approve(taker_swap_v2_contract, U256::max_value()).compat().await?;
                    self.wait_for_required_allowance(taker_swap_v2_contract, payment_amount, args.funding_time_lock)
                        .compat()
                        .await
                        .map_err(|e| {
                            TransactionErr::Plain(ERRL!(
                                "Allowed value was not updated in time after sending approve transaction {:02x}: {}",
                                approved_tx.tx_hash_as_bytes(),
                                e
                            ))
                        })?;
                    self.sign_and_send_transaction(
                        0.into(),
                        Action::Call(taker_swap_v2_contract),
                        data,
                        // TODO need new consts and params for v2 calls. now it uses v1
                        U256::from(self.gas_limit.erc20_payment),
                    )
                    .compat()
                    .await
                } else {
                    self.sign_and_send_transaction(
                        0.into(),
                        Action::Call(taker_swap_v2_contract),
                        data,
                        // TODO need new consts and params for v2 calls. now it uses v1
                        U256::from(self.gas_limit.erc20_payment),
                    )
                    .compat()
                    .await
                }
            },
            EthCoinType::Nft { .. } => Err(TransactionErr::ProtocolNotSupported(
                "NFT protocol is not supported for ETH and ERC20 Swaps".to_string(),
            )),
        }
    }

    pub(crate) async fn validate_taker_funding_impl(
        &self,
        args: ValidateTakerFundingArgs<'_, Self>,
    ) -> ValidateSwapV2TxResult {
        if let EthCoinType::Nft { .. } = self.coin_type {
            return MmError::err(ValidateSwapV2TxError::Internal(
                "EthCoinType must be ETH or ERC20".to_string(),
            ));
        }
        let taker_swap_v2_contract = self
            .swap_v2_contracts
            .as_ref()
            .map(|contracts| contracts.taker_swap_v2_contract)
            .ok_or_else(|| {
                ValidateSwapV2TxError::Internal("Expected swap_v2_contracts to be Some, but found None".to_string())
            })?;
        validate_payment_args(args.taker_secret_hash, args.maker_secret_hash, &args.trading_amount)
            .map_err(ValidateSwapV2TxError::Internal)?;

        let _taker_address = public_to_address(args.taker_pub);
        let _funding_time_lock: u32 = args
            .funding_time_lock
            .try_into()
            .map_to_mm(|e: TryFromIntError| ValidateSwapV2TxError::LocktimeOverflow(e.to_string()))?;
        let payment_time_lock: u32 = args
            .payment_time_lock
            .try_into()
            .map_to_mm(|e: TryFromIntError| ValidateSwapV2TxError::LocktimeOverflow(e.to_string()))?;
        let swap_id = self.etomic_swap_id(payment_time_lock, args.maker_secret_hash);
        let taker_status = self
            .payment_status_v2(
                taker_swap_v2_contract,
                Token::FixedBytes(swap_id.clone()),
                &TAKER_SWAP_V2,
                EthPaymentType::TakerPayments,
                3,
            )
            .await?;

        // TODO move it to future validate_from_to_and_status function
        if taker_status != U256::from(TakerPaymentStateV2::PaymentSent as u8) {
            return MmError::err(ValidateSwapV2TxError::UnexpectedPaymentState(format!(
                "Taker Payment state is not PaymentSent, got {}",
                taker_status
            )));
        }
        // TODO complete validation
        Ok(())
    }

    pub(crate) async fn refund_taker_funding_timelock_impl(
        &self,
        args: RefundTakerPaymentArgs<'_>,
    ) -> Result<SignedEthTx, TransactionErr> {
        let taker_swap_v2_contract = self
            .swap_v2_contracts
            .as_ref()
            .map(|contracts| contracts.taker_swap_v2_contract)
            .ok_or_else(|| TransactionErr::Plain(ERRL!("Expected swap_v2_contracts to be Some, but found None")))?;
        let dex_fee = try_tx_s!(wei_from_big_decimal(
            &args.dex_fee.fee_amount().to_decimal(),
            self.decimals
        ));
        let payment_amount = try_tx_s!(wei_from_big_decimal(
            &(args.trading_amount + args.premium_amount),
            self.decimals
        ));
        // TODO add maker_pub created by legacy derive_htlc_pubkey support additionally?
        let maker_address = public_to_address(&Public::from_slice(args.maker_pub));
        let payment_time_lock: u32 = try_tx_s!(args.time_lock.try_into());
        let (maker_secret_hash, taker_secret_hash) = match args.tx_type_with_secret_hash {
            SwapTxTypeWithSecretHash::TakerPaymentV2 {
                maker_secret_hash,
                taker_secret_hash,
            } => (maker_secret_hash, taker_secret_hash),
            _ => {
                return Err(TransactionErr::Plain(ERRL!(
                    "Unsupported swap tx type for timelock refund"
                )))
            },
        };

        let (token_address, gas_limit) = match &self.coin_type {
            // TODO need new consts and params for v2 calls. now it uses v1
            EthCoinType::Eth => (Address::default(), self.gas_limit.eth_sender_refund),
            EthCoinType::Erc20 {
                platform: _,
                token_addr,
                // TODO need new consts and params for v2 calls. now it uses v1
            } => (*token_addr, self.gas_limit.erc20_sender_refund),
            EthCoinType::Nft { .. } => {
                return Err(TransactionErr::ProtocolNotSupported(
                    "NFT protocol is not supported for ETH and ERC20 Swaps".to_string(),
                ))
            },
        };
        let args = TakerRefundArgs {
            dex_fee,
            payment_amount,
            maker_address,
            taker_secret_hash: try_tx_s!(taker_secret_hash.try_into()),
            maker_secret_hash: try_tx_s!(maker_secret_hash.try_into()),
            payment_time_lock,
            token_address,
        };
        let data = try_tx_s!(self.prepare_taker_refund_payment_timelock_data(args).await);

        self.sign_and_send_transaction(
            0.into(),
            Action::Call(taker_swap_v2_contract),
            data,
            U256::from(gas_limit),
        )
        .compat()
        .await
    }

    pub(crate) async fn refund_taker_funding_secret_impl(
        &self,
        args: RefundFundingSecretArgs<'_, Self>,
    ) -> Result<SignedEthTx, TransactionErr> {
        let taker_swap_v2_contract = self
            .swap_v2_contracts
            .as_ref()
            .map(|contracts| contracts.taker_swap_v2_contract)
            .ok_or_else(|| TransactionErr::Plain(ERRL!("Expected swap_v2_contracts to be Some, but found None")))?;
        let taker_secret = try_tx_s!(args.taker_secret.try_into());
        let maker_secret_hash = try_tx_s!(args.maker_secret_hash.try_into());
        let dex_fee = try_tx_s!(wei_from_big_decimal(
            &args.dex_fee.fee_amount().to_decimal(),
            self.decimals
        ));
        let payment_amount = try_tx_s!(wei_from_big_decimal(
            &(args.trading_amount + args.premium_amount),
            self.decimals
        ));
        let maker_address = public_to_address(args.maker_pubkey);
        let payment_time_lock: u32 = try_tx_s!(args.payment_time_lock.try_into());
        let (token_address, gas_limit) = match &self.coin_type {
            // TODO need new consts and params for v2 calls. now it uses v1
            EthCoinType::Eth => (Address::default(), self.gas_limit.eth_sender_refund),
            EthCoinType::Erc20 {
                platform: _,
                token_addr,
                // TODO need new consts and params for v2 calls. now it uses v1
            } => (*token_addr, self.gas_limit.erc20_sender_refund),
            EthCoinType::Nft { .. } => {
                return Err(TransactionErr::ProtocolNotSupported(
                    "NFT protocol is not supported for ETH and ERC20 Swaps".to_string(),
                ))
            },
        };
        let refund_args = TakerRefundSecretArgs {
            dex_fee,
            payment_amount,
            maker_address,
            taker_secret,
            maker_secret_hash,
            payment_time_lock,
            token_address,
        };
        let data = try_tx_s!(self.prepare_taker_refund_payment_secret_data(&refund_args).await);

        self.sign_and_send_transaction(
            0.into(),
            Action::Call(taker_swap_v2_contract),
            data,
            U256::from(gas_limit),
        )
        .compat()
        .await
    }

    /// Prepares data for EtomicSwapTakerV2 contract `ethTakerPayment` method
    ///     function ethTakerPayment(
    ///         bytes32 id,
    ///         uint256 dexFee,
    ///         address receiver,
    ///         bytes32 takerSecretHash,
    ///         bytes32 makerSecretHash,
    ///         uint32 preApproveLockTime,
    ///         uint32 paymentLockTime
    async fn prepare_taker_eth_funding_data(&self, args: &TakerFundingArgs) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("ethTakerPayment")?;
        let id = self.etomic_swap_id(args.payment_time_lock, &args.maker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(args.dex_fee),
            Token::Address(args.maker_address),
            Token::FixedBytes(args.taker_secret_hash.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Uint(args.funding_time_lock.into()),
            Token::Uint(args.payment_time_lock.into()),
        ])?;
        Ok(data)
    }

    /// Prepares data for EtomicSwapTakerV2 contract `erc20TakerPayment` method
    ///     function erc20TakerPayment(
    ///         bytes32 id,
    ///         uint256 amount,
    ///         uint256 dexFee,
    ///         address tokenAddress,
    ///         address receiver,
    ///         bytes32 takerSecretHash,
    ///         bytes32 makerSecretHash,
    ///         uint32 preApproveLockTime,
    ///         uint32 paymentLockTime
    async fn prepare_taker_erc20_funding_data(
        &self,
        args: &TakerFundingArgs,
        token_address: Address,
    ) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("erc20TakerPayment")?;
        let id = self.etomic_swap_id(args.payment_time_lock, &args.maker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(args.payment_amount),
            Token::Uint(args.dex_fee),
            Token::Address(token_address),
            Token::Address(args.maker_address),
            Token::FixedBytes(args.taker_secret_hash.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Uint(args.funding_time_lock.into()),
            Token::Uint(args.payment_time_lock.into()),
        ])?;
        Ok(data)
    }

    /// Prepares data for EtomicSwapTakerV2 contract `refundTakerPaymentTimelock` method
    /// function refundMakerPaymentTimelock(
    ///         bytes32 id,
    ///         uint256 amount,
    ///         address taker,
    ///         bytes32 takerSecretHash,
    ///         bytes32 makerSecretHash,
    ///         address tokenAddress
    async fn prepare_taker_refund_payment_timelock_data(
        &self,
        args: TakerRefundArgs,
    ) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("refundTakerPaymentTimelock")?;
        let id = self.etomic_swap_id(args.payment_time_lock, &args.maker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(args.payment_amount),
            Token::Uint(args.dex_fee),
            Token::Address(args.maker_address),
            Token::FixedBytes(args.taker_secret_hash.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Address(args.token_address),
        ])?;
        Ok(data)
    }

    /// Prepares data for EtomicSwapTakerV2 contract `refundTakerPaymentSecret` method
    /// function refundTakerPaymentSecret(
    ///         bytes32 id,
    ///         uint256 amount,
    ///         uint256 dexFee,
    ///         address maker,
    ///         bytes32 takerSecret,
    ///         bytes32 makerSecretHash,
    ///         address tokenAddress
    async fn prepare_taker_refund_payment_secret_data(
        &self,
        args: &TakerRefundSecretArgs,
    ) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("refundTakerPaymentSecret")?;
        let id = self.etomic_swap_id(args.payment_time_lock, &args.maker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(args.payment_amount),
            Token::Uint(args.dex_fee),
            Token::Address(args.maker_address),
            Token::FixedBytes(args.taker_secret.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Address(args.token_address),
        ])?;
        Ok(data)
    }

    /// Retrieves the payment status from a given smart contract address based on the swap ID and state type.
    pub(crate) async fn payment_status_v2(
        &self,
        swap_address: Address,
        swap_id: Token,
        contract_abi: &Contract,
        state_type: EthPaymentType,
        state_index: usize,
    ) -> Result<U256, PaymentStatusErr> {
        let function_name = state_type.as_str();
        let function = contract_abi.function(function_name)?;
        let data = function.encode_input(&[swap_id])?;
        let bytes = self
            .call_request(self.my_addr().await, swap_address, None, Some(data.into()))
            .await?;
        let decoded_tokens = function.decode_output(&bytes.0)?;

        let state = decoded_tokens.get(state_index).ok_or_else(|| {
            PaymentStatusErr::Internal(ERRL!(
                "Payment status must contain 'state' as the {} token",
                state_index
            ))
        })?;
        match state {
            Token::Uint(state) => Ok(*state),
            _ => Err(PaymentStatusErr::Internal(ERRL!(
                "Payment status must be Uint, got {:?}",
                state
            ))),
        }
    }
}

#[derive(Debug, Display, EnumFromStringify)]
enum PrepareTxDataError {
    #[from_stringify("ethabi::Error")]
    #[display(fmt = "Abi error: {}", _0)]
    AbiError(String),
    #[allow(dead_code)]
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
}

// TODO validate premium when add its support in swap_v2
fn validate_payment_args<'a>(
    taker_secret_hash: &'a [u8],
    maker_secret_hash: &'a [u8],
    trading_amount: &BigDecimal,
) -> Result<(), String> {
    if !is_positive(trading_amount) {
        return Err("trading_amount must be a positive value".to_string());
    }
    if taker_secret_hash.len() != 32 {
        return Err("taker_secret_hash must be 32 bytes".to_string());
    }
    if maker_secret_hash.len() != 32 {
        return Err("maker_secret_hash must be 32 bytes".to_string());
    }
    Ok(())
}

/// function to check if BigDecimal is a positive value
#[inline(always)]
fn is_positive(amount: &BigDecimal) -> bool { amount > &BigDecimal::from(0) }

pub(crate) enum EthPaymentType {
    MakerPayments,
    TakerPayments,
}

impl EthPaymentType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            EthPaymentType::MakerPayments => "makerPayments",
            EthPaymentType::TakerPayments => "takerPayments",
        }
    }
}

#[derive(Debug, Display, EnumFromStringify)]
pub(crate) enum PaymentStatusErr {
    #[from_stringify("ethabi::Error")]
    #[display(fmt = "Abi error: {}", _0)]
    AbiError(String),
    #[from_stringify("web3::Error")]
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
    #[display(fmt = "Tx deserialization error: {}", _0)]
    TxDeserializationError(String),
}
