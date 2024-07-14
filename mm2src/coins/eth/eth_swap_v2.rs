use super::eth::{addr_from_raw_pubkey, gas_limit, wei_from_big_decimal, EthCoin, EthCoinType, SignedEthTx,
                 TAKER_SWAP_V2};
use super::{RefundFundingSecretArgs, SendTakerFundingArgs, Transaction, TransactionErr};
use enum_derives::EnumFromStringify;
use ethabi::Token;
use ethcore_transaction::Action;
use ethereum_types::{Address, U256};
use ethkey::public_to_address;
use futures::compat::Future01CompatExt;
use std::convert::TryInto;

struct TakerFundingArgs<'a> {
    dex_fee: U256,
    payment_amount: U256,
    maker_address: Address,
    taker_secret_hash: &'a [u8],
    maker_secret_hash: &'a [u8],
    funding_time_lock: u32,
    payment_time_lock: u32,
}

struct TakerRefundSecretArgs<'a> {
    dex_fee: U256,
    payment_amount: U256,
    maker_address: Address,
    taker_secret: &'a [u8],
    maker_secret_hash: &'a [u8],
    funding_time_lock: u32,
    payment_time_lock: u32,
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
        let dex_fee = try_tx_s!(wei_from_big_decimal(&args.dex_fee.fee_amount().into(), self.decimals));

        let payment_amount = try_tx_s!(wei_from_big_decimal(
            &(args.trading_amount + args.premium_amount),
            self.decimals
        ));
        let maker_address = try_tx_s!(addr_from_raw_pubkey(args.maker_pub));

        let funding_time_lock: u32 = try_tx_s!(args.funding_time_lock.try_into());
        let payment_time_lock: u32 = try_tx_s!(args.payment_time_lock.try_into());
        let funding_args = TakerFundingArgs {
            dex_fee,
            payment_amount,
            maker_address,
            taker_secret_hash: args.taker_secret_hash,
            maker_secret_hash: args.maker_secret_hash,
            funding_time_lock,
            payment_time_lock,
        };

        match &self.coin_type {
            EthCoinType::Eth => {
                let data = try_tx_s!(self.prepare_taker_eth_funding_data(&funding_args).await);
                self.sign_and_send_transaction(
                    payment_amount,
                    Action::Call(taker_swap_v2_contract),
                    data,
                    U256::from(gas_limit::ETH_PAYMENT),
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
                    self.wait_for_required_allowance(
                        taker_swap_v2_contract,
                        payment_amount,
                        args.wait_for_confirmation_until,
                    )
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
                        U256::from(0),
                        Action::Call(taker_swap_v2_contract),
                        data,
                        U256::from(gas_limit::ERC20_PAYMENT),
                    )
                    .compat()
                    .await
                } else {
                    self.sign_and_send_transaction(
                        U256::from(0),
                        Action::Call(taker_swap_v2_contract),
                        data,
                        U256::from(gas_limit::ERC20_PAYMENT),
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

    pub(crate) async fn refund_taker_funding_secret_impl(
        &self,
        args: RefundFundingSecretArgs<'_, Self>,
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
        let maker_address = public_to_address(args.maker_pubkey);
        let funding_time_lock: u32 = try_tx_s!(args.funding_time_lock.try_into());
        let payment_time_lock: u32 = try_tx_s!(args.payment_time_lock.try_into());
        let refund_args = TakerRefundSecretArgs {
            dex_fee,
            payment_amount,
            maker_address,
            taker_secret: args.taker_secret,
            maker_secret_hash: args.maker_secret_hash,
            funding_time_lock,
            payment_time_lock,
        };
        match &self.coin_type {
            EthCoinType::Eth => {
                let data = try_tx_s!(self.prepare_taker_refund_eth_secret_data(&refund_args).await);
                self.sign_and_send_transaction(
                    payment_amount,
                    Action::Call(taker_swap_v2_contract),
                    data,
                    U256::from(gas_limit::ETH_PAYMENT),
                )
                .compat()
                .await
            },
            EthCoinType::Erc20 {
                platform: _,
                token_addr: _,
            } => {
                todo!()
            },
            EthCoinType::Nft { .. } => Err(TransactionErr::ProtocolNotSupported(
                "NFT protocol is not supported for ETH and ERC20 Swaps".to_string(),
            )),
        }
    }

    async fn prepare_taker_eth_funding_data(&self, args: &TakerFundingArgs<'_>) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("ethTakerPayment")?;
        let id = self.etomic_swap_v2_id(args.funding_time_lock, args.payment_time_lock, args.taker_secret_hash);
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

    async fn prepare_taker_erc20_funding_data(
        &self,
        args: &TakerFundingArgs<'_>,
        token_addr: Address,
    ) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("erc20TakerPayment")?;
        let id = self.etomic_swap_v2_id(args.funding_time_lock, args.payment_time_lock, args.taker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(args.payment_amount),
            Token::Uint(args.dex_fee),
            Token::Address(token_addr),
            Token::Address(args.maker_address),
            Token::FixedBytes(args.taker_secret_hash.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Uint(args.funding_time_lock.into()),
            Token::Uint(args.payment_time_lock.into()),
        ])?;
        Ok(data)
    }

    async fn prepare_taker_refund_eth_secret_data(
        &self,
        args: &TakerRefundSecretArgs<'_>,
    ) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function("refundTakerPaymentSecret")?;
        let id = self.etomic_swap_v2_id(args.funding_time_lock, args.payment_time_lock, args.taker_secret);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(args.payment_amount),
            Token::Uint(args.dex_fee),
            Token::Address(args.maker_address),
            Token::FixedBytes(args.taker_secret.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Address(Address::default()),
        ])?;
        Ok(data)
    }
}

#[allow(dead_code)]
#[derive(Debug, Display, EnumFromStringify)]
enum PrepareTxDataError {
    #[from_stringify("ethabi::Error")]
    #[display(fmt = "Abi error: {}", _0)]
    AbiError(String),
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
}
