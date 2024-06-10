use crate::eth::{wei_from_big_decimal, EthCoin, SignedEthTx};
use crate::{SendTakerFundingArgs, TransactionErr};

impl EthCoin {
    pub(crate) async fn send_taker_funding_impl(
        &self,
        args: SendTakerFundingArgs<'_>,
    ) -> Result<SignedEthTx, TransactionErr> {
        let _dex_fee = try_tx_s!(wei_from_big_decimal(&args.dex_fee.fee_amount().into(), self.decimals));

        let _payment_amount = try_tx_s!(wei_from_big_decimal(
            &(args.trading_amount + args.premium_amount),
            self.decimals
        ));
        todo!()
    }
}
