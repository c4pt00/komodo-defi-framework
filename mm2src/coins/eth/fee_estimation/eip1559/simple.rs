use super::{EstimationSource, FeePerGasEstimated, FeePerGasLevel, PriorityLevelId, FEE_PER_GAS_LEVELS};
use crate::eth::web3_transport::FeeHistoryResult;
use crate::eth::{Web3RpcError, Web3RpcResult};
use crate::{wei_from_gwei_decimal, wei_to_gwei_decimal, EthCoin};
use mm2_err_handle::mm_error::MmError;
use mm2_err_handle::or_mm_error::OrMmError;
use mm2_number::BigDecimal;

use ethereum_types::U256;
use num_traits::FromPrimitive;
use web3::types::BlockNumber;

#[cfg(test)] use std::str::FromStr;

/// Simple priority fee per gas estimator based on fee history
/// normally used if gas api provider is not available
pub(crate) struct FeePerGasSimpleEstimator {}

impl FeePerGasSimpleEstimator {
    // TODO: add minimal max fee and priority fee
    /// depth to look for fee history to estimate priority fees
    const FEE_PRIORITY_DEPTH: u64 = 5u64;

    /// percentiles to pass to eth_feeHistory
    const HISTORY_PERCENTILES: [f64; FEE_PER_GAS_LEVELS] = [25.0, 50.0, 75.0];

    /// percentile to predict next base fee over historical rewards
    const BASE_FEE_PERCENTILE: f64 = 75.0;

    /// percentiles to calc max priority fee over historical rewards
    const PRIORITY_FEE_PERCENTILES: [f64; FEE_PER_GAS_LEVELS] = [50.0, 50.0, 50.0];

    /// adjustment for max fee per gas picked up by sampling
    const ADJUST_MAX_FEE: [f64; FEE_PER_GAS_LEVELS] = [1.1, 1.175, 1.25]; // 1.25 assures max_fee_per_gas will be over next block base_fee

    /// adjustment for max priority fee picked up by sampling
    const ADJUST_MAX_PRIORITY_FEE: [f64; FEE_PER_GAS_LEVELS] = [1.0, 1.0, 1.0];

    /// block depth for eth_feeHistory
    fn history_depth() -> u64 { Self::FEE_PRIORITY_DEPTH }

    /// percentiles for priority rewards obtained with eth_feeHistory
    fn history_percentiles() -> &'static [f64] { &Self::HISTORY_PERCENTILES }

    /// percentile for vector
    fn percentile_of(v: &[U256], percent: f64) -> U256 {
        let mut v_mut = v.to_owned();
        v_mut.sort();

        // validate bounds:
        let percent = if percent > 100.0 { 100.0 } else { percent };
        let percent = if percent < 0.0 { 0.0 } else { percent };

        let value_pos = ((v_mut.len() - 1) as f64 * percent / 100.0).round() as usize;
        v_mut[value_pos]
    }

    pub(crate) fn is_chain_supported(_chain_id: u64) -> bool { true }

    /// Estimate simplified gas priority fees based on fee history
    pub(crate) async fn estimate_fee_by_history(coin: &EthCoin) -> Web3RpcResult<FeePerGasEstimated> {
        let res: Result<FeeHistoryResult, web3::Error> = coin
            .eth_fee_history(
                U256::from(Self::history_depth()),
                BlockNumber::Latest,
                Self::history_percentiles(),
            )
            .await;

        match res {
            Ok(fee_history) => Ok(Self::calculate_with_history(&fee_history)?),
            Err(_) => MmError::err(Web3RpcError::Internal("Eth requests failed".into())),
        }
    }

    fn predict_base_fee(base_fees: &[U256]) -> U256 { Self::percentile_of(base_fees, Self::BASE_FEE_PERCENTILE) }

    fn priority_fee_for_level(
        level: PriorityLevelId,
        base_fee: BigDecimal,
        fee_history: &FeeHistoryResult,
    ) -> Web3RpcResult<FeePerGasLevel> {
        let level_index = level as usize;
        let level_rewards = fee_history
            .priority_rewards
            .as_ref()
            .or_mm_err(|| Web3RpcError::Internal("expected reward in eth_feeHistory".into()))?
            .iter()
            .map(|rewards| rewards.get(level_index).copied().unwrap_or_else(|| U256::from(0)))
            .collect::<Vec<_>>();

        // Calculate the max priority fee per gas based on the rewards percentile.
        let max_priority_fee_per_gas = Self::percentile_of(&level_rewards, Self::PRIORITY_FEE_PERCENTILES[level_index]);
        // Convert the priority fee to BigDecimal gwei, falling back to 0 on error.
        let max_priority_fee_per_gas_gwei =
            wei_to_gwei_decimal!(max_priority_fee_per_gas).unwrap_or_else(|_| BigDecimal::from(0));

        // Calculate the max fee per gas by adjusting the base fee and adding the priority fee.
        let adjust_max_fee =
            BigDecimal::from_f64(Self::ADJUST_MAX_FEE[level_index]).unwrap_or_else(|| BigDecimal::from(0));
        let adjust_max_priority_fee =
            BigDecimal::from_f64(Self::ADJUST_MAX_PRIORITY_FEE[level_index]).unwrap_or_else(|| BigDecimal::from(0));

        // TODO: consider use checked ops
        let max_fee_per_gas_dec = base_fee * adjust_max_fee + max_priority_fee_per_gas_gwei * adjust_max_priority_fee;

        Ok(FeePerGasLevel {
            max_priority_fee_per_gas,
            max_fee_per_gas: wei_from_gwei_decimal!(&max_fee_per_gas_dec)?,
            // TODO: Consider adding default wait times if applicable (and mark them as uncertain).
            min_wait_time: None,
            max_wait_time: None,
        })
    }

    /// estimate priority fees by fee history
    fn calculate_with_history(fee_history: &FeeHistoryResult) -> Web3RpcResult<FeePerGasEstimated> {
        // For estimation of max fee and max priority fee we use latest block base_fee but adjusted.
        // Apparently for this simple fee estimator for assured high priority we should assume
        // that the real base_fee may go up by 1,25 (i.e. if the block is full). This is covered by high priority ADJUST_MAX_FEE multiplier
        let latest_base_fee = fee_history
            .base_fee_per_gas
            .first()
            .cloned()
            .unwrap_or_else(|| U256::from(0));
        let latest_base_fee_dec = wei_to_gwei_decimal!(latest_base_fee).unwrap_or_else(|_| BigDecimal::from(0));

        // The predicted base fee is not used for calculating eip1559 values here and is provided for other purposes
        // (f.e if the caller would like to do own estimates of max fee and max priority fee)
        let predicted_base_fee = Self::predict_base_fee(&fee_history.base_fee_per_gas);
        Ok(FeePerGasEstimated {
            base_fee: predicted_base_fee,
            low: Self::priority_fee_for_level(PriorityLevelId::Low, latest_base_fee_dec.clone(), fee_history)?,
            medium: Self::priority_fee_for_level(PriorityLevelId::Medium, latest_base_fee_dec.clone(), fee_history)?,
            high: Self::priority_fee_for_level(PriorityLevelId::High, latest_base_fee_dec, fee_history)?,
            source: EstimationSource::Simple,
            base_fee_trend: String::default(),
            priority_fee_trend: String::default(),
        })
    }
}

#[test]
fn test_gas_fee_history_estimator() {
    // depth = 5 levels = 3
    let test_history = FeeHistoryResult {
        oldest_block: U256::from_dec_str("0").unwrap(),
        base_fee_per_gas: vec![
            U256::from_dec_str("45333333333").unwrap(),
            U256::from_dec_str("51345678912").unwrap(),
            U256::from_dec_str("60200000000").unwrap(),
            U256::from_dec_str("55131313131").unwrap(),
            U256::from_dec_str("40000000000").unwrap(),
        ],
        gas_used_ratio: vec![],
        priority_rewards: Some(vec![
            vec![
                U256::from_dec_str("2000000000").unwrap(),
                U256::from_dec_str("5000000000").unwrap(),
                U256::from_dec_str("7200000000").unwrap(),
            ],
            vec![
                U256::from_dec_str("1000000000").unwrap(),
                U256::from_dec_str("5500000000").unwrap(),
                U256::from_dec_str("7100000000").unwrap(),
            ],
            vec![
                U256::from_dec_str("2500000000").unwrap(),
                U256::from_dec_str("4500000000").unwrap(),
                U256::from_dec_str("7500000000").unwrap(),
            ],
            vec![
                U256::from_dec_str("3000000000").unwrap(),
                U256::from_dec_str("3500000000").unwrap(),
                U256::from_dec_str("7300000000").unwrap(),
            ],
            vec![
                U256::from_dec_str("1500000000").unwrap(),
                U256::from_dec_str("6000000000").unwrap(),
                U256::from_dec_str("7400000000").unwrap(),
            ],
        ]),
    };

    let estimated = FeePerGasSimpleEstimator::calculate_with_history(&test_history).unwrap();

    let base_fee_latest = BigDecimal::from_str("45.333333333").unwrap();

    // fee percentiles how they are set in simple estimator (in gwei)
    let base_fee_perc_75 = BigDecimal::from_str("55.131313131").unwrap();
    let low_perc50 = BigDecimal::from_str("2").unwrap();
    let medium_perc50 = BigDecimal::from_str("5").unwrap();
    let high_perc50 = BigDecimal::from_str("7.3").unwrap();

    // adjust priority fee
    let max_priority_low = low_perc50.clone();
    let max_priority_medium = medium_perc50.clone();
    let max_priority_high = high_perc50.clone();

    // adjust max fee
    let max_fee_low =
        base_fee_latest.clone() * BigDecimal::from_f64(1.1).unwrap() + low_perc50 * BigDecimal::from_f64(1.0).unwrap();
    let max_fee_medium = base_fee_latest.clone() * BigDecimal::from_f64(1.175).unwrap()
        + medium_perc50 * BigDecimal::from_f64(1.0).unwrap();
    let max_fee_high =
        base_fee_latest * BigDecimal::from_f64(1.25).unwrap() + high_perc50 * BigDecimal::from_f64(1.0).unwrap();

    assert_eq!(wei_from_gwei_decimal!(&base_fee_perc_75).unwrap(), estimated.base_fee);
    assert_eq!(
        wei_from_gwei_decimal!(&max_priority_low).unwrap(),
        estimated.low.max_priority_fee_per_gas
    );
    assert_eq!(
        wei_from_gwei_decimal!(&max_fee_low).unwrap(),
        estimated.low.max_fee_per_gas
    );
    assert_eq!(
        wei_from_gwei_decimal!(&max_priority_medium).unwrap(),
        estimated.medium.max_priority_fee_per_gas
    );
    assert_eq!(
        wei_from_gwei_decimal!(&max_fee_medium).unwrap(),
        estimated.medium.max_fee_per_gas
    );
    assert_eq!(
        wei_from_gwei_decimal!(&max_priority_high).unwrap(),
        estimated.high.max_priority_fee_per_gas
    );
    assert_eq!(
        wei_from_gwei_decimal!(&max_fee_high).unwrap(),
        estimated.high.max_fee_per_gas
    );
}
