use super::eth_fee_events::EstimatorType;
use super::ser::FeePerGasEstimated;
use crate::{lp_coinfind, MmCoinEnum};
use common::HttpStatusCode;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::mm_error::MmResult;

use http::StatusCode;
use std::convert::TryFrom;

#[derive(Deserialize)]
pub struct GetFeeEstimationRequest {
    coin: String,
    #[serde(default)]
    estimator_type: EstimatorType,
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum GetFeeEstimationRequestError {
    CoinNotFound,
    Internal(String),
    CoinNotSupported,
}

impl HttpStatusCode for GetFeeEstimationRequestError {
    fn status_code(&self) -> StatusCode {
        match self {
            GetFeeEstimationRequestError::CoinNotFound => StatusCode::NOT_FOUND,
            GetFeeEstimationRequestError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GetFeeEstimationRequestError::CoinNotSupported => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

/// get_eth_estimated_fee_per_gas rpc implementation.
/// TODO: maybe should we add a rate limiter for calling it as for simple estimator the interval is blocktime (12s) so no need to call it more often  
/// For blocknative and infura gas api there is number of requests per license so we would like to limit it.
/// Maybe the intermediate kdf proxy will have a rate limiter instead.
pub async fn get_eth_estimated_fee_per_gas(
    ctx: MmArc,
    req: GetFeeEstimationRequest,
) -> MmResult<FeePerGasEstimated, GetFeeEstimationRequestError> {
    let coin = lp_coinfind(&ctx, &req.coin)
        .await
        .map_err(GetFeeEstimationRequestError::Internal)?
        .ok_or(GetFeeEstimationRequestError::CoinNotFound)?;

    match coin {
        MmCoinEnum::EthCoin(coin) => {
            let use_simple = matches!(req.estimator_type, EstimatorType::Simple);
            let fee = coin
                .get_eip1559_gas_fee(use_simple)
                .await
                .map_err(|e| GetFeeEstimationRequestError::Internal(e.to_string()))?;
            let ser_fee =
                FeePerGasEstimated::try_from(fee).map_err(|e| GetFeeEstimationRequestError::Internal(e.to_string()))?;
            Ok(ser_fee)
        },
        _ => Err(GetFeeEstimationRequestError::CoinNotSupported)?,
    }
}
