use super::{EstimationSource, FeePerGasEstimated, FeePerGasLevel, HeaderParams, FEE_PER_GAS_LEVELS};
use crate::eth::{Web3RpcError, Web3RpcResult};
use crate::{wei_from_gwei_decimal, NumConversError};
use mm2_err_handle::mm_error::MmError;
use mm2_err_handle::prelude::*;
use mm2_net::transport::slurp_url_with_headers;
use mm2_number::BigDecimal;

use http::StatusCode;
use serde_json::{self as json};
use std::convert::TryFrom;
use std::convert::TryInto;
use url::Url;

lazy_static! {
    /// API key for testing
    static ref BLOCKNATIVE_GAS_API_AUTH_TEST: String = std::env::var("BLOCKNATIVE_GAS_API_AUTH_TEST").unwrap_or_default();
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct BlocknativeBlockPrices {
    #[serde(rename = "blockNumber")]
    pub block_number: u32,
    #[serde(rename = "estimatedTransactionCount")]
    pub estimated_transaction_count: u32,
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: BigDecimal,
    #[serde(rename = "estimatedPrices")]
    pub estimated_prices: Vec<BlocknativeEstimatedPrices>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct BlocknativeEstimatedPrices {
    pub confidence: u32,
    pub price: BigDecimal,
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: BigDecimal,
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: BigDecimal,
}

/// Blocknative gas prices response
/// see https://docs.blocknative.com/gas-prediction/gas-platform
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct BlocknativeBlockPricesResponse {
    pub system: String,
    pub network: String,
    pub unit: String,
    #[serde(rename = "maxPrice")]
    pub max_price: BigDecimal,
    #[serde(rename = "currentBlockNumber")]
    pub current_block_number: u32,
    #[serde(rename = "msSinceLastBlock")]
    pub ms_since_last_block: u32,
    #[serde(rename = "blockPrices")]
    pub block_prices: Vec<BlocknativeBlockPrices>,
}

impl TryFrom<BlocknativeBlockPricesResponse> for FeePerGasEstimated {
    type Error = MmError<NumConversError>;

    fn try_from(block_prices: BlocknativeBlockPricesResponse) -> Result<Self, Self::Error> {
        if block_prices.block_prices.is_empty() {
            return Ok(FeePerGasEstimated::default());
        }
        if block_prices.block_prices[0].estimated_prices.len() < FEE_PER_GAS_LEVELS {
            return Ok(FeePerGasEstimated::default());
        }
        Ok(Self {
            base_fee: wei_from_gwei_decimal!(&block_prices.block_prices[0].base_fee_per_gas)?,
            low: FeePerGasLevel {
                max_fee_per_gas: wei_from_gwei_decimal!(
                    &block_prices.block_prices[0].estimated_prices[2].max_fee_per_gas
                )?,
                max_priority_fee_per_gas: wei_from_gwei_decimal!(
                    &block_prices.block_prices[0].estimated_prices[2].max_priority_fee_per_gas
                )?,
                min_wait_time: None,
                max_wait_time: None,
            },
            medium: FeePerGasLevel {
                max_fee_per_gas: wei_from_gwei_decimal!(
                    &block_prices.block_prices[0].estimated_prices[1].max_fee_per_gas
                )?,
                max_priority_fee_per_gas: wei_from_gwei_decimal!(
                    &block_prices.block_prices[0].estimated_prices[1].max_priority_fee_per_gas
                )?,
                min_wait_time: None,
                max_wait_time: None,
            },
            high: FeePerGasLevel {
                max_fee_per_gas: wei_from_gwei_decimal!(
                    &block_prices.block_prices[0].estimated_prices[0].max_fee_per_gas
                )?,
                max_priority_fee_per_gas: wei_from_gwei_decimal!(
                    &block_prices.block_prices[0].estimated_prices[0].max_priority_fee_per_gas
                )?,
                min_wait_time: None,
                max_wait_time: None,
            },
            source: EstimationSource::Blocknative,
            base_fee_trend: String::default(),
            priority_fee_trend: String::default(),
        })
    }
}

/// Blocknative gas api provider caller
#[allow(dead_code)]
pub(crate) struct BlocknativeGasApiCaller {}

#[allow(dead_code)]
impl BlocknativeGasApiCaller {
    const BLOCKNATIVE_GAS_PRICES_ENDPOINT: &'static str = "gasprices/blockprices";
    const BLOCKNATIVE_GAS_PRICES_LOW: &'static str = "10";
    const BLOCKNATIVE_GAS_PRICES_MEDIUM: &'static str = "50";
    const BLOCKNATIVE_GAS_PRICES_HIGH: &'static str = "90";

    const BLOCKNATIVE_GAS_API_CHAINS: &[(&'static str, u64)] =
        &[("EthereumMainnet", 1), ("PolygonMainnet", 137), ("SeiMainnet", 1329)];

    pub(crate) fn is_chain_supported(chain_id: u64) -> bool {
        Self::BLOCKNATIVE_GAS_API_CHAINS
            .iter()
            .any(|(_name, id)| *id == chain_id)
    }

    fn get_blocknative_gas_api_url(base_url: &Url, chain_id: u64) -> (Url, HeaderParams) {
        let mut url = base_url.clone();
        url.set_path(Self::BLOCKNATIVE_GAS_PRICES_ENDPOINT);
        url.query_pairs_mut()
            .append_pair("chainid", chain_id.to_string().as_str())
            .append_pair("confidenceLevels", Self::BLOCKNATIVE_GAS_PRICES_LOW)
            .append_pair("confidenceLevels", Self::BLOCKNATIVE_GAS_PRICES_MEDIUM)
            .append_pair("confidenceLevels", Self::BLOCKNATIVE_GAS_PRICES_HIGH)
            .append_pair("withBaseFees", "true");

        let headers = vec![("Authorization", BLOCKNATIVE_GAS_API_AUTH_TEST.as_str())];
        (url, headers)
    }

    async fn make_blocknative_gas_api_request(
        url: &Url,
        headers: HeaderParams,
    ) -> MmResult<BlocknativeBlockPricesResponse, String> {
        let resp = slurp_url_with_headers(url.as_str(), headers)
            .await
            .mm_err(|e| e.to_string())?;
        if resp.0 != StatusCode::OK {
            let error = format!("{} failed with status code {}", url, resp.0);
            return MmError::err(error);
        }
        let block_prices = json::from_slice(&resp.2).map_err(|e| e.to_string())?;
        Ok(block_prices)
    }

    /// Fetch fee per gas estimations from blocknative provider
    pub async fn fetch_blocknative_fee_estimation(base_url: &Url, chain_id: u64) -> Web3RpcResult<FeePerGasEstimated> {
        let (url, headers) = Self::get_blocknative_gas_api_url(base_url, chain_id);
        let block_prices = Self::make_blocknative_gas_api_request(&url, headers)
            .await
            .mm_err(Web3RpcError::Transport)?;
        block_prices.try_into().mm_err(Into::into)
    }
}
