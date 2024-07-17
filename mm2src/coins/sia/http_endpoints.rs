use crate::sia::address::Address;
use crate::sia::transaction::SiacoinElement;
use crate::sia::types::{Event, BlockID};
use crate::sia::SiaApiClientError;
use mm2_number::MmNumber;
use reqwest::{Method, Request, Url};
use rpc::v1::types::H256;
use serde::de::DeserializeOwned;

const ENDPOINT_CONSENSUS_TIP: &str = "api/consensus/tip";

pub trait SiaApiRequest {
    type Response: SiaApiResponse + DeserializeOwned;

    fn to_http_request(&self, base_url: &Url) -> Result<Request, SiaApiClientError>;
}

// marker trait
pub trait SiaApiResponse {}

#[derive(Deserialize, Serialize, Debug)]
pub struct ConsensusTipRequest;

impl SiaApiRequest for ConsensusTipRequest {
    type Response = ConsensusTipResponse;

    fn to_http_request(&self, base_url: &Url) -> Result<reqwest::Request, SiaApiClientError> {
        let endpoint_url = base_url
            .join(ENDPOINT_CONSENSUS_TIP)
            .map_err(SiaApiClientError::UrlParse)?;

        let request = reqwest::Request::new(Method::GET, endpoint_url);
        Ok(request)
    }
}

// https://github.com/SiaFoundation/core/blob/4e46803f702891e7a83a415b7fcd7543b13e715e/types/types.go#L181
#[derive(Deserialize, Serialize, Debug)]
pub struct ConsensusTipResponse {
    pub height: u64,
    pub id: BlockID,
}

impl SiaApiResponse for ConsensusTipResponse {}

// GET /addresses/:addr/balance
#[derive(Deserialize, Serialize, Debug)]
pub struct AddressBalanceRequest {
    pub address: Address,
}

impl SiaApiRequest for AddressBalanceRequest {
    type Response = AddressBalanceResponse;

    fn to_http_request(&self, base_url: &Url) -> Result<Request, SiaApiClientError> {
        // TODO use .join method of Url to prevent any possibility of path traversal
        let endpoint_path = format!("api/addresses/{}/balance", self.address);
        let endpoint_url = base_url.join(&endpoint_path).map_err(SiaApiClientError::UrlParse)?;

        let request = Request::new(Method::GET, endpoint_url);
        Ok(request)
    }
}

// https://github.com/SiaFoundation/walletd/blob/9574e69ff0bf84de1235b68e78db2a41d5e27516/api/api.go#L36
// https://github.com/SiaFoundation/walletd/blob/9574e69ff0bf84de1235b68e78db2a41d5e27516/wallet/wallet.go#L25
#[derive(Deserialize, Serialize, Debug)]
pub struct AddressBalanceResponse {
    pub siacoins: MmNumber,
    #[serde(rename = "immatureSiacoins")]
    pub immature_siacoins: MmNumber,
    pub siafunds: MmNumber,
}

impl SiaApiResponse for AddressBalanceResponse {}

// GET /events/:id
#[derive(Deserialize, Serialize, Debug)]
pub struct EventsTxidRequest {
    pub txid: H256,
}

impl SiaApiRequest for EventsTxidRequest {
    type Response = EventsTxidResponse;

    fn to_http_request(&self, base_url: &Url) -> Result<Request, SiaApiClientError> {
        let endpoint_path = format!("api/events/{}", self.txid);
        let endpoint_url = base_url.join(&endpoint_path).map_err(SiaApiClientError::UrlParse)?;

        let request = Request::new(Method::GET, endpoint_url);
        Ok(request)
    }
}

#[derive(Deserialize, Serialize)]
pub struct EventsTxidResponse(pub Event);

impl SiaApiResponse for EventsTxidResponse {}

// GET /addresses/:addr/events
#[derive(Deserialize, Serialize, Debug)]
pub struct AddressesEventsRequest {
    pub address: Address,
}

impl SiaApiRequest for AddressesEventsRequest {
    type Response = Vec<Event>;

    fn to_http_request(&self, base_url: &Url) -> Result<Request, SiaApiClientError> {
        let endpoint_path = format!("api/addresses/{}/events", self.address);
        let endpoint_url = base_url.join(&endpoint_path).map_err(SiaApiClientError::UrlParse)?;

        let request = Request::new(Method::GET, endpoint_url);
        Ok(request)
    }
}

pub type AddressesEventsResponse = Vec<Event>;

impl SiaApiResponse for Vec<Event> {}

// GET /addresses/:addr/outputs/siacoin
#[derive(Deserialize, Serialize, Debug)]
pub struct AddressUtxosRequest {
    pub address: Address,
}

pub type AddressUtxosResponse = Vec<SiacoinElement>;

impl SiaApiResponse for AddressUtxosResponse {}

impl SiaApiRequest for AddressUtxosRequest {
    type Response = AddressUtxosResponse;

    fn to_http_request(&self, base_url: &Url) -> Result<Request, SiaApiClientError> {
        let endpoint_path = format!("api/addresses/{}/outputs/siacoin", self.address);
        let endpoint_url = base_url.join(&endpoint_path).map_err(SiaApiClientError::UrlParse)?;

        let request = Request::new(Method::GET, endpoint_url);
        Ok(request)
    }
}
