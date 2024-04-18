use crate::sia::address::Address;
use crate::sia::http_endpoints::{AddressBalanceRequest, AddressBalanceResponse, ConsensusTipRequest, SiaApiRequest};
use crate::sia::SiaHttpConf;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _; // required for .encode() method
use core::fmt::Display;
use core::time::Duration;
use mm2_number::MmNumber;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Error, Url};
use serde::de::DeserializeOwned;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SiaApiClient(pub Arc<SiaApiClientImpl>);

impl Deref for SiaApiClient {
    type Target = SiaApiClientImpl;
    fn deref(&self) -> &SiaApiClientImpl { &self.0 }
}

impl SiaApiClient {
    pub fn new(_coin_ticker: &str, http_conf: SiaHttpConf) -> Result<Self, SiaApiClientError> {
        let new_arc = SiaApiClientImpl::new(http_conf.url, &http_conf.auth)?;
        Ok(SiaApiClient(Arc::new(new_arc)))
    }
}

#[derive(Debug)]
pub struct SiaApiClientImpl {
    client: Client,
    base_url: Url,
}

// this is neccesary to show the URL in error messages returned to the user
// this can be removed in favor of using ".with_url()" once reqwest is updated to v0.11.23
#[derive(Debug)]
pub struct ReqwestErrorWithUrl {
    error: Error,
    url: Url,
}

impl Display for ReqwestErrorWithUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error: {}, URL: {}", self.error, self.url)
    }
}

#[derive(Debug, Display)]
pub enum SiaApiClientError {
    Timeout(String),
    BuildError(String),
    ServerUnreachable(String),
    ReqwestError(ReqwestErrorWithUrl),
    UrlParse(url::ParseError),
    UnexpectedResponse(String),
}

impl From<SiaApiClientError> for String {
    fn from(e: SiaApiClientError) -> Self { format!("{:?}", e) }
}

async fn fetch_and_parse<T: DeserializeOwned>(client: &Client, url: Url) -> Result<T, SiaApiClientError> {
    client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| {
            SiaApiClientError::ReqwestError(ReqwestErrorWithUrl {
                error: e,
                url: url.clone(),
            })
        })?
        .json::<T>()
        .await
        .map_err(|e| SiaApiClientError::ReqwestError(ReqwestErrorWithUrl { error: e, url }))
}

impl SiaApiClientImpl {
    fn new(base_url: Url, password: &str) -> Result<Self, SiaApiClientError> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Basic {}", BASE64.encode(format!(":{}", password)));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).map_err(|e| SiaApiClientError::BuildError(e.to_string()))?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10)) // TODO make this configurable
            .build()
            .map_err(|e| {
                SiaApiClientError::ReqwestError(ReqwestErrorWithUrl {
                    error: e,
                    url: base_url.clone(),
                })
            })?;
        Ok(SiaApiClientImpl { client, base_url })
    }

    pub async fn dispatcher<R: SiaApiRequest + Send>(&self, request: R) -> Result<R::Response, SiaApiClientError> {
        let req = request.to_http_request(&self.base_url)?;
        fetch_and_parse::<R::Response>(&self.client, req.url().clone()).await
    }

    pub async fn current_height(&self) -> Result<u64, SiaApiClientError> {
        let response = self.dispatcher(ConsensusTipRequest).await?;
        Ok(response.height)
    }

    pub async fn address_balance(&self, address: Address) -> Result<AddressBalanceResponse, SiaApiClientError> {
        let request = AddressBalanceRequest { address };
        self.dispatcher(request).await
    }
}

/*
#[cfg(test)] use std::str::FromStr;
#[tokio::test]
#[ignore]
async fn test_api_client_timeout() {
    let api_client = SiaApiClientImpl::new(Url::parse("http://foo").unwrap(), "password").unwrap();
    let result = api_client.dispatcher(ConsensusTipRequest).await;
    result.unwrap();
    //assert!(matches!(result, Err(SiaApiClientError::Timeout(_))));
}


// TODO all of the following must be adapted to use Docker Sia node
#[tokio::test]
#[ignore]
async fn test_api_client_invalid_auth() {
    let api_client = SiaApiClientImpl::new(Url::parse("http://127.0.0.1:9980").unwrap(), "password").unwrap();
    let result = api_client.dispatcher(ConsensusTipRequest).await;
    assert!(matches!(result, Err(SiaApiClientError::BuildError(_))));
}

// TODO must be adapted to use Docker Sia node
#[tokio::test]
#[ignore]
async fn test_api_client() {
    let api_client = SiaApiClientImpl::new(Url::parse("http://127.0.0.1:9980").unwrap(), "password").unwrap();
    let _result = api_client.dispatcher(ConsensusTipRequest).await;
}

#[tokio::test]
#[ignore]
async fn test_api_get_addresses_balance() {
    let api_client = SiaApiClientImpl::new(Url::parse("http://127.0.0.1:9980").unwrap(), "password").unwrap();
    let address =
        Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f").unwrap();
    let result = api_client.get_address_balance(&address).await.unwrap();
    println!("ret {:?}", result);
}

#[tokio::test]
#[ignore]
async fn test_api_get_addresses_balance_invalid() {
    let api_client = SiaApiClientImpl::new(Url::parse("http://127.0.0.1:9980").unwrap(), "password").unwrap();
    let result = api_client.get_address_balance_str("foo").await.unwrap();
    println!("ret {:?}", result);
}
*/
