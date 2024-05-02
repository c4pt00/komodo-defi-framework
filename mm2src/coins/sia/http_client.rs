use crate::sia::address::Address;
use crate::sia::http_endpoints::{AddressBalanceRequest, AddressBalanceResponse, ConsensusTipRequest, SiaApiRequest};
use crate::sia::SiaHttpConf;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _; // required for .encode() method
use core::fmt::Display;
use core::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Error as ReqwestError, Url};
use serde::de::DeserializeOwned;

#[derive(Debug, Clone)]
pub struct SiaApiClient {
    client: Client,
    conf: SiaHttpConf,
}

// this is neccesary to show the URL in error messages returned to the user
// this can be removed in favor of using ".with_url()" once reqwest is updated to v0.11.23
#[derive(Debug)]
pub struct ReqwestErrorWithUrl {
    error: ReqwestError,
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
    ReqwestFetchError(ReqwestErrorWithUrl), // TODO make an enum
    ReqwestParseError(ReqwestErrorWithUrl),
    ReqwestTlsError(ReqwestErrorWithUrl),
    UrlParse(url::ParseError),
    UnexpectedHttpStatus(u16),
    ApiInternalError(String),
}

impl From<SiaApiClientError> for String {
    fn from(e: SiaApiClientError) -> Self { format!("{:?}", e) }
}

/// Generic function to fetch data from a URL and deserialize it into a specified type.
async fn fetch_and_parse<T: DeserializeOwned>(client: &Client, url: Url) -> Result<T, SiaApiClientError> {
    let fetched = client.get(url.clone()).send().await.map_err(|e| {
        SiaApiClientError::ReqwestFetchError(ReqwestErrorWithUrl {
            error: e,
            url: url.clone(),
        })
    })?;
    let status = fetched.status().as_u16();
    match status {
        200 => {},
        500 => {
            // FIXME handle unwrap gracefully
            return Err(SiaApiClientError::ApiInternalError(fetched.text().await.unwrap()));
        },
        _ => {
            return Err(SiaApiClientError::UnexpectedHttpStatus(status));
        },
    }
    // COME BACK TO THIS - handle OK 200 but unexpected response
    // eg, internal error or user error
    fetched
        .json::<T>()
        .await
        .map_err(|e| SiaApiClientError::ReqwestParseError(ReqwestErrorWithUrl { error: e, url }))
}

/// Implements the methods for sending specific requests and handling their responses.
impl SiaApiClient {
    /// Constructs a new instance of the API client using the provided base URL and password for authentication.
    pub async fn new(conf: SiaHttpConf) -> Result<Self, SiaApiClientError> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Basic {}", BASE64.encode(format!(":{}", conf.password)));
        headers.insert(
            AUTHORIZATION,
            // This error does not require a test case as it is impossible to trigger in practice
            // the from_str method can only return Err if the str is invalid ASCII
            // the encode() method can only return valid ASCII
            HeaderValue::from_str(&auth_value).map_err(|e| SiaApiClientError::BuildError(e.to_string()))?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10)) // TODO make this configurable
            .build()
            // covering this with a unit test seems to require altering the system's ssl certificates
            .map_err(|e| {
                SiaApiClientError::ReqwestTlsError(ReqwestErrorWithUrl {
                    error: e,
                    url: conf.url.clone(),
                })
            })?;
        let ret = SiaApiClient { client, conf };
        ret.dispatcher(ConsensusTipRequest).await?;
        Ok(ret)
    }

    /// General method for dispatching requests, handling routing and response parsing.
    pub async fn dispatcher<R: SiaApiRequest + Send>(&self, request: R) -> Result<R::Response, SiaApiClientError> {
        let req = request.to_http_request(&self.conf.url)?;
        fetch_and_parse::<R::Response>(&self.client, req.url().clone()).await
    }

    pub async fn current_height(&self) -> Result<u64, SiaApiClientError> {
        let response = self.dispatcher(ConsensusTipRequest).await?;
        Ok(response.height)
    }

    pub async fn address_balance(&self, address: Address) -> Result<AddressBalanceResponse, SiaApiClientError> {
        self.dispatcher(AddressBalanceRequest { address }).await
    }
}
/*
WIP: None of these belong in this file. They must be handled in the Docker test suite

#[cfg(test)] use std::str::FromStr;
#[cfg(test)]
const TEST_URL: &str = "http://localhost:9980/";

#[tokio::test]
async fn test_api_client_new_connection_refused() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:19999").unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await;
    match api_client {
        Err(SiaApiClientError::ReqwestFetchError(e)) => assert!(e.error.is_connect()),
        _ => panic!("unexpected result: {:?}", api_client),
    }
}

#[tokio::test]
#[ignore] // WIP COME BACK
async fn test_api_address_balance() {
    let conf = SiaHttpConf {
        url: Url::parse(TEST_URL).unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await.unwrap();

    let address = Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f").unwrap();

    let balance_resp = api_client.address_balance(address).await.unwrap();
    println!("balance_resp: {:?}", balance_resp);
}

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
