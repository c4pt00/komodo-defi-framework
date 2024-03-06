use core::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use std::ops::Deref;
use std::sync::Arc;

/// HTTP(s) client for Sia-protocol coins
#[derive(Debug)]
pub struct SiaHttpClientImpl {
    /// Name of coin the http client is intended to work with
    pub coin_ticker: String,
    /// The uri to send requests to
    pub uri: String,
    /// Value of Authorization header password, e.g. "Basic base64(:password)"
    pub auth: String,
}

#[derive(Clone, Debug)]
pub struct SiaApiClient(pub Arc<SiaApiClientImpl>);
impl Deref for SiaApiClient {
    type Target = SiaApiClientImpl;
    fn deref(&self) -> &SiaApiClientImpl { &self.0 }
}

impl SiaApiClient {
    pub fn new(_coin_ticker: &str, uri: &str, auth: &str) -> Result<Self, SiaApiClientError> {
        let new_arc = SiaApiClientImpl::new(uri, auth)?;
        Ok(SiaApiClient(Arc::new(new_arc)))
    }
}

#[derive(Debug)]
pub struct SiaApiClientImpl {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Display)]

pub enum SiaApiClientError {
    Timeout(String),
    BuildError(String),
    ApiUnreachable(String),
}

impl From<reqwest::Error> for SiaApiClientError {
    fn from(e: reqwest::Error) -> Self { SiaApiClientError::Timeout(format!("reqwest failure: {}", e)) }
}

impl From<SiaApiClientError> for String {
    fn from(e: SiaApiClientError) -> Self { format!("{:?}", e) }
}

// https://github.com/SiaFoundation/core/blob/4e46803f702891e7a83a415b7fcd7543b13e715e/types/types.go#L181
#[derive(Deserialize, Serialize, Debug)]
pub struct GetConsensusTipResponse {
    pub height: u64,
    pub id: String, // TODO this can match "BlockID" type
}

impl SiaApiClientImpl {
    fn new(base_url: &str, password: &str) -> Result<Self, SiaApiClientError> {
        let mut headers = HeaderMap::new();
        let auth_value = format!("Basic {}", base64::encode(&format!(":{}", password)));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).map_err(|e| SiaApiClientError::BuildError(e.to_string()))?,
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| SiaApiClientError::BuildError(e.to_string()))?;

        Ok(SiaApiClientImpl {
            client,
            base_url: base_url.to_string(),
        })
    }

    pub async fn get_consensus_tip(&self) -> Result<GetConsensusTipResponse, SiaApiClientError> {
        let response = self
            .client
            .get(format!("{}/api/consensus/tip", self.base_url))
            .send()
            .await?
            .json::<GetConsensusTipResponse>()
            .await?;
        Ok(response)
    }

    pub async fn get_height(&self) -> Result<u64, SiaApiClientError> {
        let resp = self.get_consensus_tip().await?;
        Ok(resp.height)
    }
}

#[tokio::test]
async fn test_api_client_timeout() {
    let api_client = SiaApiClientImpl::new("http://foo", "password").unwrap();
    let result = api_client.get_consensus_tip().await;
    assert!(matches!(result, Err(SiaApiClientError::Timeout(_))));
}

// TODO must be adapted to use Docker Sia node
#[tokio::test]
async fn test_api_client_invalid_auth() {
    let api_client = SiaApiClientImpl::new("http://127.0.0.1:9980", "password").unwrap();
    let result = api_client.get_consensus_tip().await;
    assert!(matches!(result, Err(SiaApiClientError::BuildError(_))));
}

// TODO must be adapted to use Docker Sia node
#[tokio::test]
async fn test_api_client() {
    let api_client = SiaApiClientImpl::new("http://127.0.0.1:9980", "password").unwrap();
    let result = api_client.get_consensus_tip().await.unwrap();
}
