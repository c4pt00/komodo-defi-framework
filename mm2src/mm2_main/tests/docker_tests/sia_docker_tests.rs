use coins::sia::http_endpoints::{ConsensusTipRequest, AddressBalanceRequest};
use coins::sia::http_client::SiaApiClient;
use coins::sia::SiaHttpConf;
use url::Url;

#[tokio::test]
async fn test_sia_client() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "password".to_string(),
    };
    let _api_client = SiaApiClient::new(conf).await.unwrap();
}

#[tokio::test]
async fn test_sia_client_bad_auth() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "foo".to_string(),
    };
    let _api_client = SiaApiClient::new(conf).await.unwrap();
}