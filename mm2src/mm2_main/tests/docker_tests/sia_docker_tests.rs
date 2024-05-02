use coins::sia::address::Address;
use coins::sia::http_client::{SiaApiClient, SiaApiClientError};
use coins::sia::http_endpoints::{AddressBalanceRequest, ConsensusTipRequest};
use coins::sia::SiaHttpConf;
use std::process::Command;
use std::str::FromStr;
use url::Url;

#[tokio::test]
async fn test_sia_new_client() {
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
    let result = SiaApiClient::new(conf).await;
    assert!(matches!(result, Err(SiaApiClientError::UnexpectedHttpStatus(401))));
}

#[tokio::test]
async fn test_sia_client_consensus_tip() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await.unwrap();
    let _response = api_client.dispatcher(ConsensusTipRequest).await.unwrap();
}

#[tokio::test]
async fn test_sia_client_address_balance() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await.unwrap();

    mine_blocks(
        10,
        Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f").unwrap(),
    );

    let request = AddressBalanceRequest {
        address: Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f")
            .unwrap(),
    };
    let result = api_client.dispatcher(request).await;

    assert!(matches!(result, Err(SiaApiClientError::ApiInternalError(_))));
    // TODO investigate why this gives an error on the API?
    // the address should have a balance at this point
}

#[tokio::test]
async fn test_sia_client_mine_blocks() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await.unwrap();
    let request = AddressBalanceRequest {
        address: Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f")
            .unwrap(),
    };
    let result = api_client.dispatcher(request).await;
    assert!(matches!(result, Err(SiaApiClientError::ApiInternalError(_))));
}

#[cfg(test)]
fn mine_blocks(n: u64, addr: Address) {
    Command::new("docker")
        .arg("exec")
        .arg("sia-docker")
        .arg("walletd")
        .arg("mine")
        .arg(format!("-addr={}", addr.to_string()))
        .arg(format!("-n={}", n))
        .status()
        .expect("Failed to execute docker command");
}

#[tokio::test]
async fn test_sia_mining() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await.unwrap();

    mine_blocks(
        10,
        Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f").unwrap(),
    );

    let consensus_tip_response = api_client.dispatcher(ConsensusTipRequest).await.unwrap();
    assert_eq!(consensus_tip_response.height, 10);
}
