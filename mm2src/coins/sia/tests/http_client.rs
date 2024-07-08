use crate::sia::address::Address;
use crate::sia::http_endpoints::AddressesEventsRequest;
use crate::sia::{SiaApiClient, SiaHttpConf};
use reqwest::Url;
use std::str::FromStr;

// These tests assume walletd is listening at localhost:9980 with the default password "password"
// They are likely to be removed in the future in favor of Docker based tests but are useful for now

#[tokio::test]
#[ignore]
async fn test_sia_client_address_events() {
    let conf = SiaHttpConf {
        url: Url::parse("http://localhost:9980/").unwrap(),
        password: "password".to_string(),
    };
    let api_client = SiaApiClient::new(conf).await.unwrap();

    let request = AddressesEventsRequest {
        address: Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f")
            .unwrap(),
    };
    let resp = api_client.dispatcher(request).await.unwrap();
    println!("\nresp: {:?}", resp);
}
