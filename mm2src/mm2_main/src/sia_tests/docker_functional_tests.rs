use testcontainers::clients::Cli;

use super::*;

use crate::lp_swap::SecretHashAlgo;
use mm2_core::mm_ctx::{MmArc, MmCtxBuilder};
use mm2_main::lp_wallet::initialize_wallet_passphrase;

use tokio;

use testcontainers::{Container, GenericImage};

fn init_walletd_container(docker: &Cli) -> Container<GenericImage> {
    // Define the Docker image with a tag
    let image = GenericImage::new("docker.io/alrighttt/walletd-komodo", "latest");

    // Start the container. It will run until Container falls out of scope
    docker.run(image)
}

async fn init_ctx(passphrase: &str, netid: u16) -> MmArc {
    let kdf_conf = json!({
        "gui": "sia-docker-tests",
        "netid": netid,
        "rpc_password": "rpc_password",
        "passphrase": passphrase,
    });

    let ctx = MmCtxBuilder::new().with_conf(kdf_conf).into_mm_arc();

    initialize_wallet_passphrase(&ctx).await.unwrap();
    ctx
}

#[tokio::test]
async fn test_send_maker_payment() {
    let docker = Cli::default();

    // Start the container
    let _container = init_walletd_container(&docker);

    // let hash_algo = SecretHashAlgo::SHA256;
    // let secret = vec![0u8; 32];
    // let secret_hash = hash_algo.hash_secret(&secret);
    tokio::time::sleep(std::time::Duration::from_secs(5)).await
}
