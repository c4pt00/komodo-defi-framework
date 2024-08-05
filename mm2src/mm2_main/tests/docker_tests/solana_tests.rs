use serde_json as json;

use mm2_number::bigdecimal::Zero;
use mm2_test_helpers::for_tests::{disable_coin, enable_solana_with_tokens, enable_spl, sign_message, verify_message};
use mm2_test_helpers::structs::{EnableSolanaWithTokensResponse, EnableSplResponse, RpcV2Response, SignatureResponse,
                                VerificationResponse};

use crate::docker_tests::docker_tests_common::*;
use coins::solana::solana_tests::{solana_coin_send_and_refund_maker_payment, solana_coin_send_and_spend_maker_payment,
                                  solana_keypair_from_secp, solana_test_transactions, solana_transaction_simulations,
                                  solana_transaction_simulations_not_enough_for_fees, solana_transaction_zero_balance};

const SOLANA_CLIENT_URL: &str = "http://localhost:8899";

#[test]
fn test_solana_and_spl_balance_enable_spl_v2() {
    let mm = _solana_supplied_node();
    let tx_history = false;
    let enable_solana_with_tokens = block_on(enable_solana_with_tokens(
        &mm,
        "SOL-DEVNET",
        &["USDC-SOL-DEVNET"],
        SOLANA_CLIENT_URL,
        tx_history,
    ));
    let enable_solana_with_tokens: RpcV2Response<EnableSolanaWithTokensResponse> =
        json::from_value(enable_solana_with_tokens).unwrap();

    let (_, solana_balance) = enable_solana_with_tokens
        .result
        .solana_addresses_infos
        .into_iter()
        .next()
        .unwrap();
    assert!(solana_balance.balances.unwrap().spendable > 0.into());

    let spl_balances = enable_solana_with_tokens
        .result
        .spl_addresses_infos
        .into_iter()
        .next()
        .unwrap()
        .1
        .balances
        .unwrap();
    let usdc_spl = spl_balances.get("USDC-SOL-DEVNET").unwrap();
    assert!(usdc_spl.spendable.is_zero());

    let enable_spl = block_on(enable_spl(&mm, "ADEX-SOL-DEVNET"));
    let enable_spl: RpcV2Response<EnableSplResponse> = json::from_value(enable_spl).unwrap();
    assert_eq!(1, enable_spl.result.balances.len());

    let (_, balance) = enable_spl.result.balances.into_iter().next().unwrap();
    assert!(balance.spendable > 0.into());
}

#[test]
fn test_sign_verify_message_solana() {
    let mm = _solana_supplied_node();
    let tx_history = false;
    block_on(enable_solana_with_tokens(
        &mm,
        "SOL-DEVNET",
        &["USDC-SOL-DEVNET"],
        SOLANA_CLIENT_URL,
        tx_history,
    ));

    let response = block_on(sign_message(&mm, "SOL-DEVNET"));
    let response: RpcV2Response<SignatureResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert_eq!(
        response.signature,
        "3AoWCXHq3ACYHYEHUsCzPmRNiXn5c6kodXn9KDd1tz52e1da3dZKYXD5nrJW31XLtN6zzJiwHWtDta52w7Cd7qyE"
    );

    let response = block_on(verify_message(
        &mm,
        "SOL-DEVNET",
        "3AoWCXHq3ACYHYEHUsCzPmRNiXn5c6kodXn9KDd1tz52e1da3dZKYXD5nrJW31XLtN6zzJiwHWtDta52w7Cd7qyE",
        "FJktmyjV9aBHEShT4hfnLpr9ELywdwVtEL1w1rSWgbVf",
    ));
    let response: RpcV2Response<VerificationResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert!(response.is_valid);
}

#[test]
fn test_sign_verify_message_spl() {
    let mm = _solana_supplied_node();
    let tx_history = false;
    block_on(enable_solana_with_tokens(
        &mm,
        "SOL-DEVNET",
        &["USDC-SOL-DEVNET"],
        SOLANA_CLIENT_URL,
        tx_history,
    ));

    block_on(enable_spl(&mm, "ADEX-SOL-DEVNET"));

    let response = block_on(sign_message(&mm, "ADEX-SOL-DEVNET"));
    let response: RpcV2Response<SignatureResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert_eq!(
        response.signature,
        "3AoWCXHq3ACYHYEHUsCzPmRNiXn5c6kodXn9KDd1tz52e1da3dZKYXD5nrJW31XLtN6zzJiwHWtDta52w7Cd7qyE"
    );

    let response = block_on(verify_message(
        &mm,
        "ADEX-SOL-DEVNET",
        "3AoWCXHq3ACYHYEHUsCzPmRNiXn5c6kodXn9KDd1tz52e1da3dZKYXD5nrJW31XLtN6zzJiwHWtDta52w7Cd7qyE",
        "FJktmyjV9aBHEShT4hfnLpr9ELywdwVtEL1w1rSWgbVf",
    ));
    let response: RpcV2Response<VerificationResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert!(response.is_valid);
}

#[test]
fn test_disable_solana_platform_coin_with_tokens() {
    let mm = _solana_supplied_node();
    block_on(enable_solana_with_tokens(
        &mm,
        "SOL-DEVNET",
        &["USDC-SOL-DEVNET"],
        SOLANA_CLIENT_URL,
        false,
    ));
    block_on(enable_spl(&mm, "ADEX-SOL-DEVNET"));

    // Try to passive platform coin, SOL-DEVNET.
    let res = block_on(disable_coin(&mm, "SOL-DEVNET", false));
    assert!(res.passivized);

    // Try to disable ADEX-SOL-DEVNET and USDC-SOL-DEVNET
    // This should work, because platform coin is still in the memory.
    let res = block_on(disable_coin(&mm, "ADEX-SOL-DEVNET", false));
    assert!(!res.passivized);
    let res = block_on(disable_coin(&mm, "USDC-SOL-DEVNET", false));
    assert!(!res.passivized);

    // Then try to force disable SOL-DEVNET platform coin.
    let res = block_on(disable_coin(&mm, "SOL-DEVNET", true));
    assert!(!res.passivized);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn solana_keypair_from_secp_dockerized() { solana_keypair_from_secp(); }

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn solana_transaction_simulations_dockerized() { solana_transaction_simulations(); }

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn solana_transaction_zero_balance_dockerized() { solana_transaction_zero_balance(); }

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn solana_transaction_simulations_not_enough_for_fees_dockerized() {
    solana_transaction_simulations_not_enough_for_fees();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn solana_transaction_simulations_max_dockerized() { solana_transaction_simulations_not_enough_for_fees(); }

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn solana_test_transactions_dockerized() { solana_test_transactions(); }

// This test is just a unit test for brainstorming around tx_history for base_coin.
#[test]
#[ignore]
#[cfg(not(target_arch = "wasm32"))]
fn solana_test_tx_history_dockerized() { solana_test_transactions(); }

#[test]
fn solana_coin_send_and_refund_maker_payment_dockerized() { solana_coin_send_and_refund_maker_payment(); }

#[test]
fn solana_coin_send_and_spend_maker_payment_dockerized() { solana_coin_send_and_spend_maker_payment(); }
