use crate::docker_tests::{docker_tests_common::SOL_USDC_PUBKEY,
                          solana_common_tests::{solana_coin_for_test, spl_coin_for_test, SolanaNet, ACCOUNT_PUBKEY,
                                                ADDITIONAL_PASSPHRASE, PASSPHRASE}};
use coins::{solana::solana_sdk, MarketCoinOps, MmCoin, WithdrawRequest};
use common::{block_on, Future01CompatExt};
use mm2_number::BigDecimal;
use std::{env, ops::Neg, str::FromStr};

const USDC: &str = "USDC";
const ADEX: &str = "ADEX";
const WSOL: &str = "WSOL";
const ADEX_PUBKEY: &str = "3e9KpjwQejx9Y7WkfaXJTybH6ecG7AdXoAoxk279hdFh";
const WSOL_PUBKEY: &str = "So11111111111111111111111111111111111111112";
const SIGNATURE: &str = "4dzKwEteN8nch76zPMEjPX19RsaQwGTxsbtfg2bwGTkGenLfrdm31zvn9GH5rvaJBwivp6ESXx1KYR672ngs3UfF";
const VERIFY_PUBKEY: &str = "8UF6jSVE1jW8mSiGqt8Hft1rLwPjdKLaTfhkNozFwoAG";
const VERIFY_MESSAGE: &str = "test";
const PUBKEY_FOR_USDC: &str = "CpMah17kQEL2wqyMKt3mZBdTnZbkbfx4nqmQMFDP5vwp";

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn spl_coin_creation() {
    let (_, sol_coin) = solana_coin_for_test(PASSPHRASE.to_owned(), SolanaNet::Local);
    let sol_spl_usdc_coin = spl_coin_for_test(
        sol_coin,
        USDC.to_string(),
        6,
        solana_sdk::pubkey::Pubkey::from_str(ADEX_PUBKEY).unwrap(),
    );

    log!("address: {}", sol_spl_usdc_coin.my_address().unwrap());
    assert_eq!(sol_spl_usdc_coin.my_address().unwrap(), ACCOUNT_PUBKEY,);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sign_message() {
    let (_, sol_coin) = solana_coin_for_test(ADDITIONAL_PASSPHRASE.to_owned(), SolanaNet::Local);
    let sol_spl_usdc_coin = spl_coin_for_test(
        sol_coin,
        USDC.to_string(),
        6,
        solana_sdk::pubkey::Pubkey::from_str(PUBKEY_FOR_USDC).unwrap(),
    );
    let signature = sol_spl_usdc_coin.sign_message(VERIFY_MESSAGE).unwrap();
    assert_eq!(signature, SIGNATURE);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_verify_message() {
    let (_, sol_coin) = solana_coin_for_test(ADDITIONAL_PASSPHRASE.to_owned(), SolanaNet::Local);
    let sol_spl_usdc_coin = spl_coin_for_test(
        sol_coin,
        USDC.to_string(),
        6,
        solana_sdk::pubkey::Pubkey::from_str(PUBKEY_FOR_USDC).unwrap(),
    );
    let is_valid = sol_spl_usdc_coin
        .verify_message(SIGNATURE, VERIFY_MESSAGE, VERIFY_PUBKEY)
        .unwrap();
    assert!(is_valid);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn spl_my_balance() {
    let adex_token_address = env::var("ADEX_TOKEN_ADDRESS").expect("ADEX_TOKEN_ADDRESS not set");
    let (_, sol_coin) = solana_coin_for_test(PASSPHRASE.to_owned(), SolanaNet::Local);
    let sol_spl_adex_coin = spl_coin_for_test(
        sol_coin.clone(),
        ADEX.to_string(),
        9,
        solana_sdk::pubkey::Pubkey::from_str(&adex_token_address).unwrap(),
    );

    let res = block_on(sol_spl_adex_coin.my_balance().compat()).unwrap();
    assert_ne!(res.spendable, BigDecimal::from(0));
    assert!(res.spendable < BigDecimal::from(1000000001));

    let sol_spl_wsol_coin = spl_coin_for_test(
        sol_coin,
        WSOL.to_string(),
        8,
        solana_sdk::pubkey::Pubkey::from_str(WSOL_PUBKEY).unwrap(),
    );
    let res = block_on(sol_spl_wsol_coin.my_balance().compat()).unwrap();
    assert_eq!(res.spendable, BigDecimal::from(0));
}

// Stop ignoring when Solana is released
#[test]
#[ignore]
#[cfg(not(target_arch = "wasm32"))]
fn test_spl_transactions() {
    let (_, sol_coin) = solana_coin_for_test(PASSPHRASE.to_owned(), SolanaNet::Local);
    let usdc_sol_coin = spl_coin_for_test(
        sol_coin,
        USDC.to_string(),
        6,
        solana_sdk::pubkey::Pubkey::from_str(SOL_USDC_PUBKEY).unwrap(),
    );
    let withdraw_amount = BigDecimal::from_str("0.0001").unwrap();
    let valid_tx_details = block_on(
        usdc_sol_coin
            .withdraw(WithdrawRequest::new(
                USDC.to_string(),
                None,
                "AYJmtzc9D4KU6xsDzhKShFyYKUNXY622j9QoQEo4LfpX".to_string(),
                withdraw_amount.clone(),
                false,
                None,
                None,
            ))
            .compat(),
    )
    .unwrap();
    log!("{:?}", valid_tx_details);
    assert_eq!(valid_tx_details.total_amount, withdraw_amount);
    assert_eq!(valid_tx_details.my_balance_change, withdraw_amount.neg());
    assert_eq!(valid_tx_details.coin, USDC.to_string());
    assert_ne!(valid_tx_details.timestamp, 0);

    let tx_str = hex::encode(&*valid_tx_details.tx.tx_hex().unwrap().0);
    let res = block_on(usdc_sol_coin.send_raw_tx(&tx_str).compat()).unwrap();
    log!("{:?}", res);

    let res2 = block_on(
        usdc_sol_coin
            .send_raw_tx_bytes(&valid_tx_details.tx.tx_hex().unwrap().0)
            .compat(),
    )
    .unwrap();
    assert_eq!(res, res2);
}
