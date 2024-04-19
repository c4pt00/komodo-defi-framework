use crate::docker_tests::eth_docker_tests::{erc1155_balance, erc1155_contract, erc712_owner, erc721_contract,
                                            global_nft_with_random_privkey, nft_maker_swap_v2, TestNftType};
use bitcrypto::sha256;
use coins::eth::EthCoin;
use coins::nft::nft_structs::ContractType;
use coins::{ConfirmPaymentInput, MakerNftSwapOpsV2, MarketCoinOps, NftSwapInfo, ParseCoinAssocTypes,
            SendNftMakerPaymentArgs, SpendNftMakerPaymentArgs, SwapOps, ToBytes, Transaction,
            ValidateNftMakerPaymentArgs};
use common::{block_on, now_sec};
use ethereum_types::U256;
use futures01::Future;
use mm2_number::BigUint;

#[test]
fn send_and_spend_erc721_maker_payment() {
    // TODO: Evaluate implementation strategy — either employing separate contracts for maker and taker
    // functionalities for both coins and NFTs, or utilizing the Diamond Standard (EIP-2535) for a unified contract approach.
    // Decision will inform whether to maintain multiple "swap_contract_address" fields in `EthCoin` for distinct contract types
    // or a singular field for a Diamond Standard-compatible contract address.

    let erc721_nft = TestNftType::Erc721 { token_id: 2 };

    let maker_global_nft = global_nft_with_random_privkey(nft_maker_swap_v2(), Some(erc721_nft));
    let taker_global_nft = global_nft_with_random_privkey(nft_maker_swap_v2(), None);

    let time_lock = now_sec() + 1000;
    let maker_pubkey = maker_global_nft.derive_htlc_pubkey(&[]);
    let taker_pubkey = taker_global_nft.derive_htlc_pubkey(&[]);

    let maker_secret = &[1; 32];
    let maker_secret_hash = sha256(maker_secret).to_vec();

    let nft_swap_info = NftSwapInfo {
        token_address: &erc721_contract(),
        token_id: &BigUint::from(2u32).to_bytes(),
        contract_type: &ContractType::Erc721,
        swap_contract_address: &nft_maker_swap_v2(),
    };

    let send_payment_args: SendNftMakerPaymentArgs<EthCoin> = SendNftMakerPaymentArgs {
        time_lock,
        taker_secret_hash: &[0; 32],
        maker_secret_hash: &maker_secret_hash,
        amount: 1.into(),
        taker_pub: &taker_global_nft.parse_pubkey(&taker_pubkey).unwrap(),
        swap_unique_data: &[],
        nft_swap_info: &nft_swap_info,
    };
    let maker_payment = block_on(maker_global_nft.send_nft_maker_payment_v2(send_payment_args)).unwrap();
    log!("Maker sent ERC721 NFT Payment tx hash {:02x}", maker_payment.tx_hash());

    let confirm_input = ConfirmPaymentInput {
        payment_tx: maker_payment.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 70,
        check_every: 1,
    };
    maker_global_nft.wait_for_confirmations(confirm_input).wait().unwrap();

    let validate_args = ValidateNftMakerPaymentArgs {
        maker_payment_tx: &maker_payment,
        time_lock,
        taker_secret_hash: &[1; 32],
        maker_secret_hash: &maker_secret_hash,
        amount: 1.into(),
        taker_pub: &taker_global_nft.parse_pubkey(&taker_pubkey).unwrap(),
        maker_pub: &maker_global_nft.parse_pubkey(&maker_pubkey).unwrap(),
        swap_unique_data: &[],
        nft_swap_info: &nft_swap_info,
    };
    block_on(maker_global_nft.validate_nft_maker_payment_v2(validate_args)).unwrap();

    let spend_payment_args = SpendNftMakerPaymentArgs {
        maker_payment_tx: &maker_payment,
        time_lock,
        taker_secret_hash: &[0; 32],
        maker_secret_hash: &maker_secret_hash,
        maker_secret,
        maker_pub: &maker_global_nft.parse_pubkey(&maker_pubkey).unwrap(),
        swap_unique_data: &[],
        contract_type: &ContractType::Erc721,
        swap_contract_address: &nft_maker_swap_v2(),
    };
    let spend_tx = block_on(taker_global_nft.spend_nft_maker_payment_v2(spend_payment_args)).unwrap();

    let confirm_input = ConfirmPaymentInput {
        payment_tx: spend_tx.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 70,
        check_every: 1,
    };
    taker_global_nft.wait_for_confirmations(confirm_input).wait().unwrap();

    let new_owner = erc712_owner(U256::from(2));
    assert_eq!(new_owner, taker_global_nft.my_address);
}

#[test]
fn send_and_spend_erc1155_maker_payment() {
    let erc1155_nft = TestNftType::Erc1155 { token_id: 4, amount: 3 };

    let maker_global_nft = global_nft_with_random_privkey(nft_maker_swap_v2(), Some(erc1155_nft));
    let taker_global_nft = global_nft_with_random_privkey(nft_maker_swap_v2(), None);

    let time_lock = now_sec() + 1000;
    let maker_pubkey = maker_global_nft.derive_htlc_pubkey(&[]);
    let taker_pubkey = taker_global_nft.derive_htlc_pubkey(&[]);

    let maker_secret = &[1; 32];
    let maker_secret_hash = sha256(maker_secret).to_vec();

    let nft_swap_info = NftSwapInfo {
        token_address: &erc1155_contract(),
        token_id: &BigUint::from(4u32).to_bytes(),
        contract_type: &ContractType::Erc1155,
        swap_contract_address: &nft_maker_swap_v2(),
    };

    let send_payment_args: SendNftMakerPaymentArgs<EthCoin> = SendNftMakerPaymentArgs {
        time_lock,
        taker_secret_hash: &[0; 32],
        maker_secret_hash: &maker_secret_hash,
        amount: 3.into(),
        taker_pub: &taker_global_nft.parse_pubkey(&taker_pubkey).unwrap(),
        swap_unique_data: &[],
        nft_swap_info: &nft_swap_info,
    };
    let maker_payment = block_on(maker_global_nft.send_nft_maker_payment_v2(send_payment_args)).unwrap();
    log!("Maker sent ERC1155 NFT Payment tx hash {:02x}", maker_payment.tx_hash());

    let confirm_input = ConfirmPaymentInput {
        payment_tx: maker_payment.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    maker_global_nft.wait_for_confirmations(confirm_input).wait().unwrap();

    let validate_args = ValidateNftMakerPaymentArgs {
        maker_payment_tx: &maker_payment,
        time_lock,
        taker_secret_hash: &[1; 32],
        maker_secret_hash: &maker_secret_hash,
        amount: 3.into(),
        taker_pub: &taker_global_nft.parse_pubkey(&taker_pubkey).unwrap(),
        maker_pub: &maker_global_nft.parse_pubkey(&maker_pubkey).unwrap(),
        swap_unique_data: &[],
        nft_swap_info: &nft_swap_info,
    };
    block_on(maker_global_nft.validate_nft_maker_payment_v2(validate_args)).unwrap();

    let spend_payment_args = SpendNftMakerPaymentArgs {
        maker_payment_tx: &maker_payment,
        time_lock,
        taker_secret_hash: &[0; 32],
        maker_secret_hash: &maker_secret_hash,
        maker_secret,
        maker_pub: &maker_global_nft.parse_pubkey(&maker_pubkey).unwrap(),
        swap_unique_data: &[],
        contract_type: &ContractType::Erc1155,
        swap_contract_address: &nft_maker_swap_v2(),
    };
    let spend_tx = block_on(taker_global_nft.spend_nft_maker_payment_v2(spend_payment_args)).unwrap();

    let confirm_input = ConfirmPaymentInput {
        payment_tx: spend_tx.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    taker_global_nft.wait_for_confirmations(confirm_input).wait().unwrap();

    let balance = erc1155_balance(taker_global_nft.my_address, U256::from(4));
    assert_eq!(balance, U256::from(3));
}
