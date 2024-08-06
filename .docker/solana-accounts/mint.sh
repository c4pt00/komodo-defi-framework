#!/bin/bash

# Directory containing the accounts
ACCOUNTS_DIR="./accounts"
# Amount of tokens to mint for each account (in smallest unit, e.g., lamports if the token has 9 decimals)
MINT_AMOUNT_USDC=1000000000  # 1000 USDC if the token has 6 decimals
MINT_AMOUNT_ADEX=1000000000  # 1 ADEX if the token has 9 decimals
# Path to your keypair file
AUTHORITY_KEYPAIR=/root/accounts/iguana
# Path to the fee payer keypair file
FEE_PAYER_KEYPAIR=/root/accounts/iguana
# Ensure the solana-test-validator is running and solana-cli is set to use local network
solana config set --url http://127.0.0.1:8899
solana config set --keypair /root/accounts/iguana
# Create new SPL tokens with your keypair as the mint authority
USDC_TOKEN=$(spl-token create-token --decimals 6 --mint-authority "$AUTHORITY_KEYPAIR" --fee-payer "$FEE_PAYER_KEYPAIR" | grep -o -E 'Creating token [A-Za-z0-9]+' | awk '{print $3}')
ADEX_TOKEN=$(spl-token create-token --decimals 9 --mint-authority "$AUTHORITY_KEYPAIR" --fee-payer "$FEE_PAYER_KEYPAIR" | grep -o -E 'Creating token [A-Za-z0-9]+' | awk '{print $3}')

echo "Created new USDC token: $USDC_TOKEN"
echo "Created new ADEX token: $ADEX_TOKEN"
spl-token create-account "$USDC_TOKEN" --owner "$ACCOUNTS_DIR"/iguana
spl-token create-account "$ADEX_TOKEN" --owner "$ACCOUNTS_DIR"/iguana
spl-token mint "$USDC_TOKEN" 100000
spl-token mint "$ADEX_TOKEN" 100000
# Iterate over each account file in the directory
for ACCOUNT_FILE in "$ACCOUNTS_DIR"/*.json; do
    echo "Processing account: $ACCOUNT_FILE"

    # Extract the public key from the account file
    PUBKEY=$(jq -r '.pubkey' "$ACCOUNT_FILE")

    # Create associated token account for USDC if it doesn't exist
    USDC_ASSOCIATED_TOKEN_ADDRESS=$(spl-token accounts --owner "$PUBKEY" | grep "$USDC_TOKEN" | awk '{print $1}')
    if [ -z "$USDC_ASSOCIATED_TOKEN_ADDRESS" ]; then
        USDC_ASSOCIATED_TOKEN_ADDRESS=$(spl-token create-account "$USDC_TOKEN" --owner "$PUBKEY" --fee-payer "$FEE_PAYER_KEYPAIR" | grep -o -E 'Creating account [A-Za-z0-9]+' | awk '{print $3}')
        echo "Created associated token account for USDC: $USDC_ASSOCIATED_TOKEN_ADDRESS"
    else
        echo "Associated token account for USDC already exists: $USDC_ASSOCIATED_TOKEN_ADDRESS"
    fi

    # Create associated token account for ADEX if it doesn't exist
    ADEX_ASSOCIATED_TOKEN_ADDRESS=$(spl-token accounts --owner "$PUBKEY" | grep "$ADEX_TOKEN" | awk '{print $1}')
    if [ -z "$ADEX_ASSOCIATED_TOKEN_ADDRESS" ]; then
        ADEX_ASSOCIATED_TOKEN_ADDRESS=$(spl-token create-account "$ADEX_TOKEN" --owner "$PUBKEY" --fee-payer "$FEE_PAYER_KEYPAIR" | grep -o -E 'Creating account [A-Za-z0-9]+' | awk '{print $3}')
        echo "Created associated token account for ADEX: $ADEX_ASSOCIATED_TOKEN_ADDRESS"
    else
        echo "Associated token account for ADEX already exists: $ADEX_ASSOCIATED_TOKEN_ADDRESS"
    fi

    # Mint USDC tokens to the associated token account
    echo "Minting $MINT_AMOUNT_USDC USDC tokens"
    spl-token mint "$USDC_TOKEN" "$MINT_AMOUNT_USDC" --mint-authority "$AUTHORITY_KEYPAIR" --recipient-owner "$PUBKEY" --fee-payer "$FEE_PAYER_KEYPAIR"

    # Mint ADEX tokens to the associated token account
    echo "Minting $MINT_AMOUNT_ADEX ADEX tokens"
    spl-token mint "$ADEX_TOKEN" "$MINT_AMOUNT_ADEX" --mint-authority "$AUTHORITY_KEYPAIR" --recipient-owner "$PUBKEY" --fee-payer "$FEE_PAYER_KEYPAIR"

    # Check the balance of the token accounts
    USDC_BALANCE=$(spl-token balance "$USDC_TOKEN" --owner "$PUBKEY")
    ADEX_BALANCE=$(spl-token balance "$ADEX_TOKEN" --owner "$PUBKEY")
    echo "Account: $PUBKEY, USDC Token Balance: $USDC_BALANCE, ADEX Token Balance: $ADEX_BALANCE"
done

echo $USDC_TOKEN > /root/accounts/usdc_token_address
echo $ADEX_TOKEN > /root/accounts/adex_token_address

echo "New token addresses:"
echo "USDC Token Address: $USDC_TOKEN"
echo "ADEX Token Address: $ADEX_TOKEN"
