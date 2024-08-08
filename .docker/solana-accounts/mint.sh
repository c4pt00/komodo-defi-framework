#!/bin/bash

MINT_AMOUNT_USDC=1000000000
MINT_AMOUNT_ADEX=1000000000

OWNER_KEYPAIR=/root/accounts/iguana

solana config set --url http://127.0.0.1:8899
solana config set --keypair "$OWNER_KEYPAIR"

USDC_TOKEN=$(spl-token create-token --decimals 6 --mint-authority "$OWNER_KEYPAIR" --fee-payer "$OWNER_KEYPAIR" | grep -o -E 'Creating token [A-Za-z0-9]+' | awk '{print $3}')
ADEX_TOKEN=$(spl-token create-token --decimals 9 --mint-authority "$OWNER_KEYPAIR" --fee-payer "$OWNER_KEYPAIR" | grep -o -E 'Creating token [A-Za-z0-9]+' | awk '{print $3}')

spl-token create-account "$USDC_TOKEN" --owner "$OWNER_KEYPAIR"
spl-token create-account "$ADEX_TOKEN" --owner "$OWNER_KEYPAIR"

spl-token mint "$USDC_TOKEN" 100000
spl-token mint "$ADEX_TOKEN" 100000

echo "New token addresses:"
echo "USDC Token Address: $USDC_TOKEN"
echo "ADEX Token Address: $ADEX_TOKEN"
