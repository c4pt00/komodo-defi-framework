#!/bin/bash
solana-test-validator > validator.log 2>&1 &
sleep 10
solana program deploy /usr/src/satomic-swap/target/sbf-solana-solana/release/satomic_swap.so > deploy.log
PROGRAM_ID=$(grep -oP '(?<=Program Id: )\w+' deploy.log)
solana airdrop 10 > airdrop.log
export PROGRAM_ID=$PROGRAM_ID

sleep infinity
# cd /usr/src/komodo-defi-framework/mm2src/
# cargo test
