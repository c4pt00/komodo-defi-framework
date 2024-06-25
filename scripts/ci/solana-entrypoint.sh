#!/bin/bash

# Starting Solana Local Node
solana-test-validator > /var/log/validator.log 2>&1 &
sleep 10

# Deploying the program
solana config set --url http://127.0.0.1:8899 && \
solana-keygen new --no-passphrase --outfile /root/.config/solana/id.json && \
solana airdrop 10 --url http://127.0.0.1:8899 && \
solana program deploy --keypair /root/.config/solana/id.json /tmp/program.so > /var/log/deploy.log
export PROGRAM_ID=$(grep -oP '(?<=Program Id: )\w+' /var/log/deploy.log)

sleep infinity
# Running tests
cd /usr/src/komodo-defi-framework/mm2src/coins && cargo test --features enable-solana
