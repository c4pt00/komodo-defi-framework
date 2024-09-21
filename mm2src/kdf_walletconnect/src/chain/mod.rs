pub mod cosmos;

use relay_rpc::rpc::params::session::{ProposeNamespace, ProposeNamespaces};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const SUPPORTED_EVENTS: &[&str] = &["chainChanged", "accountsChanged"];

pub(crate) const ETH_SUPPORTED_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
];
pub(crate) const ETH_SUPPORTED_CHAINS: &[&str] = &["eip155:1", "eip155:5"];

pub(crate) const COSMOS_SUPPORTED_METHODS: &[&str] = &["cosmos_getAccounts", "cosmos_signDirect", "cosmos_signAmino"];
pub(crate) const COSMOS_SUPPORTED_CHAINS: &[&str] = &["cosmos:cosmoshub-4"];

#[derive(Debug, Clone)]
pub enum WcRequestMethods {
    EthSendTransaction,
    EthSignTransaction,
    EthSign,
    EthPersonalSign,
    EthSignTypedData,
    CosmosSignDirect,
    CosmosSignAmino,
    CosmosGetAccounts,
}

impl AsRef<str> for WcRequestMethods {
    fn as_ref(&self) -> &str {
        match self {
            Self::EthSignTransaction => "eth_signTransaction",
            Self::EthSendTransaction => "eth_sendTransaction",
            Self::EthSign => "eth_sign",
            Self::EthPersonalSign => "personal_sign",
            Self::EthSignTypedData => "eth_signTypedData",
            Self::CosmosSignDirect => "cosmos_signDirect",
            Self::CosmosSignAmino => "cosmos_signAmino",
            Self::CosmosGetAccounts => "cosmos_getAccounts",
        }
    }
}

pub(crate) fn build_required_namespaces() -> ProposeNamespaces {
    let mut required = BTreeMap::new();

    // build eth
    required.insert("eip155".to_string(), ProposeNamespace {
        chains: ETH_SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
        methods: ETH_SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
    });

    required.insert("cosmos".to_string(), ProposeNamespace {
        chains: COSMOS_SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
        methods: COSMOS_SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        events: BTreeSet::new(),
    });

    ProposeNamespaces(required)
}
