use mm2_err_handle::prelude::{MmError, MmResult};
use relay_rpc::rpc::params::session::{ProposeNamespace, ProposeNamespaces};
use std::{collections::{BTreeMap, BTreeSet},
          str::FromStr};

use crate::error::WalletConnectError;

pub(crate) const SUPPORTED_PROTOCOL: &str = "irn";

pub(crate) const COSMOS_SUPPORTED_METHODS: &[&str] = &["cosmos_getAccounts", "cosmos_signDirect", "cosmos_signAmino"];
pub(crate) const COSMOS_SUPPORTED_CHAINS: &[&str] = &["cosmos:cosmoshub-4"];

pub(crate) const ETH_SUPPORTED_METHODS: &[&str] = &["eth_signTransaction", "personal_sign"];
pub(crate) const ETH_SUPPORTED_CHAINS: &[&str] = &["eip155:1", "eip155:137"];
pub(crate) const ETH_SUPPORTED_EVENTS: &[&str] = &["accountsChanged", "chainChanged"];

#[derive(Debug)]
pub struct WcChainId {
    pub chain: WcChain,
    pub id: String,
}

impl std::fmt::Display for WcChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.chain.as_ref(), self.id)
    }
}

impl WcChainId {
    pub fn new_eip155(id: String) -> Self {
        Self {
            chain: WcChain::Eip155,
            id,
        }
    }

    pub fn new_cosmos(id: String) -> Self {
        Self {
            chain: WcChain::Cosmos,
            id,
        }
    }

    pub fn try_from_str(chain_id: &str) -> MmResult<Self, WalletConnectError> {
        let sp = chain_id.split(':').collect::<Vec<_>>();
        if sp.len() != 2 {
            return MmError::err(WalletConnectError::InvalidChainId(chain_id.to_string()));
        };

        Ok(Self {
            chain: WcChain::from_str(sp[0])?,
            id: sp[1].to_owned(),
        })
    }

    pub(crate) fn chain_id_from_id(&self, id: &str) -> String { format!("{}:{}", self.chain.as_ref(), id) }
}

#[derive(Debug)]
pub enum WcChain {
    Eip155,
    Cosmos,
}

impl FromStr for WcChain {
    type Err = MmError<WalletConnectError>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "eip155" => Ok(WcChain::Eip155),
            "cosmos" => Ok(WcChain::Cosmos),
            _ => MmError::err(WalletConnectError::InvalidChainId(format!(
                "chain_id not supported: {s}"
            ))),
        }
    }
}

impl AsRef<str> for WcChain {
    fn as_ref(&self) -> &str {
        match self {
            Self::Eip155 => "eip155",
            Self::Cosmos => "cosmos",
        }
    }
}

#[derive(Debug, Clone)]
pub enum WcRequestMethods {
    CosmosSignDirect,
    CosmosSignAmino,
    CosmosGetAccounts,
    EthSignTransaction,
    PersonalSign,
}

impl AsRef<str> for WcRequestMethods {
    fn as_ref(&self) -> &str {
        match self {
            Self::CosmosSignDirect => "cosmos_signDirect",
            Self::CosmosSignAmino => "cosmos_signAmino",
            Self::CosmosGetAccounts => "cosmos_getAccounts",
            Self::EthSignTransaction => "eth_signTransaction",
            Self::PersonalSign => "personal_sign",
        }
    }
}

pub(crate) fn build_default_required_namespaces() -> ProposeNamespaces {
    let required = BTreeMap::from([(WcChain::Eip155.as_ref().to_string(), ProposeNamespace {
        events: ETH_SUPPORTED_EVENTS.iter().map(|m| m.to_string()).collect(),
        chains: ETH_SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
        methods: ETH_SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
    })]);

    ProposeNamespaces(required)
}

pub(crate) fn build_optional_namespaces() -> ProposeNamespaces {
    let required = BTreeMap::from([(WcChain::Cosmos.as_ref().to_string(), ProposeNamespace {
        methods: COSMOS_SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        chains: COSMOS_SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
        events: BTreeSet::default(),
    })]);

    ProposeNamespaces(required)
}
