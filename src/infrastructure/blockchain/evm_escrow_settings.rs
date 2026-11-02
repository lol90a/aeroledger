//! Deployment settings for the Solidity escrow.
//!
//! The same all-or-nothing rule as the Solana side, for the same reason: a
//! half-configured escrow is worse than an absent one, because it issues price
//! authorizations the contract rejects for reasons no error connects back to a
//! missing variable.
//!
//! One extra thing is required here that Solana does not need — a chain id.
//! It is inside the EIP-712 domain, so an authorization signed for the wrong
//! chain is not merely useless, it is a signature for a *different contract on
//! a different network*. Getting it wrong is the one mistake in this file that
//! could matter beyond a failed payment.

use std::env;
use std::sync::Arc;

use crate::infrastructure::blockchain::eip712::parse_address;
use crate::infrastructure::blockchain::evm_escrow_gateway::EvmEscrowGateway;
use crate::infrastructure::blockchain::evm_quote_authority::EvmQuoteAuthority;

/// The contract's sentinel for the native coin (ETH, BNB).
pub const NATIVE_TOKEN: &str = "0x0000000000000000000000000000000000000000";

/// Block tag reads are made against unless overridden.
///
/// `finalized`, because a re-org can unmake a transaction `latest` already
/// reported, and settling a booking on an orphaned block releases a service
/// against a payment that no longer exists.
const DEFAULT_BLOCK_TAG: &str = "finalized";

#[derive(Clone)]
pub struct EvmEscrowSettings {
    pub contract: String,
    pub chain_id: u64,
    pub rpc_url: String,
    pub seller: String,
    pub payout_wallet: String,
    pub treasury: String,
    /// The ERC-20 escrowed, or the zero address for the native coin.
    pub token: String,
    pub block_tag: String,
    pub quote_authority: Arc<EvmQuoteAuthority>,
}

impl std::fmt::Debug for EvmEscrowSettings {
    /// Hand-written so that no formatting of this struct can emit the signing
    /// key: it is not reachable from here, only the address it derives to.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmEscrowSettings")
            .field("contract", &self.contract)
            .field("chain_id", &self.chain_id)
            .field("seller", &self.seller)
            .field("payout_wallet", &self.payout_wallet)
            .field("treasury", &self.treasury)
            .field("token", &self.token)
            .field("block_tag", &self.block_tag)
            .field("quote_signer", &self.quote_authority.address_hex())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmEscrowConfigError {
    Partial {
        missing: Vec<&'static str>,
    },
    InvalidAddress {
        key: &'static str,
    },
    InvalidChainId,
    InvalidRpcUrl,
    /// The value is never echoed.
    InvalidQuoteKey,
}

impl std::fmt::Display for EvmEscrowConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Partial { missing } => write!(
                f,
                "EVM escrow is partially configured; missing: {}",
                missing.join(", ")
            ),
            Self::InvalidAddress { key } => write!(f, "{} is not a valid 0x address", key),
            Self::InvalidChainId => {
                write!(f, "ESCROW_EVM_CHAIN_ID must be a non-zero integer")
            }
            Self::InvalidRpcUrl => write!(f, "ESCROW_EVM_RPC_URL must be an http(s) URL"),
            Self::InvalidQuoteKey => write!(
                f,
                "ESCROW_EVM_QUOTE_SIGNER_KEY is not a valid secp256k1 private key"
            ),
        }
    }
}

impl std::error::Error for EvmEscrowConfigError {}

const REQUIRED: [&str; 7] = [
    "ESCROW_EVM_CONTRACT",
    "ESCROW_EVM_CHAIN_ID",
    "ESCROW_EVM_RPC_URL",
    "ESCROW_EVM_SELLER",
    "ESCROW_EVM_PAYOUT_WALLET",
    "ESCROW_EVM_TREASURY",
    "ESCROW_EVM_QUOTE_SIGNER_KEY",
];

impl EvmEscrowSettings {
    pub fn from_env() -> Result<Option<Self>, EvmEscrowConfigError> {
        Self::from_lookup(|key| env::var(key).ok().filter(|v| !v.trim().is_empty()))
    }

    /// The same rules over an arbitrary lookup, so they are testable without
    /// mutating the process environment — global state that makes tests
    /// order-dependent the moment two of them touch it.
    pub fn from_lookup(
        get: impl Fn(&'static str) -> Option<String>,
    ) -> Result<Option<Self>, EvmEscrowConfigError> {
        let present = REQUIRED
            .iter()
            .copied()
            .filter(|k| get(k).is_some())
            .count();
        if present == 0 {
            return Ok(None);
        }
        if present != REQUIRED.len() {
            return Err(EvmEscrowConfigError::Partial {
                missing: REQUIRED
                    .iter()
                    .copied()
                    .filter(|k| get(k).is_none())
                    .collect(),
            });
        }

        let address = |key: &'static str| -> Result<String, EvmEscrowConfigError> {
            let value = get(key).unwrap_or_default().trim().to_string();
            parse_address(&value).ok_or(EvmEscrowConfigError::InvalidAddress { key })?;
            Ok(value)
        };

        let contract = address("ESCROW_EVM_CONTRACT")?;
        let seller = address("ESCROW_EVM_SELLER")?;
        let payout_wallet = address("ESCROW_EVM_PAYOUT_WALLET")?;
        let treasury = address("ESCROW_EVM_TREASURY")?;

        let chain_id: u64 = get("ESCROW_EVM_CHAIN_ID")
            .unwrap_or_default()
            .trim()
            .parse()
            .map_err(|_| EvmEscrowConfigError::InvalidChainId)?;
        if chain_id == 0 {
            return Err(EvmEscrowConfigError::InvalidChainId);
        }

        let rpc_url = get("ESCROW_EVM_RPC_URL")
            .unwrap_or_default()
            .trim()
            .to_string();
        if !rpc_url.starts_with("http://") && !rpc_url.starts_with("https://") {
            return Err(EvmEscrowConfigError::InvalidRpcUrl);
        }

        let token = match get("ESCROW_EVM_TOKEN") {
            Some(value) => {
                let value = value.trim().to_string();
                parse_address(&value).ok_or(EvmEscrowConfigError::InvalidAddress {
                    key: "ESCROW_EVM_TOKEN",
                })?;
                value
            }
            None => NATIVE_TOKEN.to_string(),
        };

        let block_tag = get("ESCROW_EVM_BLOCK_TAG")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_BLOCK_TAG.to_string());

        let quote_authority = EvmQuoteAuthority::from_hex_key(
            &get("ESCROW_EVM_QUOTE_SIGNER_KEY").unwrap_or_default(),
            chain_id,
            &contract,
        )
        // The underlying error describes the shape of a secret, and errors have
        // a way of reaching a log aggregator.
        .map_err(|_| EvmEscrowConfigError::InvalidQuoteKey)?;

        Ok(Some(Self {
            contract,
            chain_id,
            rpc_url,
            seller,
            payout_wallet,
            treasury,
            token,
            block_tag,
            quote_authority: Arc::new(quote_authority),
        }))
    }

    /// The address the contract must have recorded as `quoteSigner`.
    pub fn quote_signer_address(&self) -> String {
        self.quote_authority.address_hex()
    }

    /// True when this deployment escrows the chain's native coin.
    ///
    /// The contract has two entry points -- `createOrder` is `payable` and
    /// `createOrderERC20` is not -- so the browser has to know which to call.
    pub fn is_native(&self) -> bool {
        parse_address(&self.token) == Some([0u8; 20])
    }

    pub fn gateway(&self) -> EvmEscrowGateway {
        EvmEscrowGateway::new(
            self.rpc_url.clone(),
            self.contract.clone(),
            self.block_tag.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn full() -> HashMap<&'static str, String> {
        HashMap::from([
            ("ESCROW_EVM_CONTRACT", ADDR.to_string()),
            ("ESCROW_EVM_CHAIN_ID", "11155111".to_string()),
            ("ESCROW_EVM_RPC_URL", "https://rpc.example/v1".to_string()),
            ("ESCROW_EVM_SELLER", ADDR.to_string()),
            ("ESCROW_EVM_PAYOUT_WALLET", ADDR.to_string()),
            ("ESCROW_EVM_TREASURY", ADDR.to_string()),
            ("ESCROW_EVM_QUOTE_SIGNER_KEY", KEY.to_string()),
        ])
    }

    fn load(
        map: HashMap<&'static str, String>,
    ) -> Result<Option<EvmEscrowSettings>, EvmEscrowConfigError> {
        EvmEscrowSettings::from_lookup(move |k| map.get(k).cloned())
    }

    fn load_err(map: HashMap<&'static str, String>) -> EvmEscrowConfigError {
        match load(map) {
            Err(e) => e,
            Ok(_) => panic!("expected the configuration to be refused"),
        }
    }

    #[test]
    fn absent_configuration_switches_evm_escrow_off() {
        assert!(load(HashMap::new()).unwrap().is_none());
    }

    #[test]
    fn a_complete_configuration_loads_and_defaults_to_native() {
        let s = load(full()).unwrap().expect("configured");
        assert_eq!(s.chain_id, 11155111);
        assert_eq!(s.token, NATIVE_TOKEN);
        assert!(s.is_native());
        assert_eq!(s.block_tag, "finalized", "reads must default to finalized");
    }

    #[test]
    fn a_partial_configuration_names_what_is_missing() {
        let mut map = full();
        map.remove("ESCROW_EVM_TREASURY");
        map.remove("ESCROW_EVM_CHAIN_ID");
        match load_err(map) {
            EvmEscrowConfigError::Partial { missing } => {
                assert!(missing.contains(&"ESCROW_EVM_TREASURY"));
                assert!(missing.contains(&"ESCROW_EVM_CHAIN_ID"));
            }
            other => panic!("expected Partial, got {:?}", other),
        }
    }

    #[test]
    fn a_zero_or_unparseable_chain_id_is_refused() {
        // The chain id is inside the EIP-712 domain, so a wrong one signs for a
        // different network entirely.
        let mut map = full();
        map.insert("ESCROW_EVM_CHAIN_ID", "0".to_string());
        assert_eq!(load_err(map), EvmEscrowConfigError::InvalidChainId);

        let mut map = full();
        map.insert("ESCROW_EVM_CHAIN_ID", "mainnet".to_string());
        assert_eq!(load_err(map), EvmEscrowConfigError::InvalidChainId);
    }

    #[test]
    fn an_rpc_url_that_is_not_http_is_refused() {
        let mut map = full();
        map.insert("ESCROW_EVM_RPC_URL", "rpc.example".to_string());
        assert_eq!(load_err(map), EvmEscrowConfigError::InvalidRpcUrl);
    }

    #[test]
    fn a_malformed_address_is_refused_and_named() {
        let mut map = full();
        map.insert("ESCROW_EVM_PAYOUT_WALLET", "0x1234".to_string());
        assert_eq!(
            load_err(map),
            EvmEscrowConfigError::InvalidAddress {
                key: "ESCROW_EVM_PAYOUT_WALLET"
            }
        );
    }

    #[test]
    fn an_unusable_signing_key_is_refused_without_echoing_it() {
        let mut map = full();
        map.insert("ESCROW_EVM_QUOTE_SIGNER_KEY", "0xdeadbeef".to_string());
        let err = load_err(map);
        assert_eq!(err, EvmEscrowConfigError::InvalidQuoteKey);
        assert!(!err.to_string().contains("deadbeef"));
    }

    #[test]
    fn an_erc20_token_turns_off_the_native_path() {
        let mut map = full();
        let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        map.insert("ESCROW_EVM_TOKEN", usdc.to_string());
        let s = load(map).unwrap().unwrap();
        assert_eq!(s.token, usdc);
        assert!(
            !s.is_native(),
            "an ERC20 route must not use the payable entry point"
        );
    }

    #[test]
    fn the_block_tag_can_be_overridden_for_local_chains() {
        let mut map = full();
        map.insert("ESCROW_EVM_BLOCK_TAG", "latest".to_string());
        assert_eq!(load(map).unwrap().unwrap().block_tag, "latest");
    }

    #[test]
    fn debug_prints_the_signer_address_and_never_the_key() {
        let s = load(full()).unwrap().unwrap();
        let printed = format!("{:?}", s);
        assert!(printed.contains(&s.quote_signer_address()));
        assert!(!printed.to_lowercase().contains("4c0883a6"));
    }

    #[test]
    fn the_signer_address_is_derived_not_configured() {
        // The operator supplies a private key; the address comes from it. A
        // mismatch between the two is impossible by construction.
        let s = load(full()).unwrap().unwrap();
        assert_eq!(
            s.quote_signer_address().to_lowercase(),
            "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
        );
    }
}
