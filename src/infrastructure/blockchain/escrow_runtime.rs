//! The escrow flow as the HTTP layer sees it, across both chains.
//!
//! Assembled once at startup. Each gateway owns an HTTP client with its own
//! connection pool, and rebuilding that per request would open a fresh TLS
//! connection to an RPC every time a customer refreshes a page.
//!
//! Either chain may be absent, both may be, and that is a valid deployment:
//! escrow is opt-in per chain, and a deployment offering neither still settles
//! by direct transfer. What is not valid is a half-configured one, which the
//! settings types refuse at startup.

use std::sync::Arc;

use crate::application::use_cases::authorize_escrow::{
    EscrowDeployment, EscrowDeployments, EvmEscrow, SolanaEscrow,
};
use crate::application::use_cases::verify_escrow_deposit::{ChainEscrow, EscrowGateways};
use crate::domain::ports::escrow_gateway::EscrowGateway;
use crate::infrastructure::blockchain::escrow_settings::EscrowSettings;
use crate::infrastructure::blockchain::evm_escrow_settings::EvmEscrowSettings;
use crate::infrastructure::blockchain::solana_escrow_gateway::SolanaEscrowGateway;

/// One chain's configured escrow: how to read it, how to describe it, and the
/// key that authorises prices on it.
#[derive(Clone)]
struct SolanaRuntime {
    settings: EscrowSettings,
    gateway: Arc<dyn EscrowGateway>,
    deployment: EscrowDeployment,
}

#[derive(Clone)]
struct EvmRuntime {
    settings: EvmEscrowSettings,
    gateway: Arc<dyn EscrowGateway>,
    deployment: EscrowDeployment,
}

#[derive(Clone, Default)]
pub struct EscrowRuntime {
    solana: Option<SolanaRuntime>,
    evm: Option<EvmRuntime>,
}

impl EscrowRuntime {
    pub fn new(
        solana: Option<EscrowSettings>,
        solana_rpc_url: String,
        evm: Option<EvmEscrowSettings>,
    ) -> Self {
        let solana = solana.map(|settings| SolanaRuntime {
            gateway: Arc::new(SolanaEscrowGateway::new(
                solana_rpc_url.clone(),
                settings.program_id.clone(),
            )),
            deployment: EscrowDeployment {
                program_id: settings.program_id.clone(),
                rpc_url: solana_rpc_url,
                seller: settings.seller.clone(),
                payout_wallet: settings.payout_wallet.clone(),
                treasury: settings.treasury.clone(),
                mint: settings.mint.clone(),
            },
            settings,
        });

        let evm = evm.map(|settings| EvmRuntime {
            gateway: Arc::new(settings.gateway()),
            deployment: EscrowDeployment {
                // The contract address plays the part the program id plays on
                // Solana: the thing an order must belong to.
                program_id: settings.contract.clone(),
                rpc_url: settings.rpc_url.clone(),
                seller: settings.seller.clone(),
                payout_wallet: settings.payout_wallet.clone(),
                treasury: settings.treasury.clone(),
                mint: settings.token.clone(),
            },
            settings,
        });

        Self { solana, evm }
    }

    /// True when at least one chain can take an escrow payment.
    pub fn is_enabled(&self) -> bool {
        self.solana.is_some() || self.evm.is_some()
    }

    pub fn solana_enabled(&self) -> bool {
        self.solana.is_some()
    }

    pub fn evm_enabled(&self) -> bool {
        self.evm.is_some()
    }

    /// The deployments the authorization use case dispatches over.
    pub fn deployments(&self) -> EscrowDeployments {
        EscrowDeployments {
            solana: self.solana.as_ref().map(|r| SolanaEscrow {
                deployment: r.deployment.clone(),
                signer: r.settings.quote_authority.clone(),
            }),
            evm: self.evm.as_ref().map(|r| EvmEscrow {
                deployment: r.deployment.clone(),
                chain_id: r.settings.chain_id,
                native: r.settings.is_native(),
                signer: r.settings.quote_authority.clone(),
            }),
        }
    }

    /// The gateways the verification use case dispatches over.
    pub fn gateways(&self) -> EscrowGateways {
        EscrowGateways {
            solana: self.solana.as_ref().map(|r| ChainEscrow {
                gateway: r.gateway.clone(),
                deployment: r.deployment.clone(),
            }),
            evm: self.evm.as_ref().map(|r| ChainEscrow {
                gateway: r.gateway.clone(),
                deployment: r.deployment.clone(),
            }),
        }
    }

    /// Every configured gateway, for the reconciliation sweep.
    ///
    /// A sweep has no quote to dispatch on -- it is re-reading orders that
    /// already exist -- so it tries each chain and matches on the order id it
    /// already has recorded.
    pub fn all_gateways(&self) -> Vec<Arc<dyn EscrowGateway>> {
        self.solana
            .iter()
            .map(|r| r.gateway.clone())
            .chain(self.evm.iter().map(|r| r.gateway.clone()))
            .collect()
    }

    /// One line per configured chain, for the startup log.
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(r) = &self.solana {
            out.push(format!(
                "Solana escrow: program {}, quote authority {}",
                r.settings.program_id,
                r.settings.quote_authority_base58()
            ));
        }
        if let Some(r) = &self.evm {
            out.push(format!(
                "EVM escrow: contract {} on chain {}, quote signer {}, reads at {}",
                r.settings.contract,
                r.settings.chain_id,
                r.settings.quote_signer_address(),
                r.settings.block_tag
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::blockchain::evm_escrow_settings::EvmEscrowSettings;
    use std::collections::HashMap;

    const SOL_ADDR: &str = "So11111111111111111111111111111111111111112";
    /// Deliberately not a run of 1s. The obvious filler seed is a substring of
    /// the obvious filler address, which makes "the seed was not printed" pass
    /// or fail by coincidence rather than by behaviour.
    const SOL_SEED: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
    const EVM_ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const EVM_KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn solana_settings() -> EscrowSettings {
        let map: HashMap<&'static str, String> = HashMap::from([
            ("ESCROW_PROGRAM_ID", SOL_ADDR.to_string()),
            ("ESCROW_SELLER", SOL_ADDR.to_string()),
            ("ESCROW_PAYOUT_WALLET", SOL_ADDR.to_string()),
            ("ESCROW_TREASURY", SOL_ADDR.to_string()),
            ("ESCROW_QUOTE_AUTHORITY_SEED", SOL_SEED.to_string()),
        ]);
        EscrowSettings::from_lookup(move |k| map.get(k).cloned())
            .unwrap()
            .unwrap()
    }

    fn evm_settings() -> EvmEscrowSettings {
        let map: HashMap<&'static str, String> = HashMap::from([
            ("ESCROW_EVM_CONTRACT", EVM_ADDR.to_string()),
            ("ESCROW_EVM_CHAIN_ID", "11155111".to_string()),
            ("ESCROW_EVM_RPC_URL", "https://rpc.example".to_string()),
            ("ESCROW_EVM_SELLER", EVM_ADDR.to_string()),
            ("ESCROW_EVM_PAYOUT_WALLET", EVM_ADDR.to_string()),
            ("ESCROW_EVM_TREASURY", EVM_ADDR.to_string()),
            ("ESCROW_EVM_QUOTE_SIGNER_KEY", EVM_KEY.to_string()),
        ]);
        EvmEscrowSettings::from_lookup(move |k| map.get(k).cloned())
            .unwrap()
            .unwrap()
    }

    fn rpc() -> String {
        "https://api.devnet.solana.com".to_string()
    }

    #[test]
    fn a_deployment_with_neither_chain_offers_no_escrow() {
        let runtime = EscrowRuntime::new(None, rpc(), None);
        assert!(!runtime.is_enabled());
        assert!(runtime.deployments().solana.is_none());
        assert!(runtime.deployments().evm.is_none());
        assert!(runtime.all_gateways().is_empty());
        assert!(runtime.describe().is_empty());
    }

    #[test]
    fn one_chain_may_be_configured_without_the_other() {
        // Not a half-configured escrow -- that is refused at startup -- but a
        // deliberate choice to offer escrow on one network only.
        let solana_only = EscrowRuntime::new(Some(solana_settings()), rpc(), None);
        assert!(solana_only.solana_enabled());
        assert!(!solana_only.evm_enabled());
        assert_eq!(solana_only.all_gateways().len(), 1);

        let evm_only = EscrowRuntime::new(None, rpc(), Some(evm_settings()));
        assert!(!evm_only.solana_enabled());
        assert!(evm_only.evm_enabled());
        assert_eq!(evm_only.all_gateways().len(), 1);
    }

    #[test]
    fn both_chains_can_be_live_at_once() {
        let runtime = EscrowRuntime::new(Some(solana_settings()), rpc(), Some(evm_settings()));
        assert!(runtime.is_enabled());
        assert_eq!(runtime.all_gateways().len(), 2);
        assert_eq!(runtime.describe().len(), 2);

        let deployments = runtime.deployments();
        assert!(deployments.solana.is_some());
        assert!(deployments.evm.is_some());
    }

    #[test]
    fn the_evm_deployment_uses_the_contract_where_solana_uses_a_program_id() {
        // Both answer "what must this order belong to", which is why one shared
        // field carries them and verification needs no chain-specific branch.
        let runtime = EscrowRuntime::new(None, rpc(), Some(evm_settings()));
        let deployments = runtime.deployments();
        let evm = deployments.evm.expect("configured");
        assert_eq!(evm.deployment.program_id, EVM_ADDR);
        assert_eq!(evm.chain_id, 11155111);
        assert!(evm.native, "the default token is the native coin");
    }

    #[test]
    fn the_gateways_and_deployments_describe_the_same_escrow() {
        // They are handed to two different use cases, and a disagreement
        // between them would mean verifying against a contract we did not
        // authorise for.
        let runtime = EscrowRuntime::new(Some(solana_settings()), rpc(), Some(evm_settings()));
        let deployments = runtime.deployments();
        let gateways = runtime.gateways();

        assert_eq!(
            deployments.solana.unwrap().deployment.program_id,
            gateways.solana.unwrap().deployment.program_id
        );
        assert_eq!(
            deployments.evm.unwrap().deployment.program_id,
            gateways.evm.unwrap().deployment.program_id
        );
    }

    #[test]
    fn the_startup_description_names_the_keys_but_never_the_secrets() {
        let runtime = EscrowRuntime::new(Some(solana_settings()), rpc(), Some(evm_settings()));
        let printed = runtime.describe().join("\n");
        assert!(printed.contains(EVM_ADDR) || printed.contains("chain 11155111"));
        assert!(!printed.contains(SOL_SEED));
        assert!(!printed.to_lowercase().contains("4c0883a6"));
    }
}
