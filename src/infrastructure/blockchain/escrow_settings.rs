//! Deployment settings for the Solana escrow flow.
//!
//! Escrow is **opt-in**. A deployment that has not registered a program, a
//! merchant and a quote authority on-chain simply does not offer it, and the
//! existing direct-transfer settlement keeps working untouched. That is why
//! these live behind an `Option` rather than being folded into [`AppConfig`]
//! with empty-string defaults: a half-configured escrow is far more dangerous
//! than an absent one, because it produces authorizations the program will
//! reject for reasons no error message explains.
//!
//! So configuration is all-or-nothing, and a partial one refuses to start.
//!
//! ## The key
//!
//! `ESCROW_QUOTE_AUTHORITY_SEED` is the private half of the key the program
//! records in `Config.quote_authority`. It never leaves this process: it is
//! loaded into a [`QuoteAuthority`], which has no `Debug`, no `Serialize` and
//! no accessor that returns the secret. Only the *public* key is ever returned
//! to a client, and then only so the browser can check it against the chain.
//!
//! [`AppConfig`]: crate::infrastructure::config::AppConfig

use std::env;
use std::sync::Arc;

use crate::infrastructure::blockchain::quote_authority::QuoteAuthority;

/// Wrapped SOL. The escrow holds SPL tokens only, so a SOL payment is a wrapped
/// SOL payment; see `Frontend/src/app/lib/escrow/wsol.ts` for the browser half.
pub const WRAPPED_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Everything the escrow flow needs that is not derived from the chain itself.
///
/// The seller, payout wallet and treasury are *mirrors* of on-chain state, not
/// the source of truth for it. The program reads all three from accounts it
/// controls; these exist so the backend can build an authorization without a
/// round trip, and so a mismatch between what we believe and what is deployed
/// is caught by the browser's pre-flight and by verification rather than
/// silently producing orders that pay the wrong party.
#[derive(Clone)]
pub struct EscrowSettings {
    pub program_id: String,
    /// `Merchant.authority` -- the seller orders are created against.
    pub seller: String,
    /// `Merchant.payout_wallet`, snapshotted into each order at creation.
    pub payout_wallet: String,
    /// `Config.treasury`, which receives the platform fee.
    pub treasury: String,
    /// The SPL mint escrowed. Wrapped SOL unless overridden.
    pub mint: String,
    /// Signs price commitments. Shared, never cloned into a response.
    pub quote_authority: Arc<QuoteAuthority>,
}

/// Prints the settings with the signing key reduced to its public half.
///
/// Hand-written rather than derived, and rather than omitted: operators do
/// reach for `{:?}` on configuration, and a type that cannot be printed tends to
/// get a field pulled out and printed individually instead. This makes the safe
/// thing the easy thing -- there is no formatting of this struct that can emit
/// the seed, because the seed is not reachable from here.
impl std::fmt::Debug for EscrowSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EscrowSettings")
            .field("program_id", &self.program_id)
            .field("seller", &self.seller)
            .field("payout_wallet", &self.payout_wallet)
            .field("treasury", &self.treasury)
            .field("mint", &self.mint)
            .field("quote_authority", &self.quote_authority_base58())
            .finish()
    }
}

/// Why escrow configuration was rejected at startup.
///
/// Rejecting at startup rather than per-request is deliberate: an operator
/// finds out when they deploy, not when the first customer tries to pay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowConfigError {
    /// Some escrow variables are set and others are not.
    Partial { missing: Vec<&'static str> },
    /// A value is set but is not a 32-byte base58 address.
    InvalidAddress { key: &'static str },
    /// The signing seed is not a usable Ed25519 key. The value is never echoed.
    InvalidQuoteKey,
}

impl std::fmt::Display for EscrowConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Partial { missing } => write!(
                f,
                "escrow is partially configured; missing: {}",
                missing.join(", ")
            ),
            Self::InvalidAddress { key } => {
                write!(f, "{} is not a valid base58 Solana address", key)
            }
            // Deliberately says nothing about the value itself.
            Self::InvalidQuoteKey => {
                write!(f, "ESCROW_QUOTE_AUTHORITY_SEED is not a valid Ed25519 key")
            }
        }
    }
}

impl std::error::Error for EscrowConfigError {}

/// A base58 string that decodes to exactly 32 bytes.
///
/// Checked here rather than at first use because an address that is one
/// character short produces a `create_order` failure deep in the validator with
/// nothing to connect it back to a typo in an environment file.
fn valid_address(value: &str) -> bool {
    matches!(bs58::decode(value.trim()).into_vec(), Ok(bytes) if bytes.len() == 32)
}

/// The variables that must appear together.
const REQUIRED: [&str; 5] = [
    "ESCROW_PROGRAM_ID",
    "ESCROW_SELLER",
    "ESCROW_PAYOUT_WALLET",
    "ESCROW_TREASURY",
    "ESCROW_QUOTE_AUTHORITY_SEED",
];

impl EscrowSettings {
    /// Read from the environment.
    ///
    /// `Ok(None)` means escrow is switched off, which is a valid deployment.
    /// `Err` means someone tried to switch it on and got it wrong.
    pub fn from_env() -> Result<Option<Self>, EscrowConfigError> {
        Self::from_lookup(|key| env::var(key).ok().filter(|v| !v.trim().is_empty()))
    }

    /// The same logic over an arbitrary lookup, so the rules are testable
    /// without mutating the process environment -- which is global state that
    /// makes tests order-dependent the moment two of them touch it.
    pub fn from_lookup(
        get: impl Fn(&'static str) -> Option<String>,
    ) -> Result<Option<Self>, EscrowConfigError> {
        let present: Vec<&'static str> = REQUIRED
            .iter()
            .copied()
            .filter(|k| get(k).is_some())
            .collect();

        if present.is_empty() {
            return Ok(None);
        }
        if present.len() != REQUIRED.len() {
            let missing = REQUIRED
                .iter()
                .copied()
                .filter(|k| get(k).is_none())
                .collect();
            return Err(EscrowConfigError::Partial { missing });
        }

        let read = |key: &'static str| -> Result<String, EscrowConfigError> {
            let value = get(key).unwrap_or_default().trim().to_string();
            if !valid_address(&value) {
                return Err(EscrowConfigError::InvalidAddress { key });
            }
            Ok(value)
        };

        let program_id = read("ESCROW_PROGRAM_ID")?;
        let seller = read("ESCROW_SELLER")?;
        let payout_wallet = read("ESCROW_PAYOUT_WALLET")?;
        let treasury = read("ESCROW_TREASURY")?;

        let mint = match get("ESCROW_MINT") {
            Some(value) => {
                let value = value.trim().to_string();
                if !valid_address(&value) {
                    return Err(EscrowConfigError::InvalidAddress { key: "ESCROW_MINT" });
                }
                value
            }
            None => WRAPPED_SOL_MINT.to_string(),
        };

        let seed = get("ESCROW_QUOTE_AUTHORITY_SEED").unwrap_or_default();
        let quote_authority = QuoteAuthority::from_base58_seed(&seed)
            // The underlying error is dropped on purpose: it describes the
            // shape of a secret, and an error about a secret has a way of
            // ending up in a log aggregator.
            .map_err(|_| EscrowConfigError::InvalidQuoteKey)?;

        Ok(Some(Self {
            program_id,
            seller,
            payout_wallet,
            treasury,
            mint,
            quote_authority: Arc::new(quote_authority),
        }))
    }

    /// The public key a client checks against `Config.quote_authority` on-chain.
    pub fn quote_authority_base58(&self) -> String {
        self.quote_authority.authority_base58()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A valid 32-byte base58 address, and a seed that is a usable Ed25519 key.
    const ADDR: &str = "So11111111111111111111111111111111111111112";
    const SEED: &str = "11111111111111111111111111111112"; // 32 bytes of base58

    fn full() -> HashMap<&'static str, String> {
        HashMap::from([
            ("ESCROW_PROGRAM_ID", ADDR.to_string()),
            ("ESCROW_SELLER", ADDR.to_string()),
            ("ESCROW_PAYOUT_WALLET", ADDR.to_string()),
            ("ESCROW_TREASURY", ADDR.to_string()),
            ("ESCROW_QUOTE_AUTHORITY_SEED", SEED.to_string()),
        ])
    }

    fn load(
        map: HashMap<&'static str, String>,
    ) -> Result<Option<EscrowSettings>, EscrowConfigError> {
        EscrowSettings::from_lookup(move |k| map.get(k).cloned())
    }

    #[test]
    fn absent_configuration_switches_escrow_off() {
        // Not an error: a deployment may legitimately offer direct transfer only.
        assert!(load(HashMap::new()).unwrap().is_none());
    }

    #[test]
    fn a_complete_configuration_loads() {
        let settings = load(full()).unwrap().expect("configured");
        assert_eq!(settings.program_id, ADDR);
        assert_eq!(settings.mint, WRAPPED_SOL_MINT, "defaults to wrapped SOL");
    }

    #[test]
    fn a_partial_configuration_is_refused_and_names_what_is_missing() {
        // The dangerous case: escrow looks enabled, issues authorizations, and
        // every one of them fails on-chain for a reason no error explains.
        let mut map = full();
        map.remove("ESCROW_TREASURY");
        map.remove("ESCROW_SELLER");

        match load(map) {
            Err(EscrowConfigError::Partial { missing }) => {
                assert!(missing.contains(&"ESCROW_TREASURY"));
                assert!(missing.contains(&"ESCROW_SELLER"));
                assert_eq!(missing.len(), 2);
            }
            other => panic!("expected Partial, got {:?}", other),
        }
    }

    #[test]
    fn a_blank_value_counts_as_missing() {
        // `FOO=` in an env file is a typo, not a configuration.
        let mut map = full();
        map.insert("ESCROW_TREASURY", "   ".to_string());
        let result = EscrowSettings::from_lookup(move |k| {
            map.get(k).cloned().filter(|v| !v.trim().is_empty())
        });
        assert!(matches!(result, Err(EscrowConfigError::Partial { .. })));
    }

    #[test]
    fn an_address_that_is_not_32_bytes_is_refused() {
        let mut map = full();
        map.insert("ESCROW_PAYOUT_WALLET", "abc".to_string());
        assert_eq!(
            load(map).unwrap_err(),
            EscrowConfigError::InvalidAddress {
                key: "ESCROW_PAYOUT_WALLET"
            }
        );
    }

    #[test]
    fn a_non_base58_address_is_refused() {
        let mut map = full();
        // 0, O, I and l are not in the base58 alphabet.
        map.insert("ESCROW_PROGRAM_ID", "0OIl".repeat(11));
        assert_eq!(
            load(map).unwrap_err(),
            EscrowConfigError::InvalidAddress {
                key: "ESCROW_PROGRAM_ID"
            }
        );
    }

    #[test]
    fn an_unusable_signing_seed_is_refused_without_echoing_it() {
        let mut map = full();
        map.insert("ESCROW_QUOTE_AUTHORITY_SEED", "not-a-key".to_string());
        let err = load(map).unwrap_err();
        assert_eq!(err, EscrowConfigError::InvalidQuoteKey);
        // The message must not carry the value, however mangled: errors reach logs.
        assert!(!err.to_string().contains("not-a-key"));
    }

    #[test]
    fn a_custom_mint_overrides_wrapped_sol() {
        let mut map = full();
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        map.insert("ESCROW_MINT", usdc.to_string());
        assert_eq!(load(map).unwrap().unwrap().mint, usdc);
    }

    #[test]
    fn a_malformed_custom_mint_is_refused() {
        let mut map = full();
        map.insert("ESCROW_MINT", "nope".to_string());
        assert_eq!(
            load(map).unwrap_err(),
            EscrowConfigError::InvalidAddress { key: "ESCROW_MINT" }
        );
    }

    #[test]
    fn the_public_key_is_exposed_but_the_seed_is_not() {
        let settings = load(full()).unwrap().unwrap();
        let public = settings.quote_authority_base58();
        assert!(valid_address(&public));
        assert_ne!(public, SEED, "the public key is derived, not the seed");
    }
}
