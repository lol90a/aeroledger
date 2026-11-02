//! Authorise a buyer to open an escrow order at an already-agreed price.
//!
//! This is the hinge between the reservation the customer accepted and the
//! transaction their wallet is about to sign. It produces a short-lived
//! signature over the exact figures, which the escrow refuses to take a single
//! token without.
//!
//! ## Two chains, one decision
//!
//! Both escrows exist, and which one settles a booking is decided by the quote
//! the customer accepted, not by anything the client sends. A Solana quote gets
//! an Ed25519 attestation over a flat message; an EVM quote gets a secp256k1
//! EIP-712 signature bound to a chain id and a contract address. The response
//! is tagged with the chain so the browser knows which transaction to build,
//! and carries only the fields that chain actually uses -- a shared shape with
//! half its fields null would invite reading the wrong one.
//!
//! ## What it refuses, and why
//!
//! The buyer's browser supplies two things: which booking, and which wallet.
//! Everything else -- the amount, the fee split, the seller, the asset, the
//! expiry -- is read from the accepted quote and from deployment configuration.
//! There is deliberately no input here that lets a caller influence what gets
//! signed, because a signature is an instruction to the escrow and the escrow
//! has no way to second-guess it.
//!
//! The quote must be **accepted**: a price the user has explicitly approved. An
//! active-but-unapproved quote is a number they have merely been shown, and
//! authorising it would charge them something they never agreed to.
//!
//! ## Why the order id is the quote id
//!
//! The order's address (a PDA on Solana, a mapping key on EVM) is derived from
//! the order id, so the id fixes where it lives. Using the booking id would
//! give each booking exactly one escrow slot for all time: a first attempt that
//! half-failed, or an order that was refunded, would leave that slot occupied
//! and the customer permanently unable to pay. The quote id changes whenever
//! the price is re-quoted, so a buyer can always get a fresh slot by getting a
//! fresh price -- which is what they would have to do anyway.

use std::sync::Arc;

use uuid::Uuid;

use crate::domain::ports::evm_quote_signer::{EvmEscrowQuote, EvmQuoteSigner};
use crate::domain::ports::quote_signer::{EscrowQuote, QuoteSigner};
use crate::domain::repositories::quote_repository::QuoteRepository;
use crate::domain::value_objects::Chain;
use crate::shared::errors::DomainError;

/// Where an escrow order lives and the parties it names.
///
/// Shared by both chains and by verification, because the questions it answers
/// are the same either side: who is the seller, where do proceeds go, which
/// asset is held. Only the spelling of an address differs.
#[derive(Debug, Clone)]
pub struct EscrowDeployment {
    /// Program id on Solana; contract address on EVM.
    pub program_id: String,
    pub rpc_url: String,
    pub seller: String,
    pub payout_wallet: String,
    pub treasury: String,
    /// SPL mint on Solana; ERC-20 address, or the zero address, on EVM.
    pub mint: String,
}

/// A configured Solana escrow and the key that authorises prices on it.
pub struct SolanaEscrow {
    pub deployment: EscrowDeployment,
    pub signer: Arc<dyn QuoteSigner>,
}

/// A configured EVM escrow, plus the two things only EVM needs.
pub struct EvmEscrow {
    pub deployment: EscrowDeployment,
    /// Inside the EIP-712 domain, so a signature is bound to one network.
    pub chain_id: u64,
    /// The contract has two entry points and only one is `payable`, so the
    /// browser must know which to call before it builds anything.
    pub native: bool,
    pub signer: Arc<dyn EvmQuoteSigner>,
}

/// Whichever escrows this deployment offers. Both may be absent.
#[derive(Default)]
pub struct EscrowDeployments {
    pub solana: Option<SolanaEscrow>,
    pub evm: Option<EvmEscrow>,
}

pub struct AuthorizeEscrowInput {
    pub booking_id: Uuid,
    pub user_id: Uuid,
    /// The wallet that will sign. Bound into the signature, so an authorization
    /// issued for one wallet is useless to any other.
    pub buyer_wallet: String,
}

/// Everything the browser needs to build the transaction, tagged by chain.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "chain", rename_all = "lowercase")]
pub enum EscrowAuthorizationView {
    Solana {
        program_id: String,
        rpc_url: String,
        order_id: String,
        buyer: String,
        seller: String,
        payout_wallet: String,
        treasury: String,
        mint: String,
        quote_authority: String,
        /// Decimal strings: these exceed what a JSON number holds exactly.
        amount: String,
        fee_amount: String,
        expiry: i64,
        /// Base64, 64 bytes decoded.
        signature: String,
        quote_id: Uuid,
    },
    Evm {
        contract: String,
        chain_id: u64,
        rpc_url: String,
        order_id: String,
        /// The contract's storage key for this order, `0x`-prefixed.
        order_hash: String,
        buyer: String,
        seller: String,
        payout_wallet: String,
        treasury: String,
        /// The ERC-20 being escrowed, or the zero address for the native coin.
        token: String,
        /// True when the buyer must call the `payable` entry point.
        native: bool,
        quote_signer: String,
        amount: String,
        fee_amount: String,
        expiry: i64,
        /// 65 bytes as `0x` hex.
        signature: String,
        quote_id: Uuid,
    },
}

impl EscrowAuthorizationView {
    /// The quote this authorises, for the audit record.
    pub fn quote_id(&self) -> Uuid {
        match self {
            Self::Solana { quote_id, .. } | Self::Evm { quote_id, .. } => *quote_id,
        }
    }

    pub fn order_id(&self) -> &str {
        match self {
            Self::Solana { order_id, .. } | Self::Evm { order_id, .. } => order_id,
        }
    }

    pub fn buyer(&self) -> &str {
        match self {
            Self::Solana { buyer, .. } | Self::Evm { buyer, .. } => buyer,
        }
    }

    pub fn amount(&self) -> &str {
        match self {
            Self::Solana { amount, .. } | Self::Evm { amount, .. } => amount,
        }
    }

    pub fn fee_amount(&self) -> &str {
        match self {
            Self::Solana { fee_amount, .. } | Self::Evm { fee_amount, .. } => fee_amount,
        }
    }

    pub fn expiry(&self) -> i64 {
        match self {
            Self::Solana { expiry, .. } | Self::Evm { expiry, .. } => *expiry,
        }
    }

    pub fn chain_name(&self) -> &'static str {
        match self {
            Self::Solana { .. } => "solana",
            Self::Evm { .. } => "evm",
        }
    }
}

pub struct AuthorizeEscrow<QR: QuoteRepository> {
    quotes: QR,
    deployments: EscrowDeployments,
}

impl<QR: QuoteRepository> AuthorizeEscrow<QR> {
    pub fn new(quotes: QR, deployments: EscrowDeployments) -> Self {
        Self {
            quotes,
            deployments,
        }
    }

    pub async fn execute(
        &self,
        input: AuthorizeEscrowInput,
    ) -> Result<EscrowAuthorizationView, DomainError> {
        let quote = self
            .quotes
            .find_accepted_for_booking(&input.booking_id)
            .await?
            .ok_or_else(|| {
                DomainError::Conflict("Accept a price quote before paying into escrow".to_string())
            })?;

        if quote.user_id != input.user_id {
            return Err(DomainError::Unauthorized);
        }

        let split = quote.escrow_split()?;
        let now = chrono::Utc::now().timestamp();
        let order_id = quote.id.to_string();
        let reservation_ends = quote.expires_at.timestamp();

        match quote.chain {
            Chain::Solana => {
                let escrow = self.deployments.solana.as_ref().ok_or_else(unavailable)?;
                // The Solana program stores token amounts as u64, so this is
                // where a chain-agnostic split meets a chain-specific limit.
                let (amount, fee_amount) = split.to_u64()?;
                let expiry =
                    expiry_or_requote(escrow.signer.authorization_expiry(now, reservation_ends))?;

                let signed = escrow.signer.sign_escrow_quote(
                    &order_id,
                    &input.buyer_wallet,
                    &escrow.deployment.seller,
                    &escrow.deployment.mint,
                    EscrowQuote {
                        amount,
                        fee_amount,
                        expiry,
                    },
                )?;

                Ok(EscrowAuthorizationView::Solana {
                    program_id: escrow.deployment.program_id.clone(),
                    rpc_url: escrow.deployment.rpc_url.clone(),
                    order_id,
                    buyer: input.buyer_wallet,
                    seller: escrow.deployment.seller.clone(),
                    payout_wallet: escrow.deployment.payout_wallet.clone(),
                    treasury: escrow.deployment.treasury.clone(),
                    mint: escrow.deployment.mint.clone(),
                    quote_authority: signed.authority,
                    amount: amount.to_string(),
                    fee_amount: fee_amount.to_string(),
                    expiry,
                    signature: base64_encode(&signed.signature),
                    quote_id: quote.id,
                })
            }

            Chain::Ethereum | Chain::Bsc => {
                let escrow = self.deployments.evm.as_ref().ok_or_else(unavailable)?;
                let expiry =
                    expiry_or_requote(escrow.signer.authorization_expiry(now, reservation_ends))?;

                let signed = escrow.signer.sign_evm_quote(
                    &order_id,
                    &input.buyer_wallet,
                    &escrow.deployment.seller,
                    &escrow.deployment.mint,
                    EvmEscrowQuote {
                        amount: split.amount,
                        fee: split.fee_amount,
                        expiry,
                    },
                )?;

                Ok(EscrowAuthorizationView::Evm {
                    contract: escrow.deployment.program_id.clone(),
                    chain_id: escrow.chain_id,
                    rpc_url: escrow.deployment.rpc_url.clone(),
                    order_id,
                    order_hash: signed.order_hash,
                    buyer: input.buyer_wallet,
                    seller: escrow.deployment.seller.clone(),
                    payout_wallet: escrow.deployment.payout_wallet.clone(),
                    treasury: escrow.deployment.treasury.clone(),
                    token: escrow.deployment.mint.clone(),
                    native: escrow.native,
                    quote_signer: signed.signer,
                    amount: split.amount.to_string(),
                    fee_amount: split.fee_amount.to_string(),
                    expiry,
                    signature: signed.signature,
                    quote_id: quote.id,
                })
            }

            // Bitcoin has no escrow contract, and pretending otherwise would
            // offer a customer a payment method that cannot exist.
            Chain::Bitcoin => Err(DomainError::ValidationError(
                "Escrow payment is not available for this currency".to_string(),
            )),
        }
    }
}

fn unavailable() -> DomainError {
    DomainError::Conflict("Escrow payment is not available on this network".to_string())
}

/// The reservation has run out. Extending the signature past it would hold the
/// old price open indefinitely, so the customer re-quotes and approves the
/// current one instead.
fn expiry_or_requote(expiry: Option<i64>) -> Result<i64, DomainError> {
    expiry.ok_or_else(|| {
        DomainError::Conflict("This price reservation has expired; request a new quote".to_string())
    })
}

/// Standard base64, which is what `atob` in the browser expects.
///
/// Spelled out rather than pulled in: the only encoder already in the tree is
/// behind a feature of another crate, and sixteen lines of table lookup is a
/// smaller liability than a dependency for one call site.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evm_view(amount: &str) -> EscrowAuthorizationView {
        EscrowAuthorizationView::Evm {
            contract: "0xc".to_string(),
            chain_id: 11155111,
            rpc_url: "https://rpc".to_string(),
            order_id: "o".to_string(),
            order_hash: "0xh".to_string(),
            buyer: "0xb".to_string(),
            seller: "0xs".to_string(),
            payout_wallet: "0xp".to_string(),
            treasury: "0xt".to_string(),
            token: "0x0".to_string(),
            native: true,
            quote_signer: "0xq".to_string(),
            amount: amount.to_string(),
            fee_amount: "0".to_string(),
            expiry: 1,
            signature: "0xsig".to_string(),
            quote_id: Uuid::nil(),
        }
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        // The RFC 4648 vectors, which pin both the alphabet and each of the
        // three padding cases.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encodes_the_high_bytes_a_signature_contains() {
        // A signature is arbitrary bytes, not text: the 62nd and 63rd symbols
        // only appear for high bit patterns, so ASCII vectors never reach them.
        assert_eq!(base64_encode(&[0xff, 0xef, 0xbe]), "/+++");
        assert_eq!(base64_encode(&[0x00, 0x00, 0x00]), "AAAA");
    }

    #[test]
    fn a_signature_encodes_to_the_length_a_client_expects() {
        // 64 bytes -> 88 characters with one pad. A client decoding fewer has
        // been handed a truncated signature.
        let encoded = base64_encode(&[7u8; 64]);
        assert_eq!(encoded.len(), 88);
        assert!(encoded.ends_with('='));
    }

    /// The tag is how the browser knows which transaction to build, and the two
    /// variants deliberately carry different fields.
    #[test]
    fn the_view_is_serialised_with_a_chain_tag() {
        let json = serde_json::to_value(evm_view("1")).unwrap();
        assert_eq!(json["chain"], "evm");
        assert_eq!(json["native"], true);
        assert_eq!(json["chain_id"], 11155111);
        // A Solana-only field must not appear on an EVM authorization: a shared
        // shape with half its fields null is how a client reads the wrong one.
        assert!(json.get("mint").is_none());
        assert!(json.get("program_id").is_none());
    }

    #[test]
    fn amounts_are_strings_so_wide_values_survive_json() {
        // 2 x 10^19 wei exceeds what a JSON number represents exactly, so a
        // numeric field would hand the browser a rounded price.
        let json = serde_json::to_value(evm_view("20000000000000000000")).unwrap();
        assert!(json["amount"].is_string());
        assert_eq!(json["amount"], "20000000000000000000");
    }

    #[test]
    fn the_accessors_read_both_variants() {
        let evm = evm_view("5");
        assert_eq!(evm.amount(), "5");
        assert_eq!(evm.chain_name(), "evm");
        assert_eq!(evm.buyer(), "0xb");

        let solana = EscrowAuthorizationView::Solana {
            program_id: "Prog".to_string(),
            rpc_url: "https://rpc".to_string(),
            order_id: "o".to_string(),
            buyer: "Buyer".to_string(),
            seller: "Seller".to_string(),
            payout_wallet: "Payout".to_string(),
            treasury: "Treasury".to_string(),
            mint: "Mint".to_string(),
            quote_authority: "Auth".to_string(),
            amount: "7".to_string(),
            fee_amount: "1".to_string(),
            expiry: 2,
            signature: "sig".to_string(),
            quote_id: Uuid::nil(),
        };
        assert_eq!(solana.amount(), "7");
        assert_eq!(solana.fee_amount(), "1");
        assert_eq!(solana.chain_name(), "solana");
        assert_eq!(solana.expiry(), 2);
    }
}
