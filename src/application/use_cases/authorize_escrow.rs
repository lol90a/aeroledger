//! Authorise a buyer to open an escrow order at an already-agreed price.
//!
//! This is the hinge between the reservation the customer accepted and the
//! transaction their wallet is about to sign. It produces a short-lived Ed25519
//! signature over the exact figures, which the escrow program verifies before it
//! will take a single token.
//!
//! ## What it refuses, and why
//!
//! The buyer's browser supplies two things: which booking, and which wallet.
//! Everything else -- the amount, the fee split, the seller, the mint, the
//! expiry -- is read from the accepted quote and from deployment configuration.
//! There is deliberately no input here that lets a caller influence what gets
//! signed, because a signature is an instruction to the program and the program
//! has no way to second-guess it.
//!
//! The quote must be **accepted**: a price the user has explicitly approved. An
//! active-but-unapproved quote is a number they have merely been shown, and
//! authorising it would charge them something they never agreed to.
//!
//! ## Why the order id is the quote id
//!
//! The order PDA is derived from the order id, so the id fixes the address.
//! Using the booking id would give each booking exactly one escrow address for
//! all time: a first attempt that half-failed, or an order that was refunded,
//! would leave that address occupied and the customer permanently unable to
//! pay. The quote id changes whenever the price is re-quoted, so a buyer can
//! always get a fresh address by getting a fresh price -- which is the same
//! thing they would have to do anyway.

use crate::domain::ports::quote_signer::{EscrowQuote, QuoteSigner};
use crate::domain::repositories::quote_repository::QuoteRepository;
use crate::domain::value_objects::Chain;
use crate::shared::errors::DomainError;
use uuid::Uuid;

/// Where the order will live on-chain, and the parties it names.
///
/// Mirrors the deployment's escrow settings. Passed in rather than read here so
/// the application layer stays unaware of how configuration is loaded.
#[derive(Debug, Clone)]
pub struct EscrowDeployment {
    pub program_id: String,
    pub rpc_url: String,
    pub seller: String,
    pub payout_wallet: String,
    pub treasury: String,
    pub mint: String,
}

pub struct AuthorizeEscrowInput {
    pub booking_id: Uuid,
    pub user_id: Uuid,
    /// The wallet that will sign the transaction. Bound into the signature, so
    /// an authorization issued for one wallet is useless to another.
    pub buyer_wallet: String,
}

/// Everything the browser needs to build the transaction.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscrowAuthorizationView {
    pub program_id: String,
    pub rpc_url: String,
    pub order_id: String,
    pub buyer: String,
    pub seller: String,
    pub payout_wallet: String,
    pub treasury: String,
    pub mint: String,
    pub quote_authority: String,
    /// Decimal strings: these exceed what a JSON number holds exactly.
    pub amount: String,
    pub fee_amount: String,
    pub expiry: i64,
    /// Base64, 64 bytes decoded.
    pub signature: String,
    /// The quote this authorises, so the client can tie it back to what it displayed.
    pub quote_id: Uuid,
}

pub struct AuthorizeEscrow<QR: QuoteRepository, S: QuoteSigner + ?Sized> {
    quotes: QR,
    signer: std::sync::Arc<S>,
    deployment: EscrowDeployment,
}

impl<QR: QuoteRepository, S: QuoteSigner + ?Sized> AuthorizeEscrow<QR, S> {
    pub fn new(quotes: QR, signer: std::sync::Arc<S>, deployment: EscrowDeployment) -> Self {
        Self {
            quotes,
            signer,
            deployment,
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
        // The escrow program is a Solana program. A quote priced for another
        // chain cannot be settled through it, and silently pricing it in SOL
        // would charge a different amount than the one accepted.
        if quote.chain != Chain::Solana {
            return Err(DomainError::ValidationError(
                "Escrow payment is available for Solana quotes only".to_string(),
            ));
        }

        let split = quote.escrow_split()?;
        // The Solana program stores token amounts as u64, so this is where a
        // chain-agnostic split meets a chain-specific limit.
        let (amount, fee_amount) = split.to_u64()?;

        let now = chrono::Utc::now().timestamp();
        let expiry = self
            .signer
            .authorization_expiry(now, quote.expires_at.timestamp())
            .ok_or_else(|| {
                // The reservation has run out. Extending the signature past it
                // would hold the old price open indefinitely, so the customer
                // re-quotes and approves the current one instead.
                DomainError::Conflict(
                    "This price reservation has expired; request a new quote".to_string(),
                )
            })?;

        let order_id = quote.id.to_string();
        let signed = self.signer.sign_escrow_quote(
            &order_id,
            &input.buyer_wallet,
            &self.deployment.seller,
            &self.deployment.mint,
            EscrowQuote {
                amount,
                fee_amount,
                expiry,
            },
        )?;

        Ok(EscrowAuthorizationView {
            program_id: self.deployment.program_id.clone(),
            rpc_url: self.deployment.rpc_url.clone(),
            order_id,
            buyer: input.buyer_wallet,
            seller: self.deployment.seller.clone(),
            payout_wallet: self.deployment.payout_wallet.clone(),
            treasury: self.deployment.treasury.clone(),
            mint: self.deployment.mint.clone(),
            quote_authority: signed.authority,
            amount: amount.to_string(),
            fee_amount: fee_amount.to_string(),
            expiry,
            signature: base64_encode(&signed.signature),
            quote_id: quote.id,
        })
    }
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

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        // The classic RFC 4648 vectors, which pin both the alphabet and each of
        // the three padding cases.
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
}
