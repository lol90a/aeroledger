//! Signed price-quote attestations for the Solana escrow program.
//!
//! The program will not let a buyer invent what they pay. The authoritative
//! amount is computed here, signed with an Ed25519 key, and the buyer must
//! embed that signature in the *same transaction* as `create_order` using
//! Solana's native Ed25519 program. The program then introspects the
//! instruction list and proves the verification happened over exactly these
//! bytes.
//!
//! This module is the backend half of that protocol. The message layout below
//! must stay byte-identical to `quote_message` in
//! `contracts/solana/programs/aeroledger-escrow/src/quote.rs`; the domain
//! prefix exists so that if it ever changes, old signatures cannot be replayed
//! against the new layout.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::infrastructure::blockchain::solana_escrow_gateway::keccak256;
use crate::shared::errors::InfraError;

/// Domain separator. Must equal `QUOTE_DOMAIN` in the program.
const QUOTE_DOMAIN: &[u8] = b"AEROLEDGER_ORDER_QUOTE_V1";

/// domain(25) + order_id_hash(32) + buyer(32) + seller(32) + mint(32)
/// + amount(8) + fee_amount(8) + expiry(8)
const QUOTE_MESSAGE_LEN: usize = 25 + 32 + 32 + 32 + 32 + 8 + 8 + 8;

/// The program's ceiling on how far ahead a signed quote may expire, from
/// `MAX_QUOTE_LIFETIME_SECS` in the escrow program. `create_order` rejects
/// anything beyond it, measured against the slot clock at execution time.
pub const PROGRAM_MAX_QUOTE_LIFETIME_SECS: i64 = 900;

/// How long *we* choose to make an on-chain authorization valid.
///
/// This is a policy decision, not the program's limit, and the two are
/// different things:
///
///   * the **price reservation** (`QUOTE_TTL_SECONDS`, ten minutes) is the
///     business promise that the amount will not move;
///   * an **authorization** is a short-lived signature permitting one on-chain
///     attempt at that already-agreed amount.
///
/// Short, because a leaked signature is only useful until it expires. Not too
/// short, because the buyer has to read a Phantom prompt, approve it, and the
/// transaction has to reach execution. Three minutes covers a slow human and a
/// congested cluster while keeping the window small.
pub const AUTHORIZATION_TTL_SECONDS: i64 = 180;

/// Compile-time invariants, so a careless edit to any of these three numbers
/// fails the build rather than a test run — or worse, only shows up as
/// signatures the program rejects at execution.
const _: () = {
    // An authorization the program would refuse outright is useless.
    assert!(AUTHORIZATION_TTL_SECONDS < PROGRAM_MAX_QUOTE_LIFETIME_SECS);
    // If the TTL were not shorter than the reservation, every authorization
    // would be clamped to the reservation and the policy would do nothing.
    assert!(AUTHORIZATION_TTL_SECONDS < crate::domain::entities::quote::QUOTE_TTL_SECONDS);
};

/// What the backend commits to, and what the program enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteCommitment {
    /// Total base units the buyer must escrow.
    pub amount: u64,
    /// Platform fee, carved out of `amount` at payout.
    pub fee_amount: u64,
    /// Unix seconds after which the program refuses this quote.
    pub expiry: i64,
}

/// A quote the browser can put on-chain: the exact bytes that were signed, the
/// signature over them, and the key that produced it.
#[derive(Debug, Clone)]
pub struct SignedQuote {
    pub message: Vec<u8>,
    pub signature: [u8; 64],
    pub authority: String,
    pub commitment: QuoteCommitment,
}

/// Build the canonical quote message.
///
/// Field order and widths are fixed and every integer is little-endian. Pubkeys
/// are the raw 32 bytes, not base58. Any change is a breaking protocol change
/// and must be paired with a new domain.
pub fn quote_message(
    order_id: &str,
    buyer: &[u8; 32],
    seller: &[u8; 32],
    mint: &[u8; 32],
    quote: &QuoteCommitment,
) -> [u8; QUOTE_MESSAGE_LEN] {
    let mut out = [0u8; QUOTE_MESSAGE_LEN];
    let mut at = 0usize;

    let mut put = |src: &[u8], out: &mut [u8; QUOTE_MESSAGE_LEN]| {
        out[at..at + src.len()].copy_from_slice(src);
        at += src.len();
    };

    put(QUOTE_DOMAIN, &mut out);
    put(&keccak256(order_id.as_bytes()), &mut out);
    put(buyer, &mut out);
    put(seller, &mut out);
    put(mint, &mut out);
    put(&quote.amount.to_le_bytes(), &mut out);
    put(&quote.fee_amount.to_le_bytes(), &mut out);
    put(&quote.expiry.to_le_bytes(), &mut out);

    debug_assert_eq!(at, QUOTE_MESSAGE_LEN);
    out
}

/// Holds the Ed25519 key the escrow program trusts to price orders.
///
/// Deliberately separate from any other credential: it is a hot key that must
/// be rotatable without touching the program's admin, which is exactly why the
/// program stores `quote_authority` apart from `admin`.
#[derive(Clone)]
pub struct QuoteAuthority {
    key: SigningKey,
}

impl QuoteAuthority {
    /// Load from a base58-encoded 32-byte seed, which is how the key is carried
    /// in configuration. Never log the input.
    pub fn from_base58_seed(seed: &str) -> Result<Self, InfraError> {
        let bytes = bs58::decode(seed.trim())
            .into_vec()
            .map_err(|_| InfraError::InvalidRequest("quote key is not base58".to_string()))?;

        // Accept either a bare 32-byte seed or a 64-byte Solana-style keypair
        // file (seed followed by public key), since both are common on disk.
        let seed_bytes: [u8; 32] = match bytes.len() {
            32 => bytes[..32].try_into().expect("checked length"),
            64 => bytes[..32].try_into().expect("checked length"),
            n => {
                return Err(InfraError::InvalidRequest(format!(
                    "quote key must decode to 32 or 64 bytes, got {}",
                    n
                )))
            }
        };

        Ok(Self {
            key: SigningKey::from_bytes(&seed_bytes),
        })
    }

    /// Generate a throwaway authority. Development and tests only — a real
    /// deployment loads a key that the on-chain config already names.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Base58 public key, as the program stores it in `Config.quote_authority`.
    pub fn authority_base58(&self) -> String {
        bs58::encode(self.verifying_key().to_bytes()).into_string()
    }

    /// Work out when an authorization issued now should expire.
    ///
    /// Two independent bounds, and the earliest wins:
    ///
    ///   * our own [`AUTHORIZATION_TTL_SECONDS`], keeping the signature's useful
    ///     life short;
    ///   * the price reservation itself. **An authorization must never outlive
    ///     the reservation it authorises.** If it could, a buyer who let the
    ///     reservation lapse would still hold a valid signature for the old
    ///     price, which is silent repricing in the buyer's favour and exactly
    ///     the hole that makes a short-lived signature pointless.
    ///
    /// Returns `None` when the reservation has already expired or has less than
    /// a second left: there is nothing left to authorise, and the caller must
    /// re-quote and have the buyer approve the new amount.
    pub fn authorization_expiry(now: i64, reservation_expires_at: i64) -> Option<i64> {
        if reservation_expires_at <= now {
            return None;
        }
        let ours = now.saturating_add(AUTHORIZATION_TTL_SECONDS);
        let expiry = ours.min(reservation_expires_at);

        // Defensive: our TTL is well inside the program's ceiling, but a future
        // change to either constant must not start issuing quotes the program
        // will reject outright.
        debug_assert!(expiry - now <= PROGRAM_MAX_QUOTE_LIFETIME_SECS);
        if expiry - now > PROGRAM_MAX_QUOTE_LIFETIME_SECS {
            return Some(now + PROGRAM_MAX_QUOTE_LIFETIME_SECS);
        }
        Some(expiry)
    }

    /// Sign a price commitment for one specific order, buyer, seller and mint.
    ///
    /// Every one of those is inside the signed bytes, so a signature issued for
    /// one order cannot be replayed onto another, moved to a different buyer,
    /// re-pointed at a different seller, or reused for a different token.
    pub fn sign_quote(
        &self,
        order_id: &str,
        buyer: &[u8; 32],
        seller: &[u8; 32],
        mint: &[u8; 32],
        commitment: QuoteCommitment,
    ) -> SignedQuote {
        let message = quote_message(order_id, buyer, seller, mint, &commitment);
        let signature = self.key.sign(&message);

        SignedQuote {
            message: message.to_vec(),
            signature: signature.to_bytes(),
            authority: self.authority_base58(),
            commitment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    const BUYER: [u8; 32] = [7u8; 32];
    const SELLER: [u8; 32] = [8u8; 32];
    const MINT: [u8; 32] = [9u8; 32];

    fn commitment() -> QuoteCommitment {
        QuoteCommitment {
            amount: 1_833_740_832,
            fee_amount: 15_000_000,
            expiry: 1_900_000_000,
        }
    }

    /// The layout is a protocol shared with the on-chain program. These offsets
    /// are the contract; if they drift, every signature silently stops
    /// verifying on-chain and the failure looks like a wrong key.
    #[test]
    fn message_layout_matches_the_program_byte_for_byte() {
        let m = quote_message("booking-1", &BUYER, &SELLER, &MINT, &commitment());

        assert_eq!(m.len(), 177);
        assert_eq!(&m[0..25], b"AEROLEDGER_ORDER_QUOTE_V1");
        assert_eq!(&m[25..57], &keccak256(b"booking-1"));
        assert_eq!(&m[57..89], &BUYER);
        assert_eq!(&m[89..121], &SELLER);
        assert_eq!(&m[121..153], &MINT);
        assert_eq!(&m[153..161], &1_833_740_832u64.to_le_bytes());
        assert_eq!(&m[161..169], &15_000_000u64.to_le_bytes());
        assert_eq!(&m[169..177], &1_900_000_000i64.to_le_bytes());
    }

    /// The same golden vector the on-chain program asserts against, in
    /// `contracts/solana/programs/aeroledger-escrow/src/quote_golden.txt`.
    ///
    /// The offsets test above only proves this file agrees with itself. This
    /// one proves it agrees with the program. If either implementation drifts,
    /// one of the two tests fails — which matters, because a silent divergence
    /// would make every signature fail on-chain and the symptom would look like
    /// a wrong key rather than a wrong message.
    #[test]
    fn message_matches_the_programs_own_golden_vector() {
        let golden = include_str!(
            "../../../contracts/solana/programs/aeroledger-escrow/src/quote_golden.txt"
        )
        .trim();

        let m = quote_message("booking-1", &BUYER, &SELLER, &MINT, &commitment());
        let hex: String = m.iter().map(|b| format!("{:02x}", b)).collect();

        assert_eq!(hex, golden);
    }

    #[test]
    fn a_signature_verifies_under_the_declared_authority() {
        let authority = QuoteAuthority::generate();
        let signed = authority.sign_quote("booking-1", &BUYER, &SELLER, &MINT, commitment());

        let key = authority.verifying_key();
        let sig = Signature::from_bytes(&signed.signature);
        assert!(key.verify(&signed.message, &sig).is_ok());
        assert_eq!(signed.authority, authority.authority_base58());
    }

    /// Each of these is inside the signed bytes, so changing any one of them
    /// must invalidate the signature. This is what stops a quote issued for a
    /// cheap order being replayed against an expensive one.
    #[test]
    fn a_signature_does_not_transfer_to_a_different_order() {
        let authority = QuoteAuthority::generate();
        let signed = authority.sign_quote("booking-1", &BUYER, &SELLER, &MINT, commitment());
        let key = authority.verifying_key();
        let sig = Signature::from_bytes(&signed.signature);

        let others = [
            quote_message("booking-2", &BUYER, &SELLER, &MINT, &commitment()),
            quote_message("booking-1", &[1u8; 32], &SELLER, &MINT, &commitment()),
            quote_message("booking-1", &BUYER, &[1u8; 32], &MINT, &commitment()),
            quote_message("booking-1", &BUYER, &SELLER, &[1u8; 32], &commitment()),
            quote_message(
                "booking-1",
                &BUYER,
                &SELLER,
                &MINT,
                &QuoteCommitment {
                    amount: 1,
                    ..commitment()
                },
            ),
            quote_message(
                "booking-1",
                &BUYER,
                &SELLER,
                &MINT,
                &QuoteCommitment {
                    fee_amount: 1,
                    ..commitment()
                },
            ),
            quote_message(
                "booking-1",
                &BUYER,
                &SELLER,
                &MINT,
                &QuoteCommitment {
                    expiry: 1,
                    ..commitment()
                },
            ),
        ];

        for (i, other) in others.iter().enumerate() {
            assert!(
                key.verify(other, &sig).is_err(),
                "variant {} must not verify under the original signature",
                i
            );
        }
    }

    #[test]
    fn a_signature_from_another_key_does_not_verify() {
        let a = QuoteAuthority::generate();
        let b = QuoteAuthority::generate();
        let signed = a.sign_quote("booking-1", &BUYER, &SELLER, &MINT, commitment());

        let sig = Signature::from_bytes(&signed.signature);
        assert!(b.verifying_key().verify(&signed.message, &sig).is_err());
    }

    #[test]
    fn loads_from_a_32_byte_seed_and_a_64_byte_keypair() {
        let seed = [3u8; 32];
        let from_seed =
            QuoteAuthority::from_base58_seed(&bs58::encode(seed).into_string()).unwrap();

        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&seed);
        keypair[32..].copy_from_slice(&from_seed.verifying_key().to_bytes());
        let from_keypair =
            QuoteAuthority::from_base58_seed(&bs58::encode(keypair).into_string()).unwrap();

        assert_eq!(
            from_seed.authority_base58(),
            from_keypair.authority_base58()
        );
    }

    #[test]
    fn rejects_a_key_that_is_not_the_right_length() {
        assert!(QuoteAuthority::from_base58_seed(&bs58::encode([1u8; 16]).into_string()).is_err());
        assert!(QuoteAuthority::from_base58_seed("not base58!!").is_err());
    }

    /// Two different orders must never produce the same signed bytes, or a
    /// quote could be reused across bookings.
    /// A reservation and an authorization are different things with different
    /// lifetimes, and conflating them is how a buyer ends up holding a valid
    /// signature for a price that is no longer on offer.
    mod authorization_expiry {
        use super::*;

        const NOW: i64 = 1_700_000_000;

        #[test]
        fn uses_our_short_ttl_while_the_reservation_has_plenty_left() {
            // Ten minutes of reservation remaining, so our own TTL is the bound.
            let got = QuoteAuthority::authorization_expiry(NOW, NOW + 600);
            assert_eq!(got, Some(NOW + AUTHORIZATION_TTL_SECONDS));
        }

        /// The decisive one. Near the end of a reservation the authorization
        /// must be cut short, never extended past it.
        #[test]
        fn never_outlives_the_reservation_it_authorises() {
            for remaining in [1, 30, AUTHORIZATION_TTL_SECONDS - 1] {
                let got = QuoteAuthority::authorization_expiry(NOW, NOW + remaining);
                assert_eq!(
                    got,
                    Some(NOW + remaining),
                    "with {}s of reservation left the authorization must end with it",
                    remaining
                );
            }
        }

        #[test]
        fn refuses_once_the_reservation_has_expired() {
            assert_eq!(QuoteAuthority::authorization_expiry(NOW, NOW), None);
            assert_eq!(QuoteAuthority::authorization_expiry(NOW, NOW - 1), None);
            assert_eq!(QuoteAuthority::authorization_expiry(NOW, 0), None);
        }

        #[test]
        fn exactly_at_the_ttl_boundary_the_two_bounds_agree() {
            let got = QuoteAuthority::authorization_expiry(NOW, NOW + AUTHORIZATION_TTL_SECONDS);
            assert_eq!(got, Some(NOW + AUTHORIZATION_TTL_SECONDS));
        }

        /// Whatever the policy, the program rejects anything beyond its own
        /// ceiling at execution time, so we must never issue one.
        #[test]
        fn never_exceeds_the_programs_ceiling() {
            let got =
                QuoteAuthority::authorization_expiry(NOW, NOW + 10_000).expect("reservation open");
            assert!(got - NOW <= PROGRAM_MAX_QUOTE_LIFETIME_SECS);
        }

        // The relationship between the three lifetimes is asserted at compile
        // time at the top of this module, which is stronger than a test.
    }

    #[test]
    fn different_orders_produce_different_messages() {
        let a = quote_message("booking-1", &BUYER, &SELLER, &MINT, &commitment());
        let b = quote_message("booking-2", &BUYER, &SELLER, &MINT, &commitment());
        assert_ne!(a, b);
    }
}
