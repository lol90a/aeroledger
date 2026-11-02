//! Authorising a price for the escrow program.
//!
//! The escrow program will not let a buyer name their own amount. It requires an
//! Ed25519 signature, from a key it has been told to trust, over a canonical
//! message naming the order, the buyer, the seller, the mint and the figures.
//! The buyer carries that signature into the same transaction as `create_order`.
//!
//! This port exists so the application layer can say "authorise this price"
//! without knowing what an Ed25519 key is, let alone holding one. The signing
//! key lives in infrastructure and never leaves it -- there is deliberately no
//! method here that returns, exports or derives the private half.

use crate::shared::errors::DomainError;

/// How long an on-chain price authorization is valid for, in seconds.
///
/// A policy decision, and chain-agnostic, which is why it lives beside the port
/// rather than in either chain's adapter. Three distinct lifetimes are at play
/// and conflating any two of them is a real bug:
///
///   * the **contract's ceiling** -- 900 seconds on both deployments -- checked
///     against the block timestamp at execution;
///   * the **price reservation** (`QUOTE_TTL_SECONDS`, ten minutes), the
///     business promise that the amount will not move;
///   * this, the life of one signature permitting one on-chain attempt at the
///     already-agreed amount.
///
/// Short, because a leaked signature is only useful until it expires. Not too
/// short, because the buyer has to read a wallet prompt, approve it, and the
/// transaction has to reach execution on a congested chain.
pub const AUTHORIZATION_TTL_SECONDS: i64 = 180;

/// The earliest of our TTL and the reservation behind it.
///
/// **An authorization must never outlive the reservation it authorises.** If it
/// could, a buyer who let the reservation lapse would still hold a valid
/// signature for the old price -- silent repricing in their favour, and it makes
/// a short-lived signature pointless.
///
/// `None` once the reservation has lapsed: there is nothing left to authorise,
/// and the caller must re-quote rather than quietly extend.
pub fn authorization_expiry_within(
    now: i64,
    reservation_expires_at: i64,
    contract_ceiling_secs: i64,
) -> Option<i64> {
    if reservation_expires_at <= now {
        return None;
    }
    let ours = now.saturating_add(AUTHORIZATION_TTL_SECONDS);
    let expiry = ours.min(reservation_expires_at);

    // Defensive: our TTL sits well inside both contracts' ceilings, but a future
    // change to either must not start issuing quotes they reject outright.
    if expiry - now > contract_ceiling_secs {
        return Some(now + contract_ceiling_secs);
    }
    Some(expiry)
}

/// The figures being authorised, in the token's smallest unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowQuote {
    /// Total the buyer must escrow.
    pub amount: u64,
    /// Platform fee, carved out of `amount` at settlement.
    pub fee_amount: u64,
    /// Unix seconds after which the program refuses this authorization.
    pub expiry: i64,
}

/// What the browser needs to put the authorization on-chain.
///
/// `message` is included rather than left for the client to rebuild: the client
/// must pass the exact bytes to the Ed25519 instruction, and a client that
/// reconstructs them from the parts has one more place to drift from the
/// program's layout -- a drift whose only symptom is a rejected transaction.
#[derive(Debug, Clone)]
pub struct SignedEscrowQuote {
    pub message: Vec<u8>,
    pub signature: [u8; 64],
    /// Base58 public key, so the client can check it against the chain.
    pub authority: String,
    pub quote: EscrowQuote,
}

/// Signs price authorizations for the escrow program.
#[async_trait::async_trait]
pub trait QuoteSigner: Send + Sync {
    /// Sign one price, bound to one order, buyer, seller and mint.
    ///
    /// All four are inside the signed bytes, so an authorization cannot be
    /// replayed onto a different order, moved to a different buyer, re-pointed
    /// at a different seller, or reused for a different token.
    fn sign_escrow_quote(
        &self,
        order_id: &str,
        buyer: &str,
        seller: &str,
        mint: &str,
        quote: EscrowQuote,
    ) -> Result<SignedEscrowQuote, DomainError>;

    /// The public key the program must have recorded as its quote authority.
    fn authority_base58(&self) -> String;

    /// When an authorization issued at `now` should expire, given that the
    /// price reservation behind it ends at `reservation_expires_at`.
    ///
    /// `None` once the reservation has lapsed: there is nothing left to
    /// authorise, and the caller must re-quote rather than quietly extend.
    fn authorization_expiry(&self, now: i64, reservation_expires_at: i64) -> Option<i64>;
}
