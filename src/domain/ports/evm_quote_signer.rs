//! Authorising a price for the Solidity escrow.
//!
//! The same job as [`QuoteSigner`] does for Solana, and deliberately a separate
//! port rather than a generalisation of it. The two chains sign genuinely
//! different things:
//!
//! |              | Solana                         | EVM                          |
//! |--------------|--------------------------------|------------------------------|
//! | scheme       | Ed25519 over a flat message    | secp256k1 over EIP-712       |
//! | the client   | carries the message *and* sig  | carries the signature only   |
//! | amounts      | `u64` lamports                 | `u128` wei                   |
//! | bound to     | mint, order id hash            | token, chain id, contract    |
//!
//! Forcing one trait over both would mean a lowest-common-denominator shape
//! with optional fields that are mandatory on one chain and meaningless on the
//! other — which is how a caller ends up passing `None` for something the
//! contract requires and finding out at execution.
//!
//! [`QuoteSigner`]: super::quote_signer::QuoteSigner

use crate::shared::errors::DomainError;

/// The figures being authorised, in the asset's smallest unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmEscrowQuote {
    /// Total the buyer must escrow. Wei for the native coin.
    ///
    /// `u128`, not `u64`: one ether is 10^18 wei and twenty ether is 2 × 10^19,
    /// which a `u64` cannot hold. Truncating would sign a quote for a fraction
    /// of the real price.
    pub amount: u128,
    /// Platform fee, carved out of `amount`. Strictly less than it.
    pub fee: u128,
    /// Unix seconds after which the contract refuses this authorization.
    pub expiry: i64,
}

/// What the browser needs to call `createOrder`.
///
/// Unlike the Solana side there is no message to carry: the contract rebuilds
/// the EIP-712 digest from the call's own arguments and recovers the signer
/// from the signature. So the client passes the figures and the signature, and
/// any disagreement between them recovers a different address and reverts.
#[derive(Debug, Clone)]
pub struct SignedEvmQuote {
    /// `keccak256(abi.encode(buyer, orderId))` — the contract's storage key for
    /// this order, `0x`-prefixed. Returned so the backend can later read the
    /// order back without re-deriving it from a client-supplied value.
    pub order_hash: String,
    /// 65 bytes as `0x` hex: r, s, then v as 27 or 28.
    pub signature: String,
    /// The address the contract must have recorded as `quoteSigner`, so the
    /// client can check the two agree before asking anyone to sign.
    pub signer: String,
    pub quote: EvmEscrowQuote,
}

/// Signs EIP-712 price authorizations for the Solidity escrow.
#[async_trait::async_trait]
pub trait EvmQuoteSigner: Send + Sync {
    /// Sign one price, bound to one order, buyer, seller, token, chain and
    /// contract.
    ///
    /// The chain id and contract address are inside the EIP-712 domain, so an
    /// authorization for a testnet deployment can never authorise the same
    /// payment on mainnet — which a flat signed message would not prevent.
    fn sign_evm_quote(
        &self,
        order_id: &str,
        buyer: &str,
        seller: &str,
        token: &str,
        quote: EvmEscrowQuote,
    ) -> Result<SignedEvmQuote, DomainError>;

    /// The address the contract must have recorded as `quoteSigner`.
    fn signer_address(&self) -> String;

    /// When an authorization issued at `now` should expire, given the price
    /// reservation behind it. `None` once the reservation has lapsed.
    fn authorization_expiry(&self, now: i64, reservation_expires_at: i64) -> Option<i64>;
}
