use crate::shared::errors::DomainError;

/// Lifecycle of an escrow order, mirroring the on-chain `OrderStatus` enum.
///
/// Borsh serialises a fieldless enum as one discriminant byte, so these values
/// are the wire format and their order is part of the contract with the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowOrderStatus {
    Pending,
    Confirmed,
    Completed,
    Refunded,
}

impl EscrowOrderStatus {
    pub fn from_discriminant(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Pending),
            1 => Some(Self::Confirmed),
            2 => Some(Self::Completed),
            3 => Some(Self::Refunded),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Completed => "completed",
            Self::Refunded => "refunded",
        }
    }
}

/// An escrow order as it exists on-chain, decoded from the program's account.
///
/// Every field is read from the chain, never from the client. The client only
/// says *which* account to look at, and even that is checked: the account must
/// be owned by the escrow program, and `order_id` must match the booking the
/// caller claims to be settling.
#[derive(Debug, Clone)]
pub struct EscrowOrder {
    pub buyer: String,
    pub seller: String,
    pub mint: String,
    pub payout_wallet: String,
    pub treasury: String,
    /// Escrowed amount in the asset's smallest unit.
    ///
    /// `u128`, not `u64`, because this type serves both chains. Solana's
    /// program stores a `u64` and widens on read; an EVM amount is wei, where
    /// twenty ether is 2 x 10^19 and a `u64` would silently truncate it.
    pub amount: u128,
    /// Platform fee carved out of `amount` at completion.
    pub fee_amount: u128,
    pub status: EscrowOrderStatus,
    pub created_at: i64,
    pub settlement_deadline: i64,
    pub timeout_deadline: i64,
    pub quote_expiry: i64,
    /// The 32-byte key the chain derives from the order id: keccak256 of the id
    /// on Solana, where it seeds the order PDA, and
    /// `keccak256(abi.encode(buyer, orderId))` on EVM, where it is the storage
    /// slot. Both are a commitment to the same identifier.
    pub order_id_hash: [u8; 32],
    pub order_id: String,
}

/// Reads escrow state from the chain the program is deployed on.
///
/// Deliberately read-only. The backend never builds, signs or submits an escrow
/// transaction: the buyer's wallet does that, and the backend's job is to decide
/// whether what landed on-chain actually settles the order it is shown against.
#[async_trait::async_trait]
pub trait EscrowGateway: Send + Sync {
    /// Fetch and decode the order account at `order_account`.
    ///
    /// `Ok(None)` means no such account yet, which is an ordinary "not deposited
    /// yet" answer rather than a failure.
    async fn fetch_order(&self, order_account: &str) -> Result<Option<EscrowOrder>, DomainError>;

    /// The program id this gateway will accept accounts from.
    fn program_id(&self) -> &str;
}
