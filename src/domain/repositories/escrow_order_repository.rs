use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::entities::escrow_order::EscrowOrderRecord;
use crate::domain::ports::escrow_gateway::EscrowOrderStatus;
use crate::shared::errors::DomainError;

/// Persistence for the backend's mirror of on-chain escrow orders.
#[async_trait::async_trait]
pub trait EscrowOrderRepository: Send + Sync {
    async fn find_by_booking(
        &self,
        booking_id: &Uuid,
    ) -> Result<Option<EscrowOrderRecord>, DomainError>;

    async fn find_by_order_id(
        &self,
        order_id: &str,
    ) -> Result<Option<EscrowOrderRecord>, DomainError>;

    /// Record a verified deposit, or return the row already there.
    ///
    /// **Idempotent, and that is the point.** A buyer can submit the same
    /// verification twice -- a double-click, a retried request, a page reload --
    /// and the program's own `init` means there is at most one order per
    /// `order_id` on-chain regardless. So a second call must observe the first
    /// rather than insert a second row or fail the customer's request.
    ///
    /// Returns the stored record: the one just inserted, or the pre-existing
    /// one. The caller compares it against what it just verified, so that a
    /// *different* order claiming an id we have already settled is caught
    /// instead of silently accepted.
    async fn record_verified(
        &self,
        record: &EscrowOrderRecord,
    ) -> Result<EscrowOrderRecord, DomainError>;

    /// Update the mirrored chain state after re-reading the account.
    ///
    /// `at` stamps `settled_at` or `refunded_at` when the status moves into a
    /// terminal state, so the moment the funds left the vault is recorded once
    /// and not overwritten by later sweeps.
    async fn update_chain_status(
        &self,
        order_id: &str,
        status: EscrowOrderStatus,
        at: DateTime<Utc>,
    ) -> Result<(), DomainError>;

    /// Orders whose funds are still held, for the reconciliation sweep.
    async fn find_open(&self) -> Result<Vec<EscrowOrderRecord>, DomainError>;
}
