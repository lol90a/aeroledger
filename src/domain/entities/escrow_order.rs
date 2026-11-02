//! The backend's record of an escrow order that exists on-chain.
//!
//! Every field except the local timestamps is a **mirror**. The program owns
//! this state; nothing here is authoritative, and nothing is written that was
//! not first read back from a program-owned account. The record exists so the
//! backend can answer "has this booking been paid, and where are the funds" and
//! reconcile against the chain without re-deriving it from scratch each time.
//!
//! It is deliberately separate from [`Payment`]. The two answer different
//! questions: a payment says whether the customer has settled their obligation,
//! an escrow order says where the money currently is. A refunded order that
//! still reads as a completed payment is exactly the bug the separation
//! prevents.
//!
//! [`Payment`]: crate::domain::entities::payment::Payment

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::ports::escrow_gateway::EscrowOrderStatus;

#[derive(Debug, Clone)]
pub struct EscrowOrderRecord {
    pub id: Uuid,
    pub booking_id: Uuid,
    /// The quote this order settles. Also the source of `order_id`.
    pub quote_id: Uuid,
    /// The string the program hashes into the order PDA's seed.
    pub order_id: String,
    /// The order PDA.
    pub order_account: String,
    pub program_id: String,
    pub buyer: String,
    pub seller: String,
    pub mint: String,
    pub amount_base_units: u64,
    pub fee_base_units: u64,
    /// Last state read from the chain.
    pub chain_status: EscrowOrderStatus,
    /// When this backend verified the funded order. The only thing that may
    /// mark a booking paid.
    pub verified_at: Option<DateTime<Utc>>,
    pub settled_at: Option<DateTime<Utc>>,
    pub refunded_at: Option<DateTime<Utc>>,
    /// The transaction that funded the escrow, for support and reconciliation.
    pub deposit_signature: Option<String>,
}

impl EscrowOrderRecord {
    /// What the seller receives when this order settles.
    pub fn seller_amount(&self) -> u64 {
        self.amount_base_units.saturating_sub(self.fee_base_units)
    }

    /// True while the funds are still held by the program.
    ///
    /// `Pending` and `Confirmed` both mean "in the vault": confirmation is the
    /// seller accepting the job, which does not move anything.
    pub fn funds_are_escrowed(&self) -> bool {
        matches!(
            self.chain_status,
            EscrowOrderStatus::Pending | EscrowOrderStatus::Confirmed
        )
    }

    /// True once the booking can be treated as paid for.
    ///
    /// Settlement is not required: the money is in the program's custody and
    /// the buyer cannot take it back before the timeout, which is what the
    /// seller needs in order to begin. A refunded order is never paid, however
    /// far the booking had otherwise progressed.
    pub fn is_paid(&self) -> bool {
        self.verified_at.is_some() && !matches!(self.chain_status, EscrowOrderStatus::Refunded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(status: EscrowOrderStatus, verified: bool) -> EscrowOrderRecord {
        EscrowOrderRecord {
            id: Uuid::new_v4(),
            booking_id: Uuid::new_v4(),
            quote_id: Uuid::new_v4(),
            order_id: "order-1".to_string(),
            order_account: "Acct".to_string(),
            program_id: "Prog".to_string(),
            buyer: "Buyer".to_string(),
            seller: "Seller".to_string(),
            mint: "Mint".to_string(),
            amount_base_units: 1_150_000_000,
            fee_base_units: 150_000_000,
            chain_status: status,
            verified_at: verified.then(Utc::now),
            settled_at: None,
            refunded_at: None,
            deposit_signature: None,
        }
    }

    #[test]
    fn the_seller_receives_the_amount_less_the_fee() {
        assert_eq!(
            record(EscrowOrderStatus::Pending, true).seller_amount(),
            1_000_000_000
        );
    }

    #[test]
    fn funds_are_escrowed_while_pending_or_confirmed() {
        // Confirmation is the seller accepting the job. It moves no tokens.
        assert!(record(EscrowOrderStatus::Pending, true).funds_are_escrowed());
        assert!(record(EscrowOrderStatus::Confirmed, true).funds_are_escrowed());
        assert!(!record(EscrowOrderStatus::Completed, true).funds_are_escrowed());
        assert!(!record(EscrowOrderStatus::Refunded, true).funds_are_escrowed());
    }

    #[test]
    fn an_unverified_order_is_never_paid() {
        // An order can exist on-chain without this backend having accepted it:
        // anyone may create an account, and only verification decides it settles
        // the booking it claims to.
        assert!(!record(EscrowOrderStatus::Pending, false).is_paid());
        assert!(!record(EscrowOrderStatus::Confirmed, false).is_paid());
    }

    #[test]
    fn a_verified_order_is_paid_while_the_money_is_in_or_past_escrow() {
        assert!(record(EscrowOrderStatus::Pending, true).is_paid());
        assert!(record(EscrowOrderStatus::Confirmed, true).is_paid());
        // Completed means the seller has been paid out — still paid, more so.
        assert!(record(EscrowOrderStatus::Completed, true).is_paid());
    }

    #[test]
    fn a_refund_unmakes_the_payment() {
        // The money went back to the buyer. However far the booking had
        // progressed, it is not paid for.
        assert!(!record(EscrowOrderStatus::Refunded, true).is_paid());
    }
}
