use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::domain::entities::quote::PaymentQuote;
use crate::domain::value_objects::{Money, TxHash};
use crate::shared::errors::DomainError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentStatus {
    Pending,
    Confirmed,
    Failed,
}

impl PaymentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
        }
    }
    pub fn from_str(s: &str) -> Self {
        match s {
            "confirmed" => Self::Confirmed,
            "failed" => Self::Failed,
            _ => Self::Pending,
        }
    }
}

/// A settlement obligation derived from an accepted quote.
///
/// `crypto_base_units` is the authoritative figure: it is what on-chain verification
/// compares against, in the token's smallest unit. `crypto_amount` and `amount` exist
/// for display and accounting respectively and are never used for the comparison --
/// mixing USD cents with token units is exactly the class of bug this separation
/// exists to prevent.
#[derive(Debug, Clone)]
pub struct Payment {
    pub id: Uuid,
    pub booking_id: Uuid,
    /// The accepted quote that fixed this amount.
    pub quote_id: Option<Uuid>,
    pub chain: String,
    pub token: String,
    pub token_decimals: u8,
    /// Fiat value of the booking this payment settles.
    pub amount: Money,
    /// Expected on-chain amount in whole token units (display only).
    pub crypto_amount: Decimal,
    /// Expected on-chain amount in the token's smallest unit. Authoritative.
    pub crypto_base_units: u128,
    pub sender_address: Option<String>,
    pub receiver_address: String,
    pub tx_hash: Option<TxHash>,
    pub status: PaymentStatus,
    pub created_at: DateTime<Utc>,
}

impl Payment {
    /// The only supported construction path: copy an accepted quote verbatim.
    ///
    /// There is deliberately no constructor that takes a caller-supplied amount, so
    /// no code path can create a payment for a price nobody approved.
    pub fn from_quote(id: Uuid, quote: &PaymentQuote) -> Result<Self, DomainError> {
        if !quote.is_settleable() {
            return Err(DomainError::Conflict(
                "Only an accepted quote can be turned into a payment".to_string(),
            ));
        }
        Ok(Self {
            id,
            booking_id: quote.booking_id,
            quote_id: Some(quote.id),
            chain: quote.chain.as_str().to_string(),
            token: quote.token.as_str().to_string(),
            token_decimals: quote.token_decimals,
            amount: quote.pricing.total,
            crypto_amount: quote.crypto_amount,
            crypto_base_units: quote.crypto_base_units,
            sender_address: None,
            receiver_address: quote.receiver_address.clone(),
            tx_hash: None,
            status: PaymentStatus::Pending,
            created_at: Utc::now(),
        })
    }

    pub fn confirm(&mut self, tx_hash: TxHash) -> Result<(), DomainError> {
        if self.status != PaymentStatus::Pending {
            return Err(DomainError::ValidationError(format!(
                "Cannot confirm payment in status '{}'",
                self.status.as_str()
            )));
        }
        self.tx_hash = Some(tx_hash);
        self.status = PaymentStatus::Confirmed;
        Ok(())
    }

    /// Settle because a verified escrow order holds the money.
    ///
    /// Separate from [`confirm`] because the evidence is a different thing. A
    /// direct transfer is settled by a transaction hash this backend looked up
    /// and checked; an escrow payment is settled by an order account this
    /// backend read and checked. `tx_hash` is deliberately left alone: that
    /// column feeds direct-transfer verification and replay detection, and it
    /// holds hashes we verified ourselves. The escrow record carries the
    /// escrow's own evidence.
    ///
    /// Idempotent, because verification is naturally repeated -- a reload, a
    /// retried request, a reconciliation sweep -- and the second pass must not
    /// turn a settled payment into an error.
    ///
    /// [`confirm`]: Self::confirm
    pub fn settle_via_escrow(&mut self, buyer_wallet: &str) -> Result<(), DomainError> {
        match self.status {
            PaymentStatus::Confirmed => Ok(()),
            PaymentStatus::Pending => {
                self.sender_address = Some(buyer_wallet.to_string());
                self.status = PaymentStatus::Confirmed;
                Ok(())
            }
            // A failed payment is a decision somebody made. Reviving it from an
            // escrow deposit would paper over whatever caused it.
            PaymentStatus::Failed => Err(DomainError::Conflict(
                "This payment was marked failed; it cannot be settled from an escrow deposit"
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::quote::{PaymentQuote, QuoteStatus};
    use crate::domain::value_objects::money::{FiatCurrency, Money, PriceBreakdown};
    use crate::domain::value_objects::{Chain, CryptoToken};
    use std::str::FromStr as _;

    const BUYER: &str = "Buyer11111111111111111111111111111111111";

    fn pending_payment() -> Payment {
        let now = Utc::now();
        let pricing =
            PriceBreakdown::calculate(Money::from_cents(100_000, FiatCurrency::Usd).unwrap())
                .unwrap();
        let mut quote = PaymentQuote::issue(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "sol",
            Chain::Solana,
            CryptoToken::Sol,
            pricing,
            Decimal::from(150),
            "test".to_string(),
            now,
            Decimal::from_str("1.15").unwrap(),
            1_150_000_000,
            "SoLReceiver".to_string(),
            now,
        )
        .unwrap();
        quote.status = QuoteStatus::Accepted;
        quote.accepted_at = Some(now);
        Payment::from_quote(Uuid::new_v4(), &quote).unwrap()
    }

    /// Settling from escrow is a different transition from settling a direct
    /// transfer, and the difference is what counts as evidence: a transaction
    /// hash this backend looked up, versus an order account it read.
    mod settle_via_escrow {
        use super::*;

        #[test]
        fn settles_a_pending_payment_and_records_who_paid() {
            let mut payment = pending_payment();
            payment.settle_via_escrow(BUYER).unwrap();

            assert_eq!(payment.status, PaymentStatus::Confirmed);
            assert_eq!(payment.sender_address.as_deref(), Some(BUYER));
        }

        #[test]
        fn leaves_tx_hash_alone() {
            // That column feeds direct-transfer verification and replay
            // detection, and holds hashes we verified ourselves. A deposit
            // signature the client handed us is not one of those.
            let mut payment = pending_payment();
            payment.settle_via_escrow(BUYER).unwrap();
            assert!(payment.tx_hash.is_none());
        }

        #[test]
        fn is_idempotent() {
            // Verification is naturally repeated: a reload, a retried request,
            // a reconciliation sweep. The second pass must not error.
            let mut payment = pending_payment();
            payment.settle_via_escrow(BUYER).unwrap();
            payment.settle_via_escrow(BUYER).unwrap();
            assert_eq!(payment.status, PaymentStatus::Confirmed);
        }

        #[test]
        fn does_not_overwrite_the_original_payer_on_a_repeat() {
            let mut payment = pending_payment();
            payment.settle_via_escrow(BUYER).unwrap();
            payment.settle_via_escrow("SomeoneElse").unwrap();
            assert_eq!(
                payment.sender_address.as_deref(),
                Some(BUYER),
                "the first settlement is the one that happened"
            );
        }

        #[test]
        fn refuses_to_revive_a_failed_payment() {
            // Failure is a decision somebody made. Settling over it would paper
            // over whatever caused it.
            let mut payment = pending_payment();
            payment.status = PaymentStatus::Failed;

            let err = payment.settle_via_escrow(BUYER).unwrap_err();
            assert!(matches!(err, DomainError::Conflict(_)));
            assert_eq!(payment.status, PaymentStatus::Failed);
        }
    }

    #[test]
    fn confirm_still_requires_a_pending_payment() {
        let mut payment = pending_payment();
        payment.settle_via_escrow(BUYER).unwrap();

        // The direct-transfer path is unchanged: it will not confirm twice.
        let err = payment
            .confirm(TxHash::new("0xabcdef0123456789").unwrap())
            .unwrap_err();
        assert!(matches!(err, DomainError::ValidationError(_)));
    }
}
