//! Keep the backend's view of escrow orders in step with the chain.
//!
//! Everything else in the escrow flow is driven by the buyer: they pay, then
//! they ask us to verify. Nothing after that point is. An order is confirmed by
//! the seller, completed by the seller or an admin, and refunded by the seller,
//! an admin, or the buyer themselves once the timeout passes — none of which
//! goes through this backend, because none of it needs to.
//!
//! So without a sweep the database would record every order as it looked the
//! moment it was funded, forever. The case that matters is a **refund**: the
//! money has gone back to the buyer and the booking is not paid for, and
//! nothing would ever say so.
//!
//! ## Read-only, and deliberately so
//!
//! This observes and records. It never settles, refunds or completes anything
//! on-chain — the backend holds no key that could, which is the point of the
//! design rather than a limitation of this module.
//!
//! ## One sweep per chain
//!
//! A deployment may run escrows on both Solana and an EVM chain, and each gets
//! its own sweep. Each only touches orders belonging to its own contract: an
//! order hash is a `0x` string on EVM and a base58 address on Solana, so a
//! cross-chain read is not a subtle mistake, it is an immediate decode failure.
//! Filtering keeps the logs quiet and, more to the point, keeps `failed` in the
//! summary meaning something — if every sweep counted the other chain's orders
//! as unreadable, a genuinely unreachable RPC would look like business as usual.

use chrono::Utc;

use crate::domain::entities::payment::Payment;
use crate::domain::ports::escrow_gateway::{EscrowGateway, EscrowOrderStatus};
use crate::domain::repositories::escrow_order_repository::EscrowOrderRepository;
use crate::domain::repositories::payment_repository::PaymentRepository;
use crate::shared::errors::DomainError;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Orders whose funds were still held, so worth re-reading.
    pub checked: usize,
    /// Orders whose on-chain status had moved since we last looked.
    pub changed: usize,
    /// Orders refunded, each of which unmakes a payment.
    pub refunded: usize,
    /// Orders that could not be read. Counted rather than aborting the sweep.
    pub failed: usize,
}

pub struct ReconcileEscrowOrders<ER, PR, G>
where
    ER: EscrowOrderRepository,
    PR: PaymentRepository,
    G: EscrowGateway + ?Sized,
{
    escrow_orders: ER,
    payments: PR,
    gateway: std::sync::Arc<G>,
}

impl<ER, PR, G> ReconcileEscrowOrders<ER, PR, G>
where
    ER: EscrowOrderRepository,
    PR: PaymentRepository,
    G: EscrowGateway + ?Sized,
{
    pub fn new(escrow_orders: ER, payments: PR, gateway: std::sync::Arc<G>) -> Self {
        Self {
            escrow_orders,
            payments,
            gateway,
        }
    }

    pub async fn execute(&self) -> Result<ReconcileSummary, DomainError> {
        let program_id = self.gateway.program_id();
        let open: Vec<_> = self
            .escrow_orders
            .find_open()
            .await?
            .into_iter()
            .filter(|record| record.program_id == program_id)
            .collect();

        let mut summary = ReconcileSummary {
            checked: open.len(),
            ..Default::default()
        };

        for record in open {
            // One unreadable account -- a flaky RPC, a rate limit -- must not
            // stop the sweep from reaching the rest. The next cycle retries it.
            match self.reconcile_one(&record).await {
                Ok(Some(status)) => {
                    summary.changed += 1;
                    if status == EscrowOrderStatus::Refunded {
                        summary.refunded += 1;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    summary.failed += 1;
                    log::warn!(
                        "escrow reconciliation skipped order {}: {}",
                        record.order_id,
                        e
                    );
                }
            }
        }

        Ok(summary)
    }

    /// `Ok(Some(status))` when the chain had moved on; `Ok(None)` when it had not.
    async fn reconcile_one(
        &self,
        record: &crate::domain::entities::escrow_order::EscrowOrderRecord,
    ) -> Result<Option<EscrowOrderStatus>, DomainError> {
        let order = match self.gateway.fetch_order(&record.order_account).await? {
            Some(order) => order,
            // The account is gone. An order PDA is not closed by any instruction
            // the program has, so this means the RPC is behind, or pointed at a
            // different cluster. Either way, not something to act on: leaving
            // the record alone is strictly safer than inferring a settlement
            // from an absence.
            None => return Ok(None),
        };

        if order.status == record.chain_status {
            return Ok(None);
        }

        let now = Utc::now();
        self.escrow_orders
            .update_chain_status(&record.order_id, order.status, now)
            .await?;

        if order.status == EscrowOrderStatus::Refunded {
            self.unmake_payment(record).await?;
        }

        Ok(Some(order.status))
    }

    /// The money went back to the buyer, so the booking is not paid for.
    ///
    /// The payment row is moved out of `confirmed`; the escrow record keeps the
    /// precise state, including when the refund was observed. The two are not
    /// redundant: `payments` answers "has this booking been settled" and is read
    /// by everything that does not know escrow exists.
    async fn unmake_payment(
        &self,
        record: &crate::domain::entities::escrow_order::EscrowOrderRecord,
    ) -> Result<(), DomainError> {
        let mut payment: Payment = match self.payments.find_by_booking_id(&record.booking_id).await
        {
            Ok(payment) => payment,
            // No payment row to correct. The refund is still recorded against
            // the escrow order, which is where the truth lives.
            Err(DomainError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };

        if payment.mark_refunded() {
            self.payments.update(&payment).await?;
            log::info!(
                "escrow order {} was refunded; booking {} is no longer settled",
                record.order_id,
                record.booking_id
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::escrow_order::EscrowOrderRecord;
    use crate::domain::entities::payment::PaymentStatus;
    use crate::domain::entities::quote::{PaymentQuote, QuoteStatus};
    use crate::domain::ports::escrow_gateway::EscrowOrder;
    use crate::domain::value_objects::money::{FiatCurrency, Money, PriceBreakdown};
    use crate::domain::value_objects::{Chain, CryptoToken};
    use async_trait::async_trait;
    use chrono::DateTime;
    use rust_decimal::Decimal;
    use std::collections::HashMap;
    use std::str::FromStr as _;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    fn record(booking_id: Uuid, order_id: &str, status: EscrowOrderStatus) -> EscrowOrderRecord {
        EscrowOrderRecord {
            id: Uuid::new_v4(),
            booking_id,
            quote_id: Uuid::new_v4(),
            order_id: order_id.to_string(),
            order_account: format!("Acct-{}", order_id),
            program_id: "Prog".to_string(),
            buyer: "Buyer".to_string(),
            seller: "Seller".to_string(),
            mint: "So11111111111111111111111111111111111111112".to_string(),
            amount_base_units: 1_150_000_000u128,
            fee_base_units: 150_000_000u128,
            chain_status: status,
            verified_at: Some(Utc::now()),
            settled_at: None,
            refunded_at: None,
            deposit_signature: None,
        }
    }

    fn on_chain(order_id: &str, status: EscrowOrderStatus) -> EscrowOrder {
        EscrowOrder {
            buyer: "Buyer".to_string(),
            seller: "Seller".to_string(),
            mint: "So11111111111111111111111111111111111111112".to_string(),
            payout_wallet: "Payout".to_string(),
            treasury: "Treasury".to_string(),
            amount: 1_150_000_000,
            fee_amount: 150_000_000,
            status,
            created_at: 1_700_000_000,
            settlement_deadline: 1_700_003_600,
            timeout_deadline: 1_700_005_400,
            quote_expiry: 1_700_000_180,
            order_id_hash: [0u8; 32],
            order_id: order_id.to_string(),
        }
    }

    fn confirmed_payment(booking_id: Uuid) -> Payment {
        let now = Utc::now();
        let pricing =
            PriceBreakdown::calculate(Money::from_cents(100_000, FiatCurrency::Usd).unwrap())
                .unwrap();
        let mut quote = PaymentQuote::issue(
            Uuid::new_v4(),
            booking_id,
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
        let mut payment = Payment::from_quote(Uuid::new_v4(), &quote).unwrap();
        payment.status = PaymentStatus::Confirmed;
        payment
    }

    #[derive(Clone, Default)]
    struct EscrowOrders {
        rows: Arc<Mutex<Vec<EscrowOrderRecord>>>,
        status_writes: Arc<Mutex<Vec<(String, EscrowOrderStatus)>>>,
    }

    #[async_trait]
    impl EscrowOrderRepository for EscrowOrders {
        async fn find_by_booking(
            &self,
            _: &Uuid,
        ) -> Result<Option<EscrowOrderRecord>, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn find_by_order_id(
            &self,
            _: &str,
        ) -> Result<Option<EscrowOrderRecord>, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn record_verified(
            &self,
            _: &EscrowOrderRecord,
        ) -> Result<EscrowOrderRecord, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn update_chain_status(
            &self,
            order_id: &str,
            status: EscrowOrderStatus,
            _: DateTime<Utc>,
        ) -> Result<(), DomainError> {
            self.status_writes
                .lock()
                .unwrap()
                .push((order_id.to_string(), status));
            Ok(())
        }
        async fn find_open(&self) -> Result<Vec<EscrowOrderRecord>, DomainError> {
            Ok(self.rows.lock().unwrap().clone())
        }
    }

    #[derive(Clone, Default)]
    struct Payments {
        by_booking: Arc<Mutex<HashMap<Uuid, Payment>>>,
        updates: Arc<Mutex<Vec<Payment>>>,
    }

    #[async_trait]
    impl PaymentRepository for Payments {
        async fn find_by_booking_id(&self, booking_id: &Uuid) -> Result<Payment, DomainError> {
            self.by_booking
                .lock()
                .unwrap()
                .get(booking_id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound("payment".to_string()))
        }
        async fn find_all(&self) -> Result<Vec<Payment>, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn find_pending_with_tx(&self) -> Result<Vec<Payment>, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn find_by_tx_hash(&self, _: &str) -> Result<Option<Payment>, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn save(&self, _: &Payment) -> Result<(), DomainError> {
            unreachable!("not used by this use case")
        }
        async fn update(&self, payment: &Payment) -> Result<(), DomainError> {
            self.by_booking
                .lock()
                .unwrap()
                .insert(payment.booking_id, payment.clone());
            self.updates.lock().unwrap().push(payment.clone());
            Ok(())
        }
    }

    /// Answers per order account, so one sweep can see several outcomes.
    struct Gateway {
        orders: HashMap<String, Option<EscrowOrder>>,
        fail: Vec<String>,
    }

    #[async_trait]
    impl EscrowGateway for Gateway {
        async fn fetch_order(&self, account: &str) -> Result<Option<EscrowOrder>, DomainError> {
            if self.fail.iter().any(|a| a == account) {
                return Err(DomainError::InternalError("rpc exploded".to_string()));
            }
            Ok(self.orders.get(account).cloned().flatten())
        }
        fn program_id(&self) -> &str {
            "Prog"
        }
    }

    struct Harness {
        booking_id: Uuid,
        escrow_orders: EscrowOrders,
        payments: Payments,
        use_case: ReconcileEscrowOrders<EscrowOrders, Payments, Gateway>,
    }

    fn harness(stored: EscrowOrderStatus, chain: Option<EscrowOrderStatus>) -> Harness {
        let booking_id = Uuid::new_v4();
        let order_id = "order-1";
        let rec = record(booking_id, order_id, stored);

        let escrow_orders = EscrowOrders::default();
        escrow_orders.rows.lock().unwrap().push(rec.clone());

        let payments = Payments::default();
        payments
            .by_booking
            .lock()
            .unwrap()
            .insert(booking_id, confirmed_payment(booking_id));

        let mut orders = HashMap::new();
        orders.insert(
            rec.order_account.clone(),
            chain.map(|s| on_chain(order_id, s)),
        );

        Harness {
            booking_id,
            escrow_orders: escrow_orders.clone(),
            payments: payments.clone(),
            use_case: ReconcileEscrowOrders::new(
                escrow_orders,
                payments,
                Arc::new(Gateway {
                    orders,
                    fail: Vec::new(),
                }),
            ),
        }
    }

    #[tokio::test]
    async fn an_unchanged_order_is_left_alone() {
        // The common case by far. A sweep that writes every cycle would churn
        // the table and the audit trail for nothing.
        let h = harness(EscrowOrderStatus::Pending, Some(EscrowOrderStatus::Pending));
        let summary = h.use_case.execute().await.unwrap();

        assert_eq!(summary.checked, 1);
        assert_eq!(summary.changed, 0);
        assert!(h.escrow_orders.status_writes.lock().unwrap().is_empty());
        assert!(h.payments.updates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_sellers_confirmation_is_picked_up() {
        // Nothing moves on-chain and nothing changes about the payment -- the
        // seller has simply accepted the job, and the mirror should say so.
        let h = harness(
            EscrowOrderStatus::Pending,
            Some(EscrowOrderStatus::Confirmed),
        );
        let summary = h.use_case.execute().await.unwrap();

        assert_eq!(summary.changed, 1);
        assert_eq!(summary.refunded, 0);
        assert_eq!(
            h.escrow_orders
                .status_writes
                .lock()
                .unwrap()
                .first()
                .unwrap()
                .1,
            EscrowOrderStatus::Confirmed
        );
        assert!(
            h.payments.updates.lock().unwrap().is_empty(),
            "a confirmation does not change whether the booking is paid"
        );
    }

    #[tokio::test]
    async fn settlement_is_recorded_without_unsettling_the_payment() {
        let h = harness(
            EscrowOrderStatus::Confirmed,
            Some(EscrowOrderStatus::Completed),
        );
        let summary = h.use_case.execute().await.unwrap();

        assert_eq!(summary.changed, 1);
        assert_eq!(summary.refunded, 0);
        // Completed means the seller has been paid out. More paid, not less.
        assert_eq!(
            h.payments
                .by_booking
                .lock()
                .unwrap()
                .get(&h.booking_id)
                .unwrap()
                .status,
            PaymentStatus::Confirmed
        );
    }

    /// The reason this sweep exists. A refund is issued on-chain by the seller,
    /// an admin, or the buyer themselves after the timeout -- never through this
    /// backend. Without the sweep the booking would read as paid forever.
    #[tokio::test]
    async fn a_refund_unmakes_the_payment() {
        let h = harness(
            EscrowOrderStatus::Confirmed,
            Some(EscrowOrderStatus::Refunded),
        );
        let summary = h.use_case.execute().await.unwrap();

        assert_eq!(summary.refunded, 1);
        assert_eq!(
            h.payments
                .by_booking
                .lock()
                .unwrap()
                .get(&h.booking_id)
                .unwrap()
                .status,
            PaymentStatus::Failed
        );
    }

    #[tokio::test]
    async fn a_refund_seen_twice_writes_the_payment_once() {
        let h = harness(
            EscrowOrderStatus::Confirmed,
            Some(EscrowOrderStatus::Refunded),
        );
        h.use_case.execute().await.unwrap();
        // The row is still in `find_open` from this fake's point of view, so the
        // second cycle sees the same refund again.
        h.use_case.execute().await.unwrap();

        assert_eq!(
            h.payments.updates.lock().unwrap().len(),
            1,
            "the status had already moved; there was nothing to write"
        );
    }

    #[tokio::test]
    async fn a_missing_account_is_not_treated_as_a_settlement() {
        // An order PDA is never closed by any instruction the program has, so
        // this means the RPC is behind or on another cluster. Inferring
        // anything from an absence would be inferring it from a bug.
        let h = harness(EscrowOrderStatus::Pending, None);
        let summary = h.use_case.execute().await.unwrap();

        assert_eq!(summary.changed, 0);
        assert_eq!(summary.failed, 0);
        assert!(h.escrow_orders.status_writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_unreadable_order_does_not_starve_the_rest() {
        let booking_a = Uuid::new_v4();
        let booking_b = Uuid::new_v4();
        let bad = record(booking_a, "order-bad", EscrowOrderStatus::Confirmed);
        let good = record(booking_b, "order-good", EscrowOrderStatus::Confirmed);

        let escrow_orders = EscrowOrders::default();
        escrow_orders.rows.lock().unwrap().push(bad.clone());
        escrow_orders.rows.lock().unwrap().push(good.clone());

        let payments = Payments::default();
        payments
            .by_booking
            .lock()
            .unwrap()
            .insert(booking_b, confirmed_payment(booking_b));

        let mut orders = HashMap::new();
        orders.insert(
            good.order_account.clone(),
            Some(on_chain("order-good", EscrowOrderStatus::Refunded)),
        );

        let use_case = ReconcileEscrowOrders::new(
            escrow_orders,
            payments.clone(),
            Arc::new(Gateway {
                orders,
                fail: vec![bad.order_account.clone()],
            }),
        );

        let summary = use_case.execute().await.unwrap();
        assert_eq!(summary.checked, 2);
        assert_eq!(summary.failed, 1);
        // The reachable one was still reconciled.
        assert_eq!(summary.refunded, 1);
        assert_eq!(
            payments
                .by_booking
                .lock()
                .unwrap()
                .get(&booking_b)
                .unwrap()
                .status,
            PaymentStatus::Failed
        );
    }

    #[tokio::test]
    async fn a_refund_with_no_payment_row_is_still_recorded() {
        // The escrow record is where the truth lives; a missing bookkeeping row
        // must not stop the chain state being written down.
        let booking_id = Uuid::new_v4();
        let rec = record(booking_id, "order-1", EscrowOrderStatus::Confirmed);
        let escrow_orders = EscrowOrders::default();
        escrow_orders.rows.lock().unwrap().push(rec.clone());

        let mut orders = HashMap::new();
        orders.insert(
            rec.order_account.clone(),
            Some(on_chain("order-1", EscrowOrderStatus::Refunded)),
        );

        let use_case = ReconcileEscrowOrders::new(
            escrow_orders.clone(),
            Payments::default(),
            Arc::new(Gateway {
                orders,
                fail: Vec::new(),
            }),
        );

        let summary = use_case.execute().await.unwrap();
        assert_eq!(summary.refunded, 1);
        assert_eq!(
            escrow_orders
                .status_writes
                .lock()
                .unwrap()
                .first()
                .unwrap()
                .1,
            EscrowOrderStatus::Refunded
        );
    }

    /// A deployment may run both escrows, and each sweep sees every open row.
    /// Reading an EVM order hash through the Solana gateway is not a subtle
    /// mistake -- base58 decoding fails immediately -- but it would count as a
    /// failure every cycle, and a summary where `failed` is always non-zero is
    /// a summary nobody reads.
    #[tokio::test]
    async fn a_sweep_ignores_orders_belonging_to_the_other_chain() {
        let ours = record(Uuid::new_v4(), "order-ours", EscrowOrderStatus::Confirmed);
        let mut theirs = record(Uuid::new_v4(), "order-theirs", EscrowOrderStatus::Confirmed);
        theirs.program_id = "0xSomeOtherContract".to_string();

        let escrow_orders = EscrowOrders::default();
        escrow_orders.rows.lock().unwrap().push(ours.clone());
        escrow_orders.rows.lock().unwrap().push(theirs.clone());

        // The gateway answers for either account, so only the filter can stop
        // the other chain's order being reconciled.
        let mut orders = HashMap::new();
        orders.insert(
            ours.order_account.clone(),
            Some(on_chain("order-ours", EscrowOrderStatus::Refunded)),
        );
        orders.insert(
            theirs.order_account.clone(),
            Some(on_chain("order-theirs", EscrowOrderStatus::Refunded)),
        );

        let use_case = ReconcileEscrowOrders::new(
            escrow_orders.clone(),
            Payments::default(),
            Arc::new(Gateway {
                orders,
                fail: Vec::new(),
            }),
        );

        let summary = use_case.execute().await.unwrap();
        assert_eq!(summary.checked, 1, "only this chain's orders are swept");
        assert_eq!(summary.failed, 0);

        let written = escrow_orders.status_writes.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].0, "order-ours");
    }

    #[tokio::test]
    async fn an_empty_sweep_does_nothing() {
        let use_case = ReconcileEscrowOrders::new(
            EscrowOrders::default(),
            Payments::default(),
            Arc::new(Gateway {
                orders: HashMap::new(),
                fail: Vec::new(),
            }),
        );
        assert_eq!(
            use_case.execute().await.unwrap(),
            ReconcileSummary::default()
        );
    }
}
