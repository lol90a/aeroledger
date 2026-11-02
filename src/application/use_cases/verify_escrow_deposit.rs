//! Decide whether an on-chain escrow order actually settles a booking.
//!
//! This is the only thing in the system that may turn a booking into a paid
//! booking over the escrow route. Everything the browser did -- wrapping SOL,
//! assembling the transaction, getting it signed -- is work it did for its own
//! benefit; none of it is evidence. The evidence is the order account, read back
//! from the chain through a gateway that will only accept accounts owned by the
//! escrow program.
//!
//! ## What the client supplies, and why it does not matter
//!
//! One address. That is all. A caller can name any account they like, including
//! a real, fully funded escrow order belonging to somebody else's booking --
//! which is precisely the attack this use case exists to defeat, because the
//! naive version ("it decoded, it has money in it, mark them paid") accepts it.
//!
//! Three layers stop it:
//!
//! 1. the gateway rejects any account the escrow program does not own, and any
//!    account whose recorded `order_id_hash` is not the keccak of its own
//!    `order_id` -- so the decoded contents are internally consistent;
//! 2. this use case requires that `order_id` to be the one **this** quote
//!    derives, so an order belonging to another booking is refused however
//!    genuine it is;
//! 3. every figure and counterparty is compared against the accepted quote and
//!    the deployment, so an order for the right booking at the wrong price, in
//!    the wrong token, or paying a different seller is refused too.
//!
//! ## Idempotency
//!
//! Verification is naturally repeated: a retried request, a reload, a
//! reconciliation sweep. The program allows exactly one order per id, so a
//! second verification must observe the first rather than create a second
//! record. The repository enforces that with a first-write-wins insert, and the
//! stored row is compared against what was just verified -- a different order
//! claiming an id already settled is a conflict, not a no-op.

use chrono::Utc;
use uuid::Uuid;

use crate::domain::entities::escrow_order::EscrowOrderRecord;
use crate::domain::ports::escrow_gateway::{EscrowGateway, EscrowOrder, EscrowOrderStatus};
use crate::domain::repositories::escrow_order_repository::EscrowOrderRepository;
use crate::domain::repositories::payment_repository::PaymentRepository;
use crate::domain::repositories::quote_repository::QuoteRepository;
use crate::shared::errors::DomainError;

use super::authorize_escrow::EscrowDeployment;

pub struct VerifyEscrowDepositInput {
    pub booking_id: Uuid,
    pub user_id: Uuid,
    /// The order PDA. The only thing the client contributes.
    pub order_account: String,
    /// The funding transaction, for support and reconciliation only. Never
    /// trusted, never used to decide whether anything was paid.
    pub deposit_signature: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EscrowDepositView {
    pub booking_id: Uuid,
    pub quote_id: Uuid,
    pub order_account: String,
    pub status: String,
    /// Base units, as a string for the same reason the quote uses one.
    pub amount: String,
    pub fee_amount: String,
    pub seller_amount: String,
    pub paid: bool,
    pub verified_at: Option<String>,
}

pub struct VerifyEscrowDeposit<QR, PR, ER, G>
where
    QR: QuoteRepository,
    PR: PaymentRepository,
    ER: EscrowOrderRepository,
    G: EscrowGateway + ?Sized,
{
    quotes: QR,
    payments: PR,
    escrow_orders: ER,
    gateway: std::sync::Arc<G>,
    deployment: EscrowDeployment,
}

impl<QR, PR, ER, G> VerifyEscrowDeposit<QR, PR, ER, G>
where
    QR: QuoteRepository,
    PR: PaymentRepository,
    ER: EscrowOrderRepository,
    G: EscrowGateway + ?Sized,
{
    pub fn new(
        quotes: QR,
        payments: PR,
        escrow_orders: ER,
        gateway: std::sync::Arc<G>,
        deployment: EscrowDeployment,
    ) -> Self {
        Self {
            quotes,
            payments,
            escrow_orders,
            gateway,
            deployment,
        }
    }

    pub async fn execute(
        &self,
        input: VerifyEscrowDepositInput,
    ) -> Result<EscrowDepositView, DomainError> {
        let quote = self
            .quotes
            .find_accepted_for_booking(&input.booking_id)
            .await?
            .ok_or_else(|| {
                DomainError::Conflict("This booking has no accepted price quote".to_string())
            })?;

        if quote.user_id != input.user_id {
            return Err(DomainError::Unauthorized);
        }

        let expected_order_id = quote.id.to_string();
        let split = quote.escrow_split()?;

        let order = self
            .gateway
            .fetch_order(&input.order_account)
            .await?
            .ok_or_else(|| {
                // No account yet. Ordinary, not a failure: the transaction may
                // still be propagating, or the buyer may not have signed.
                DomainError::NotFound(
                    "No escrow order at that address yet. If you have just paid, wait a moment and try again.".to_string(),
                )
            })?;

        self.check_order_matches(&order, &expected_order_id, split.amount, split.fee_amount)?;

        let now = Utc::now();
        let candidate = EscrowOrderRecord {
            id: Uuid::new_v4(),
            booking_id: input.booking_id,
            quote_id: quote.id,
            order_id: expected_order_id,
            order_account: input.order_account.clone(),
            program_id: self.deployment.program_id.clone(),
            buyer: order.buyer.clone(),
            seller: order.seller.clone(),
            mint: order.mint.clone(),
            amount_base_units: order.amount,
            fee_base_units: order.fee_amount,
            chain_status: order.status,
            verified_at: Some(now),
            settled_at: None,
            refunded_at: None,
            deposit_signature: input.deposit_signature,
        };

        // First write wins. What comes back is whatever is actually stored.
        let stored = self.escrow_orders.record_verified(&candidate).await?;

        // A record already existed for this order id pointing at a different
        // account. One of the two is not the order the program created, and
        // guessing which would be guessing about money.
        if stored.order_account != input.order_account {
            return Err(DomainError::Conflict(
                "This booking is already settled by a different escrow order".to_string(),
            ));
        }

        // Keep the mirror current: the first writer recorded the status it saw,
        // which may be older than what we just read.
        if stored.chain_status != order.status {
            self.escrow_orders
                .update_chain_status(&stored.order_id, order.status, now)
                .await?;
        }

        let record = EscrowOrderRecord {
            chain_status: order.status,
            ..stored
        };

        self.mark_payment_settled(&input.booking_id, &record)
            .await?;

        Ok(EscrowDepositView {
            booking_id: input.booking_id,
            quote_id: quote.id,
            order_account: record.order_account.clone(),
            status: record.chain_status.as_str().to_string(),
            amount: record.amount_base_units.to_string(),
            fee_amount: record.fee_base_units.to_string(),
            seller_amount: record.seller_amount().to_string(),
            paid: record.is_paid(),
            verified_at: record.verified_at.map(|t| t.to_rfc3339()),
        })
    }

    /// Every way the presented order can fail to be the one this booking needs.
    ///
    /// Each check gets its own message. "Verification failed" tells a customer
    /// nothing and tells an engineer less; the difference between "you paid the
    /// wrong amount" and "that order belongs to another booking" is the
    /// difference between a refund and a security incident.
    fn check_order_matches(
        &self,
        order: &EscrowOrder,
        expected_order_id: &str,
        expected_amount: u64,
        expected_fee: u64,
    ) -> Result<(), DomainError> {
        // The decisive one. The gateway has already proved this order's id
        // hashes to the PDA seed it was found under, so an order id that is not
        // ours means a genuine order for a different booking.
        if order.order_id != expected_order_id {
            return Err(DomainError::ValidationError(
                "That escrow order belongs to a different booking".to_string(),
            ));
        }

        if order.seller != self.deployment.seller {
            return Err(DomainError::ValidationError(
                "That escrow order names a different seller".to_string(),
            ));
        }
        if order.mint != self.deployment.mint {
            return Err(DomainError::ValidationError(
                "That escrow order is denominated in a different token".to_string(),
            ));
        }
        // Both destinations are snapshotted into the order by the program at
        // creation and cannot be changed afterwards -- so checking them here
        // checks where the money will actually go, not where someone says it will.
        if order.payout_wallet != self.deployment.payout_wallet {
            return Err(DomainError::ValidationError(
                "That escrow order would pay a different wallet".to_string(),
            ));
        }
        if order.treasury != self.deployment.treasury {
            return Err(DomainError::ValidationError(
                "That escrow order names a different fee destination".to_string(),
            ));
        }

        // Exact, not "at least". The program only accepts the amount this
        // backend signed, so anything else means the signature did not come
        // from us -- which is a far more serious finding than an underpayment.
        if order.amount != expected_amount {
            return Err(DomainError::ValidationError(format!(
                "Escrowed amount does not match the accepted quote: expected {}, found {}",
                expected_amount, order.amount
            )));
        }
        if order.fee_amount != expected_fee {
            return Err(DomainError::ValidationError(
                "The fee recorded on that escrow order does not match the accepted quote"
                    .to_string(),
            ));
        }

        if order.status == EscrowOrderStatus::Refunded {
            return Err(DomainError::Conflict(
                "That escrow order was refunded; the booking is not paid".to_string(),
            ));
        }

        Ok(())
    }

    /// Mark the booking's payment confirmed.
    ///
    /// The escrow record carries the evidence; `payments` carries the answer to
    /// "has the customer settled". The funding transaction signature is
    /// deliberately *not* written to `payments.tx_hash`: that column feeds
    /// direct-transfer verification and replay detection, and it holds hashes
    /// this backend checked itself. A client-supplied signature belongs with
    /// the escrow record, which is explicitly a support artefact.
    async fn mark_payment_settled(
        &self,
        booking_id: &Uuid,
        record: &EscrowOrderRecord,
    ) -> Result<(), DomainError> {
        if !record.is_paid() {
            return Ok(());
        }

        let mut payment = match self.payments.find_by_booking_id(booking_id).await {
            Ok(payment) => payment,
            // No payment row yet is not a failure of verification. The deposit
            // is real and recorded either way; the booking's payment row is
            // created by `init_payment`, and a reconciliation sweep will pick
            // this up once it exists.
            Err(DomainError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };

        if payment.status == crate::domain::entities::payment::PaymentStatus::Confirmed {
            return Ok(());
        }

        payment.status = crate::domain::entities::payment::PaymentStatus::Confirmed;
        payment.sender_address = Some(record.buyer.clone());
        self.payments.update(&payment).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::payment::{Payment, PaymentStatus};
    use crate::domain::entities::quote::{PaymentQuote, QuoteStatus};
    use crate::domain::value_objects::money::{FiatCurrency, Money, PriceBreakdown};
    use crate::domain::value_objects::{Chain, CryptoToken};
    use async_trait::async_trait;
    use chrono::DateTime;
    use rust_decimal::Decimal;
    use std::str::FromStr as _;
    use std::sync::{Arc, Mutex};

    const SELLER: &str = "SeLLer111111111111111111111111111111111111";
    const PAYOUT: &str = "PayOut111111111111111111111111111111111111";
    const TREASURY: &str = "TreaSury1111111111111111111111111111111111";
    const MINT: &str = "So11111111111111111111111111111111111111112";
    const PROGRAM: &str = "Prog1111111111111111111111111111111111111";
    const ACCOUNT: &str = "Order111111111111111111111111111111111111";

    // A 1,000 dollar base becomes 1,150 after the 10% markup and 5% service
    // fee, so the platform's share is 150/1150 of whatever is escrowed.
    const BASE_UNITS: u128 = 1_150_000_000;
    const EXPECTED_AMOUNT: u64 = 1_150_000_000;
    const EXPECTED_FEE: u64 = 150_000_000;

    fn deployment() -> EscrowDeployment {
        EscrowDeployment {
            program_id: PROGRAM.to_string(),
            rpc_url: "http://localhost:8899".to_string(),
            seller: SELLER.to_string(),
            payout_wallet: PAYOUT.to_string(),
            treasury: TREASURY.to_string(),
            mint: MINT.to_string(),
        }
    }

    fn accepted_quote(user_id: Uuid, booking_id: Uuid) -> PaymentQuote {
        let now = Utc::now();
        let pricing =
            PriceBreakdown::calculate(Money::from_cents(100_000, FiatCurrency::Usd).unwrap())
                .unwrap();
        let mut quote = PaymentQuote::issue(
            Uuid::new_v4(),
            booking_id,
            user_id,
            "sol",
            Chain::Solana,
            CryptoToken::Sol,
            pricing,
            Decimal::from(150),
            "test".to_string(),
            now,
            Decimal::from_str("1.15").unwrap(),
            BASE_UNITS,
            SELLER.to_string(),
            now,
        )
        .unwrap();
        quote.status = QuoteStatus::Accepted;
        quote.accepted_at = Some(now);
        quote
    }

    /// An order that should verify cleanly. Tests mutate one field at a time to
    /// show that each check is load-bearing.
    fn good_order(order_id: &str) -> EscrowOrder {
        EscrowOrder {
            buyer: "Buyer11111111111111111111111111111111111".to_string(),
            seller: SELLER.to_string(),
            mint: MINT.to_string(),
            payout_wallet: PAYOUT.to_string(),
            treasury: TREASURY.to_string(),
            amount: EXPECTED_AMOUNT,
            fee_amount: EXPECTED_FEE,
            status: EscrowOrderStatus::Pending,
            created_at: 1_700_000_000,
            settlement_deadline: 1_700_003_600,
            timeout_deadline: 1_700_005_400,
            quote_expiry: 1_700_000_180,
            order_id_hash: [0u8; 32],
            order_id: order_id.to_string(),
        }
    }

    #[derive(Clone)]
    struct Quotes(Option<PaymentQuote>);

    #[async_trait]
    impl QuoteRepository for Quotes {
        async fn issue(&self, _: &PaymentQuote) -> Result<(), DomainError> {
            unreachable!("not used by this use case")
        }
        async fn find_by_id(&self, _: &Uuid) -> Result<PaymentQuote, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn find_active_for_booking(
            &self,
            _: &Uuid,
        ) -> Result<Option<PaymentQuote>, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn find_accepted_for_booking(
            &self,
            _: &Uuid,
        ) -> Result<Option<PaymentQuote>, DomainError> {
            Ok(self.0.clone())
        }
        async fn mark_accepted(&self, _: &PaymentQuote) -> Result<bool, DomainError> {
            unreachable!("not used by this use case")
        }
        async fn expire_stale(&self) -> Result<u64, DomainError> {
            unreachable!("not used by this use case")
        }
    }

    #[derive(Clone, Default)]
    struct Payments {
        stored: Arc<Mutex<Option<Payment>>>,
        updates: Arc<Mutex<Vec<Payment>>>,
    }

    #[async_trait]
    impl PaymentRepository for Payments {
        async fn find_by_booking_id(&self, _: &Uuid) -> Result<Payment, DomainError> {
            self.stored
                .lock()
                .unwrap()
                .clone()
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
            *self.stored.lock().unwrap() = Some(payment.clone());
            self.updates.lock().unwrap().push(payment.clone());
            Ok(())
        }
    }

    /// First-write-wins, exactly like the SQL `ON CONFLICT DO NOTHING`.
    #[derive(Clone, Default)]
    struct EscrowOrders {
        rows: Arc<Mutex<Vec<EscrowOrderRecord>>>,
    }

    #[async_trait]
    impl EscrowOrderRepository for EscrowOrders {
        async fn find_by_booking(
            &self,
            _: &Uuid,
        ) -> Result<Option<EscrowOrderRecord>, DomainError> {
            Ok(self.rows.lock().unwrap().last().cloned())
        }
        async fn find_by_order_id(
            &self,
            order_id: &str,
        ) -> Result<Option<EscrowOrderRecord>, DomainError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.order_id == order_id)
                .cloned())
        }
        async fn record_verified(
            &self,
            record: &EscrowOrderRecord,
        ) -> Result<EscrowOrderRecord, DomainError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(existing) = rows.iter().find(|r| r.order_id == record.order_id) {
                return Ok(existing.clone());
            }
            rows.push(record.clone());
            Ok(record.clone())
        }
        async fn update_chain_status(
            &self,
            order_id: &str,
            status: EscrowOrderStatus,
            _: DateTime<Utc>,
        ) -> Result<(), DomainError> {
            if let Some(row) = self
                .rows
                .lock()
                .unwrap()
                .iter_mut()
                .find(|r| r.order_id == order_id)
            {
                row.chain_status = status;
            }
            Ok(())
        }
        async fn find_open(&self) -> Result<Vec<EscrowOrderRecord>, DomainError> {
            unreachable!("not used by this use case")
        }
    }

    struct Gateway(Option<EscrowOrder>);

    #[async_trait]
    impl EscrowGateway for Gateway {
        async fn fetch_order(&self, _: &str) -> Result<Option<EscrowOrder>, DomainError> {
            Ok(self.0.clone())
        }
        fn program_id(&self) -> &str {
            PROGRAM
        }
    }

    struct Harness {
        user_id: Uuid,
        booking_id: Uuid,
        quote_id: Uuid,
        payments: Payments,
        escrow_orders: EscrowOrders,
        use_case: VerifyEscrowDeposit<Quotes, Payments, EscrowOrders, Gateway>,
    }

    /// `mutate` adjusts the otherwise-valid on-chain order, so each test says in
    /// one line exactly which field it is attacking.
    fn harness(mutate: impl FnOnce(&mut EscrowOrder)) -> Harness {
        harness_with_payment(Some(PaymentStatus::Pending), mutate)
    }

    fn harness_with_payment(
        payment_status: Option<PaymentStatus>,
        mutate: impl FnOnce(&mut EscrowOrder),
    ) -> Harness {
        let user_id = Uuid::new_v4();
        let booking_id = Uuid::new_v4();
        let quote = accepted_quote(user_id, booking_id);
        let quote_id = quote.id;

        let mut order = good_order(&quote_id.to_string());
        mutate(&mut order);

        let payments = Payments::default();
        if let Some(status) = payment_status {
            let mut payment = Payment::from_quote(Uuid::new_v4(), &quote).unwrap();
            payment.status = status;
            *payments.stored.lock().unwrap() = Some(payment);
        }

        let escrow_orders = EscrowOrders::default();

        Harness {
            user_id,
            booking_id,
            quote_id,
            payments: payments.clone(),
            escrow_orders: escrow_orders.clone(),
            use_case: VerifyEscrowDeposit::new(
                Quotes(Some(quote)),
                payments,
                escrow_orders,
                Arc::new(Gateway(Some(order))),
                deployment(),
            ),
        }
    }

    impl Harness {
        async fn verify(&self) -> Result<EscrowDepositView, DomainError> {
            self.use_case
                .execute(VerifyEscrowDepositInput {
                    booking_id: self.booking_id,
                    user_id: self.user_id,
                    order_account: ACCOUNT.to_string(),
                    deposit_signature: Some("sig".to_string()),
                })
                .await
        }
    }

    #[tokio::test]
    async fn a_matching_order_settles_the_booking() {
        let h = harness(|_| {});
        let view = h.verify().await.unwrap();

        assert!(view.paid);
        assert_eq!(view.amount, EXPECTED_AMOUNT.to_string());
        assert_eq!(view.fee_amount, EXPECTED_FEE.to_string());
        assert_eq!(view.seller_amount, "1000000000");
        assert_eq!(view.quote_id, h.quote_id);
        assert!(view.verified_at.is_some());

        let payment = h.payments.stored.lock().unwrap().clone().unwrap();
        assert_eq!(payment.status, PaymentStatus::Confirmed);
    }

    /// The attack this use case exists for: a real, correctly funded escrow
    /// order that belongs to another customer's booking. Everything about it
    /// decodes; it simply is not ours.
    #[tokio::test]
    async fn a_genuine_order_for_another_booking_is_refused() {
        let h = harness(|o| o.order_id = Uuid::new_v4().to_string());
        let err = h.verify().await.unwrap_err();
        assert!(
            format!("{}", err).contains("different booking"),
            "unexpected: {}",
            err
        );
        assert_eq!(
            h.payments.stored.lock().unwrap().as_ref().unwrap().status,
            PaymentStatus::Pending
        );
    }

    #[tokio::test]
    async fn an_underpaid_order_is_refused() {
        let h = harness(|o| o.amount = EXPECTED_AMOUNT - 1);
        let err = h.verify().await.unwrap_err();
        assert!(format!("{}", err).contains("does not match the accepted quote"));
    }

    /// Overpayment is refused too, and not out of pedantry: the program only
    /// accepts the amount this backend signed, so a different figure means the
    /// signature came from somewhere else.
    #[tokio::test]
    async fn an_overpaid_order_is_refused() {
        let h = harness(|o| o.amount = EXPECTED_AMOUNT + 1);
        assert!(h.verify().await.is_err());
    }

    #[tokio::test]
    async fn an_order_with_a_tampered_fee_split_is_refused() {
        // Same total, more of it to the platform. The buyer pays the same and
        // the seller is quietly short-changed.
        let h = harness(|o| o.fee_amount = EXPECTED_FEE * 2);
        let err = h.verify().await.unwrap_err();
        assert!(format!("{}", err).contains("fee recorded"));
    }

    #[tokio::test]
    async fn an_order_naming_a_different_seller_is_refused() {
        let h = harness(|o| o.seller = "SomeoneElse1111111111111111111111111111".to_string());
        assert!(format!("{}", h.verify().await.unwrap_err()).contains("different seller"));
    }

    #[tokio::test]
    async fn an_order_that_would_pay_a_different_wallet_is_refused() {
        let h = harness(|o| o.payout_wallet = "Attacker111111111111111111111111111111".to_string());
        assert!(format!("{}", h.verify().await.unwrap_err()).contains("different wallet"));
    }

    #[tokio::test]
    async fn an_order_with_a_different_fee_destination_is_refused() {
        let h = harness(|o| o.treasury = "Attacker111111111111111111111111111111".to_string());
        assert!(format!("{}", h.verify().await.unwrap_err()).contains("fee destination"));
    }

    #[tokio::test]
    async fn an_order_in_a_different_token_is_refused() {
        // A stablecoin order for the same nominal number of base units is worth
        // a fraction of the SOL one.
        let h = harness(|o| o.mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string());
        assert!(format!("{}", h.verify().await.unwrap_err()).contains("different token"));
    }

    #[tokio::test]
    async fn a_refunded_order_never_settles_the_booking() {
        let h = harness(|o| o.status = EscrowOrderStatus::Refunded);
        let err = h.verify().await.unwrap_err();
        assert!(format!("{}", err).contains("refunded"));
        assert_eq!(
            h.payments.stored.lock().unwrap().as_ref().unwrap().status,
            PaymentStatus::Pending
        );
    }

    /// Confirmation is the seller accepting the job; the funds have not moved.
    #[tokio::test]
    async fn a_confirmed_order_settles_the_booking() {
        let h = harness(|o| o.status = EscrowOrderStatus::Confirmed);
        assert!(h.verify().await.unwrap().paid);
    }

    /// Completed means the seller has already been paid out of the vault.
    #[tokio::test]
    async fn a_completed_order_settles_the_booking() {
        let h = harness(|o| o.status = EscrowOrderStatus::Completed);
        assert!(h.verify().await.unwrap().paid);
    }

    #[tokio::test]
    async fn no_account_yet_reports_not_found_rather_than_failing() {
        let user_id = Uuid::new_v4();
        let booking_id = Uuid::new_v4();
        let quote = accepted_quote(user_id, booking_id);
        let use_case = VerifyEscrowDeposit::new(
            Quotes(Some(quote)),
            Payments::default(),
            EscrowOrders::default(),
            Arc::new(Gateway(None)),
            deployment(),
        );
        let err = use_case
            .execute(VerifyEscrowDepositInput {
                booking_id,
                user_id,
                order_account: ACCOUNT.to_string(),
                deposit_signature: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn another_users_booking_cannot_be_verified() {
        let h = harness(|_| {});
        let err = h
            .use_case
            .execute(VerifyEscrowDepositInput {
                booking_id: h.booking_id,
                user_id: Uuid::new_v4(),
                order_account: ACCOUNT.to_string(),
                deposit_signature: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn a_booking_with_no_accepted_quote_is_refused() {
        let use_case = VerifyEscrowDeposit::new(
            Quotes(None),
            Payments::default(),
            EscrowOrders::default(),
            Arc::new(Gateway(Some(good_order("whatever")))),
            deployment(),
        );
        let err = use_case
            .execute(VerifyEscrowDepositInput {
                booking_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                order_account: ACCOUNT.to_string(),
                deposit_signature: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Conflict(_)));
    }

    /// A reload, a double-click, a retried request. The program allows one order
    /// per id, so a second verification must observe the first.
    #[tokio::test]
    async fn verifying_twice_records_one_order_and_one_payment_update() {
        let h = harness(|_| {});
        let first = h.verify().await.unwrap();
        let second = h.verify().await.unwrap();

        assert_eq!(first.order_account, second.order_account);
        assert!(second.paid);
        assert_eq!(h.escrow_orders.rows.lock().unwrap().len(), 1);
        // The second pass finds the payment already confirmed and leaves it be.
        assert_eq!(h.payments.updates.lock().unwrap().len(), 1);
    }

    /// Two different addresses cannot both settle one order id. The program
    /// makes that impossible on-chain; the mirror must not disagree.
    #[tokio::test]
    async fn a_second_address_claiming_the_same_order_id_is_a_conflict() {
        let h = harness(|_| {});
        h.verify().await.unwrap();

        let err = h
            .use_case
            .execute(VerifyEscrowDepositInput {
                booking_id: h.booking_id,
                user_id: h.user_id,
                order_account: "Impostor11111111111111111111111111111111".to_string(),
                deposit_signature: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{}", err).contains("already settled by a different escrow order"));
    }

    /// The deposit is real whether or not `init_payment` has run. Refusing here
    /// would lose a verified payment because of a missing bookkeeping row.
    #[tokio::test]
    async fn a_missing_payment_row_does_not_fail_verification() {
        let h = harness_with_payment(None, |_| {});
        let view = h.verify().await.unwrap();
        assert!(view.paid);
        assert_eq!(h.escrow_orders.rows.lock().unwrap().len(), 1);
    }
}
