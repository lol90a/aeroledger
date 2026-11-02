//! Periodically re-read open escrow orders from the chain.
//!
//! Separate from [`PaymentReconciliationWorker`] rather than folded into it,
//! because the two are gated on different things. Payment reconciliation is
//! switched off in manual verification mode, where there is no on-chain source
//! of truth and auto-confirming would rubber-stamp unpaid bookings. Escrow has
//! a source of truth by construction -- the order account -- so it reconciles
//! whenever escrow is configured at all, including on a developer's machine
//! pointed at a local validator.
//!
//! [`PaymentReconciliationWorker`]: super::payment_reconciliation::PaymentReconciliationWorker

use std::sync::Arc;

use tokio::time::{sleep, Duration};

use crate::application::use_cases::reconcile_escrow_orders::ReconcileEscrowOrders;
use crate::domain::ports::escrow_gateway::EscrowGateway;
use crate::infrastructure::db::DbPool;
use crate::infrastructure::persistence::postgres::pg_escrow_order_repository::PgEscrowOrderRepository;
use crate::infrastructure::persistence::postgres::pg_payment_repository::PgPaymentRepository;
use crate::shared::errors::DomainError;

pub struct EscrowReconciliationWorker {
    pool: DbPool,
    gateway: Arc<dyn EscrowGateway>,
    interval_seconds: u64,
}

impl EscrowReconciliationWorker {
    pub fn new(pool: DbPool, gateway: Arc<dyn EscrowGateway>, interval_seconds: u64) -> Self {
        Self {
            pool,
            gateway,
            interval_seconds,
        }
    }

    pub fn spawn(self) {
        log::info!(
            "escrow reconciliation every {}s against program {}",
            self.interval_seconds,
            self.gateway.program_id()
        );
        tokio::spawn(async move {
            loop {
                match self.run_once().await {
                    // Quiet when nothing moved, which is almost every cycle.
                    // A log line per sweep would bury everything else.
                    Ok(summary) if summary.changed == 0 && summary.failed == 0 => {}
                    Ok(summary) => log::info!(
                        "escrow reconciliation: {} checked, {} changed, {} refunded, {} unreadable",
                        summary.checked,
                        summary.changed,
                        summary.refunded,
                        summary.failed
                    ),
                    Err(e) => log::error!("escrow reconciliation cycle failed: {}", e),
                }
                sleep(Duration::from_secs(self.interval_seconds)).await;
            }
        });
    }

    pub async fn run_once(
        &self,
    ) -> Result<crate::application::use_cases::reconcile_escrow_orders::ReconcileSummary, DomainError>
    {
        ReconcileEscrowOrders::new(
            PgEscrowOrderRepository::new(self.pool.clone()),
            PgPaymentRepository::new(self.pool.clone()),
            self.gateway.clone(),
        )
        .execute()
        .await
    }
}
