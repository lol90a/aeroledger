use chrono::{DateTime, NaiveDateTime, Utc};
use uuid::Uuid;

use crate::domain::entities::escrow_order::EscrowOrderRecord;
use crate::domain::ports::escrow_gateway::EscrowOrderStatus;
use crate::domain::repositories::escrow_order_repository::EscrowOrderRepository;
use crate::infrastructure::db::DbPool;
use crate::shared::errors::{DomainError, InfraError};

/// Base units are `NUMERIC(40,0)` and come back as text, then parse to `u64`.
/// Reading them as a float somewhere in the middle is how a payment ends up
/// being compared against an amount that is off by a lamport.
const SELECT_COLUMNS: &str = "id, booking_id, quote_id, order_id, order_account, program_id,
     buyer, seller, mint,
     CAST(amount_base_units AS TEXT), CAST(fee_base_units AS TEXT),
     chain_status, verified_at, settled_at, refunded_at, deposit_signature";

pub struct PgEscrowOrderRepository {
    pool: DbPool,
}

impl PgEscrowOrderRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    async fn client(&self) -> Result<deadpool_postgres::Client, DomainError> {
        self.pool
            .get()
            .await
            .map_err(|e| InfraError::Database(e.to_string()).into())
    }

    fn row_to_record(row: &tokio_postgres::Row) -> Result<EscrowOrderRecord, DomainError> {
        let bad =
            |what: &str| DomainError::InternalError(format!("corrupt escrow order row: {}", what));

        let amount_raw: String = row.get(9);
        let fee_raw: String = row.get(10);
        let status_raw: String = row.get(11);

        let utc = |t: Option<NaiveDateTime>| {
            t.map(|t| DateTime::<Utc>::from_naive_utc_and_offset(t, Utc))
        };

        Ok(EscrowOrderRecord {
            id: row.get(0),
            booking_id: row.get(1),
            quote_id: row.get(2),
            order_id: row.get(3),
            order_account: row.get(4),
            program_id: row.get(5),
            buyer: row.get(6),
            seller: row.get(7),
            mint: row.get(8),
            amount_base_units: amount_raw.parse().map_err(|_| bad("amount_base_units"))?,
            fee_base_units: fee_raw.parse().map_err(|_| bad("fee_base_units"))?,
            chain_status: status_from_str(&status_raw).ok_or_else(|| bad("chain_status"))?,
            verified_at: utc(row.get(12)),
            settled_at: utc(row.get(13)),
            refunded_at: utc(row.get(14)),
            deposit_signature: row.get(15),
        })
    }
}

fn status_from_str(value: &str) -> Option<EscrowOrderStatus> {
    match value {
        "pending" => Some(EscrowOrderStatus::Pending),
        "confirmed" => Some(EscrowOrderStatus::Confirmed),
        "completed" => Some(EscrowOrderStatus::Completed),
        "refunded" => Some(EscrowOrderStatus::Refunded),
        _ => None,
    }
}

#[async_trait::async_trait]
impl EscrowOrderRepository for PgEscrowOrderRepository {
    async fn find_by_booking(
        &self,
        booking_id: &Uuid,
    ) -> Result<Option<EscrowOrderRecord>, DomainError> {
        let client = self.client().await?;
        let sql = format!(
            "SELECT {} FROM escrow_orders WHERE booking_id = $1 ORDER BY created_at DESC LIMIT 1",
            SELECT_COLUMNS
        );
        let row = client
            .query_opt(&sql, &[booking_id])
            .await
            .map_err(|e| DomainError::from(InfraError::Database(e.to_string())))?;
        row.as_ref().map(Self::row_to_record).transpose()
    }

    async fn find_by_order_id(
        &self,
        order_id: &str,
    ) -> Result<Option<EscrowOrderRecord>, DomainError> {
        let client = self.client().await?;
        let sql = format!(
            "SELECT {} FROM escrow_orders WHERE order_id = $1",
            SELECT_COLUMNS
        );
        let row = client
            .query_opt(&sql, &[&order_id])
            .await
            .map_err(|e| DomainError::from(InfraError::Database(e.to_string())))?;
        row.as_ref().map(Self::row_to_record).transpose()
    }

    async fn record_verified(
        &self,
        record: &EscrowOrderRecord,
    ) -> Result<EscrowOrderRecord, DomainError> {
        let client = self.client().await?;

        // `ON CONFLICT DO NOTHING` plus a follow-up read, rather than an upsert:
        // a second verification of the same order must not be able to rewrite
        // the amount, the buyer or the account that was accepted the first time.
        // The first write wins, and the caller is handed it to compare against.
        let sql = format!(
            "INSERT INTO escrow_orders
                 (booking_id, quote_id, order_id, order_account, program_id,
                  buyer, seller, mint, amount_base_units, fee_base_units,
                  chain_status, verified_at, deposit_signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                     CAST($9 AS NUMERIC), CAST($10 AS NUMERIC),
                     $11, $12, $13)
             ON CONFLICT (order_id) DO NOTHING
             RETURNING {}",
            SELECT_COLUMNS
        );

        let amount = record.amount_base_units.to_string();
        let fee = record.fee_base_units.to_string();
        let status = record.chain_status.as_str();
        let verified_at = record.verified_at.map(|t| t.naive_utc());

        let inserted = client
            .query_opt(
                &sql,
                &[
                    &record.booking_id,
                    &record.quote_id,
                    &record.order_id,
                    &record.order_account,
                    &record.program_id,
                    &record.buyer,
                    &record.seller,
                    &record.mint,
                    &amount,
                    &fee,
                    &status,
                    &verified_at,
                    &record.deposit_signature,
                ],
            )
            .await
            .map_err(|e| DomainError::from(InfraError::Database(e.to_string())))?;

        match inserted {
            Some(row) => Self::row_to_record(&row),
            // The conflict fired: someone recorded this order first.
            None => self
                .find_by_order_id(&record.order_id)
                .await?
                .ok_or_else(|| {
                    DomainError::InternalError(
                        "escrow order insert conflicted but the row is not readable".to_string(),
                    )
                }),
        }
    }

    async fn update_chain_status(
        &self,
        order_id: &str,
        status: EscrowOrderStatus,
        at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let client = self.client().await?;
        let naive = at.naive_utc();
        let status_str = status.as_str();

        // COALESCE on the terminal timestamps: the moment funds left the vault
        // is recorded once. A later reconciliation sweep re-reading the same
        // terminal state must not keep moving the time forward.
        client
            .execute(
                "UPDATE escrow_orders
                    SET chain_status = $2,
                        settled_at  = CASE WHEN $2 = 'completed'
                                           THEN COALESCE(settled_at, $3) ELSE settled_at END,
                        refunded_at = CASE WHEN $2 = 'refunded'
                                           THEN COALESCE(refunded_at, $3) ELSE refunded_at END,
                        updated_at  = $3
                  WHERE order_id = $1",
                &[&order_id, &status_str, &naive],
            )
            .await
            .map_err(|e| DomainError::from(InfraError::Database(e.to_string())))?;
        Ok(())
    }

    async fn find_open(&self) -> Result<Vec<EscrowOrderRecord>, DomainError> {
        let client = self.client().await?;
        let sql = format!(
            "SELECT {} FROM escrow_orders
              WHERE chain_status IN ('pending','confirmed')
              ORDER BY created_at ASC",
            SELECT_COLUMNS
        );
        let rows = client
            .query(&sql, &[])
            .await
            .map_err(|e| DomainError::from(InfraError::Database(e.to_string())))?;
        rows.iter().map(Self::row_to_record).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string form is the database's `CHECK` constraint and the on-chain
    /// discriminant order in one. A rename on either side has to break here.
    #[test]
    fn status_round_trips_through_its_stored_form() {
        for status in [
            EscrowOrderStatus::Pending,
            EscrowOrderStatus::Confirmed,
            EscrowOrderStatus::Completed,
            EscrowOrderStatus::Refunded,
        ] {
            assert_eq!(status_from_str(status.as_str()), Some(status));
        }
    }

    #[test]
    fn an_unknown_status_is_rejected_rather_than_defaulted() {
        // Defaulting to `pending` would read a corrupt row as "funds held",
        // which is the one answer that must never be guessed.
        assert_eq!(status_from_str("settled"), None);
        assert_eq!(status_from_str(""), None);
    }
}
