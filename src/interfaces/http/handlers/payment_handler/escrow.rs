//! The escrow endpoints: authorise a price, then verify what landed on-chain.
//!
//! Two calls, with the buyer's wallet doing the work between them:
//!
//! ```text
//!   POST /payments/escrow/authorize   -> figures + a signature over them
//!        (browser builds and signs the transaction, the chain executes it)
//!   POST /payments/escrow/verify      -> the backend reads the order back
//! ```
//!
//! The backend never builds, signs or submits an escrow transaction. It
//! authorises a price and it checks what happened; the buyer's wallet is the
//! only thing that can move the buyer's tokens, which is the property that makes
//! this escrow rather than custody.
//!
//! Both endpoints 503 when the deployment has no escrow configured. That is a
//! real state -- escrow is opt-in -- and it is reported as unavailable rather
//! than as a client error, because nothing the caller did is wrong.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use uuid::Uuid;

use crate::application::use_cases::authorize_escrow::{AuthorizeEscrow, AuthorizeEscrowInput};
use crate::application::use_cases::verify_escrow_deposit::{
    VerifyEscrowDeposit, VerifyEscrowDepositInput,
};
use crate::infrastructure::blockchain::escrow_settings::EscrowRuntime;
use crate::infrastructure::db::DbPool;
use crate::interfaces::http::error_response::into_response;

use super::access::authorize_booking_access;
use super::audit;
use super::repositories::Repositories;

#[derive(Deserialize)]
pub struct AuthorizeEscrowRequest {
    pub booking_id: Uuid,
    /// The wallet that will sign. Bound into the signature, so an authorization
    /// issued for one wallet is useless to any other.
    pub buyer_wallet: String,
}

#[derive(Deserialize)]
pub struct VerifyEscrowRequest {
    pub booking_id: Uuid,
    /// The order PDA. The only thing the client contributes to verification.
    pub order_account: String,
    /// The funding transaction, kept for support. Never trusted.
    pub deposit_signature: Option<String>,
}

/// Longest wallet address this will look at before rejecting it.
///
/// A base58 Solana address is 32-44 characters. The cap is not about
/// correctness -- the signer parses and rejects anything that is not 32 bytes --
/// but about not handing a megabyte of base58 to a decoder because a request
/// body said so.
const MAX_ADDRESS_LEN: usize = 64;

fn escrow_unavailable() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(serde_json::json!({
        "error": "Escrow payment is not available on this deployment"
    }))
}

fn reject_oversized_address() -> HttpResponse {
    HttpResponse::BadRequest()
        .json(serde_json::json!({ "error": "That is not a valid Solana address" }))
}

/// Issue a short-lived, signed authorization for the accepted price.
pub(super) async fn authorize_escrow(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    escrow: web::Data<Option<EscrowRuntime>>,
    body: web::Json<AuthorizeEscrowRequest>,
) -> HttpResponse {
    let Some(runtime) = escrow.get_ref() else {
        return escrow_unavailable();
    };
    if body.buyer_wallet.len() > MAX_ADDRESS_LEN {
        return reject_oversized_address();
    }

    let repos = Repositories::new(&pool);
    let owner_id = match authorize_booking_access(&req, &repos, &body.booking_id).await {
        Ok(id) => id,
        Err(e) => return into_response(e),
    };

    let use_case = AuthorizeEscrow::new(
        repos.quotes(),
        runtime.settings.quote_authority.clone(),
        runtime.deployment.clone(),
    );

    match use_case
        .execute(AuthorizeEscrowInput {
            booking_id: body.booking_id,
            user_id: owner_id,
            buyer_wallet: body.buyer_wallet.clone(),
        })
        .await
    {
        Ok(view) => {
            audit::record(
                &repos,
                &req,
                owner_id,
                "payment.escrow_authorized",
                "quote",
                &view.quote_id.to_string(),
                // The signature itself is deliberately not logged. It is a
                // bearer token for one on-chain attempt at this price, and an
                // audit log is a durable, widely-read place to put one.
                serde_json::json!({
                    "booking_id": view.quote_id,
                    "order_id": view.order_id,
                    "buyer": view.buyer,
                    "amount": view.amount,
                    "fee_amount": view.fee_amount,
                    "expiry": view.expiry,
                }),
            )
            .await;
            HttpResponse::Ok().json(view)
        }
        Err(e) => into_response(e),
    }
}

/// Read the escrow order back off the chain and decide whether it pays.
pub(super) async fn verify_escrow(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    escrow: web::Data<Option<EscrowRuntime>>,
    body: web::Json<VerifyEscrowRequest>,
) -> HttpResponse {
    let Some(runtime) = escrow.get_ref() else {
        return escrow_unavailable();
    };
    if body.order_account.len() > MAX_ADDRESS_LEN {
        return reject_oversized_address();
    }

    let repos = Repositories::new(&pool);
    let owner_id = match authorize_booking_access(&req, &repos, &body.booking_id).await {
        Ok(id) => id,
        Err(e) => return into_response(e),
    };

    let use_case = VerifyEscrowDeposit::new(
        repos.quotes(),
        repos.payments(),
        repos.escrow_orders(),
        runtime.gateway.clone(),
        runtime.deployment.clone(),
    );

    match use_case
        .execute(VerifyEscrowDepositInput {
            booking_id: body.booking_id,
            user_id: owner_id,
            order_account: body.order_account.clone(),
            deposit_signature: body.deposit_signature.clone(),
        })
        .await
    {
        Ok(view) => {
            audit::record(
                &repos,
                &req,
                owner_id,
                "payment.escrow_verified",
                "escrow_order",
                &view.order_account,
                serde_json::json!({
                    "booking_id": view.booking_id,
                    "quote_id": view.quote_id,
                    "status": view.status,
                    "amount": view.amount,
                    "fee_amount": view.fee_amount,
                    "paid": view.paid,
                }),
            )
            .await;
            HttpResponse::Ok().json(view)
        }
        Err(e) => into_response(e),
    }
}
