use base64::Engine;
use reqwest::Client;
use sha2::Digest;
use std::time::Duration;

use crate::domain::ports::escrow_gateway::{EscrowGateway, EscrowOrder, EscrowOrderStatus};
use crate::shared::errors::{DomainError, InfraError};

/// Commitment for every escrow read. `finalized` is the only level that cannot
/// be rolled back, and the whole point of reading escrow state is to decide
/// whether to hand over goods.
const COMMITMENT: &str = "finalized";

/// Anchor prefixes every account with eight bytes of `sha256("account:<Name>")`.
/// Checking it stops a same-sized account of a different type decoding into
/// plausible-looking rubbish.
fn account_discriminator(name: &str) -> [u8; 8] {
    let digest = sha2::Sha256::digest(format!("account:{}", name).as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// keccak256, which is what the program hashes `order_id` with to seed the PDA.
/// Note this is keccak, not SHA3-256: the two differ in padding and Solana's
/// `keccak::hash` is the original.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use sha3::Keccak256;
    let digest = Keccak256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[derive(Clone)]
pub struct SolanaEscrowGateway {
    client: Client,
    rpc_url: String,
    program_id: String,
}

/// Cursor over the account payload. Every read is length-checked, so a
/// truncated or unexpected account is a clean error rather than a panic.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], InfraError> {
        let end = self.at.checked_add(n).ok_or_else(|| short(self.at, n))?;
        if end > self.bytes.len() {
            return Err(short(self.at, n));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn pubkey(&mut self) -> Result<String, InfraError> {
        Ok(bs58::encode(self.take(32)?).into_string())
    }

    fn u64(&mut self) -> Result<u64, InfraError> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("checked length");
        Ok(u64::from_le_bytes(b))
    }

    fn i64(&mut self) -> Result<i64, InfraError> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("checked length");
        Ok(i64::from_le_bytes(b))
    }

    fn u8(&mut self) -> Result<u8, InfraError> {
        Ok(self.take(1)?[0])
    }

    fn bytes32(&mut self) -> Result<[u8; 32], InfraError> {
        Ok(self.take(32)?.try_into().expect("checked length"))
    }

    /// Borsh string: a four-byte little-endian length then UTF-8 bytes.
    fn string(&mut self) -> Result<String, InfraError> {
        let len = u32::from_le_bytes(self.take(4)?.try_into().expect("checked length")) as usize;
        // A corrupt length must not turn into a huge allocation attempt.
        if len > self.bytes.len() {
            return Err(InfraError::Blockchain(format!(
                "escrow order declares a {}-byte order id in a {}-byte account",
                len,
                self.bytes.len()
            )));
        }
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| InfraError::Blockchain("escrow order id is not valid UTF-8".to_string()))
    }
}

fn short(at: usize, want: usize) -> InfraError {
    InfraError::Blockchain(format!(
        "escrow order account ended early: wanted {} bytes at offset {}",
        want, at
    ))
}

impl SolanaEscrowGateway {
    pub fn new(rpc_url: String, program_id: String) -> Self {
        Self {
            client: crate::infrastructure::http::client(Duration::from_secs(10)),
            rpc_url,
            program_id,
        }
    }

    /// Decode an `Order` account body. Public so the layout can be tested
    /// against fixtures without a live RPC.
    pub fn decode_order(data: &[u8]) -> Result<EscrowOrder, InfraError> {
        let expected = account_discriminator("Order");
        if data.len() < 8 || data[..8] != expected {
            return Err(InfraError::Blockchain(
                "account is not an escrow Order (discriminator mismatch)".to_string(),
            ));
        }

        let mut r = Reader::new(&data[8..]);
        let buyer = r.pubkey()?;
        let seller = r.pubkey()?;
        let mint = r.pubkey()?;
        let payout_wallet = r.pubkey()?;
        let treasury = r.pubkey()?;
        let amount = r.u64()?;
        let fee_amount = r.u64()?;
        let status_byte = r.u8()?;
        let created_at = r.i64()?;
        let settlement_deadline = r.i64()?;
        let timeout_deadline = r.i64()?;
        let quote_expiry = r.i64()?;
        let order_id_hash = r.bytes32()?;
        let order_id = r.string()?;

        let status = EscrowOrderStatus::from_discriminant(status_byte).ok_or_else(|| {
            InfraError::Blockchain(format!("escrow order has unknown status {}", status_byte))
        })?;

        // The seed the program derived its PDA from is recorded in the account.
        // Checking it here means a caller cannot point us at some other real
        // order and have its fields read as if they belonged to this booking.
        if keccak256(order_id.as_bytes()) != order_id_hash {
            return Err(InfraError::Blockchain(
                "escrow order id does not hash to the order_id_hash it records".to_string(),
            ));
        }

        Ok(EscrowOrder {
            buyer,
            seller,
            mint,
            payout_wallet,
            treasury,
            // Widened here: the account stores u64, the domain carries u128 so
            // that one order type serves both chains.
            amount: u128::from(amount),
            fee_amount: u128::from(fee_amount),
            status,
            created_at,
            settlement_deadline,
            timeout_deadline,
            quote_expiry,
            order_id_hash,
            order_id,
        })
    }
}

#[async_trait::async_trait]
impl EscrowGateway for SolanaEscrowGateway {
    fn program_id(&self) -> &str {
        &self.program_id
    }

    async fn fetch_order(&self, order_account: &str) -> Result<Option<EscrowOrder>, DomainError> {
        // Reject anything that is not a base58 32-byte key before spending an
        // RPC round trip, and so a typo reads as a typo.
        if bs58::decode(order_account).into_vec().map(|v| v.len()) != Ok(32) {
            return Err(DomainError::from(InfraError::InvalidRequest(
                "That is not a valid Solana account address.".to_string(),
            )));
        }

        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "getAccountInfo",
            "params": [order_account, { "encoding": "base64", "commitment": COMMITMENT }]
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| InfraError::Blockchain(e.to_string()))?;
        let text = response
            .text()
            .await
            .map_err(|e| InfraError::Blockchain(e.to_string()))?;
        let json: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
            InfraError::Blockchain(format!(
                "Provider returned a non-JSON response: {}",
                text.chars().take(200).collect::<String>()
            ))
        })?;

        if let Some(err) = json.get("error").filter(|e| !e.is_null()) {
            return Err(DomainError::from(InfraError::Blockchain(format!(
                "RPC error: {}",
                err.to_string().chars().take(200).collect::<String>()
            ))));
        }

        let Some(value) = json["result"]["value"].as_object() else {
            // No account yet. The buyer has not deposited, which is a normal
            // answer and not an error.
            return Ok(None);
        };

        // An account the escrow program does not own cannot be one of its
        // orders, whatever its contents happen to look like.
        let owner = value.get("owner").and_then(|o| o.as_str()).unwrap_or("");
        if owner != self.program_id {
            return Err(DomainError::from(InfraError::Blockchain(format!(
                "account {} is owned by {}, not the escrow program",
                order_account, owner
            ))));
        }

        let encoded = value
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.as_str())
            .ok_or_else(|| InfraError::Blockchain("account payload missing".to_string()))?;

        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| InfraError::Blockchain("account payload is not base64".to_string()))?;

        Ok(Some(Self::decode_order(&raw).map_err(DomainError::from)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUYER: [u8; 32] = [1u8; 32];
    const SELLER: [u8; 32] = [2u8; 32];
    const MINT: [u8; 32] = [3u8; 32];
    const PAYOUT: [u8; 32] = [4u8; 32];
    const TREASURY: [u8; 32] = [5u8; 32];

    /// Builds the exact bytes the program would write, so the decoder is tested
    /// against the real layout rather than against itself.
    fn encode_order(order_id: &str, amount: u64, fee: u64, status: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&account_discriminator("Order"));
        v.extend_from_slice(&BUYER);
        v.extend_from_slice(&SELLER);
        v.extend_from_slice(&MINT);
        v.extend_from_slice(&PAYOUT);
        v.extend_from_slice(&TREASURY);
        v.extend_from_slice(&amount.to_le_bytes());
        v.extend_from_slice(&fee.to_le_bytes());
        v.push(status);
        v.extend_from_slice(&1_000i64.to_le_bytes()); // created_at
        v.extend_from_slice(&4_600i64.to_le_bytes()); // settlement_deadline
        v.extend_from_slice(&8_200i64.to_le_bytes()); // timeout_deadline
        v.extend_from_slice(&1_900i64.to_le_bytes()); // quote_expiry
        v.extend_from_slice(&keccak256(order_id.as_bytes()));
        v.extend_from_slice(&(order_id.len() as u32).to_le_bytes());
        v.extend_from_slice(order_id.as_bytes());
        v.push(254); // bump
        v
    }

    #[test]
    fn decodes_every_field_of_a_real_layout() {
        let data = encode_order("booking-123", 1_830_627_189, 15_000_000, 1);
        let order = SolanaEscrowGateway::decode_order(&data).expect("should decode");

        assert_eq!(order.buyer, bs58::encode(BUYER).into_string());
        assert_eq!(order.seller, bs58::encode(SELLER).into_string());
        assert_eq!(order.mint, bs58::encode(MINT).into_string());
        assert_eq!(order.payout_wallet, bs58::encode(PAYOUT).into_string());
        assert_eq!(order.treasury, bs58::encode(TREASURY).into_string());
        assert_eq!(order.amount, 1_830_627_189);
        assert_eq!(order.fee_amount, 15_000_000);
        assert_eq!(order.status, EscrowOrderStatus::Confirmed);
        assert_eq!(order.settlement_deadline, 4_600);
        assert_eq!(order.timeout_deadline, 8_200);
        assert_eq!(order.order_id, "booking-123");
    }

    #[test]
    fn maps_every_status_discriminant() {
        for (byte, expected) in [
            (0u8, EscrowOrderStatus::Pending),
            (1, EscrowOrderStatus::Confirmed),
            (2, EscrowOrderStatus::Completed),
            (3, EscrowOrderStatus::Refunded),
        ] {
            let data = encode_order("o", 1, 0, byte);
            assert_eq!(
                SolanaEscrowGateway::decode_order(&data).unwrap().status,
                expected
            );
        }
    }

    #[test]
    fn rejects_an_unknown_status_rather_than_guessing() {
        let data = encode_order("o", 1, 0, 9);
        assert!(SolanaEscrowGateway::decode_order(&data).is_err());
    }

    /// Anchor's discriminator is what stops a same-sized account of a different
    /// type decoding into plausible-looking rubbish.
    #[test]
    fn rejects_an_account_that_is_not_an_order() {
        let mut data = encode_order("o", 1, 0, 0);
        data[0] ^= 0xFF;
        let err = SolanaEscrowGateway::decode_order(&data).unwrap_err();
        assert!(format!("{:?}", err).contains("discriminator"));
    }

    /// The decisive check. `order_id_hash` is the PDA seed, so an order whose
    /// recorded id does not hash to it is not the order it claims to be.
    #[test]
    fn rejects_an_order_whose_id_does_not_match_its_pda_seed() {
        let mut data = encode_order("booking-123", 1, 0, 0);
        // Corrupt the recorded hash, leaving the id intact.
        let hash_at = 8 + 32 * 5 + 8 + 8 + 1 + 8 * 4;
        data[hash_at] ^= 0xFF;
        let err = SolanaEscrowGateway::decode_order(&data).unwrap_err();
        assert!(format!("{:?}", err).contains("order_id_hash"));
    }

    #[test]
    fn rejects_a_truncated_account_without_panicking() {
        let data = encode_order("booking-123", 1, 0, 0);
        for cut in [8, 40, 100, data.len() - 2] {
            assert!(
                SolanaEscrowGateway::decode_order(&data[..cut]).is_err(),
                "a {}-byte account must not decode",
                cut
            );
        }
    }

    #[test]
    fn rejects_an_order_id_length_larger_than_the_account() {
        let mut data = encode_order("booking-123", 1, 0, 0);
        let len_at = 8 + 32 * 5 + 8 + 8 + 1 + 8 * 4 + 32;
        data[len_at..len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SolanaEscrowGateway::decode_order(&data).is_err());
    }

    /// Pinned because the program seeds its PDA with keccak256, not SHA3-256.
    /// The two differ only in padding, so a mix-up would be invisible until a
    /// real account failed to verify.
    #[test]
    fn hashes_with_keccak_not_sha3() {
        let got = keccak256(b"");
        assert_eq!(
            bs58::encode(got).into_string(),
            bs58::encode(hex_literal(
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            ))
            .into_string()
        );
    }

    fn hex_literal(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }
}
