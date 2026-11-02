//! Reads escrow orders from the Solidity contract.
//!
//! The EVM counterpart of [`SolanaEscrowGateway`], and deliberately the same
//! shape: one `eth_call`, a careful decode, and three checks that stop the
//! caller pointing at something that is not the order it claims.
//!
//! ## Decoding, and why it is done by hand
//!
//! `getOrder(bytes32)` returns a struct containing a `string`, which makes it
//! dynamic, so the return data is not a flat run of slots. It is an offset to
//! the struct, then the struct's own head of twelve slots -- the last of which
//! is itself an offset, relative to the start of the struct, to the string's
//! length and bytes.
//!
//! Pulling in a full ABI codec for one read would add a large dependency and a
//! JSON artefact that has to be kept in step with the contract. A hand-written
//! decoder for one known function is smaller, has no build step, and is
//! bounds-checked at every step so a truncated or hostile response is an error
//! rather than a panic in a request handler.
//!
//! ## What is checked
//!
//! The caller supplies an order hash. That is all they supply, and on its own
//! it proves nothing:
//!
//!   * a status of `None` (zero) means no such order, reported as "not found"
//!     rather than decoded as a zero-value order;
//!   * the recorded `orderId` must hash, with the recorded buyer, back to the
//!     hash we looked it up under. The contract computes that key itself, so a
//!     mismatch means the response did not come from this contract;
//!   * everything else -- amount, seller, payout destination -- is compared by
//!     the verification use case against the accepted quote.
//!
//! [`SolanaEscrowGateway`]: super::solana_escrow_gateway::SolanaEscrowGateway

use std::time::Duration;

use serde_json::json;

use crate::domain::ports::escrow_gateway::{EscrowGateway, EscrowOrder, EscrowOrderStatus};
use crate::infrastructure::blockchain::eip712::{compute_order_hash, keccak256, to_hex};
use crate::shared::errors::{DomainError, InfraError};

/// `getOrder(bytes32)`, as a four-byte selector.
///
/// Computed rather than pasted: renaming the function on the Solidity side
/// changes this, and a stale constant would call into whatever else happens to
/// share the old selector.
fn get_order_selector() -> [u8; 4] {
    let hash = keccak256(b"getOrder(bytes32)");
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Reads a bounded cursor over ABI-encoded return data.
///
/// Every accessor is offset-based rather than sequential, because ABI decoding
/// jumps: the head says where the tail is. Each one bounds-checks, so a short
/// or malicious response errors instead of panicking.
struct AbiReader<'a> {
    data: &'a [u8],
}

impl<'a> AbiReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn slot(&self, at: usize) -> Result<&'a [u8], InfraError> {
        self.data
            .get(at..at + 32)
            .ok_or_else(|| InfraError::Blockchain(format!("response truncated at offset {}", at)))
    }

    /// A `uint256` narrowed to `usize`, for offsets and lengths.
    ///
    /// The upper 24 bytes must be zero. A real `uint256` offset would be an
    /// absurd response, and accepting a truncated one is how a decoder is
    /// talked into reading somewhere it should not.
    fn size(&self, at: usize) -> Result<usize, InfraError> {
        let slot = self.slot(at)?;
        if slot[..24].iter().any(|b| *b != 0) {
            return Err(InfraError::Blockchain(
                "response contains an implausibly large offset or length".to_string(),
            ));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&slot[24..]);
        Ok(u64::from_be_bytes(bytes) as usize)
    }

    /// A `uint256` as `u128`.
    ///
    /// Refuses anything above 2^128 rather than truncating. No honest escrow
    /// holds that much of anything, and a silently truncated amount would be
    /// compared against the quote and could match.
    fn u256(&self, at: usize) -> Result<u128, InfraError> {
        let slot = self.slot(at)?;
        if slot[..16].iter().any(|b| *b != 0) {
            return Err(InfraError::Blockchain(
                "escrow amount exceeds what this backend will handle".to_string(),
            ));
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&slot[16..]);
        Ok(u128::from_be_bytes(bytes))
    }

    fn u8_value(&self, at: usize) -> Result<u8, InfraError> {
        let slot = self.slot(at)?;
        if slot[..31].iter().any(|b| *b != 0) {
            return Err(InfraError::Blockchain(
                "expected a single-byte value in a 32-byte slot".to_string(),
            ));
        }
        Ok(slot[31])
    }

    /// An `int256` timestamp. The contract only writes block timestamps, which
    /// are positive and small, so anything wide is a malformed response.
    fn timestamp(&self, at: usize) -> Result<i64, InfraError> {
        Ok(self.size(at)? as i64)
    }

    /// An `address`: the low twenty bytes, with the top twelve required zero.
    fn address(&self, at: usize) -> Result<[u8; 20], InfraError> {
        let slot = self.slot(at)?;
        if slot[..12].iter().any(|b| *b != 0) {
            return Err(InfraError::Blockchain(
                "address slot has dirty upper bytes".to_string(),
            ));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&slot[12..]);
        Ok(out)
    }

    /// A `string` whose length and bytes live at `at`.
    fn string_at(&self, at: usize) -> Result<String, InfraError> {
        let len = self.size(at)?;
        // Bounded before allocating: a length field is attacker-influenced in
        // the general case, and `Vec::with_capacity` on it is a denial of
        // service waiting to happen.
        if len > 1024 {
            return Err(InfraError::Blockchain(
                "escrow order id is implausibly long".to_string(),
            ));
        }
        let bytes = self
            .data
            .get(at + 32..at + 32 + len)
            .ok_or_else(|| InfraError::Blockchain("string data truncated".to_string()))?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| InfraError::Blockchain("escrow order id is not valid UTF-8".to_string()))
    }
}

/// Maps the contract's `OrderStatus` onto the chain-agnostic one.
///
/// The discriminants differ from Solana's: Solidity's enum starts at `None`,
/// so `Pending` is 1 here and 0 there. That difference is exactly the kind of
/// thing that belongs in a gateway and nowhere else.
fn status_from_discriminant(byte: u8) -> Option<Option<EscrowOrderStatus>> {
    match byte {
        // `None` is the zero value of an unwritten mapping slot, so it means
        // "no such order" rather than a status.
        0 => Some(None),
        1 => Some(Some(EscrowOrderStatus::Pending)),
        2 => Some(Some(EscrowOrderStatus::Confirmed)),
        3 => Some(Some(EscrowOrderStatus::Completed)),
        4 => Some(Some(EscrowOrderStatus::Refunded)),
        _ => None,
    }
}

pub struct EvmEscrowGateway {
    client: reqwest::Client,
    rpc_url: String,
    contract: String,
    /// Block tag reads are made against.
    block_tag: String,
}

impl EvmEscrowGateway {
    /// `block_tag` should be `finalized` anywhere real.
    ///
    /// A re-org can unmake a transaction that `latest` already reported, and
    /// settling a booking on a block that is later orphaned means releasing a
    /// service against a payment that no longer exists. `latest` exists as an
    /// option only because local development chains do not all implement
    /// `finalized`.
    pub fn new(rpc_url: String, contract: String, block_tag: String) -> Self {
        Self {
            client: crate::infrastructure::http::client(Duration::from_secs(10)),
            rpc_url,
            contract,
            block_tag,
        }
    }

    /// Decode `getOrder`'s return data.
    ///
    /// Public so the layout can be tested against fixtures without an RPC.
    /// `Ok(None)` means the order does not exist.
    pub fn decode_order(data: &[u8]) -> Result<Option<EscrowOrder>, InfraError> {
        let r = AbiReader::new(data);

        // The single return value is a dynamic struct, so the first slot is an
        // offset to where it actually begins.
        let base = r.size(0)?;

        let status_byte = r.u8_value(base + 32 * 7)?;
        let status = status_from_discriminant(status_byte).ok_or_else(|| {
            InfraError::Blockchain(format!("unknown order status {}", status_byte))
        })?;
        let Some(status) = status else {
            return Ok(None);
        };

        let buyer = r.address(base)?;
        let order_id_offset = r.size(base + 32 * 11)?;
        // The string's offset is relative to the start of the struct, not to
        // the start of the response. Treating it as absolute reads a different
        // part of the buffer, usually successfully and always wrongly.
        let order_id = r.string_at(base + order_id_offset)?;

        // The contract derives its storage key from exactly these two values.
        // Recomputing it is what makes "this is the order you asked for" a
        // check rather than an assumption.
        let order_id_hash = compute_order_hash(&buyer, &order_id);

        Ok(Some(EscrowOrder {
            buyer: to_hex(&buyer),
            seller: to_hex(&r.address(base + 32)?),
            payout_wallet: to_hex(&r.address(base + 32 * 2)?),
            treasury: to_hex(&r.address(base + 32 * 3)?),
            mint: to_hex(&r.address(base + 32 * 4)?),
            amount: r.u256(base + 32 * 5)?,
            fee_amount: r.u256(base + 32 * 6)?,
            status,
            created_at: r.timestamp(base + 32 * 8)?,
            settlement_deadline: r.timestamp(base + 32 * 9)?,
            timeout_deadline: r.timestamp(base + 32 * 10)?,
            // The Solidity contract has no separate quote expiry on the order:
            // the quote's own expiry is enforced at creation and not stored.
            // Reported as the creation time so the field is never mistaken for
            // a deadline that is still in force.
            quote_expiry: r.timestamp(base + 32 * 8)?,
            order_id_hash,
            order_id,
        }))
    }

    async fn eth_call(&self, data: &str) -> Result<Vec<u8>, DomainError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{ "to": self.contract, "data": data }, self.block_tag],
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| InfraError::Blockchain(format!("escrow RPC unreachable: {}", e)))?;

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|e| InfraError::Blockchain(format!("escrow RPC returned non-JSON: {}", e)))?;

        if let Some(error) = payload.get("error") {
            // Surface the node's own message: "execution reverted" and "method
            // not found" are different problems and the operator needs to know
            // which one they have.
            return Err(InfraError::Blockchain(format!(
                "escrow RPC error: {}",
                error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown")
            ))
            .into());
        }

        let hex = payload
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| InfraError::Blockchain("escrow RPC returned no result".to_string()))?;

        decode_hex(hex).map_err(Into::into)
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, InfraError> {
    let trimmed = value.trim().trim_start_matches("0x");
    if !trimmed.len().is_multiple_of(2) {
        return Err(InfraError::Blockchain(
            "RPC returned an odd number of hex digits".to_string(),
        ));
    }
    (0..trimmed.len() / 2)
        .map(|i| {
            u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|_| InfraError::Blockchain("RPC returned invalid hex".to_string()))
        })
        .collect()
}

#[async_trait::async_trait]
impl EscrowGateway for EvmEscrowGateway {
    /// `order_account` is the order hash, `0x`-prefixed.
    ///
    /// Named for the Solana case, where it is an account address. On EVM there
    /// is no per-order account -- orders live in a mapping -- so the same slot
    /// carries the storage key instead. One identifier from the client either
    /// way, and believed neither way.
    async fn fetch_order(&self, order_account: &str) -> Result<Option<EscrowOrder>, DomainError> {
        let key = decode_hex(order_account)?;
        if key.len() != 32 {
            return Err(DomainError::ValidationError(
                "that is not a valid escrow order reference".to_string(),
            ));
        }

        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&get_order_selector());
        calldata.extend_from_slice(&key);

        let data = self.eth_call(&to_hex(&calldata)).await?;
        // An empty result means no contract at that address, which is a
        // configuration fault rather than an absent order.
        if data.is_empty() {
            return Err(InfraError::Blockchain(
                "no escrow contract at the configured address".to_string(),
            )
            .into());
        }

        let order = Self::decode_order(&data)?;

        // The response must describe the order we asked about. The contract
        // derives its key from the buyer and order id, so recomputing it
        // catches a response that has been substituted wholesale.
        if let Some(order) = &order {
            if to_hex(&order.order_id_hash).to_lowercase() != order_account.trim().to_lowercase() {
                return Err(InfraError::Blockchain(
                    "escrow order does not hash to the key it was read under".to_string(),
                )
                .into());
            }
        }

        Ok(order)
    }

    fn program_id(&self) -> &str {
        &self.contract
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUYER: [u8; 20] = [0x11; 20];
    const SELLER: [u8; 20] = [0x22; 20];
    const PAYOUT: [u8; 20] = [0x33; 20];
    const TREASURY: [u8; 20] = [0x44; 20];

    fn slot(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        out
    }

    fn u256(value: u128) -> Vec<u8> {
        slot(&value.to_be_bytes())
    }

    /// Build `getOrder`'s return data by hand, exactly as the ABI prescribes:
    /// an offset to the struct, the struct's twelve-slot head, then the
    /// string's length and padded bytes.
    fn encode_order(order_id: &str, status: u8, amount: u128, fee: u128) -> Vec<u8> {
        let mut head = Vec::new();
        head.extend(slot(&BUYER));
        head.extend(slot(&SELLER));
        head.extend(slot(&PAYOUT));
        head.extend(slot(&TREASURY));
        head.extend(slot(&[0u8; 20])); // token: native
        head.extend(u256(amount));
        head.extend(u256(fee));
        head.extend(u256(status as u128));
        head.extend(u256(1_700_000_000)); // createdAt
        head.extend(u256(1_700_003_600)); // settlementDeadline
        head.extend(u256(1_700_005_400)); // timeoutDeadline
        head.extend(u256(32 * 12)); // offset to orderId, relative to the struct

        let bytes = order_id.as_bytes();
        let mut tail = u256(bytes.len() as u128);
        tail.extend_from_slice(bytes);
        tail.extend(std::iter::repeat_n(0u8, (32 - bytes.len() % 32) % 32));

        // The single return value is dynamic, so the response opens with an
        // offset to where the struct begins.
        let mut out = u256(32);
        out.extend(head);
        out.extend(tail);
        out
    }

    fn order_id_for(buyer: &[u8; 20], id: &str) -> String {
        to_hex(&compute_order_hash(buyer, id))
    }

    #[test]
    fn the_selector_is_the_one_the_contract_exposes() {
        // keccak256("getOrder(bytes32)")[..4], as reported by the compiled ABI:
        //   npx hardhat console
        //   new ethers.Interface(abi).getFunction("getOrder").selector
        //
        // Computed in the code rather than pasted, so renaming the Solidity
        // function breaks the call here instead of silently dispatching to
        // whatever else happens to share the old selector. The expected value
        // is pinned so a change to the signature fails loudly.
        assert_eq!(to_hex(&get_order_selector()), "0x5778472a");

        // Not `orders(bytes32)`, which returns the same struct from a different
        // selector. Calling the wrong one is a revert, not a wrong answer, but
        // the distinction is worth recording.
        assert_ne!(to_hex(&get_order_selector()), "0x9c3f1e90");
    }

    #[test]
    fn decodes_a_pending_order() {
        let data = encode_order(
            "order-1",
            1,
            20_000_000_000_000_000_000,
            2_000_000_000_000_000_000,
        );
        let order = EvmEscrowGateway::decode_order(&data)
            .unwrap()
            .expect("exists");

        assert_eq!(order.buyer, to_hex(&BUYER));
        assert_eq!(order.seller, to_hex(&SELLER));
        assert_eq!(order.payout_wallet, to_hex(&PAYOUT));
        assert_eq!(order.treasury, to_hex(&TREASURY));
        assert_eq!(order.status, EscrowOrderStatus::Pending);
        assert_eq!(order.order_id, "order-1");
        assert_eq!(order.amount, 20_000_000_000_000_000_000);
        assert_eq!(order.fee_amount, 2_000_000_000_000_000_000);
        assert_eq!(order.settlement_deadline, 1_700_003_600);
        assert_eq!(order.timeout_deadline, 1_700_005_400);
    }

    #[test]
    fn carries_amounts_a_u64_could_not_hold() {
        // Twenty ether is 2 x 10^19 wei. Decoding into a u64 would wrap, and
        // the wrapped value would then be compared against the quote.
        let data = encode_order("order-1", 1, 20_000_000_000_000_000_000, 1);
        let order = EvmEscrowGateway::decode_order(&data).unwrap().unwrap();
        assert!(order.amount > u64::MAX as u128);
    }

    #[test]
    fn an_unwritten_mapping_slot_is_no_order_rather_than_a_zero_order() {
        // Solidity returns the zero value for a key that was never written, so
        // status None is the only thing distinguishing "no such order" from a
        // real one whose fields happen to be zero.
        let data = encode_order("", 0, 0, 0);
        assert!(EvmEscrowGateway::decode_order(&data).unwrap().is_none());
    }

    #[test]
    fn maps_every_status_the_contract_defines() {
        for (byte, expected) in [
            (1u8, EscrowOrderStatus::Pending),
            (2, EscrowOrderStatus::Confirmed),
            (3, EscrowOrderStatus::Completed),
            (4, EscrowOrderStatus::Refunded),
        ] {
            let data = encode_order("order-1", byte, 10, 1);
            assert_eq!(
                EvmEscrowGateway::decode_order(&data)
                    .unwrap()
                    .unwrap()
                    .status,
                expected
            );
        }
    }

    #[test]
    fn solidity_and_solana_discriminants_are_not_the_same() {
        // Solidity's enum starts at None, so Pending is 1 here and 0 on Solana.
        // Reading one with the other's mapping turns a pending order into a
        // completed one.
        let data = encode_order("order-1", 1, 10, 1);
        let order = EvmEscrowGateway::decode_order(&data).unwrap().unwrap();
        assert_eq!(order.status, EscrowOrderStatus::Pending);
        assert_ne!(order.status, EscrowOrderStatus::Confirmed);
    }

    #[test]
    fn refuses_a_status_the_contract_never_writes() {
        let data = encode_order("order-1", 9, 10, 1);
        assert!(EvmEscrowGateway::decode_order(&data).is_err());
    }

    #[test]
    fn recomputes_the_storage_key_from_the_order_it_decoded() {
        // The contract derives its key from the buyer and the order id, so this
        // is what makes "the order you asked for" a check and not a hope.
        let data = encode_order("order-1", 1, 10, 1);
        let order = EvmEscrowGateway::decode_order(&data).unwrap().unwrap();
        assert_eq!(
            to_hex(&order.order_id_hash),
            order_id_for(&BUYER, "order-1")
        );
    }

    #[test]
    fn truncated_data_errors_rather_than_panicking() {
        // A short response reaches this from a misbehaving or hostile node, and
        // an index out of bounds in a request handler is a crash.
        let data = encode_order("order-1", 1, 10, 1);
        for cut in [0, 31, 64, 200, 380] {
            assert!(
                EvmEscrowGateway::decode_order(&data[..cut.min(data.len())]).is_err(),
                "a {}-byte response should not decode",
                cut
            );
        }
    }

    #[test]
    fn an_implausible_offset_is_refused_before_it_is_followed() {
        let mut data = encode_order("order-1", 1, 10, 1);
        // A full-width uint256 in the leading offset slot.
        for byte in data.iter_mut().take(32) {
            *byte = 0xff;
        }
        assert!(EvmEscrowGateway::decode_order(&data).is_err());
    }

    #[test]
    fn an_amount_above_u128_is_refused_rather_than_truncated() {
        let mut data = encode_order("order-1", 1, 10, 1);
        // Dirty the high bytes of the amount slot: offset 32 for the leading
        // offset, then five address slots.
        let amount_at = 32 + 32 * 5;
        data[amount_at] = 0x01;
        assert!(EvmEscrowGateway::decode_order(&data).is_err());
    }

    #[test]
    fn an_address_slot_with_dirty_upper_bytes_is_refused() {
        let mut data = encode_order("order-1", 1, 10, 1);
        data[32] = 0x01; // first byte of the buyer slot
        assert!(EvmEscrowGateway::decode_order(&data).is_err());
    }

    #[test]
    fn an_order_id_that_is_not_utf8_is_refused() {
        let mut data = encode_order("order-1", 1, 10, 1);
        let string_at = 32 + 32 * 12 + 32;
        data[string_at] = 0xff;
        assert!(EvmEscrowGateway::decode_order(&data).is_err());
    }

    #[test]
    fn decodes_an_order_id_spanning_two_slots() {
        // A 36-character UUID needs two slots, so the padding arithmetic is
        // exercised by the common case rather than only by a contrived one.
        let uuid = "3f8a1c2e-0b4d-4e6f-9a1b-2c3d4e5f6071";
        let data = encode_order(uuid, 1, 10, 1);
        assert_eq!(
            EvmEscrowGateway::decode_order(&data)
                .unwrap()
                .unwrap()
                .order_id,
            uuid
        );
    }

    #[test]
    fn hex_decoding_rejects_malformed_input() {
        assert!(decode_hex("0x1").is_err());
        assert!(decode_hex("0xzz").is_err());
        assert_eq!(decode_hex("0x").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_hex("0xff00").unwrap(), vec![0xff, 0x00]);
    }
}

/// Decoding bytes this contract actually produced.
///
/// The tests above encode and decode with one understanding of the ABI layout.
/// If that understanding is wrong in the same way twice, they pass and
/// production fails -- which is exactly the failure a hand-written decoder
/// invites. This reads a real `eth_call` response, recorded from a deployed
/// contract with a funded order in it, and checks every field.
#[cfg(test)]
mod golden {
    use super::*;

    const GOLDEN: &str = include_str!("../../../contracts/ethereum/test/eip712_golden.json");

    #[test]
    fn decodes_a_response_the_contract_really_returned() {
        let g: serde_json::Value = serde_json::from_str(GOLDEN).expect("valid JSON");
        let fixture = &g["getOrder"];
        let expected = &fixture["expected"];
        let text = |v: &serde_json::Value, k: &str| v[k].as_str().expect(k).to_string();

        // The selector the contract's own ABI reports.
        assert_eq!(text(fixture, "selector"), to_hex(&get_order_selector()));

        let data = decode_hex(&text(fixture, "returnData")).expect("hex");
        let order = EvmEscrowGateway::decode_order(&data)
            .expect("decodes")
            .expect("the order exists");

        let same_address = |got: &str, want: &str| {
            assert_eq!(got.to_lowercase(), want.to_lowercase(), "address mismatch");
        };
        same_address(&order.buyer, &text(expected, "buyer"));
        same_address(&order.seller, &text(expected, "seller"));
        same_address(&order.payout_wallet, &text(expected, "payoutWallet"));
        same_address(&order.treasury, &text(expected, "treasury"));
        same_address(&order.mint, &text(expected, "token"));

        assert_eq!(order.amount.to_string(), text(expected, "amount"));
        assert_eq!(order.fee_amount.to_string(), text(expected, "fee"));
        assert_eq!(order.order_id, text(expected, "orderId"));
        assert_eq!(order.created_at.to_string(), text(expected, "createdAt"));
        assert_eq!(
            order.settlement_deadline.to_string(),
            text(expected, "settlementDeadline")
        );
        assert_eq!(
            order.timeout_deadline.to_string(),
            text(expected, "timeoutDeadline")
        );

        // Status 1 is Pending in Solidity's enum, which starts at None.
        assert_eq!(expected["status"].as_u64(), Some(1));
        assert_eq!(order.status, EscrowOrderStatus::Pending);
    }

    #[test]
    fn recomputes_the_storage_key_the_contract_filed_it_under() {
        // The whole substitution defence: the key is derived from the buyer and
        // order id the response itself carries, and must equal the key the
        // order was read under.
        let g: serde_json::Value = serde_json::from_str(GOLDEN).expect("valid JSON");
        let fixture = &g["getOrder"];
        let data = decode_hex(fixture["returnData"].as_str().expect("returnData")).expect("hex");
        let order = EvmEscrowGateway::decode_order(&data).unwrap().unwrap();

        assert_eq!(
            to_hex(&order.order_id_hash).to_lowercase(),
            fixture["orderHash"]
                .as_str()
                .expect("orderHash")
                .to_lowercase()
        );
    }
}
