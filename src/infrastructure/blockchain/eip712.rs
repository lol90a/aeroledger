//! EIP-712 typed-data hashing for the Solidity escrow.
//!
//! The Solidity contract will not open an order without a signature from
//! `quoteSigner` over an EIP-712 digest of the price. This module builds that
//! digest, byte for byte, from the same inputs the contract uses.
//!
//! ## Why this is fiddlier than the Solana side
//!
//! Solana's quote message is a flat concatenation with fixed widths, and it was
//! written to be one. EIP-712 is layered on top of Solidity's ABI encoding,
//! which this code has to reproduce exactly:
//!
//!   * every static value occupies a full 32-byte slot, left-padded, so an
//!     address is 12 zero bytes then 20 bytes of address;
//!   * `abi.encode` of a tuple containing a **dynamic** member -- and the order
//!     hash's `(address, string)` is one -- writes a *head* of 32-byte slots
//!     where the dynamic member's slot holds a byte offset, then a *tail* with
//!     the length and the padded bytes;
//!   * inside an EIP-712 struct hash, dynamic members are replaced by their
//!     keccak hash, so the struct hash itself is a flat slot concatenation.
//!
//! Those are three different rules and the contract uses all three, in three
//! different places. Everything here is checked against a golden vector the
//! Hardhat suite generates from the deployed contract, because reasoning about
//! ABI encoding is exactly the sort of thing that feels right and is not.
//!
//! ## What a mistake costs
//!
//! Nothing can be let through: the contract recovers the signer from the digest
//! it computes itself, so a wrong digest recovers a different address and the
//! order is refused. The cost is that every payment fails with
//! `InvalidQuoteSignature`, which points at the key rather than the message --
//! the same misleading symptom the Solana golden vector exists to prevent.

use sha3::{Digest, Keccak256};

/// `name` in the contract's `EIP712("AeroLedgerEscrow", "2")` constructor.
pub const DOMAIN_NAME: &str = "AeroLedgerEscrow";
/// `version`. Bumped when the signing payload changes, so old signatures die.
pub const DOMAIN_VERSION: &str = "2";

/// The contract's `MAX_QUOTE_LIFETIME`, in seconds.
pub const MAX_QUOTE_LIFETIME_SECS: i64 = 15 * 60;

/// EIP-712's own type string for the domain, fixed by the standard.
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Must match `QUOTE_TYPEHASH` in the contract exactly, whitespace included.
const QUOTE_TYPE: &str = "Quote(bytes32 orderHash,address buyer,address seller,address token,uint256 amount,uint256 fee,uint256 expiry)";

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A 32-byte ABI slot holding a left-padded value.
fn slot(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(bytes);
    out
}

/// An address in a 32-byte slot: twelve zero bytes, then the twenty address bytes.
fn address_slot(address: &[u8; 20]) -> [u8; 32] {
    slot(address)
}

/// A `uint256` in a slot, from a `u128`.
///
/// `u128` rather than `u64` because EVM amounts are wei: one ether is 10^18,
/// and twenty ether overflows a `u64`. A real `uint256` is wider still, but no
/// honest quote reaches 2^128 of anything, and refusing to sign one is better
/// than silently truncating it.
fn u256_slot(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// `abi.encode(buyer, orderId)` -- the preimage of the contract's order hash.
///
/// A tuple with one dynamic member, so: the address slot, then a slot holding
/// the offset at which the string's data begins (0x40, being two slots in),
/// then the string's length, then its bytes padded up to a 32-byte boundary.
///
/// Concatenating the address and the string directly would be the obvious
/// implementation and would produce a different hash, hence a different storage
/// key, hence an order the contract has never heard of.
fn abi_encode_address_string(buyer: &[u8; 20], order_id: &str) -> Vec<u8> {
    let data = order_id.as_bytes();
    let mut out = Vec::with_capacity(96 + data.len().div_ceil(32) * 32);

    out.extend_from_slice(&address_slot(buyer));
    // Offset to the dynamic member's data, counted from the start of the tuple.
    out.extend_from_slice(&u256_slot(64));
    out.extend_from_slice(&u256_slot(data.len() as u128));
    out.extend_from_slice(data);
    // Right-padded, unlike every static value, which is left-padded.
    let padding = (32 - data.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

/// The key the contract stores an order under: `keccak256(abi.encode(buyer, orderId))`.
///
/// Note what is *not* in it: the seller, the token, the amount. The order slot
/// is the contract's replay guard -- a second `createOrder` for the same buyer
/// and order id collides with the existing order and reverts -- so the key is
/// deliberately the identity of the purchase, not its terms.
pub fn compute_order_hash(buyer: &[u8; 20], order_id: &str) -> [u8; 32] {
    keccak256(&abi_encode_address_string(buyer, order_id))
}

/// The domain separator, binding a signature to one contract on one chain.
///
/// Without `chainId` and `verifyingContract` in here, a signature authorising a
/// payment on a testnet deployment would authorise the same payment on mainnet.
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    // Dynamic members of a struct hash are replaced by their own hash, so the
    // name and version appear as hashes rather than as offsets and bytes.
    buf.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
    buf.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    buf.extend_from_slice(&u256_slot(chain_id as u128));
    buf.extend_from_slice(&address_slot(verifying_contract));
    keccak256(&buf)
}

/// The price commitment the contract enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmQuote {
    /// Escrowed amount in the asset's smallest unit (wei for native).
    pub amount: u128,
    /// Platform fee, carved out of `amount`. Must be strictly less.
    pub fee: u128,
    /// Unix seconds after which the contract refuses the quote.
    pub expiry: i64,
}

/// Everything the `Quote` struct hash covers.
#[derive(Debug, Clone, Copy)]
pub struct QuoteFields<'a> {
    pub order_hash: &'a [u8; 32],
    pub buyer: &'a [u8; 20],
    pub seller: &'a [u8; 20],
    /// The ERC-20 being escrowed, or all zeroes for the native coin.
    pub token: &'a [u8; 20],
    pub quote: EvmQuote,
}

/// `keccak256(abi.encode(QUOTE_TYPEHASH, ...))`.
///
/// Every member is static here -- `bytes32`, three addresses, three `uint256`s --
/// so this one really is a flat run of slots with no head/tail split.
pub fn quote_struct_hash(fields: QuoteFields<'_>) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 8);
    buf.extend_from_slice(&keccak256(QUOTE_TYPE.as_bytes()));
    buf.extend_from_slice(fields.order_hash);
    buf.extend_from_slice(&address_slot(fields.buyer));
    buf.extend_from_slice(&address_slot(fields.seller));
    buf.extend_from_slice(&address_slot(fields.token));
    buf.extend_from_slice(&u256_slot(fields.quote.amount));
    buf.extend_from_slice(&u256_slot(fields.quote.fee));
    buf.extend_from_slice(&u256_slot(fields.quote.expiry as u128));
    keccak256(&buf)
}

/// The digest a quote signature must cover: `0x19 0x01 || domain || structHash`.
///
/// The `0x19 0x01` prefix is EIP-191's "this is structured data, not a
/// transaction", and it is what stops a signature obtained here from ever being
/// replayable as a transaction the signer did not intend.
pub fn quote_digest(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    fields: QuoteFields<'_>,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_separator(chain_id, verifying_contract));
    buf.extend_from_slice(&quote_struct_hash(fields));
    keccak256(&buf)
}

/// Parse a `0x`-prefixed 20-byte hex address.
///
/// Case-insensitive and EIP-55 checksums are *not* verified. A checksum catches
/// a typo, which is worth having at a UI boundary; here the address has come
/// from configuration an operator wrote deliberately, and rejecting a correct
/// address for being lower-case would be a worse failure than accepting one.
pub fn parse_address(value: &str) -> Option<[u8; 20]> {
    let hex = value.trim().strip_prefix("0x").or_else(|| {
        // Tolerate the prefix being absent; reject anything else outright.
        value.trim().len().eq(&40).then_some(value.trim())
    })?;
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Render bytes as `0x`-prefixed lower-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// The all-zero address, which the contract uses to mean "the native coin".
pub const NATIVE_TOKEN: [u8; 20] = [0u8; 20];

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector generated by the contract itself, through its own
    /// `computeOrderHash`, `domainSeparator` and `quoteDigest` view functions.
    ///
    /// The Hardhat suite asserts the same file. Two readers of one vector, in
    /// two languages, from one source of truth -- the same arrangement that
    /// keeps the Solana quote message honest.
    const GOLDEN: &str = include_str!("../../../contracts/ethereum/test/eip712_golden.json");

    fn golden() -> serde_json::Value {
        serde_json::from_str(GOLDEN).expect("golden vector is valid JSON")
    }

    fn field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
        v[key].as_str().unwrap_or_else(|| panic!("missing {}", key))
    }

    #[test]
    fn order_hash_matches_the_contracts_own_computation() {
        let g = golden();
        let buyer = parse_address(field(&g["input"], "buyer")).expect("buyer");
        let order_id = field(&g["input"], "orderId");
        assert_eq!(
            to_hex(&compute_order_hash(&buyer, order_id)),
            field(&g["expected"], "orderHash")
        );
    }

    #[test]
    fn domain_separator_matches_the_deployed_contract() {
        let g = golden();
        let contract = parse_address(field(&g["input"], "verifyingContract")).expect("contract");
        let chain_id = g["input"]["chainId"].as_u64().expect("chainId");
        assert_eq!(
            to_hex(&domain_separator(chain_id, &contract)),
            field(&g["expected"], "domainSeparator")
        );
    }

    #[test]
    fn quote_digest_matches_the_contracts_own_digest() {
        let g = golden();
        let buyer = parse_address(field(&g["input"], "buyer")).expect("buyer");
        let seller = parse_address(field(&g["input"], "seller")).expect("seller");
        let token = parse_address(field(&g["input"], "token")).expect("token");
        let contract = parse_address(field(&g["input"], "verifyingContract")).expect("contract");
        let chain_id = g["input"]["chainId"].as_u64().expect("chainId");
        let order_hash = compute_order_hash(&buyer, field(&g["input"], "orderId"));

        let digest = quote_digest(
            chain_id,
            &contract,
            QuoteFields {
                order_hash: &order_hash,
                buyer: &buyer,
                seller: &seller,
                token: &token,
                quote: EvmQuote {
                    amount: field(&g["input"], "amount").parse().expect("amount"),
                    fee: field(&g["input"], "fee").parse().expect("fee"),
                    expiry: field(&g["input"], "expiry").parse().expect("expiry"),
                },
            },
        );
        assert_eq!(to_hex(&digest), field(&g["expected"], "quoteDigest"));
    }

    /// The order key is `keccak256(abi.encode(buyer, orderId))`, and
    /// `abi.encode` of a tuple with a dynamic member is not concatenation. This
    /// pins the difference, because the plausible-looking wrong version derives
    /// a different storage key and the contract then has no such order.
    #[test]
    fn abi_encoding_uses_the_head_tail_layout_not_concatenation() {
        let buyer = [0x11u8; 20];
        let encoded = abi_encode_address_string(&buyer, "ab");

        // address slot, offset slot, length slot, then the padded bytes.
        assert_eq!(encoded.len(), 32 * 4);
        assert_eq!(&encoded[0..12], &[0u8; 12], "address is left-padded");
        assert_eq!(&encoded[12..32], &buyer);
        assert_eq!(encoded[63], 64, "offset to the string data is 0x40");
        assert_eq!(encoded[95], 2, "string length");
        assert_eq!(&encoded[96..98], b"ab");
        assert_eq!(
            &encoded[98..128],
            &[0u8; 30],
            "string bytes are right-padded"
        );
    }

    #[test]
    fn a_string_of_exactly_one_slot_gets_no_extra_padding() {
        // 32 bytes exactly: the padding calculation must add nothing, not 32.
        let encoded = abi_encode_address_string(&[0u8; 20], &"a".repeat(32));
        assert_eq!(encoded.len(), 32 * 4);
    }

    #[test]
    fn a_longer_order_id_spills_into_a_second_slot() {
        let encoded = abi_encode_address_string(&[0u8; 20], &"a".repeat(33));
        assert_eq!(encoded.len(), 32 * 5);
    }

    #[test]
    fn order_hash_changes_with_the_buyer_and_the_order_id() {
        // Both are in the key, which is what makes two buyers' orders for the
        // same booking distinct slots rather than a collision.
        let a = compute_order_hash(&[1u8; 20], "order-1");
        let b = compute_order_hash(&[2u8; 20], "order-1");
        let c = compute_order_hash(&[1u8; 20], "order-2");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn the_domain_binds_a_signature_to_one_chain_and_one_contract() {
        // Without this a signature authorising a testnet payment would
        // authorise the same payment on mainnet.
        let contract = [0xab; 20];
        assert_ne!(
            domain_separator(1, &contract),
            domain_separator(11155111, &contract)
        );
        assert_ne!(
            domain_separator(1, &contract),
            domain_separator(1, &[0xcd; 20])
        );
    }

    #[test]
    fn amounts_above_u64_survive() {
        // Twenty ether is 2 * 10^19 wei, which a u64 cannot hold. Truncating it
        // would sign a quote for a fraction of the real price.
        let twenty_ether: u128 = 20_000_000_000_000_000_000;
        let s = u256_slot(twenty_ether);
        assert_eq!(&s[0..16], &[0u8; 16]);
        assert_eq!(
            u128::from_be_bytes(s[16..].try_into().unwrap()),
            twenty_ether
        );
    }

    #[test]
    fn parses_addresses_with_and_without_the_prefix() {
        let expected = [0xabu8; 20];
        let hex = "ab".repeat(20);
        assert_eq!(parse_address(&format!("0x{}", hex)), Some(expected));
        assert_eq!(parse_address(&hex), Some(expected));
        assert_eq!(parse_address(&format!("0X{}", hex.to_uppercase())), None);
    }

    #[test]
    fn rejects_addresses_of_the_wrong_length_or_alphabet() {
        assert_eq!(parse_address("0x1234"), None);
        assert_eq!(parse_address(&format!("0x{}", "ab".repeat(21))), None);
        assert_eq!(parse_address(&format!("0x{}", "zz".repeat(20))), None);
        assert_eq!(parse_address(""), None);
    }

    #[test]
    fn hex_round_trips_through_the_parser() {
        let address = [0x0au8; 20];
        assert_eq!(parse_address(&to_hex(&address)), Some(address));
    }
}
