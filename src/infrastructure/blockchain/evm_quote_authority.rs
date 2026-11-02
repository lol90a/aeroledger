//! The secp256k1 key whose EIP-712 signature authorises a price on the
//! Solidity escrow.
//!
//! Mirrors [`QuoteAuthority`] on the Solana side, down to the same policy for
//! how long an authorization lives. What differs is everything about the
//! cryptography: secp256k1 rather than Ed25519, a *recoverable* signature so
//! the contract derives the signer instead of being told it, and a digest that
//! binds the chain id and the contract address.
//!
//! The private key never leaves this type. No `Debug`, no `Serialize`, and no
//! accessor that returns it — only the address it derives to, which is public
//! information the contract already stores.
//!
//! [`QuoteAuthority`]: super::quote_authority::QuoteAuthority

use k256::ecdsa::{RecoveryId, Signature, SigningKey};

use crate::domain::ports::evm_quote_signer::{EvmEscrowQuote, EvmQuoteSigner, SignedEvmQuote};
use crate::domain::ports::quote_signer::authorization_expiry_within;
use crate::infrastructure::blockchain::eip712::{
    compute_order_hash, keccak256, parse_address, quote_digest, to_hex, EvmQuote, QuoteFields,
    MAX_QUOTE_LIFETIME_SECS,
};
use crate::shared::errors::{DomainError, InfraError};

/// Holds the signing key, the chain it signs for, and the contract it signs to.
///
/// All three together, because a signature is only meaningful for one triple.
/// Carrying the key alone and passing the chain id in per call would make it
/// possible to sign for the wrong network by passing the wrong argument, and
/// that mistake is unrecoverable once a buyer has the signature.
#[derive(Clone)]
pub struct EvmQuoteAuthority {
    key: SigningKey,
    chain_id: u64,
    verifying_contract: [u8; 20],
}

impl EvmQuoteAuthority {
    /// Load from a `0x`-prefixed 32-byte hex private key. Never log the input.
    pub fn from_hex_key(
        key_hex: &str,
        chain_id: u64,
        verifying_contract: &str,
    ) -> Result<Self, InfraError> {
        let trimmed = key_hex.trim().trim_start_matches("0x");
        if trimmed.len() != 64 {
            return Err(InfraError::InvalidRequest(
                "quote key must be 32 bytes of hex".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(
                trimmed
                    .get(i * 2..i * 2 + 2)
                    .ok_or_else(|| InfraError::InvalidRequest("quote key is malformed".into()))?,
                16,
            )
            .map_err(|_| InfraError::InvalidRequest("quote key is not hex".to_string()))?;
        }

        let key = SigningKey::from_bytes((&bytes).into())
            .map_err(|_| InfraError::InvalidRequest("quote key is not a valid scalar".into()))?;

        let verifying_contract = parse_address(verifying_contract).ok_or_else(|| {
            InfraError::InvalidRequest("escrow contract is not a valid address".to_string())
        })?;

        Ok(Self {
            key,
            chain_id,
            verifying_contract,
        })
    }

    /// Generate a throwaway authority. Development and tests only.
    pub fn generate(chain_id: u64, verifying_contract: [u8; 20]) -> Self {
        Self {
            key: SigningKey::random(&mut rand::thread_rng()),
            chain_id,
            verifying_contract,
        }
    }

    /// The Ethereum address of the signing key.
    ///
    /// The last twenty bytes of the keccak hash of the *uncompressed* public
    /// key with its `0x04` prefix removed. Hashing the compressed form, or
    /// leaving the prefix on, both produce a plausible-looking address that
    /// belongs to nobody.
    pub fn address(&self) -> [u8; 20] {
        let encoded = self.key.verifying_key().to_encoded_point(false);
        let hash = keccak256(&encoded.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    pub fn address_hex(&self) -> String {
        to_hex(&self.address())
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn verifying_contract_hex(&self) -> String {
        to_hex(&self.verifying_contract)
    }

    /// Sign a 32-byte digest, returning the 65-byte `r || s || v` the contract
    /// expects.
    ///
    /// `v` is the recovery id plus 27. The offset is a historical quirk of
    /// Ethereum's signature encoding that OpenZeppelin's `ECDSA` still requires;
    /// passing a bare 0 or 1 makes `tryRecover` return an error rather than the
    /// wrong address, so the failure at least points somewhere useful.
    ///
    /// `sign_prehash_recoverable` normalises `s` into the lower half of the
    /// curve order, which matters: OpenZeppelin rejects high-`s` signatures
    /// outright as a malleability guard, so an un-normalised signature would be
    /// refused by the contract no matter how correct the digest.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], DomainError> {
        let (signature, recovery_id): (Signature, RecoveryId) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| DomainError::InternalError("could not sign quote".to_string()))?;

        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = recovery_id.to_byte() + 27;
        Ok(out)
    }
}

#[async_trait::async_trait]
impl EvmQuoteSigner for EvmQuoteAuthority {
    fn sign_evm_quote(
        &self,
        order_id: &str,
        buyer: &str,
        seller: &str,
        token: &str,
        quote: EvmEscrowQuote,
    ) -> Result<SignedEvmQuote, DomainError> {
        let address = |label: &str, value: &str| {
            parse_address(value).ok_or_else(|| {
                DomainError::ValidationError(format!("{} is not a valid address", label))
            })
        };

        let buyer = address("buyer wallet", buyer)?;
        let seller = address("seller", seller)?;
        let token = address("token", token)?;

        if quote.amount == 0 {
            return Err(DomainError::ValidationError(
                "cannot authorise a zero amount".to_string(),
            ));
        }
        // The contract carves the fee out of the escrowed amount, so a fee
        // equal to it would leave the seller with nothing. Checked here so the
        // failure names the problem instead of arriving as `InvalidFee`.
        if quote.fee >= quote.amount {
            return Err(DomainError::ValidationError(
                "platform fee must be strictly less than the amount".to_string(),
            ));
        }

        let order_hash = compute_order_hash(&buyer, order_id);
        let digest = quote_digest(
            self.chain_id,
            &self.verifying_contract,
            QuoteFields {
                order_hash: &order_hash,
                buyer: &buyer,
                seller: &seller,
                token: &token,
                quote: EvmQuote {
                    amount: quote.amount,
                    fee: quote.fee,
                    expiry: quote.expiry,
                },
            },
        );

        Ok(SignedEvmQuote {
            order_hash: to_hex(&order_hash),
            signature: to_hex(&self.sign_digest(&digest)?),
            signer: self.address_hex(),
            quote,
        })
    }

    fn signer_address(&self) -> String {
        self.address_hex()
    }

    fn authorization_expiry(&self, now: i64, reservation_expires_at: i64) -> Option<i64> {
        authorization_expiry_within(now, reservation_expires_at, MAX_QUOTE_LIFETIME_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    const CONTRACT: [u8; 20] = [0xab; 20];
    const BUYER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const SELLER: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
    const NATIVE: &str = "0x0000000000000000000000000000000000000000";

    fn authority() -> EvmQuoteAuthority {
        // A fixed key, so the derived address is stable across runs. Test-only
        // and worthless: it controls nothing on any chain.
        EvmQuoteAuthority::from_hex_key(
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            11155111,
            &to_hex(&CONTRACT),
        )
        .expect("valid key")
    }

    fn quote() -> EvmEscrowQuote {
        EvmEscrowQuote {
            amount: 20_000_000_000_000_000_000,
            fee: 2_608_695_652_173_913_043,
            expiry: 1_900_000_000,
        }
    }

    /// Recover the signer from a 65-byte signature the way the contract does,
    /// so these tests prove the contract would accept it rather than merely
    /// that the bytes were produced.
    fn recover(digest: &[u8; 32], signature: &[u8; 65]) -> [u8; 20] {
        let sig = Signature::from_slice(&signature[..64]).expect("signature");
        let recid = RecoveryId::from_byte(signature[64] - 27).expect("recovery id");
        let key = VerifyingKey::recover_from_prehash(digest, &sig, recid).expect("recoverable");
        let encoded = key.to_encoded_point(false);
        let hash = keccak256(&encoded.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    fn hex_to_bytes(value: &str) -> Vec<u8> {
        let trimmed = value.trim_start_matches("0x");
        (0..trimmed.len() / 2)
            .map(|i| u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_signature_recovers_to_the_signers_own_address() {
        // This is the whole contract: `_verifyQuote` recovers an address from
        // the digest and compares it with `quoteSigner`. If recovery gives a
        // different address, every payment fails as `InvalidQuoteSignature`.
        let authority = authority();
        let signed = authority
            .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
            .unwrap();

        let buyer = parse_address(BUYER).unwrap();
        let order_hash = compute_order_hash(&buyer, "order-1");
        let digest = quote_digest(
            11155111,
            &CONTRACT,
            QuoteFields {
                order_hash: &order_hash,
                buyer: &buyer,
                seller: &parse_address(SELLER).unwrap(),
                token: &parse_address(NATIVE).unwrap(),
                quote: EvmQuote {
                    amount: quote().amount,
                    fee: quote().fee,
                    expiry: quote().expiry,
                },
            },
        );

        let sig: [u8; 65] = hex_to_bytes(&signed.signature)
            .try_into()
            .expect("65 bytes");
        assert_eq!(to_hex(&recover(&digest, &sig)), authority.address_hex());
        assert_eq!(signed.signer, authority.address_hex());
    }

    #[test]
    fn the_signature_is_65_bytes_with_v_as_27_or_28() {
        let signed = authority()
            .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
            .unwrap();
        let bytes = hex_to_bytes(&signed.signature);
        assert_eq!(bytes.len(), 65);
        // OpenZeppelin's ECDSA.tryRecover returns an error for anything else,
        // so a bare 0 or 1 here would fail every order.
        assert!(matches!(bytes[64], 27 | 28), "v was {}", bytes[64]);
    }

    #[test]
    fn s_is_normalised_into_the_lower_half_of_the_curve_order() {
        // OpenZeppelin rejects high-s signatures outright as a malleability
        // guard, so an un-normalised one is refused however correct the digest.
        // n/2 for secp256k1, big-endian.
        const HALF_N: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
            0x68, 0x1b, 0x20, 0xa0,
        ];
        for i in 0..16 {
            let signed = authority()
                .sign_evm_quote(&format!("order-{}", i), BUYER, SELLER, NATIVE, quote())
                .unwrap();
            let bytes = hex_to_bytes(&signed.signature);
            assert!(bytes[32..64] <= HALF_N[..], "high s on order-{}", i);
        }
    }

    #[test]
    fn the_order_hash_is_the_contracts_storage_key() {
        let signed = authority()
            .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
            .unwrap();
        let expected = compute_order_hash(&parse_address(BUYER).unwrap(), "order-1");
        assert_eq!(signed.order_hash, to_hex(&expected));
    }

    #[test]
    fn a_signature_does_not_transfer_to_a_different_order_buyer_or_price() {
        // Every one of these is inside the digest, so changing any of them
        // changes what has to be signed.
        let a = authority();
        let base = a
            .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
            .unwrap()
            .signature;

        for other in [
            a.sign_evm_quote("order-2", BUYER, SELLER, NATIVE, quote())
                .unwrap()
                .signature,
            a.sign_evm_quote("order-1", SELLER, SELLER, NATIVE, quote())
                .unwrap()
                .signature,
            a.sign_evm_quote("order-1", BUYER, BUYER, NATIVE, quote())
                .unwrap()
                .signature,
            a.sign_evm_quote(
                "order-1",
                BUYER,
                SELLER,
                NATIVE,
                EvmEscrowQuote {
                    amount: quote().amount + 1,
                    ..quote()
                },
            )
            .unwrap()
            .signature,
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn the_same_quote_on_a_different_chain_signs_differently() {
        // The chain id is inside the EIP-712 domain, so a testnet authorization
        // cannot be replayed against a mainnet deployment.
        let sepolia = authority();
        let mainnet = EvmQuoteAuthority::from_hex_key(
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            1,
            &to_hex(&CONTRACT),
        )
        .unwrap();

        assert_ne!(
            sepolia
                .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
                .unwrap()
                .signature,
            mainnet
                .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
                .unwrap()
                .signature
        );
    }

    #[test]
    fn refuses_a_fee_that_is_not_strictly_below_the_amount() {
        let err = authority()
            .sign_evm_quote(
                "order-1",
                BUYER,
                SELLER,
                NATIVE,
                EvmEscrowQuote {
                    amount: 100,
                    fee: 100,
                    expiry: 1,
                },
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::ValidationError(_)));
    }

    #[test]
    fn refuses_a_zero_amount() {
        assert!(authority()
            .sign_evm_quote(
                "order-1",
                BUYER,
                SELLER,
                NATIVE,
                EvmEscrowQuote {
                    amount: 0,
                    fee: 0,
                    expiry: 1
                },
            )
            .is_err());
    }

    #[test]
    fn refuses_a_malformed_wallet_address() {
        let err = authority()
            .sign_evm_quote("order-1", "not-an-address", SELLER, NATIVE, quote())
            .unwrap_err();
        assert!(format!("{}", err).contains("buyer wallet"));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_without_echoing_it() {
        // `unwrap_err` is not available here, and deliberately so: it would
        // require `Debug` on a type that holds a private key, and the easiest
        // way to leak a secret is to make it printable.
        let err = match EvmQuoteAuthority::from_hex_key("0xdeadbeef", 1, &to_hex(&CONTRACT)) {
            Err(e) => e,
            Ok(_) => panic!("a four-byte key was accepted"),
        };
        assert!(!format!("{}", err).contains("deadbeef"));
    }

    #[test]
    fn an_authorization_never_outlives_its_reservation() {
        let a = authority();
        let now = 1_700_000_000;
        // Reservation with two minutes left: shorter than our three-minute TTL,
        // so the reservation wins.
        assert_eq!(a.authorization_expiry(now, now + 120), Some(now + 120));
        // Reservation with ten minutes left: our TTL wins.
        assert_eq!(a.authorization_expiry(now, now + 600), Some(now + 180));
        // Lapsed: nothing left to authorise.
        assert_eq!(a.authorization_expiry(now, now), None);
        assert_eq!(a.authorization_expiry(now, now - 1), None);
    }

    #[test]
    fn every_authorization_sits_inside_the_contracts_ceiling() {
        let a = authority();
        let now = 1_700_000_000;
        for reservation in [1, 60, 180, 600, 86_400] {
            let expiry = a.authorization_expiry(now, now + reservation).unwrap();
            assert!(
                expiry - now <= MAX_QUOTE_LIFETIME_SECS,
                "reservation of {}s produced a {}s authorization",
                reservation,
                expiry - now
            );
        }
    }

    #[test]
    fn a_generated_authority_derives_a_usable_address() {
        let a = EvmQuoteAuthority::generate(1, CONTRACT);
        assert_eq!(parse_address(&a.address_hex()).map(|b| b.len()), Some(20));
        assert_ne!(a.address_hex(), to_hex(&[0u8; 20]));
    }

    /// Guards the digest itself: the signature must cover the EIP-712 digest and
    /// nothing else, so verifying against a different prehash must fail.
    #[test]
    fn the_signature_does_not_verify_against_a_different_digest() {
        let a = authority();
        let signed = a
            .sign_evm_quote("order-1", BUYER, SELLER, NATIVE, quote())
            .unwrap();
        let sig = Signature::from_slice(&hex_to_bytes(&signed.signature)[..64]).unwrap();
        assert!(a
            .key
            .verifying_key()
            .verify_prehash(&[0u8; 32], &sig)
            .is_err());
    }
}

/// Cross-implementation check against the golden vector.
///
/// The vector carries a signature produced by ethers' own EIP-712 code, for a
/// fixed key and payload. The Hardhat suite already proves the contract accepts
/// ethers-produced signatures, so matching these bytes exactly proves the
/// contract accepts ours -- without having to get a Rust-made signature into a
/// Solidity test.
///
/// ECDSA over secp256k1 is deterministic under RFC 6979, which both
/// implementations use, so "identical bytes" is a meaningful assertion rather
/// than a coincidence that would break on the next run.
#[cfg(test)]
mod golden {
    use super::*;

    const GOLDEN: &str = include_str!("../../../contracts/ethereum/test/eip712_golden.json");

    #[test]
    fn signs_a_quote_exactly_as_ethers_does() {
        let g: serde_json::Value = serde_json::from_str(GOLDEN).expect("valid JSON");
        let input = &g["input"];
        let text = |key: &str| input[key].as_str().expect(key).to_string();

        let authority = EvmQuoteAuthority::from_hex_key(
            &text("quoteSignerKey"),
            input["chainId"].as_u64().expect("chainId"),
            &text("verifyingContract"),
        )
        .expect("valid key");

        // The derived address must match what the generator recorded, or we are
        // comparing signatures from two different keys.
        assert_eq!(
            authority.address_hex().to_lowercase(),
            text("quoteSigner").to_lowercase()
        );

        let signed = authority
            .sign_evm_quote(
                &text("orderId"),
                &text("buyer"),
                &text("seller"),
                &text("token"),
                EvmEscrowQuote {
                    amount: text("amount").parse().expect("amount"),
                    fee: text("fee").parse().expect("fee"),
                    expiry: text("expiry").parse().expect("expiry"),
                },
            )
            .expect("signs");

        assert_eq!(
            signed.signature,
            g["expected"]["signature"].as_str().expect("signature")
        );
        assert_eq!(
            signed.order_hash,
            g["expected"]["orderHash"].as_str().expect("orderHash")
        );
    }
}
