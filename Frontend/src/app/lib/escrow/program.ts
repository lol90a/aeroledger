/**
 * Wire format of the AeroLedger Solana escrow program.
 *
 * This module is the browser's half of a contract with
 * `contracts/solana/programs/aeroledger-escrow`. Every constant, seed, byte
 * offset and field order here is dictated by that program; none of it is a
 * choice this file is free to make. Where a value is derived (a discriminator,
 * a PDA) it is *computed* from the same inputs the program computes it from
 * rather than pasted in as a magic constant, so a rename on the Rust side
 * breaks a test here instead of producing a transaction the validator rejects
 * with an opaque error.
 *
 * Everything in this file is pure: inputs in, bytes out, no network, no wallet,
 * no clock. That is what makes the dangerous parts -- the signed quote message
 * and the instruction encoding -- testable without a validator. The orchestration
 * that needs a connection and a wallet lives in `client.ts`.
 *
 * ## The security argument, in one paragraph
 *
 * A buyer controls their own browser, so nothing assembled here can be trusted
 * by the program on the strength of having been assembled here. The amount is
 * trustworthy only because the backend signed it with its `quote_authority` key
 * and the program re-derives the exact message those bytes must cover. This
 * module's job is to reproduce that message byte-for-byte and to place the
 * native Ed25519 verification instruction immediately before `create_order`.
 * Getting either wrong fails closed: the program rejects the transaction.
 */

import {
  Ed25519Program,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
// web3.js types instruction data as a Node `Buffer`, which a browser does not
// have. The `buffer` shim is imported explicitly rather than relying on a global
// that happens to exist in dev and vanishes in a production bundle.
import { Buffer } from "buffer";

/* ------------------------------------------------------------------ */
/* Constants fixed by the program                                     */
/* ------------------------------------------------------------------ */

/**
 * Native SOL's SPL mint. The escrow moves SPL tokens only -- it has no path
 * that touches lamports directly -- so paying in SOL means paying in *wrapped*
 * SOL. Conflating the two is the single easiest way to build a transaction that
 * looks right and transfers nothing; see `wsol.ts` for the wrapping itself.
 */
export const WRAPPED_SOL_MINT = new PublicKey(
  "So11111111111111111111111111111111111111112",
);

/** `QUOTE_DOMAIN` in `quote.rs`. Changing the message layout must change this. */
export const QUOTE_DOMAIN = "AEROLEDGER_ORDER_QUOTE_V1";

/** domain(25) + order_id_hash(32) + buyer(32) + seller(32) + mint(32) + 3x8 */
export const QUOTE_MESSAGE_LEN = 25 + 32 + 32 + 32 + 32 + 8 + 8 + 8;

/** `MAX_ORDER_ID_LEN` in `lib.rs`. A UUID is 36; the program allows 64. */
export const MAX_ORDER_ID_LEN = 64;

/**
 * A legacy transaction may not exceed this once serialized. The create_order
 * transaction is close to it -- the Ed25519 attestation alone is 289 bytes and
 * create_order takes sixteen accounts -- so `client.ts` asserts the real figure
 * rather than trusting this arithmetic. Exceeding it is a hard failure at
 * submission, not a warning.
 */
export const MAX_TRANSACTION_BYTES = 1232;

/* ------------------------------------------------------------------ */
/* Byte helpers                                                       */
/* ------------------------------------------------------------------ */

const utf8 = new TextEncoder();

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/**
 * Little-endian encoding of an unsigned 64-bit value.
 *
 * Borsh -- and therefore every integer the program reads -- is little-endian.
 * `bigint` throughout: a `number` silently loses precision above 2^53, and token
 * base units reach that in ordinary use (1 SOL is 10^9 lamports, so 9,007,199
 * SOL overflows a double).
 */
function u64le(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`u64 out of range: ${value}`);
  }
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Little-endian two's-complement encoding of a signed 64-bit value. */
function i64le(value: bigint): Uint8Array {
  const MIN = -(2n ** 63n);
  const MAX = 2n ** 63n - 1n;
  if (value < MIN || value > MAX) {
    throw new RangeError(`i64 out of range: ${value}`);
  }
  return u64le(value < 0n ? value + 2n ** 64n : value);
}

function u32le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError(`u32 out of range: ${value}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

/* ------------------------------------------------------------------ */
/* Anchor identifiers                                                 */
/* ------------------------------------------------------------------ */

/**
 * Anchor's 8-byte tag: the first half of `sha256(namespace:name)`.
 *
 * Instructions use the `global` namespace and the snake_case handler name;
 * accounts use `account` and the PascalCase struct name. Computed rather than
 * hardcoded so that renaming the Rust handler fails a test here.
 */
export function anchorDiscriminator(preimage: string): Uint8Array {
  return sha256(utf8.encode(preimage)).slice(0, 8);
}

/**
 * keccak256 of the order id -- the 32-byte seed the program derives the order
 * PDA from.
 *
 * The program hashes rather than seeding with the string directly because a PDA
 * seed may not exceed 32 bytes and an order id may be 64. The full string is
 * still stored in the account, so the backend can prove a given on-chain order
 * belongs to a given booking instead of inferring it from an address.
 *
 * keccak256, not SHA3-256: `anchor_lang::solana_program::keccak` is the original
 * Keccak padding, and the two produce different digests for the same input.
 */
export function orderIdHash(orderId: string): Uint8Array {
  return keccak_256(utf8.encode(orderId));
}

/* ------------------------------------------------------------------ */
/* Program-derived addresses                                          */
/* ------------------------------------------------------------------ */

function pda(programId: PublicKey, seeds: Uint8Array[]): PublicKey {
  return PublicKey.findProgramAddressSync(seeds, programId)[0];
}

/** `seeds = [b"config"]` -- the singleton governance account. */
export function deriveConfig(programId: PublicKey): PublicKey {
  return pda(programId, [utf8.encode("config")]);
}

/** `seeds = [b"mint", mint]` -- proof the mint is on the allow-list. */
export function deriveSupportedMint(programId: PublicKey, mint: PublicKey): PublicKey {
  return pda(programId, [utf8.encode("mint"), mint.toBytes()]);
}

/**
 * `seeds = [b"merchant", merchant.authority]`.
 *
 * Seeded by the *seller's* authority key, not by the payout wallet: the payout
 * destination is a field of the record, and separating them is what lets
 * governance redirect a seller's proceeds without the seller's identity moving.
 */
export function deriveMerchant(programId: PublicKey, sellerAuthority: PublicKey): PublicKey {
  return pda(programId, [utf8.encode("merchant"), sellerAuthority.toBytes()]);
}

/** `seeds = [b"order", keccak256(order_id)]`. */
export function deriveOrder(programId: PublicKey, orderId: string): PublicKey {
  return pda(programId, [utf8.encode("order"), orderIdHash(orderId)]);
}

/**
 * The escrow vault: the associated token account of the order PDA.
 *
 * `allowOwnerOffCurve` must be true -- the authority is a PDA, which by
 * construction has no private key and lies off the ed25519 curve. The default
 * `false` exists to catch the opposite mistake (deriving an ATA for something
 * that is not a wallet) and would reject this legitimate case.
 */
export function deriveEscrowVault(order: PublicKey, mint: PublicKey): PublicKey {
  return getAssociatedTokenAddressSync(mint, order, true);
}

/** The associated token account of an ordinary wallet. */
export function deriveWalletAta(owner: PublicKey, mint: PublicKey): PublicKey {
  return getAssociatedTokenAddressSync(mint, owner, false);
}

/* ------------------------------------------------------------------ */
/* The signed quote                                                   */
/* ------------------------------------------------------------------ */

/** The price commitment the backend signs and the program enforces. */
export type QuoteCommitment = {
  /** Total base units the buyer must escrow. */
  amount: bigint;
  /** Platform fee, carved out of `amount` at payout. Must be < `amount`. */
  feeAmount: bigint;
  /** Unix seconds after which the program will refuse the quote. */
  expiry: bigint;
};

export type QuoteMessageParams = {
  orderId: string;
  buyer: PublicKey;
  /** `merchant.authority`, the seller -- NOT the payout wallet. */
  seller: PublicKey;
  mint: PublicKey;
  quote: QuoteCommitment;
};

/**
 * Rebuild, byte for byte, the message the backend signed.
 *
 * The program constructs this same message from accounts *it* trusts and
 * compares it against what the Ed25519 instruction actually verified. So this
 * function is not a security control -- a wrong byte here cannot let anything
 * through, it can only make a legitimate payment fail. It is reproduced in the
 * browser so the client can assemble the transaction at all, and so a mismatch
 * surfaces as a test failure rather than as a rejected transaction in front of
 * a customer.
 *
 * Mirrors `quote_message` in `contracts/solana/.../src/quote.rs`.
 */
export function quoteMessage({
  orderId,
  buyer,
  seller,
  mint,
  quote,
}: QuoteMessageParams): Uint8Array {
  const message = concatBytes(
    utf8.encode(QUOTE_DOMAIN),
    orderIdHash(orderId),
    buyer.toBytes(),
    seller.toBytes(),
    mint.toBytes(),
    u64le(quote.amount),
    u64le(quote.feeAmount),
    i64le(quote.expiry),
  );
  // A length drift means the domain string or a field width has moved on one
  // side only, which is precisely the failure this assertion exists to catch.
  if (message.length !== QUOTE_MESSAGE_LEN) {
    throw new Error(
      `quote message is ${message.length} bytes, expected ${QUOTE_MESSAGE_LEN}`,
    );
  }
  return message;
}

/**
 * The native Ed25519 verification instruction carrying the backend's signature.
 *
 * The runtime verifies the signature; the escrow program then reads this
 * instruction back out of the Instructions sysvar to confirm *which* signature
 * the runtime checked. It demands a self-contained instruction -- signature,
 * key and message all inside this instruction's own data, every index set to
 * the 0xffff sentinel -- so that nothing can point at bytes elsewhere in the
 * transaction that the program never inspected.
 *
 * `Ed25519Program.createInstructionWithPublicKey` produces exactly that layout.
 * Hand-rolling the 16-byte header would be a second place for the format to
 * drift, so it is deliberately not done here; `program.test.ts` asserts the
 * layout the program parses.
 */
export function buildQuoteAttestationInstruction(params: {
  quoteAuthority: PublicKey;
  message: Uint8Array;
  /** 64-byte Ed25519 signature produced by the backend's quote authority. */
  signature: Uint8Array;
}): TransactionInstruction {
  if (params.signature.length !== 64) {
    throw new Error(`signature must be 64 bytes, got ${params.signature.length}`);
  }
  return Ed25519Program.createInstructionWithPublicKey({
    publicKey: params.quoteAuthority.toBytes(),
    message: params.message,
    signature: params.signature,
  });
}

/* ------------------------------------------------------------------ */
/* create_order                                                       */
/* ------------------------------------------------------------------ */

/**
 * Instruction data: the 8-byte discriminator followed by Borsh-encoded
 * arguments, in declaration order -- `order_id: String`, then the three fields
 * of `QuoteCommitment`.
 *
 * Borsh encodes a String as a u32 little-endian byte length followed by its
 * UTF-8 bytes. Length is counted in *bytes*, not characters, which is the same
 * thing the program's `order_id.as_bytes().len()` check counts.
 */
export function encodeCreateOrderData(orderId: string, quote: QuoteCommitment): Uint8Array {
  const idBytes = utf8.encode(orderId);
  if (idBytes.length === 0) {
    throw new Error("order id must not be empty");
  }
  if (idBytes.length > MAX_ORDER_ID_LEN) {
    throw new Error(`order id is ${idBytes.length} bytes, max ${MAX_ORDER_ID_LEN}`);
  }
  if (quote.amount <= 0n) {
    throw new Error("quote amount must be positive");
  }
  // The fee is taken out of the escrowed amount, so a fee equal to the amount
  // would leave the seller with nothing; the program requires strictly less.
  if (quote.feeAmount >= quote.amount) {
    throw new Error("quote fee must be strictly less than the amount");
  }
  return concatBytes(
    anchorDiscriminator("global:create_order"),
    u32le(idBytes.length),
    idBytes,
    u64le(quote.amount),
    u64le(quote.feeAmount),
    i64le(quote.expiry),
  );
}

export type CreateOrderAccounts = {
  programId: PublicKey;
  orderId: string;
  buyer: PublicKey;
  /** `merchant.authority` -- the seller the order is with. */
  seller: PublicKey;
  /** `merchant.payout_wallet`, snapshotted into the order at creation. */
  payoutWallet: PublicKey;
  /** `config.treasury`. */
  treasury: PublicKey;
  mint: PublicKey;
  /** The buyer's source token account. Need not be their ATA, but usually is. */
  buyerTokenAccount: PublicKey;
};

/**
 * Account metas for `create_order`, in the exact order of the `CreateOrder`
 * accounts struct.
 *
 * Anchor matches accounts positionally, so this ordering is load-bearing: a
 * transposition does not error, it hands the program the wrong account in a
 * slot whose constraints may happen to pass. The writable/signer flags mirror
 * the `#[account(...)]` attributes -- `order` and `escrow_token_account` are
 * `init`, the buyer pays for both and signs the token transfer, and everything
 * else is read-only.
 *
 * `seller_token_account` and `treasury_token_account` are NOT `init_if_needed`:
 * both must already exist or the whole order fails. That is a deliberate
 * guarantee -- funds can never enter escrow for a seller who has nowhere to be
 * paid -- and it is why `client.ts` checks for them before asking the buyer to
 * sign anything.
 */
export function createOrderAccountMetas(accounts: CreateOrderAccounts) {
  const {
    programId,
    orderId,
    buyer,
    seller,
    payoutWallet,
    treasury,
    mint,
    buyerTokenAccount,
  } = accounts;

  const order = deriveOrder(programId, orderId);

  return [
    { pubkey: deriveConfig(programId), isSigner: false, isWritable: false },
    { pubkey: deriveSupportedMint(programId, mint), isSigner: false, isWritable: false },
    { pubkey: deriveMerchant(programId, seller), isSigner: false, isWritable: false },
    { pubkey: order, isSigner: false, isWritable: true },
    { pubkey: buyer, isSigner: true, isWritable: true },
    { pubkey: mint, isSigner: false, isWritable: false },
    { pubkey: buyerTokenAccount, isSigner: false, isWritable: true },
    { pubkey: deriveEscrowVault(order, mint), isSigner: false, isWritable: true },
    { pubkey: deriveWalletAta(payoutWallet, mint), isSigner: false, isWritable: false },
    { pubkey: payoutWallet, isSigner: false, isWritable: false },
    { pubkey: deriveWalletAta(treasury, mint), isSigner: false, isWritable: false },
    { pubkey: treasury, isSigner: false, isWritable: false },
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
}

/** The assembled `create_order` instruction. */
export function buildCreateOrderInstruction(
  accounts: CreateOrderAccounts,
  quote: QuoteCommitment,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: accounts.programId,
    keys: createOrderAccountMetas(accounts),
    data: Buffer.from(encodeCreateOrderData(accounts.orderId, quote)),
  });
}
