/**
 * Building the Solidity escrow's `createOrder` call in the browser.
 *
 * The EVM counterpart of `program.ts`. The job is the same -- turn a
 * backend-signed authorization into the exact bytes a wallet will submit --
 * but almost nothing is shared, because almost nothing about the two chains is.
 * There is no transaction to assemble here, only calldata; the wallet builds
 * the transaction around it.
 *
 * ## Why this is encoded by hand
 *
 * Pulling in ethers or viem for one function call would add a few hundred
 * kilobytes to a bundle that currently has no web3 library on the EVM side at
 * all -- `wallet.ts` talks to EIP-1193 directly, on purpose. The whole encoder
 * is sixty lines and is checked byte for byte against what ethers produces for
 * the same input, so the dependency buys nothing but weight.
 *
 * ## The encoding, which is the fiddly part
 *
 * `createOrder(QuoteInput)` takes one struct, and that struct has two dynamic
 * members. So the calldata is:
 *
 * ```text
 *   selector                       4 bytes
 *   offset to the struct           0x20, because the struct is dynamic
 *   ---- struct begins here, and the offsets below are relative to IT ----
 *   offset to orderId              0xe0 (seven head slots)
 *   seller                         address, left-padded
 *   token                          address, left-padded
 *   amount                         uint256
 *   fee                            uint256
 *   expiry                         uint256
 *   offset to signature            0xe0 + 32 + padded(orderId)
 *   orderId length, bytes, padding
 *   signature length, bytes, padding
 * ```
 *
 * The trap is the word *relative*. Both inner offsets are counted from the
 * start of the struct, not from the start of the calldata, and an encoder that
 * counts from the call is off by exactly 32 bytes -- which decodes into a
 * plausible-looking struct whose fields are all wrong.
 *
 * Getting any of it wrong cannot create money: the contract rebuilds the
 * EIP-712 digest from whatever it decoded and recovers a signer, so wrong bytes
 * recover a different address and revert. What it costs is every payment
 * failing as `InvalidQuoteSignature`, which points at the key rather than at
 * the encoding.
 */

/** `createOrder((string,address,address,uint256,uint256,uint256,bytes))`. */
export const CREATE_ORDER_SELECTOR = "0xefec3b8b";

/**
 * `createOrderERC20(...)`, for a token route.
 *
 * Two entry points because only one of them can be `payable`: a native order
 * carries its value in `msg.value`, an ERC-20 order is pulled with
 * `transferFrom` and would revert if sent value.
 */
export const CREATE_ORDER_ERC20_SELECTOR = "0xfb92542b";

/** The contract's sentinel for the native coin. */
export const NATIVE_TOKEN = "0x0000000000000000000000000000000000000000";

export type EvmQuoteInput = {
  orderId: string;
  seller: string;
  /** The ERC-20 being escrowed, or `NATIVE_TOKEN`. */
  token: string;
  amount: bigint;
  fee: bigint;
  expiry: bigint;
  /** `0x`-prefixed 65-byte signature from the backend. */
  signature: string;
};

function stripHex(value: string): string {
  const trimmed = value.trim();
  return trimmed.startsWith("0x") || trimmed.startsWith("0X")
    ? trimmed.slice(2)
    : trimmed;
}

/** Parse `0x`-prefixed hex into bytes, rejecting anything malformed. */
export function hexToBytes(value: string): Uint8Array {
  const hex = stripHex(value);
  if (hex.length % 2 !== 0) {
    throw new Error("hex string has an odd number of digits");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex at byte ${i}`);
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "0x";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

/** A 32-byte slot holding a left-padded value, as every static ABI type is. */
function slot(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 32) {
    throw new Error("value does not fit in a 32-byte slot");
  }
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

function uint256(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new RangeError("uint256 cannot be negative");
  }
  if (value >= 1n << 256n) {
    throw new RangeError("value exceeds uint256");
  }
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0 && v > 0n; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function addressSlot(address: string): Uint8Array {
  const bytes = hexToBytes(address);
  if (bytes.length !== 20) {
    throw new Error(`not a 20-byte address: ${address}`);
  }
  return slot(bytes);
}

/** Length slot, then the bytes, then right-padding to a 32-byte boundary. */
function dynamicBytes(bytes: Uint8Array): Uint8Array {
  const padding = (32 - (bytes.length % 32)) % 32;
  const out = new Uint8Array(32 + bytes.length + padding);
  out.set(uint256(BigInt(bytes.length)), 0);
  out.set(bytes, 32);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** Seven slots: two offsets and five static values. */
const QUOTE_HEAD_SLOTS = 7;

/**
 * Encode the `QuoteInput` struct body, without the leading offset.
 *
 * Exported so the offsets can be asserted directly in a test, which is where
 * the "relative to the struct" rule is easiest to get wrong and hardest to see.
 */
export function encodeQuoteInput(quote: EvmQuoteInput): Uint8Array {
  if (quote.amount <= 0n) {
    throw new Error("amount must be positive");
  }
  // The contract carves the fee out of the escrowed amount, so a fee equal to
  // it would leave the seller with nothing and revert as InvalidFee.
  if (quote.fee >= quote.amount) {
    throw new Error("fee must be strictly less than the amount");
  }

  const signature = hexToBytes(quote.signature);
  if (signature.length !== 65) {
    throw new Error(`signature must be 65 bytes, got ${signature.length}`);
  }

  const orderId = new TextEncoder().encode(quote.orderId);
  if (orderId.length === 0) {
    throw new Error("order id must not be empty");
  }

  const headBytes = QUOTE_HEAD_SLOTS * 32;
  const orderIdBlock = dynamicBytes(orderId);
  // Both offsets count from the start of THIS struct. Counting from the start
  // of the calldata is off by one slot and decodes into a different struct.
  const orderIdOffset = BigInt(headBytes);
  const signatureOffset = orderIdOffset + BigInt(orderIdBlock.length);

  return concat([
    uint256(orderIdOffset),
    addressSlot(quote.seller),
    addressSlot(quote.token),
    uint256(quote.amount),
    uint256(quote.fee),
    uint256(quote.expiry),
    uint256(signatureOffset),
    orderIdBlock,
    dynamicBytes(signature),
  ]);
}

/**
 * The full calldata for `createOrder` or `createOrderERC20`.
 *
 * `native` picks the entry point, and it comes from the backend rather than
 * being inferred from the token address: the backend knows which asset the
 * deployment escrows, and a client that guesses wrong calls a non-payable
 * function with value attached and reverts.
 */
export function encodeCreateOrderCall(quote: EvmQuoteInput, native: boolean): string {
  const selector = native ? CREATE_ORDER_SELECTOR : CREATE_ORDER_ERC20_SELECTOR;
  // The single argument is a dynamic struct, so the call opens with an offset
  // to it. 0x20, because the offset slot itself is the only thing before it.
  const body = concat([uint256(32n), encodeQuoteInput(quote)]);
  return selector + bytesToHex(body).slice(2);
}

/** `value` for a native order, or zero for an ERC-20 one. */
export function callValue(quote: EvmQuoteInput, native: boolean): bigint {
  return native ? quote.amount : 0n;
}
