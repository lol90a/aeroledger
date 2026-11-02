/**
 * Decoders for the escrow program's accounts.
 *
 * The browser reads these for one reason only: to tell a buyer *why* a payment
 * cannot proceed before they are asked to sign. Nothing decoded here is trusted
 * for anything -- the program re-checks every one of these conditions, and the
 * backend verifies the resulting order against the chain independently. A
 * tampered RPC response can make the checkout refuse a payment it should have
 * accepted; it cannot make it accept one it should have refused.
 *
 * Each decoder checks the Anchor discriminator first. Several of these accounts
 * are close in size, and an owner check alone would happily decode a `Merchant`
 * as a `Config` and read a payout wallet out of the middle of a treasury key.
 */

import { PublicKey } from "@solana/web3.js";

import { anchorDiscriminator } from "./program";

class Reader {
  private at = 0;

  constructor(private readonly data: Uint8Array) {}

  private take(n: number): Uint8Array {
    const end = this.at + n;
    if (end > this.data.length) {
      throw new Error(
        `account data truncated: wanted ${n} bytes at offset ${this.at}, have ${this.data.length}`,
      );
    }
    const slice = this.data.subarray(this.at, end);
    this.at = end;
    return slice;
  }

  u8(): number {
    const [byte] = this.take(1);
    // `take` guarantees the byte exists; this keeps noUncheckedIndexedAccess happy
    // without a non-null assertion.
    return byte ?? 0;
  }

  bool(): boolean {
    return this.u8() !== 0;
  }

  pubkey(): PublicKey {
    return new PublicKey(this.take(32));
  }

  i64(): bigint {
    const bytes = this.take(8);
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigInt64(0, true);
  }

  u64(): bigint {
    const bytes = this.take(8);
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
  }

  /** Borsh `Option<T>`: a one-byte tag, then the value only when the tag is 1. */
  option<T>(read: () => T): T | null {
    const tag = this.u8();
    if (tag === 0) return null;
    if (tag !== 1) throw new Error(`invalid Option tag ${tag}`);
    return read();
  }
}

function openAccount(data: Uint8Array, accountName: string): Reader {
  if (data.length < 8) {
    throw new Error(`${accountName}: account is too small to hold a discriminator`);
  }
  const expected = anchorDiscriminator(`account:${accountName}`);
  for (let i = 0; i < 8; i += 1) {
    if (data[i] !== expected[i]) {
      throw new Error(`account is not a ${accountName} (discriminator mismatch)`);
    }
  }
  return new Reader(data.subarray(8));
}

export type EscrowConfig = {
  admin: PublicKey;
  pendingAdmin: PublicKey | null;
  quoteAuthority: PublicKey;
  treasury: PublicKey;
  refundWindowSecs: bigint;
  disputeWindowSecs: bigint;
  paused: boolean;
};

/**
 * Decode the singleton `Config`.
 *
 * `pending_admin` is a Borsh `Option<Pubkey>`, so it occupies one byte when
 * empty and thirty-three when set. Every field after it therefore moves. Reading
 * `quote_authority` from a fixed offset works right up until someone nominates a
 * new admin, at which point the checkout starts comparing the backend's signing
 * key against thirty-two bytes of a treasury address.
 */
export function decodeConfig(data: Uint8Array): EscrowConfig {
  const r = openAccount(data, "Config");
  return {
    admin: r.pubkey(),
    pendingAdmin: r.option(() => r.pubkey()),
    quoteAuthority: r.pubkey(),
    treasury: r.pubkey(),
    refundWindowSecs: r.i64(),
    disputeWindowSecs: r.i64(),
    paused: r.bool(),
  };
}

export type EscrowMerchant = {
  authority: PublicKey;
  payoutWallet: PublicKey;
  active: boolean;
};

export function decodeMerchant(data: Uint8Array): EscrowMerchant {
  const r = openAccount(data, "Merchant");
  return {
    authority: r.pubkey(),
    payoutWallet: r.pubkey(),
    active: r.bool(),
  };
}

export type EscrowSupportedMint = {
  mint: PublicKey;
  decimals: number;
};

export function decodeSupportedMint(data: Uint8Array): EscrowSupportedMint {
  const r = openAccount(data, "SupportedMint");
  return {
    mint: r.pubkey(),
    decimals: r.u8(),
  };
}

export const ORDER_STATUS = ["pending", "confirmed", "completed", "refunded"] as const;
export type OrderStatus = (typeof ORDER_STATUS)[number];

export type EscrowOrderAccount = {
  buyer: PublicKey;
  seller: PublicKey;
  mint: PublicKey;
  payoutWallet: PublicKey;
  treasury: PublicKey;
  amount: bigint;
  feeAmount: bigint;
  status: OrderStatus;
  createdAt: bigint;
  settlementDeadline: bigint;
  timeoutDeadline: bigint;
  quoteExpiry: bigint;
};

/**
 * Decode an `Order` far enough to show the buyer its state.
 *
 * Stops before `order_id` and `bump`: the browser has no use for either, and the
 * backend -- which does, because it has to prove the on-chain order belongs to a
 * particular booking -- decodes them from the chain itself rather than taking
 * the client's word for it.
 */
export function decodeOrder(data: Uint8Array): EscrowOrderAccount {
  const r = openAccount(data, "Order");
  const buyer = r.pubkey();
  const seller = r.pubkey();
  const mint = r.pubkey();
  const payoutWallet = r.pubkey();
  const treasury = r.pubkey();
  const amount = r.u64();
  const feeAmount = r.u64();
  const statusByte = r.u8();
  const status = ORDER_STATUS[statusByte];
  if (status === undefined) {
    throw new Error(`unknown order status discriminant ${statusByte}`);
  }
  return {
    buyer,
    seller,
    mint,
    payoutWallet,
    treasury,
    amount,
    feeAmount,
    status,
    createdAt: r.i64(),
    settlementDeadline: r.i64(),
    timeoutDeadline: r.i64(),
    quoteExpiry: r.i64(),
  };
}
