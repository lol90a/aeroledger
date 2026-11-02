// @vitest-environment node
import { Keypair } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import { decodeConfig, decodeMerchant, decodeOrder, decodeSupportedMint } from "./accounts";
import { anchorDiscriminator } from "./program";

function key(seed: number) {
  return Keypair.fromSeed(new Uint8Array(32).fill(seed)).publicKey;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function i64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, value, true);
  return out;
}

function u64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

const ADMIN = key(1);
const QUOTE_AUTHORITY = key(2);
const TREASURY = key(3);
const PENDING = key(4);

function configAccount(opts: { pendingAdmin: boolean; paused?: boolean }): Uint8Array {
  return concat(
    anchorDiscriminator("account:Config"),
    ADMIN.toBytes(),
    opts.pendingAdmin
      ? concat(new Uint8Array([1]), PENDING.toBytes())
      : new Uint8Array([0]),
    QUOTE_AUTHORITY.toBytes(),
    TREASURY.toBytes(),
    i64(3600n),
    i64(1800n),
    new Uint8Array([opts.paused ? 1 : 0]),
    new Uint8Array([254]), // bump
  );
}

/**
 * `pending_admin` is a Borsh `Option<Pubkey>`: one byte when empty, thirty-three
 * when set. Every field after it moves. Reading `quote_authority` from a fixed
 * offset works perfectly until someone nominates a new admin, at which point the
 * checkout starts comparing the backend's signing key against the middle of a
 * treasury address — and reports "the program does not recognise our key".
 */
describe("decodeConfig", () => {
  it("reads the fields when there is no pending admin", () => {
    const cfg = decodeConfig(configAccount({ pendingAdmin: false }));
    expect(cfg.admin.toBase58()).toBe(ADMIN.toBase58());
    expect(cfg.pendingAdmin).toBeNull();
    expect(cfg.quoteAuthority.toBase58()).toBe(QUOTE_AUTHORITY.toBase58());
    expect(cfg.treasury.toBase58()).toBe(TREASURY.toBase58());
    expect(cfg.refundWindowSecs).toBe(3600n);
    expect(cfg.disputeWindowSecs).toBe(1800n);
    expect(cfg.paused).toBe(false);
  });

  it("reads the same fields once an admin handover is pending", () => {
    const cfg = decodeConfig(configAccount({ pendingAdmin: true }));
    expect(cfg.pendingAdmin?.toBase58()).toBe(PENDING.toBase58());
    expect(cfg.quoteAuthority.toBase58()).toBe(QUOTE_AUTHORITY.toBase58());
    expect(cfg.treasury.toBase58()).toBe(TREASURY.toBase58());
    expect(cfg.refundWindowSecs).toBe(3600n);
  });

  it("reads the paused flag", () => {
    expect(decodeConfig(configAccount({ pendingAdmin: true, paused: true })).paused).toBe(
      true,
    );
  });

  it("rejects an account of a different type", () => {
    // Several of these accounts are close in size, so an owner check alone would
    // decode a Merchant as a Config and read a payout wallet as a treasury.
    const merchant = concat(
      anchorDiscriminator("account:Merchant"),
      ADMIN.toBytes(),
      TREASURY.toBytes(),
      new Uint8Array([1, 255]),
    );
    expect(() => decodeConfig(merchant)).toThrow(/not a Config/);
  });

  it("rejects truncated data rather than reading past the end", () => {
    const short = configAccount({ pendingAdmin: false }).subarray(0, 60);
    expect(() => decodeConfig(short)).toThrow(/truncated/);
  });

  it("rejects an account too small to hold a discriminator", () => {
    expect(() => decodeConfig(new Uint8Array(4))).toThrow(/too small/);
  });
});

describe("decodeMerchant", () => {
  const data = concat(
    anchorDiscriminator("account:Merchant"),
    key(5).toBytes(),
    key(6).toBytes(),
    new Uint8Array([1]),
    new Uint8Array([253]),
  );

  it("reads authority, payout wallet and active flag", () => {
    const m = decodeMerchant(data);
    expect(m.authority.toBase58()).toBe(key(5).toBase58());
    expect(m.payoutWallet.toBase58()).toBe(key(6).toBase58());
    expect(m.active).toBe(true);
  });

  it("reads an inactive merchant", () => {
    const inactive = concat(data.subarray(0, data.length - 2), new Uint8Array([0, 253]));
    expect(decodeMerchant(inactive).active).toBe(false);
  });
});

describe("decodeSupportedMint", () => {
  it("reads the mint and its decimals", () => {
    const data = concat(
      anchorDiscriminator("account:SupportedMint"),
      key(7).toBytes(),
      new Uint8Array([9]),
      new Uint8Array([252]),
    );
    const m = decodeSupportedMint(data);
    expect(m.mint.toBase58()).toBe(key(7).toBase58());
    expect(m.decimals).toBe(9);
  });
});

describe("decodeOrder", () => {
  function orderAccount(statusByte: number): Uint8Array {
    return concat(
      anchorDiscriminator("account:Order"),
      key(10).toBytes(), // buyer
      key(11).toBytes(), // seller
      key(12).toBytes(), // mint
      key(13).toBytes(), // payout_wallet
      key(14).toBytes(), // treasury
      u64(1_833_740_832n),
      u64(15_000_000n),
      new Uint8Array([statusByte]),
      i64(1_700_000_000n), // created_at
      i64(1_700_003_600n), // settlement_deadline
      i64(1_700_005_400n), // timeout_deadline
      i64(1_700_000_180n), // quote_expiry
    );
  }

  it("reads the recorded amounts and deadlines", () => {
    const order = decodeOrder(orderAccount(0));
    expect(order.buyer.toBase58()).toBe(key(10).toBase58());
    expect(order.amount).toBe(1_833_740_832n);
    expect(order.feeAmount).toBe(15_000_000n);
    expect(order.status).toBe("pending");
    expect(order.settlementDeadline).toBe(1_700_003_600n);
    expect(order.timeoutDeadline).toBe(1_700_005_400n);
  });

  it("maps every status discriminant the program defines", () => {
    // Borsh writes a fieldless enum as one discriminant byte, so this order is
    // the wire format, not a display preference.
    expect(decodeOrder(orderAccount(0)).status).toBe("pending");
    expect(decodeOrder(orderAccount(1)).status).toBe("confirmed");
    expect(decodeOrder(orderAccount(2)).status).toBe("completed");
    expect(decodeOrder(orderAccount(3)).status).toBe("refunded");
  });

  it("refuses a status the program has never written", () => {
    expect(() => decodeOrder(orderAccount(4))).toThrow(/unknown order status/);
  });

  it("rejects an account that is not an Order", () => {
    const notAnOrder = concat(
      anchorDiscriminator("account:Config"),
      new Uint8Array(200),
    );
    expect(() => decodeOrder(notAnOrder)).toThrow(/not a Order/);
  });
});
