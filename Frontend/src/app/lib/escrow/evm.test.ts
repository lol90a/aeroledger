// @vitest-environment node
//
// Nothing here touches the DOM, and jsdom costs the better part of a minute on
// a cold run -- long enough that the worker times out before the tests start.
import { describe, expect, it } from "vitest";

import GOLDEN from "../../../../../contracts/ethereum/test/eip712_golden.json";
import {
  bytesToHex,
  callValue,
  CREATE_ORDER_ERC20_SELECTOR,
  CREATE_ORDER_SELECTOR,
  encodeCreateOrderCall,
  encodeQuoteInput,
  hexToBytes,
  NATIVE_TOKEN,
  type EvmQuoteInput,
} from "./evm";

const FIXTURE = GOLDEN.createOrderCalldata;

function quoteFromFixture(): EvmQuoteInput {
  const i = FIXTURE.input;
  return {
    orderId: i.orderId,
    seller: i.seller,
    token: i.token,
    amount: BigInt(i.amount),
    fee: BigInt(i.fee),
    expiry: BigInt(i.expiry),
    signature: i.signature,
  };
}

/**
 * The decisive tests. The encoder is hand-written to keep a web3 library out of
 * the bundle, which is only defensible if it produces exactly what a real one
 * does. These bytes came from ethers, encoding against the contract's own ABI.
 */
describe("createOrder calldata, against ethers' own encoding", () => {
  it("matches byte for byte on the native path", () => {
    expect(encodeCreateOrderCall(quoteFromFixture(), true)).toBe(FIXTURE.native);
  });

  it("matches byte for byte on the ERC-20 path", () => {
    // Same struct, different entry point: only the selector differs.
    expect(encodeCreateOrderCall(quoteFromFixture(), false)).toBe(FIXTURE.erc20);
  });

  it("uses the selectors the compiled ABI reports", () => {
    expect(FIXTURE.native.slice(0, 10)).toBe(CREATE_ORDER_SELECTOR);
    expect(FIXTURE.erc20.slice(0, 10)).toBe(CREATE_ORDER_ERC20_SELECTOR);
    expect(CREATE_ORDER_SELECTOR).not.toBe(CREATE_ORDER_ERC20_SELECTOR);
  });
});

/**
 * The offsets inside the struct are counted from the start of the struct, not
 * from the start of the calldata. An encoder that counts from the call is off
 * by exactly one slot and decodes into a plausible struct whose fields are all
 * wrong -- so the rule is asserted directly rather than only via the fixture.
 */
describe("QuoteInput layout", () => {
  const body = encodeQuoteInput(quoteFromFixture());
  const slotAt = (index: number) => body.subarray(index * 32, index * 32 + 32);
  const numberAt = (index: number) => Number(BigInt(bytesToHex(slotAt(index))));

  it("opens with seven head slots", () => {
    // offset(orderId), seller, token, amount, fee, expiry, offset(signature).
    expect(numberAt(0)).toBe(7 * 32);
  });

  it("places the signature offset after the padded order id", () => {
    const orderIdBytes = new TextEncoder().encode(FIXTURE.input.orderId).length;
    const padded = Math.ceil(orderIdBytes / 32) * 32;
    expect(numberAt(6)).toBe(7 * 32 + 32 + padded);
  });

  it("writes the order id length and bytes where the offset says", () => {
    const at = numberAt(0);
    const length = Number(BigInt(bytesToHex(body.subarray(at, at + 32))));
    expect(length).toBe(FIXTURE.input.orderId.length);
    expect(new TextDecoder().decode(body.subarray(at + 32, at + 32 + length))).toBe(
      FIXTURE.input.orderId,
    );
  });

  it("writes a 65-byte signature where its offset says", () => {
    const at = numberAt(6);
    expect(Number(BigInt(bytesToHex(body.subarray(at, at + 32))))).toBe(65);
    expect(bytesToHex(body.subarray(at + 32, at + 32 + 65))).toBe(
      FIXTURE.input.signature.toLowerCase(),
    );
  });

  it("left-pads addresses and right-pads dynamic bytes", () => {
    // Opposite rules for the two kinds, and mixing them up produces an address
    // of all zeroes or an order id nobody recognises.
    expect(bytesToHex(slotAt(1).subarray(0, 12))).toBe(`0x${"00".repeat(12)}`);
    expect(bytesToHex(slotAt(1).subarray(12))).toBe(FIXTURE.input.seller.toLowerCase());

    const at = numberAt(6);
    const tail = body.subarray(at + 32 + 65);
    expect([...tail].every((b) => b === 0)).toBe(true);
  });
});

describe("guards", () => {
  it("refuses a fee that is not strictly below the amount", () => {
    const quote = { ...quoteFromFixture(), fee: quoteFromFixture().amount };
    expect(() => encodeQuoteInput(quote)).toThrow(/strictly less/);
  });

  it("refuses a zero amount", () => {
    expect(() => encodeQuoteInput({ ...quoteFromFixture(), amount: 0n })).toThrow(
      /must be positive/,
    );
  });

  it("refuses a signature that is not 65 bytes", () => {
    // 64 bytes is a valid secp256k1 signature without the recovery byte, which
    // the contract's tryRecover cannot use.
    expect(() =>
      encodeQuoteInput({ ...quoteFromFixture(), signature: `0x${"ab".repeat(64)}` }),
    ).toThrow(/65 bytes/);
  });

  it("refuses an address of the wrong length", () => {
    expect(() => encodeQuoteInput({ ...quoteFromFixture(), seller: "0x1234" })).toThrow(
      /20-byte address/,
    );
  });

  it("refuses an empty order id", () => {
    expect(() => encodeQuoteInput({ ...quoteFromFixture(), orderId: "" })).toThrow(
      /must not be empty/,
    );
  });

  it("refuses an amount beyond uint256", () => {
    expect(() =>
      encodeQuoteInput({ ...quoteFromFixture(), amount: 1n << 256n, fee: 0n }),
    ).toThrow(/uint256/);
  });
});

describe("hex helpers", () => {
  it("round-trips", () => {
    expect(bytesToHex(hexToBytes("0xdeadBEEF"))).toBe("0xdeadbeef");
    expect(hexToBytes("0x")).toEqual(new Uint8Array(0));
  });

  it("rejects malformed input rather than guessing", () => {
    expect(() => hexToBytes("0x1")).toThrow(/odd number/);
    expect(() => hexToBytes("0xzz")).toThrow(/invalid hex/);
  });
});

describe("callValue", () => {
  it("sends the amount with a native order and nothing with an ERC-20 one", () => {
    // createOrderERC20 is not payable: sending value to it reverts, and the
    // tokens are pulled with transferFrom instead.
    const quote = quoteFromFixture();
    expect(callValue(quote, true)).toBe(quote.amount);
    expect(callValue(quote, false)).toBe(0n);
  });

  it("treats the zero address as the native coin", () => {
    expect(NATIVE_TOKEN).toBe(`0x${"00".repeat(20)}`);
  });
});
