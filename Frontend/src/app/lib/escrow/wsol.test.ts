// @vitest-environment node
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { describe, expect, it } from "vitest";

import { WRAPPED_SOL_MINT } from "./program";
import { escrowDepositBudget, ORDER_ACCOUNT_BYTES, planWsolFunding } from "./wsol";

const BUYER = Keypair.fromSeed(new Uint8Array(32).fill(1)).publicKey;
const ATA = getAssociatedTokenAddressSync(WRAPPED_SOL_MINT, BUYER);
const RENT = 2_039_280n;

/** Which program each instruction in the plan targets, in order. */
function programs(ixs: { programId: PublicKey }[]): string[] {
  return ixs.map((ix) => {
    const id = ix.programId.toBase58();
    if (id === SystemProgram.programId.toBase58()) return "system";
    if (id === TOKEN_PROGRAM_ID.toBase58()) return "token";
    if (id === ASSOCIATED_TOKEN_PROGRAM_ID.toBase58()) return "ata";
    return id;
  });
}

describe("planWsolFunding — creating the account", () => {
  const plan = planWsolFunding({
    buyer: BUYER,
    ata: ATA,
    existing: null,
    required: 1_000_000_000n,
    rentExemptLamports: RENT,
  });

  it("creates the account, funds it, then syncs the native balance", () => {
    // Order matters: lamports sent to a native token account do not become a
    // token balance until syncNative runs, so the escrow transfer that follows
    // would fail against an account that visibly holds the money.
    expect(programs(plan.setup)).toEqual(["ata", "system", "token"]);
  });

  it("moves exactly the required amount", () => {
    expect(plan.topUpLamports).toBe(1_000_000_000n);
  });

  it("budgets rent on top of the payment, because the account is new", () => {
    expect(plan.nativeLamportsNeeded).toBe(1_000_000_000n + RENT);
  });

  it("closes the account afterwards to return the rent", () => {
    expect(plan.createsAccount).toBe(true);
    expect(programs(plan.cleanup)).toEqual(["token"]);
  });
});

/**
 * The rule this module exists for. Closing a *native* token account does not
 * just reclaim rent — the token program forwards the whole lamport balance to
 * the destination, unwrapping whatever was in it. Doing that to an account the
 * buyer created themselves is a silent, unasked-for change to their wallet.
 */
describe("planWsolFunding — an account the buyer already had", () => {
  it("never closes it, even when the order empties it", () => {
    const plan = planWsolFunding({
      buyer: BUYER,
      ata: ATA,
      existing: { amount: 0n },
      required: 1_000_000_000n,
      rentExemptLamports: RENT,
    });
    expect(plan.createsAccount).toBe(false);
    expect(plan.cleanup).toEqual([]);
  });

  it("never closes it when it holds a balance", () => {
    const plan = planWsolFunding({
      buyer: BUYER,
      ata: ATA,
      existing: { amount: 5_000_000_000n },
      required: 1_000_000_000n,
      rentExemptLamports: RENT,
    });
    expect(plan.cleanup).toEqual([]);
  });

  it("tops up only the shortfall", () => {
    const plan = planWsolFunding({
      buyer: BUYER,
      ata: ATA,
      existing: { amount: 400_000_000n },
      required: 1_000_000_000n,
      rentExemptLamports: RENT,
    });
    expect(plan.topUpLamports).toBe(600_000_000n);
    expect(plan.nativeLamportsNeeded).toBe(600_000_000n);
    expect(programs(plan.setup)).toEqual(["system", "token"]);
  });

  it("does not charge rent again for an account that already exists", () => {
    const plan = planWsolFunding({
      buyer: BUYER,
      ata: ATA,
      existing: { amount: 0n },
      required: 1_000_000_000n,
      rentExemptLamports: RENT,
    });
    expect(plan.nativeLamportsNeeded).toBe(1_000_000_000n);
  });

  it("moves nothing when the balance already covers the order", () => {
    // The surplus stays exactly where the buyer left it: no transfer, no sync,
    // and above all no close.
    const plan = planWsolFunding({
      buyer: BUYER,
      ata: ATA,
      existing: { amount: 2_000_000_000n },
      required: 1_000_000_000n,
      rentExemptLamports: RENT,
    });
    expect(plan.topUpLamports).toBe(0n);
    expect(plan.nativeLamportsNeeded).toBe(0n);
    expect(plan.setup).toEqual([]);
    expect(plan.cleanup).toEqual([]);
  });

  it("moves nothing when the balance is exactly the order amount", () => {
    const plan = planWsolFunding({
      buyer: BUYER,
      ata: ATA,
      existing: { amount: 1_000_000_000n },
      required: 1_000_000_000n,
      rentExemptLamports: RENT,
    });
    expect(plan.setup).toEqual([]);
  });
});

describe("planWsolFunding — guards", () => {
  it("refuses a non-positive amount", () => {
    expect(() =>
      planWsolFunding({
        buyer: BUYER,
        ata: ATA,
        existing: null,
        required: 0n,
        rentExemptLamports: RENT,
      }),
    ).toThrow(/must be positive/);
  });
});

/**
 * Getting this wrong is worse than not checking at all: the customer is told
 * they can afford the payment, approves it in their wallet, and the transaction
 * fails on-chain for insufficient lamports. They have then paid a signature fee
 * to be told what the pre-flight was supposed to tell them for free.
 */
describe("escrowDepositBudget", () => {
  const TOKEN_RENT = 2_039_280n;
  const ORDER_RENT = 3_033_600n;

  it("counts the rent for both accounts create_order opens", () => {
    // Neither comes back to the buyer at settlement. Counting only the
    // wrapped-SOL top-up leaves them about 5 million lamports short.
    const budget = escrowDepositBudget({
      topUpLamports: 1_000_000_000n,
      createsWsolAccount: false,
      tokenAccountRentLamports: TOKEN_RENT,
      orderAccountRentLamports: ORDER_RENT,
    });
    expect(budget.rentLamports).toBe(TOKEN_RENT + ORDER_RENT);
    expect(budget.lamports).toBe(1_000_000_000n + TOKEN_RENT + ORDER_RENT);
  });

  it("also holds rent for a wrapped-SOL account it creates and closes", () => {
    // Spent and returned inside the same transaction, so it nets to nothing —
    // but the buyer must hold it while the transaction runs, and a balance
    // check that ignores it passes someone who cannot pay.
    const budget = escrowDepositBudget({
      topUpLamports: 1_000_000_000n,
      createsWsolAccount: true,
      tokenAccountRentLamports: TOKEN_RENT,
      orderAccountRentLamports: ORDER_RENT,
    });
    expect(budget.lamports).toBe(1_000_000_000n + TOKEN_RENT + ORDER_RENT + TOKEN_RENT);
    // It is transient, so it is not reported as a cost the buyer bears.
    expect(budget.rentLamports).toBe(TOKEN_RENT + ORDER_RENT);
  });

  it("still charges rent when the buyer already holds enough wrapped SOL", () => {
    // No top-up needed, but the order account and the vault are still created.
    const budget = escrowDepositBudget({
      topUpLamports: 0n,
      createsWsolAccount: false,
      tokenAccountRentLamports: TOKEN_RENT,
      orderAccountRentLamports: ORDER_RENT,
    });
    expect(budget.lamports).toBe(TOKEN_RENT + ORDER_RENT);
  });
});

describe("ORDER_ACCOUNT_BYTES", () => {
  it("matches the program's own size calculation", () => {
    // 8-byte discriminator + Order::INIT_SPACE. The program asserts the same
    // expression in `account_sizes_match_their_field_layout`, so a field added
    // on that side fails there and the rent budget here stops being right.
    expect(ORDER_ACCOUNT_BYTES).toBe(8 + (32 * 5 + 8 + 8 + 1 + 32 + 32 + (4 + 64) + 1));
    expect(ORDER_ACCOUNT_BYTES).toBe(318);
  });
});
