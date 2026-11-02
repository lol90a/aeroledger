/**
 * Wrapping native SOL for the escrow.
 *
 * The escrow program moves SPL tokens and nothing else -- `Program<'info, Token>`
 * on every instruction, no lamport path at all. So "pay 2 SOL" means "put 2 SOL
 * worth of *wrapped* SOL in a token account the program can pull from". Wrapped
 * SOL is an ordinary SPL mint (`So111...112`) with one special rule: the token
 * program will treat the account's lamport balance as its token balance once
 * `syncNative` is called.
 *
 * Wrapping is therefore three steps -- make a token account, move lamports into
 * it, tell the token program to notice -- and all three have to be in the same
 * transaction as `create_order`, because a half-wrapped balance sitting in a
 * stray account is exactly the state a customer cannot recover from on their own.
 *
 * ## The rule this module exists to enforce
 *
 * **A wrapped-SOL account that already existed is never closed and never
 * drained.** Closing a native token account does not merely reclaim rent: the
 * token program sends the account's *entire* lamport balance to the destination,
 * unwrapping whatever was in it. For an account the buyer created themselves
 * that is a silent, unasked-for change to their wallet. So cleanup is emitted
 * only for an account this transaction creates, which by definition held nothing
 * beforehand.
 */

import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import {
  createAssociatedTokenAccountInstruction,
  createCloseAccountInstruction,
  createSyncNativeInstruction,
} from "@solana/spl-token";

import { WRAPPED_SOL_MINT } from "./program";

/** Size of an SPL token account, for the rent-exemption lookup. */
export const TOKEN_ACCOUNT_BYTES = 165;

/** What an existing wrapped-SOL account holds, as read from the chain. */
export type ExistingWsolAccount = {
  /** Token balance in lamports. */
  amount: bigint;
};

export type WsolFundingPlan = {
  /** Instructions that must run before `create_order`, in this order. */
  setup: TransactionInstruction[];
  /**
   * Instructions that must run after `create_order`. Empty unless this plan
   * created the token account; see the rule at the top of this file.
   */
  cleanup: TransactionInstruction[];
  /**
   * Native lamports that will leave the buyer's wallet for the wrap itself:
   * the top-up, plus rent if a new account is created. Excludes transaction
   * fees, which the caller budgets separately.
   */
  nativeLamportsNeeded: bigint;
  /** Lamports moved into the token account to reach `required`. */
  topUpLamports: bigint;
  /** True when this plan creates the token account, and may therefore close it. */
  createsAccount: boolean;
};

export type WsolFundingParams = {
  buyer: PublicKey;
  /** The buyer's associated token account for wrapped SOL. */
  ata: PublicKey;
  /**
   * What that account currently holds, or `null` if it does not exist.
   * Read from the chain immediately before building the transaction.
   */
  existing: ExistingWsolAccount | null;
  /** Token base units the escrow will pull. */
  required: bigint;
  /** Lamports to make a token account rent-exempt, from the RPC. */
  rentExemptLamports: bigint;
};

/**
 * Work out the minimum set of instructions that leaves `required` wrapped SOL in
 * the buyer's token account.
 *
 * Pure: the caller supplies the account state it read and the rent figure it
 * looked up, and gets instructions back. That keeps every branch here -- and in
 * particular the close/do-not-close decision -- testable without a validator.
 *
 * ### Why the create instruction is not the idempotent variant
 *
 * `existing` is a snapshot. Between reading it and the transaction landing, the
 * buyer could create the account in another tab. The idempotent instruction
 * would absorb that and carry on -- and then the cleanup close, emitted because
 * *we* believed we were the creator, would unwrap an account that by then held
 * the buyer's own balance. The plain instruction fails instead, the entire
 * transaction reverts, nothing is created or moved, and the caller rebuilds from
 * a fresh read. A failed transaction costs a signature fee; silently unwrapping
 * someone's position costs their trust.
 */
export function planWsolFunding(params: WsolFundingParams): WsolFundingPlan {
  const { buyer, ata, existing, required, rentExemptLamports } = params;

  if (required <= 0n) {
    throw new Error("required amount must be positive");
  }

  const setup: TransactionInstruction[] = [];
  const cleanup: TransactionInstruction[] = [];
  const createsAccount = existing === null;

  if (createsAccount) {
    setup.push(
      createAssociatedTokenAccountInstruction(buyer, ata, buyer, WRAPPED_SOL_MINT),
    );
  }

  const held = existing?.amount ?? 0n;
  // Already holding more than the order needs: nothing to move, and the surplus
  // stays exactly where the buyer left it.
  const topUpLamports = held >= required ? 0n : required - held;

  if (topUpLamports > 0n) {
    setup.push(
      SystemProgram.transfer({
        fromPubkey: buyer,
        toPubkey: ata,
        lamports: topUpLamports,
      }),
    );
    // Lamports landing in a native token account do not change its token balance
    // until the token program is told to look. Without this the escrow transfer
    // fails with "insufficient funds" against an account that visibly holds the
    // money -- which is the single most confusing failure in this whole flow.
    setup.push(createSyncNativeInstruction(ata));
  }

  if (createsAccount) {
    // Safe only because this transaction created the account: it held nothing
    // before, and `create_order` has taken everything we put in. Closing returns
    // the rent to the buyer rather than stranding it in a now-useless account.
    cleanup.push(createCloseAccountInstruction(ata, buyer, buyer));
  }

  const nativeLamportsNeeded = topUpLamports + (createsAccount ? rentExemptLamports : 0n);

  return { setup, cleanup, nativeLamportsNeeded, topUpLamports, createsAccount };
}

/**
 * Bytes the order account occupies: Anchor's 8-byte discriminator plus
 * `Order::INIT_SPACE`.
 *
 * `32 * 5` for buyer, seller, mint, payout wallet and treasury; `8 + 8` for the
 * amount and fee; `1` for the status; `32` for four timestamps; `32` for the
 * order-id hash; `4 + 64` for the length-prefixed order id at its maximum; `1`
 * for the bump. Anchor reserves the string's maximum rather than its actual
 * length, so this figure does not vary with the order id.
 *
 * Mirrors `account_sizes_match_their_field_layout` in the program, which is
 * where a field added on that side will fail first.
 */
export const ORDER_ACCOUNT_BYTES = 8 + (32 * 5 + 8 + 8 + 1 + 32 + 32 + (4 + 64) + 1);

export type DepositBudget = {
  /** Everything the buyer's native balance must cover, excluding fees. */
  lamports: bigint;
  /** Rent for accounts `create_order` creates and does not give back. */
  rentLamports: bigint;
};

/**
 * What the deposit actually costs the buyer's native balance.
 *
 * Easy to get wrong by leaving something out, and leaving something out defeats
 * the point of a pre-flight: the customer is told they can afford it, signs, and
 * the transaction fails for insufficient lamports anyway.
 *
 * Three things are paid for, not one:
 *
 *   * the tokens themselves, by way of the wrapped-SOL top-up;
 *   * rent for the **order account**, which `create_order` opens with
 *     `payer = buyer`;
 *   * rent for the **escrow vault**, likewise `init, payer = buyer`.
 *
 * Both of those are the buyer's money and neither comes back at settlement --
 * they are reclaimed by whoever closes those accounts later, which is the
 * program, not the buyer. The wrapped-SOL account is different: when this
 * transaction creates it, it also closes it, so its rent is spent and returned
 * within the same transaction and nets to nothing. It still has to be *held*
 * while the transaction runs, so it is counted.
 */
export function escrowDepositBudget(params: {
  /** From the wrapped-SOL plan. */
  topUpLamports: bigint;
  createsWsolAccount: boolean;
  /** Rent-exempt minimum for a 165-byte token account, from the RPC. */
  tokenAccountRentLamports: bigint;
  /** Rent-exempt minimum for the order account, from the RPC. */
  orderAccountRentLamports: bigint;
}): DepositBudget {
  const {
    topUpLamports,
    createsWsolAccount,
    tokenAccountRentLamports,
    orderAccountRentLamports,
  } = params;

  // The vault is a token account of the order PDA, so it costs the same rent as
  // any other token account.
  const rentLamports = orderAccountRentLamports + tokenAccountRentLamports;
  const transient = createsWsolAccount ? tokenAccountRentLamports : 0n;

  return {
    lamports: topUpLamports + rentLamports + transient,
    rentLamports,
  };
}
