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
