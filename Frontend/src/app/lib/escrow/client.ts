/**
 * Driving an escrow deposit from the browser.
 *
 * ## The shape of the flow
 *
 * 1. The backend prices the booking, reserves that price, and issues an
 *    *authorization*: the figures plus an Ed25519 signature over them from its
 *    `quote_authority` key. The private half of that key never leaves the server.
 * 2. This module assembles one transaction that wraps the SOL, carries the
 *    signature in a native Ed25519 instruction, and calls `create_order`.
 * 3. The buyer's wallet signs it. Only the buyer can: the program takes the
 *    tokens from an account they own, with them as the transfer authority.
 * 4. The backend reads the resulting order back **off the chain** and decides
 *    whether the booking is paid. It never takes that from this code.
 *
 * Step 4 is why nothing here is a security control. The browser is the buyer's
 * machine; every check in this file is a diagnostic, run so that a payment that
 * cannot succeed fails with a sentence a human can act on instead of a hex error
 * from the validator. The program enforces the real rules, and the backend
 * decides what was actually paid.
 *
 * ## Why one transaction
 *
 * Wrapping SOL and creating the order could be two transactions. They are not,
 * because the intermediate state -- lamports sitting in a wrapped-SOL account
 * with no order against them -- is one an ordinary customer has no way to
 * recover from. Atomicity means a failure anywhere leaves the buyer exactly
 * where they started, minus a signature fee.
 */

import {
  Connection,
  PublicKey,
  Transaction,
  type TransactionInstruction,
} from "@solana/web3.js";

import {
  buildCreateOrderInstruction,
  buildQuoteAttestationInstruction,
  deriveConfig,
  deriveEscrowVault,
  deriveMerchant,
  deriveOrder,
  deriveSupportedMint,
  deriveWalletAta,
  MAX_TRANSACTION_BYTES,
  quoteMessage,
  WRAPPED_SOL_MINT,
  type QuoteCommitment,
} from "./program";
import { decodeConfig, decodeMerchant, decodeOrder } from "./accounts";
import {
  escrowDepositBudget,
  ORDER_ACCOUNT_BYTES,
  planWsolFunding,
  TOKEN_ACCOUNT_BYTES,
  type WsolFundingPlan,
} from "./wsol";

/* ------------------------------------------------------------------ */
/* The backend's authorization                                        */
/* ------------------------------------------------------------------ */

/**
 * Everything the backend returns from `POST /payments/escrow/authorize`.
 *
 * Addresses and amounts are strings: a Solana address is base58 and a token
 * amount can exceed what a JSON number represents exactly. Parsing them here,
 * once, means the rest of the module works in `PublicKey` and `bigint` and
 * cannot accidentally compare a string to an address object.
 */
export type EscrowAuthorization = {
  programId: string;
  rpcUrl: string;
  /** Opaque id the backend will later use to match this order to a booking. */
  orderId: string;
  /** The wallet this authorization was issued for. */
  buyer: string;
  seller: string;
  payoutWallet: string;
  treasury: string;
  mint: string;
  quoteAuthority: string;
  /** Base-unit amounts as decimal strings. */
  amount: string;
  feeAmount: string;
  /** Unix seconds. */
  expiry: number;
  /** Base64-encoded 64-byte Ed25519 signature. */
  signature: string;
};

type ParsedAuthorization = {
  programId: PublicKey;
  orderId: string;
  buyer: PublicKey;
  seller: PublicKey;
  payoutWallet: PublicKey;
  treasury: PublicKey;
  mint: PublicKey;
  quoteAuthority: PublicKey;
  quote: QuoteCommitment;
  signature: Uint8Array;
};

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function parseAuthorization(auth: EscrowAuthorization): ParsedAuthorization {
  return {
    programId: new PublicKey(auth.programId),
    orderId: auth.orderId,
    buyer: new PublicKey(auth.buyer),
    seller: new PublicKey(auth.seller),
    payoutWallet: new PublicKey(auth.payoutWallet),
    treasury: new PublicKey(auth.treasury),
    mint: new PublicKey(auth.mint),
    quoteAuthority: new PublicKey(auth.quoteAuthority),
    quote: {
      amount: BigInt(auth.amount),
      feeAmount: BigInt(auth.feeAmount),
      expiry: BigInt(auth.expiry),
    },
    signature: decodeBase64(auth.signature),
  };
}

/* ------------------------------------------------------------------ */
/* Pre-flight                                                         */
/* ------------------------------------------------------------------ */

/**
 * Why a deposit cannot be built. Each value maps to one sentence the checkout
 * can show, and to one specific thing that is wrong -- "something went wrong" is
 * not a diagnosis a customer or an engineer can act on.
 */
export type EscrowBlockReason =
  | "wallet-mismatch"
  | "authorization-expired"
  | "program-not-deployed"
  | "escrow-not-configured"
  | "quote-authority-mismatch"
  | "escrow-paused"
  | "treasury-mismatch"
  | "seller-not-registered"
  | "seller-inactive"
  | "payout-wallet-mismatch"
  | "mint-not-supported"
  | "order-already-exists"
  | "seller-payout-account-missing"
  | "treasury-account-missing"
  | "insufficient-sol"
  | "transaction-too-large";

export type EscrowPreflight =
  | {
      state: "blocked";
      reason: EscrowBlockReason;
      /** A sentence suitable for showing to the buyer. */
      message: string;
      /** Set when `insufficient-sol`: how many more lamports are needed. */
      shortfallLamports?: bigint;
    }
  | {
      state: "ready";
      /** The order PDA the backend will verify against. */
      orderAccount: PublicKey;
      /** The vault the tokens land in. */
      escrowVault: PublicKey;
      /** Unsigned, blockhash-bearing, ready for the wallet. */
      transaction: Transaction;
      /**
       * The height past which this transaction can never land. Carried with it
       * so confirmation waits on *this* transaction's lifetime rather than on a
       * fresh blockhash's, which would keep polling a transaction that has
       * already expired.
       */
      lastValidBlockHeight: number;
      /** Serialized size, for the headroom this flow does not have much of. */
      transactionBytes: number;
      /** Lamports leaving the buyer's native balance, excluding fees. */
      nativeLamportsNeeded: bigint;
      /**
       * The part of that which is rent for accounts `create_order` opens and
       * the buyer does not get back. Surfaced because it is a real cost on top
       * of the quoted price and a customer comparing the two should be able to
       * see it.
       */
      rentLamports: bigint;
      wsol: WsolFundingPlan;
    };

/**
 * Lamports held back for the signature fee.
 *
 * One signature is 5,000 lamports. The margin is deliberately generous: a buyer
 * left with a balance too thin to sign anything at all is a worse outcome than
 * being told to top up slightly earlier than strictly necessary. Rent for the
 * wrapped-SOL account is counted separately and exactly, from the RPC.
 */
const FEE_HEADROOM_LAMPORTS = 100_000n;

/**
 * How close to expiry an authorization is refused.
 *
 * The program compares the quote's expiry against the slot clock at execution,
 * not at signature. A quote with four seconds left will usually expire while the
 * buyer is reading their wallet prompt, and the resulting failure looks to them
 * like the payment was rejected. Better to re-quote before asking.
 */
const EXPIRY_MARGIN_SECONDS = 20n;

/** SPL token account: `amount` is a little-endian u64 at offset 64. */
function readTokenAmount(data: Uint8Array): bigint {
  if (data.length < 72) {
    throw new Error("not an SPL token account: too short");
  }
  return new DataView(data.buffer, data.byteOffset + 64, 8).getBigUint64(0, true);
}

function blocked(
  reason: EscrowBlockReason,
  message: string,
  shortfallLamports?: bigint,
): EscrowPreflight {
  return shortfallLamports === undefined
    ? { state: "blocked", reason, message }
    : { state: "blocked", reason, message, shortfallLamports };
}

export type PrepareParams = {
  connection: Connection;
  auth: EscrowAuthorization;
  /** The wallet currently connected, as the checkout sees it. */
  buyer: PublicKey;
  /** Injectable for tests. Unix seconds. */
  now?: () => bigint;
};

/**
 * Check everything that can be checked, then build the transaction.
 *
 * The checks run roughly in order of how early they can be known and how
 * cheaply, but the ordering is really about diagnosis: "the seller is not
 * registered on this cluster" and "you need 0.1 more SOL" are different
 * problems, and a buyer who sees the second when the first is true will top up
 * their wallet for nothing.
 *
 * All the account reads go out in a single `getMultipleAccountsInfo` call.
 * Eight sequential round trips to a public RPC is a visible pause in a checkout,
 * and the reads have no dependencies on each other.
 */
export async function prepareEscrowDeposit(
  params: PrepareParams,
): Promise<EscrowPreflight> {
  const { connection, buyer } = params;
  const now = params.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
  const auth = parseAuthorization(params.auth);

  // The signed message commits to the buyer's key. A wallet switched between
  // quoting and paying produces a signature the program will reject, so say so
  // plainly rather than letting it fail on-chain.
  if (!auth.buyer.equals(buyer)) {
    return blocked(
      "wallet-mismatch",
      "This payment was authorized for a different wallet. Reconnect the wallet you started checkout with, or request a new quote.",
    );
  }

  if (auth.quote.expiry <= now() + EXPIRY_MARGIN_SECONDS) {
    return blocked(
      "authorization-expired",
      "This price authorization has expired. Request a new quote to continue.",
    );
  }

  const config = deriveConfig(auth.programId);
  const supportedMint = deriveSupportedMint(auth.programId, auth.mint);
  const merchant = deriveMerchant(auth.programId, auth.seller);
  const order = deriveOrder(auth.programId, auth.orderId);
  const sellerAta = deriveWalletAta(auth.payoutWallet, auth.mint);
  const treasuryAta = deriveWalletAta(auth.treasury, auth.mint);
  const buyerAta = deriveWalletAta(buyer, auth.mint);

  const [
    programAccount,
    configAccount,
    supportedMintAccount,
    merchantAccount,
    orderAccount,
    sellerAtaAccount,
    treasuryAtaAccount,
    buyerAtaAccount,
  ] = await connection.getMultipleAccountsInfo([
    auth.programId,
    config,
    supportedMint,
    merchant,
    order,
    sellerAta,
    treasuryAta,
    buyerAta,
  ]);

  // No program at that address on this RPC almost always means the endpoint and
  // the deployment are on different clusters -- the classic "balances read on
  // devnet, verification on mainnet" split. The backend owns the endpoint for
  // exactly this reason, so hitting this is a deployment fault, not a user one.
  if (!programAccount || !programAccount.executable) {
    return blocked(
      "program-not-deployed",
      "The escrow program is not deployed on the network this checkout is pointed at. This is a configuration problem on our side.",
    );
  }

  if (!configAccount) {
    return blocked(
      "escrow-not-configured",
      "The escrow program has not been initialised on this network.",
    );
  }
  const cfg = decodeConfig(configAccount.data);

  // The program will only accept a signature from the key recorded here. If the
  // backend has been rotated and the chain has not (or the reverse), every
  // payment fails at the Ed25519 check with nothing to explain it.
  if (!cfg.quoteAuthority.equals(auth.quoteAuthority)) {
    return blocked(
      "quote-authority-mismatch",
      "The escrow program does not recognise the key that signed this price. This is a configuration problem on our side.",
    );
  }

  if (cfg.paused) {
    return blocked(
      "escrow-paused",
      "Escrow payments are temporarily paused. Existing orders are unaffected.",
    );
  }

  // The treasury is read from the config by the program; an authorization naming
  // a different one would fail the account constraint at execution.
  if (!cfg.treasury.equals(auth.treasury)) {
    return blocked(
      "treasury-mismatch",
      "The fee destination in this authorization does not match the one on-chain. This is a configuration problem on our side.",
    );
  }

  if (!merchantAccount) {
    return blocked(
      "seller-not-registered",
      "This seller is not registered with the escrow program yet.",
    );
  }
  const merchantRecord = decodeMerchant(merchantAccount.data);
  if (!merchantRecord.active) {
    return blocked("seller-inactive", "This seller is not currently accepting escrow payments.");
  }
  // The payout destination is snapshotted into the order from this record, so a
  // disagreement means the authorization would create an order paying someone
  // other than whom the backend believes it is paying.
  if (!merchantRecord.payoutWallet.equals(auth.payoutWallet)) {
    return blocked(
      "payout-wallet-mismatch",
      "The seller's payout wallet has changed since this quote was issued. Request a new quote.",
    );
  }

  if (!supportedMintAccount) {
    return blocked(
      "mint-not-supported",
      "This token is not on the escrow program's accepted list.",
    );
  }

  // `order` is an `init` account: a second `create_order` for the same id fails.
  // That is the program's replay protection working, and it is worth reporting
  // as "already paid" rather than as an error.
  if (orderAccount) {
    const existing = decodeOrder(orderAccount.data);
    return blocked(
      "order-already-exists",
      `This booking already has an escrow order on-chain (status: ${existing.status}). Refresh to see its current state.`,
    );
  }

  // Neither destination is `init_if_needed`, deliberately: funds must never
  // enter escrow for a seller with nowhere to be paid. That makes their absence
  // a hard precondition rather than something the transaction can fix.
  if (!sellerAtaAccount) {
    return blocked(
      "seller-payout-account-missing",
      "The seller has no token account for this currency yet, so the order cannot be created. This is a configuration problem on our side.",
    );
  }
  if (!treasuryAtaAccount) {
    return blocked(
      "treasury-account-missing",
      "The platform fee account for this currency does not exist yet. This is a configuration problem on our side.",
    );
  }

  const isWrappedSol = auth.mint.equals(WRAPPED_SOL_MINT);
  const existingBuyerToken = buyerAtaAccount
    ? { amount: readTokenAmount(buyerAtaAccount.data) }
    : null;

  // Both rent figures come from the RPC rather than from a constant: the
  // rent parameters are cluster state, and a hardcoded 2_039_280 is right until
  // the day it is not.
  const [tokenAccountRentLamports, orderAccountRentLamports, nativeBalance] =
    await Promise.all([
      connection
        .getMinimumBalanceForRentExemption(TOKEN_ACCOUNT_BYTES)
        .then((n) => BigInt(n)),
      connection
        .getMinimumBalanceForRentExemption(ORDER_ACCOUNT_BYTES)
        .then((n) => BigInt(n)),
      connection.getBalance(buyer).then((n) => BigInt(n)),
    ]);

  // Only a wrapped-SOL route needs wrapping. A USDC route would reach this with
  // a token balance that is already in the right form, and the plan collapses to
  // "do nothing" -- but it would also need a different sufficiency check, which
  // is why the escrow checkout is wrapped-SOL only for now and says so.
  if (!isWrappedSol) {
    throw new Error(
      `escrow checkout currently supports wrapped SOL only, got mint ${auth.mint.toBase58()}`,
    );
  }

  const wsol = planWsolFunding({
    buyer,
    ata: buyerAta,
    existing: existingBuyerToken,
    required: auth.quote.amount,
    rentExemptLamports: tokenAccountRentLamports,
  });

  // `create_order` opens the order account and the escrow vault, both with
  // `payer = buyer`. Budgeting only the wrapped-SOL top-up leaves the customer
  // several million lamports short, told they can afford it, and failing
  // on-chain after they have signed.
  const budget = escrowDepositBudget({
    topUpLamports: wsol.topUpLamports,
    createsWsolAccount: wsol.createsAccount,
    tokenAccountRentLamports,
    orderAccountRentLamports,
  });

  const needed = budget.lamports + FEE_HEADROOM_LAMPORTS;
  if (nativeBalance < needed) {
    return blocked(
      "insufficient-sol",
      "This wallet does not hold enough SOL to cover the payment and network fees.",
      needed - nativeBalance,
    );
  }

  const message = quoteMessage({
    orderId: auth.orderId,
    buyer,
    seller: auth.seller,
    mint: auth.mint,
    quote: auth.quote,
  });

  const instructions: TransactionInstruction[] = [
    ...wsol.setup,
    // Must sit immediately before `create_order`: the program locates it at
    // `current_index - 1` in the Instructions sysvar. Anything inserted between
    // the two breaks the attestation.
    buildQuoteAttestationInstruction({
      quoteAuthority: auth.quoteAuthority,
      message,
      signature: auth.signature,
    }),
    buildCreateOrderInstruction(
      {
        programId: auth.programId,
        orderId: auth.orderId,
        buyer,
        seller: auth.seller,
        payoutWallet: auth.payoutWallet,
        treasury: auth.treasury,
        mint: auth.mint,
        buyerTokenAccount: buyerAta,
      },
      auth.quote,
    ),
    ...wsol.cleanup,
  ];

  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");
  const transaction = new Transaction({
    feePayer: buyer,
    recentBlockhash: blockhash,
  }).add(...instructions);

  // Sixteen accounts and a 289-byte attestation leave roughly 150 bytes of
  // headroom in a legacy transaction. Measuring beats arithmetic: an extra
  // wrapped-SOL setup instruction or a longer order id eats into it, and the
  // failure at submission says only "transaction too large".
  const transactionBytes = transaction.serialize({
    requireAllSignatures: false,
    verifySignatures: false,
  }).length;

  if (transactionBytes > MAX_TRANSACTION_BYTES) {
    return blocked(
      "transaction-too-large",
      `The payment transaction is ${transactionBytes} bytes, over the ${MAX_TRANSACTION_BYTES}-byte limit. This is a configuration problem on our side.`,
    );
  }

  return {
    state: "ready",
    orderAccount: order,
    escrowVault: deriveEscrowVault(order, auth.mint),
    transaction,
    lastValidBlockHeight,
    transactionBytes,
    nativeLamportsNeeded: budget.lamports,
    rentLamports: budget.rentLamports,
    wsol,
  };
}

/* ------------------------------------------------------------------ */
/* Signing and submission                                             */
/* ------------------------------------------------------------------ */

/**
 * The slice of the injected Solana provider this module uses.
 *
 * Phantom, Solflare and Backpack all implement these. `signTransaction` is
 * preferred over `signAndSendTransaction` because it leaves submission -- and
 * therefore the choice of RPC endpoint and commitment -- with us. The wallet's
 * own endpoint may be on a different cluster from the one the backend verifies
 * against, and that mismatch is the failure this whole flow is arranged to
 * avoid.
 */
export type SigningProvider = {
  signTransaction?(transaction: Transaction): Promise<Transaction>;
  signAndSendTransaction?(
    transaction: Transaction,
  ): Promise<{ signature: string }>;
};

export type SubmitResult = {
  signature: string;
  orderAccount: string;
};

/**
 * Hand the transaction to the wallet, submit the signed bytes, and wait for
 * confirmation.
 *
 * Confirmation is awaited at `confirmed` rather than `finalized`: the buyer
 * should not watch a spinner for thirty seconds. The backend independently
 * verifies the order at `finalized` before anything is treated as paid, so the
 * weaker commitment here only affects how quickly the UI moves on.
 *
 * A transaction signed against a devnet blockhash cannot be replayed on
 * mainnet -- the blockhash does not exist there -- so the cluster this is
 * submitted to is pinned by the blockhash the preflight fetched, not by whatever
 * network the wallet's UI happens to be showing.
 */
export async function signAndSubmitEscrowDeposit(params: {
  connection: Connection;
  provider: SigningProvider;
  transaction: Transaction;
  /** From the preflight, alongside the transaction it belongs to. */
  lastValidBlockHeight: number;
  orderAccount: PublicKey;
}): Promise<SubmitResult> {
  const { connection, provider, transaction, lastValidBlockHeight, orderAccount } =
    params;

  const blockhash = transaction.recentBlockhash;
  if (!blockhash) {
    throw new Error("transaction has no recent blockhash");
  }

  const signature = await submitSigned(connection, provider, transaction);
  await connection.confirmTransaction(
    { signature, blockhash, lastValidBlockHeight },
    "confirmed",
  );
  return { signature, orderAccount: orderAccount.toBase58() };
}

async function submitSigned(
  connection: Connection,
  provider: SigningProvider,
  transaction: Transaction,
): Promise<string> {
  if (typeof provider.signTransaction === "function") {
    const signed = await provider.signTransaction(transaction);
    return connection.sendRawTransaction(signed.serialize(), {
      // Simulate against the commitment the blockhash came from, so a blockhash
      // the simulator has not caught up to does not fail as "not found".
      preflightCommitment: "confirmed",
    });
  }

  if (typeof provider.signAndSendTransaction === "function") {
    const { signature } = await provider.signAndSendTransaction(transaction);
    return signature;
  }

  throw new Error("This wallet cannot sign transactions.");
}

/** A connection to the endpoint the backend chose. Never the wallet's own. */
export function escrowConnection(rpcUrl: string): Connection {
  return new Connection(rpcUrl, "confirmed");
}
