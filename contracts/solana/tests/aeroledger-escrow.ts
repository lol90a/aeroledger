/**
 * AeroLedger escrow — Anchor integration tests.
 *
 * These exercise the on-chain program against a local validator, with a strong
 * bias toward *adversarial* cases: every test whose name starts with "rejects"
 * asserts that a specific attack fails with a specific error code, and the happy
 * paths assert real SPL token balance deltas rather than "the call returned".
 *
 * Run with:
 *     cd contracts/solana
 *     yarn install
 *     anchor test
 *
 * Requires Anchor 0.29.0, Solana 1.18.26 and Node >= 20.18 (see the README).
 */
import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Ed25519Program,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  LAMPORTS_PER_SOL,
  Transaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddressSync,
  mintTo,
  getAccount,
  NATIVE_MINT,
  createSyncNativeInstruction,
  createAssociatedTokenAccountInstruction,
} from "@solana/spl-token";
import { keccak_256 } from "@noble/hashes/sha3";
import { assert, expect } from "chai";

const QUOTE_DOMAIN = Buffer.from("AEROLEDGER_ORDER_QUOTE_V1");
const DECIMALS = 6;
const UNIT = 10 ** DECIMALS;
const REFUND_WINDOW = 3600; // seconds; the minimum the program allows

describe("aeroledger-escrow", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AeroledgerEscrow as Program;
  const connection = provider.connection;

  // Governance / party keys.
  const admin = Keypair.generate();
  const quoteAuthority = Keypair.generate();
  const treasury = Keypair.generate();
  const seller = Keypair.generate();
  const sellerPayout = Keypair.generate();
  const buyer = Keypair.generate();
  const attacker = Keypair.generate();

  let mint: PublicKey;
  let otherMint: PublicKey;
  let configPda: PublicKey;
  let merchantPda: PublicKey;
  let supportedMintPda: PublicKey;
  let buyerAta: PublicKey;
  let attackerAta: PublicKey;
  let sellerAta: PublicKey;
  let treasuryAta: PublicKey;

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  const orderPda = (orderId: string) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("order"), Buffer.from(keccak_256(Buffer.from(orderId)))],
      program.programId
    )[0];

  const orderIdHash = (orderId: string) =>
    Buffer.from(keccak_256(Buffer.from(orderId)));

  /** Mirror of `quote::quote_message` in the program. */
  function quoteMessage(
    orderId: string,
    buyerKey: PublicKey,
    sellerKey: PublicKey,
    mintKey: PublicKey,
    amount: bigint,
    feeAmount: bigint,
    expiry: bigint
  ): Buffer {
    const le = (v: bigint) => {
      const b = Buffer.alloc(8);
      b.writeBigInt64LE(BigInt.asIntN(64, v));
      return b;
    };
    return Buffer.concat([
      QUOTE_DOMAIN,
      orderIdHash(orderId),
      buyerKey.toBuffer(),
      sellerKey.toBuffer(),
      mintKey.toBuffer(),
      le(amount),
      le(feeAmount),
      le(expiry),
    ]);
  }

  /** The Ed25519 pre-instruction that attests to a quote. */
  function attestation(message: Buffer, signer: Keypair = quoteAuthority) {
    return Ed25519Program.createInstructionWithPrivateKey({
      privateKey: signer.secretKey,
      message,
    });
  }

  function nowSeconds(): bigint {
    return BigInt(Math.floor(Date.now() / 1000));
  }

  async function airdrop(to: PublicKey, sol = 5) {
    const sig = await connection.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig, "confirmed");
  }

  async function balance(ata: PublicKey): Promise<bigint> {
    return (await getAccount(connection, ata)).amount;
  }

  /**
   * Assert that a transaction fails, and that the failure is one of the expected
   * error codes -- never just "it threw".
   *
   * Several cases legitimately have two possible codes depending on WHERE the
   * rejection happens. Terminal instructions close the escrow vault, so a second
   * attempt on a settled order fails during account validation
   * (`AccountNotInitialized`) before the handler's status guard
   * (`CannotRefund` / `InvalidStatus`) is ever reached. Both outcomes mean the
   * attack failed; the test records that either is acceptable rather than
   * pretending only one can occur.
   */
  async function expectError(promise: Promise<unknown>, ...codes: string[]) {
    try {
      await promise;
      assert.fail(`expected the transaction to fail with ${codes.join(" or ")}, but it succeeded`);
    } catch (err: any) {
      if (err?.message?.startsWith?.("expected the transaction to fail")) throw err;
      const text = JSON.stringify(err?.error ?? err?.message ?? err);
      const matched = codes.some((code) => {
        if (text.includes(code)) return true;
        // A rejection raised during preflight simulation arrives as a plain
        // SendTransactionError -- "custom program error: 0x1781" -- with no
        // logs for Anchor to translate back into a name. Matching on the name
        // alone would report a *correct* rejection as a failure, so resolve
        // the name to its numeric code and match that too.
        const num = errorCode(code);
        if (num === undefined) return false;
        return (
          text.includes(`custom program error: 0x${num.toString(16)}`) ||
          text.includes(`custom program error: ${num}`) ||
          text.includes(`"number":${num}`)
        );
      });
      const logs = Array.isArray(err?.logs) ? `\nprogram logs:\n  ${err.logs.join("\n  ")}` : "";
      expect(matched, `expected one of [${codes.join(", ")}] in: ${text}${logs}`).to.equal(true);
    }
  }

  /**
   * Resolve an error name to its numeric code: first the program's own errors
   * (6000+, from the IDL), then Anchor's built-in constraint/account errors.
   */
  function errorCode(name: string): number | undefined {
    const fromIdl = (program.idl as any)?.errors?.find((e: any) => e.name === name);
    if (fromIdl) return fromIdl.code;
    return (anchor as any).LangErrorCode?.[name];
  }

  type OrderParams = {
    orderId: string;
    amount?: bigint;
    fee?: bigint;
    expiry?: bigint;
    signer?: Keypair;
    /** Quote values that differ from the on-chain ones (attack simulation). */
    signedAmount?: bigint;
    signedBuyer?: PublicKey;
    payer?: Keypair;
    payerAta?: PublicKey;
    omitAttestation?: boolean;
  };

  /** Build and send a `create_order` transaction with its Ed25519 pre-instruction. */
  async function createOrder(p: OrderParams) {
    const amount = p.amount ?? BigInt(100 * UNIT);
    const fee = p.fee ?? BigInt(3 * UNIT);
    const expiry = p.expiry ?? nowSeconds() + 300n;
    const payer = p.payer ?? buyer;
    const payerAta = p.payerAta ?? buyerAta;

    const message = quoteMessage(
      p.orderId,
      p.signedBuyer ?? payer.publicKey,
      seller.publicKey,
      mint,
      p.signedAmount ?? amount,
      fee,
      expiry
    );

    const order = orderPda(p.orderId);
    const ix = await program.methods
      .createOrder(p.orderId, {
        amount: new BN(amount.toString()),
        feeAmount: new BN(fee.toString()),
        expiry: new BN(expiry.toString()),
      })
      .accounts({
        config: configPda,
        supportedMint: supportedMintPda,
        merchant: merchantPda,
        order,
        buyer: payer.publicKey,
        mint,
        buyerTokenAccount: payerAta,
        escrowTokenAccount: getAssociatedTokenAddressSync(mint, order, true),
        sellerTokenAccount: sellerAta,
        payoutWallet: sellerPayout.publicKey,
        treasuryTokenAccount: treasuryAta,
        treasury: treasury.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const tx = new Transaction();
    if (!p.omitAttestation) {
      tx.add(attestation(message, p.signer ?? quoteAuthority));
    }
    tx.add(ix);
    return provider.sendAndConfirm(tx, [payer]);
  }

  async function confirmOrder(orderId: string, signer: Keypair = seller) {
    return program.methods
      .confirmOrder()
      .accounts({
        config: configPda,
        order: orderPda(orderId),
        merchant: merchantPda,
        seller: signer.publicKey,
      })
      .signers([signer])
      .rpc();
  }

  async function completeOrder(
    orderId: string,
    signer: Keypair = seller,
    overrides: Partial<Record<string, PublicKey>> = {}
  ) {
    const order = orderPda(orderId);
    return program.methods
      .completeOrder()
      .accounts({
        config: configPda,
        order,
        mint,
        escrowTokenAccount: getAssociatedTokenAddressSync(mint, order, true),
        sellerTokenAccount: sellerAta,
        payoutWallet: sellerPayout.publicKey,
        treasuryTokenAccount: treasuryAta,
        treasury: treasury.publicKey,
        buyer: buyer.publicKey,
        authority: signer.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        ...overrides,
      })
      .signers([signer])
      .rpc();
  }

  async function refundOrder(
    orderId: string,
    signer: Keypair,
    method: "refundOrder" | "timeoutRefund" = "refundOrder"
  ) {
    const order = orderPda(orderId);
    return program.methods[method]()
      .accounts({
        config: configPda,
        order,
        mint,
        buyer: buyer.publicKey,
        escrowTokenAccount: getAssociatedTokenAddressSync(mint, order, true),
        buyerTokenAccount: buyerAta,
        authority: signer.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([signer])
      .rpc();
  }

  // ---------------------------------------------------------------------
  // Setup
  // ---------------------------------------------------------------------

  before(async () => {
    for (const kp of [admin, seller, buyer, attacker, sellerPayout, treasury]) {
      await airdrop(kp.publicKey);
    }

    mint = await createMint(connection, admin, admin.publicKey, null, DECIMALS);
    otherMint = await createMint(connection, admin, admin.publicKey, null, DECIMALS);

    buyerAta = (
      await getOrCreateAssociatedTokenAccount(connection, buyer, mint, buyer.publicKey)
    ).address;
    attackerAta = (
      await getOrCreateAssociatedTokenAccount(connection, attacker, mint, attacker.publicKey)
    ).address;
    sellerAta = (
      await getOrCreateAssociatedTokenAccount(connection, admin, mint, sellerPayout.publicKey)
    ).address;
    treasuryAta = (
      await getOrCreateAssociatedTokenAccount(connection, admin, mint, treasury.publicKey)
    ).address;

    await mintTo(connection, admin, mint, buyerAta, admin, 10_000 * UNIT);
    await mintTo(connection, admin, mint, attackerAta, admin, 10_000 * UNIT);

    [configPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      program.programId
    );
    [merchantPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("merchant"), seller.publicKey.toBuffer()],
      program.programId
    );
    [supportedMintPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint"), mint.toBuffer()],
      program.programId
    );

    // `initialize` is gated on the program's upgrade authority, which under
    // `anchor test` is the provider wallet.
    const [programData] = PublicKey.findProgramAddressSync(
      [program.programId.toBuffer()],
      new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111")
    );
    await program.methods
      .initialize(
        admin.publicKey,
        quoteAuthority.publicKey,
        treasury.publicKey,
        new BN(REFUND_WINDOW)
      )
      .accounts({
        config: configPda,
        payer: provider.wallet.publicKey,
        program: program.programId,
        programData,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .registerMint()
      .accounts({
        config: configPda,
        supportedMint: supportedMintPda,
        mint,
        admin: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([admin])
      .rpc();

    await program.methods
      .registerMerchant(sellerPayout.publicKey)
      .accounts({
        config: configPda,
        merchant: merchantPda,
        merchantAuthority: seller.publicKey,
        admin: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([admin])
      .rpc();
  });

  // ---------------------------------------------------------------------
  // Governance
  // ---------------------------------------------------------------------

  describe("governance", () => {
    it("records the configured parties", async () => {
      const cfg: any = await program.account.config.fetch(configPda);
      expect(cfg.admin.toBase58()).to.equal(admin.publicKey.toBase58());
      expect(cfg.quoteAuthority.toBase58()).to.equal(quoteAuthority.publicKey.toBase58());
      expect(cfg.treasury.toBase58()).to.equal(treasury.publicKey.toBase58());
      expect(cfg.paused).to.equal(false);
    });

    it("binds the merchant to a governance-controlled payout wallet", async () => {
      const m: any = await program.account.merchant.fetch(merchantPda);
      expect(m.authority.toBase58()).to.equal(seller.publicKey.toBase58());
      expect(m.payoutWallet.toBase58()).to.equal(sellerPayout.publicKey.toBase58());
      expect(m.active).to.equal(true);
    });

    it("rejects config changes from a non-admin", async () => {
      await expectError(
        program.methods
          .setPaused(true)
          .accounts({ config: configPda, admin: attacker.publicKey })
          .signers([attacker])
          .rpc(),
        "Unauthorized"
      );
    });

    it("rejects merchant registration from a non-admin", async () => {
      const [pda] = PublicKey.findProgramAddressSync(
        [Buffer.from("merchant"), attacker.publicKey.toBuffer()],
        program.programId
      );
      await expectError(
        program.methods
          .registerMerchant(attacker.publicKey)
          .accounts({
            config: configPda,
            merchant: pda,
            merchantAuthority: attacker.publicKey,
            admin: attacker.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([attacker])
          .rpc(),
        "Unauthorized"
      );
    });

    it("requires a two-step handover to change the admin", async () => {
      await program.methods
        .transferAdmin(attacker.publicKey)
        .accounts({ config: configPda, admin: admin.publicKey })
        .signers([admin])
        .rpc();

      // Nomination alone changes nothing.
      let cfg: any = await program.account.config.fetch(configPda);
      expect(cfg.admin.toBase58()).to.equal(admin.publicKey.toBase58());

      // Someone other than the nominee cannot accept.
      await expectError(
        program.methods
          .acceptAdmin()
          .accounts({ config: configPda, newAdmin: seller.publicKey })
          .signers([seller])
          .rpc(),
        "Unauthorized"
      );

      // Withdraw the nomination so the rest of the suite keeps the real admin.
      await program.methods
        .transferAdmin(admin.publicKey)
        .accounts({ config: configPda, admin: admin.publicKey })
        .signers([admin])
        .rpc();
      cfg = await program.account.config.fetch(configPda);
      expect(cfg.admin.toBase58()).to.equal(admin.publicKey.toBase58());
    });
  });

  // ---------------------------------------------------------------------
  // Quote enforcement — the core price-manipulation defence
  // ---------------------------------------------------------------------

  describe("signed quote enforcement", () => {
    it("rejects an order with no Ed25519 attestation at all", async () => {
      await expectError(
        createOrder({ orderId: "no-attestation-1", omitAttestation: true }),
        "MissingQuoteSignature"
      );
    });

    it("rejects a quote signed by a key other than the quote authority", async () => {
      await expectError(
        createOrder({ orderId: "wrong-signer-1", signer: attacker }),
        "UnauthorizedQuoteSigner"
      );
    });

    it("rejects a buyer who signs a cheaper amount than the order claims", async () => {
      await expectError(
        createOrder({
          orderId: "cheap-1",
          amount: BigInt(100 * UNIT),
          signedAmount: BigInt(1),
        }),
        "QuoteMismatch"
      );
    });

    it("rejects a quote issued to a different buyer (quote theft)", async () => {
      await expectError(
        createOrder({
          orderId: "stolen-quote-1",
          payer: attacker,
          payerAta: attackerAta,
          signedBuyer: buyer.publicKey,
        }),
        "QuoteMismatch"
      );
    });

    it("rejects an already-expired quote", async () => {
      await expectError(
        createOrder({ orderId: "expired-1", expiry: nowSeconds() - 10n }),
        "QuoteExpired"
      );
    });

    it("rejects a quote with an implausibly long lifetime", async () => {
      await expectError(
        createOrder({ orderId: "long-lived-1", expiry: nowSeconds() + 86_400n }),
        "QuoteLifetimeTooLong"
      );
    });

    it("rejects a zero amount", async () => {
      await expectError(
        createOrder({ orderId: "zero-1", amount: 0n, fee: 0n }),
        "InvalidAmount"
      );
    });

    it("rejects a fee greater than or equal to the amount", async () => {
      await expectError(
        createOrder({
          orderId: "fat-fee-1",
          amount: BigInt(10 * UNIT),
          fee: BigInt(10 * UNIT),
        }),
        "InvalidFeeAmount"
      );
    });

    it("rejects an order id longer than the 64-byte maximum", async () => {
      await expectError(createOrder({ orderId: "x".repeat(65) }), "OrderIdTooLong");
    });

    it("rejects an unsupported mint", async () => {
      const [badPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("mint"), otherMint.toBuffer()],
        program.programId
      );
      // The allow-list PDA for `otherMint` was never created, so the account
      // constraint cannot be satisfied.
      await expectError(
        program.account.supportedMint.fetch(badPda),
        "Account does not exist"
      );
    });
  });

  // ---------------------------------------------------------------------
  // Happy path — real balance assertions
  // ---------------------------------------------------------------------

  describe("buyer -> seller settlement", () => {
    const orderId = "happy-path-1";
    const amount = BigInt(100 * UNIT);
    const fee = BigInt(3 * UNIT);

    it("escrows exactly the quoted amount from the buyer", async () => {
      const before = await balance(buyerAta);
      await createOrder({ orderId, amount, fee });
      const after = await balance(buyerAta);
      expect(before - after).to.equal(amount);

      const vault = getAssociatedTokenAddressSync(mint, orderPda(orderId), true);
      expect(await balance(vault)).to.equal(amount);

      const order: any = await program.account.order.fetch(orderPda(orderId));
      expect(order.buyer.toBase58()).to.equal(buyer.publicKey.toBase58());
      expect(order.seller.toBase58()).to.equal(seller.publicKey.toBase58());
      expect(order.payoutWallet.toBase58()).to.equal(sellerPayout.publicKey.toBase58());
      expect(order.treasury.toBase58()).to.equal(treasury.publicKey.toBase58());
      expect(BigInt(order.amount.toString())).to.equal(amount);
    });

    /**
     * An order's life runs in three phases and exactly one party set may act in
     * each, so no outcome is decided by transaction ordering:
     *
     *   t <= settlementDeadline   seller settles or refunds; admin may too
     *   t <= timeoutDeadline      admin only, arbitrating a late settlement
     *   t >  timeoutDeadline      buyer only, exiting unilaterally
     *
     * An earlier version had one deadline that both opened `timeout_refund` and
     * left `complete_order` unbounded, so past it the two were live together and
     * whichever transaction landed first took the funds.
     */
    it("records a settlement deadline and a later timeout deadline", async () => {
      const id = `${orderId}-deadlines`;
      await createOrder({ orderId: id, amount, fee });
      const order: any = await program.account.order.fetch(orderPda(id));

      const createdAt = Number(order.createdAt);
      const settlement = Number(order.settlementDeadline);
      const timeout = Number(order.timeoutDeadline);

      expect(settlement - createdAt).to.equal(REFUND_WINDOW);
      // disputeWindow defaults to the settlement window at initialize.
      expect(timeout - settlement).to.equal(REFUND_WINDOW);
      expect(timeout).to.be.greaterThan(settlement);
    });

    it("rejects a duplicate order id", async () => {
      // The Order PDA for this id already exists, so `init` fails inside the
      // System Program with AccountAlreadyInUse, which is error 0. Through
      // program logs that renders as "already in use"; straight from preflight
      // simulation it arrives only as the bare code.
      await expectError(
        createOrder({ orderId, amount, fee }),
        "already in use",
        "custom program error: 0x0"
      );
    });

    it("rejects completion before the seller has confirmed", async () => {
      await expectError(completeOrder(orderId), "InvalidStatus");
    });

    it("rejects confirmation by anyone other than the seller", async () => {
      await expectError(confirmOrder(orderId, admin), "Unauthorized");
      await expectError(confirmOrder(orderId, buyer), "Unauthorized");
      await expectError(confirmOrder(orderId, attacker), "Unauthorized");
    });

    it("lets the seller confirm", async () => {
      await confirmOrder(orderId, seller);
      const order: any = await program.account.order.fetch(orderPda(orderId));
      expect(Object.keys(order.status)[0]).to.equal("confirmed");
    });

    it("rejects confirming twice", async () => {
      await expectError(confirmOrder(orderId, seller), "InvalidStatus");
    });

    it("rejects completion by an unrelated signer", async () => {
      await expectError(completeOrder(orderId, attacker), "Unauthorized");
    });

    it("rejects a substituted payout token account", async () => {
      await expectError(
        completeOrder(orderId, seller, { sellerTokenAccount: attackerAta }),
        // `associated_token::authority = payout_wallet` expands to an owner
        // check before the ATA-address check, so substituting an account owned
        // by somebody else trips ConstraintTokenOwner first. That is the
        // constraint that actually protects the payout, so assert on it.
        "ConstraintTokenOwner"
      );
    });

    it("pays the seller the net amount and the treasury the fee", async () => {
      const sellerBefore = await balance(sellerAta);
      const treasuryBefore = await balance(treasuryAta);

      await completeOrder(orderId, seller);

      expect((await balance(sellerAta)) - sellerBefore).to.equal(amount - fee);
      expect((await balance(treasuryAta)) - treasuryBefore).to.equal(fee);

      const order: any = await program.account.order.fetch(orderPda(orderId));
      expect(Object.keys(order.status)[0]).to.equal("completed");
    });

    it("rejects completing the same order twice", async () => {
      // The vault was closed on the first completion, so this fails at account
      // validation; if it somehow got past that, the status guard would stop it.
      await expectError(completeOrder(orderId, seller), "InvalidStatus", "AccountNotInitialized");
    });

    it("rejects refunding a completed order", async () => {
      await expectError(refundOrder(orderId, admin), "CannotRefund", "AccountNotInitialized");
    });
  });

  // ---------------------------------------------------------------------
  // Refunds
  // ---------------------------------------------------------------------

  describe("refunds", () => {
    it("lets the buyer cancel a still-pending order and returns every token", async () => {
      const orderId = "refund-pending-1";
      const amount = BigInt(50 * UNIT);
      const before = await balance(buyerAta);

      await createOrder({ orderId, amount, fee: BigInt(1 * UNIT) });
      expect(before - (await balance(buyerAta))).to.equal(amount);

      await refundOrder(orderId, buyer);
      expect(await balance(buyerAta)).to.equal(before);

      const order: any = await program.account.order.fetch(orderPda(orderId));
      expect(Object.keys(order.status)[0]).to.equal("refunded");
    });

    it("rejects a refund requested by an unrelated signer", async () => {
      const orderId = "refund-attacker-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });
      await expectError(refundOrder(orderId, attacker), "Unauthorized");
    });

    it("rejects refunding to an account that is not the buyer's ATA", async () => {
      const orderId = "refund-redirect-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });
      const order = orderPda(orderId);
      await expectError(
        program.methods
          .refundOrder()
          .accounts({
            config: configPda,
            order,
            mint,
            buyer: buyer.publicKey,
            escrowTokenAccount: getAssociatedTokenAddressSync(mint, order, true),
            buyerTokenAccount: attackerAta, // attacker-controlled destination
            authority: buyer.publicKey,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([buyer])
          .rpc(),
        // Same ordering as above: the refund destination is checked for owner
        // before ATA derivation, so an attacker-controlled account is rejected
        // by ConstraintTokenOwner.
        "ConstraintTokenOwner"
      );
    });

    it("rejects a buyer unilaterally refunding an order the seller confirmed", async () => {
      const orderId = "refund-confirmed-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });
      await confirmOrder(orderId, seller);
      await expectError(refundOrder(orderId, buyer), "Unauthorized");
      // ...but the seller may.
      await refundOrder(orderId, seller);
    });

    it("rejects double refund", async () => {
      const orderId = "refund-double-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });
      await refundOrder(orderId, buyer);
      await expectError(refundOrder(orderId, buyer), "CannotRefund", "AccountNotInitialized");
    });

    it("rejects a timeout refund before the deadline", async () => {
      const orderId = "timeout-early-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });
      await expectError(refundOrder(orderId, buyer, "timeoutRefund"), "TimeoutNotReached");
    });

    it("rejects a timeout refund by anyone but the buyer", async () => {
      const orderId = "timeout-wrong-signer-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });
      await expectError(refundOrder(orderId, seller, "timeoutRefund"), "Unauthorized");
    });
  });

  // ---------------------------------------------------------------------
  // Pause and merchant status
  // ---------------------------------------------------------------------

  describe("pause and merchant status", () => {
    it("blocks new orders while paused but still allows refunds", async () => {
      const orderId = "pause-1";
      await createOrder({ orderId, amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) });

      await program.methods
        .setPaused(true)
        .accounts({ config: configPda, admin: admin.publicKey })
        .signers([admin])
        .rpc();

      await expectError(
        createOrder({ orderId: "pause-2", amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) }),
        "Paused"
      );

      // Funds are never trapped by a pause.
      await refundOrder(orderId, buyer);

      await program.methods
        .setPaused(false)
        .accounts({ config: configPda, admin: admin.publicKey })
        .signers([admin])
        .rpc();
    });

    it("rejects orders with a deactivated merchant", async () => {
      await program.methods
        .updateMerchant(null, false)
        .accounts({ config: configPda, merchant: merchantPda, admin: admin.publicKey })
        .signers([admin])
        .rpc();

      await expectError(
        createOrder({ orderId: "inactive-1", amount: BigInt(10 * UNIT), fee: BigInt(1 * UNIT) }),
        "MerchantInactive"
      );

      await program.methods
        .updateMerchant(null, true)
        .accounts({ config: configPda, merchant: merchantPda, admin: admin.publicKey })
        .signers([admin])
        .rpc();
    });
  });

  // ---------------------------------------------------------------------
  // PDA / account substitution
  // ---------------------------------------------------------------------

  describe("account substitution", () => {
    it("rejects a forged escrow vault that the attacker controls", async () => {
      const orderId = "fake-vault-1";
      const amount = BigInt(10 * UNIT);
      const fee = BigInt(1 * UNIT);
      const expiry = nowSeconds() + 300n;
      const order = orderPda(orderId);

      const message = quoteMessage(
        orderId,
        buyer.publicKey,
        seller.publicKey,
        mint,
        amount,
        fee,
        expiry
      );

      const ix = await program.methods
        .createOrder(orderId, {
          amount: new BN(amount.toString()),
          feeAmount: new BN(fee.toString()),
          expiry: new BN(expiry.toString()),
        })
        .accounts({
          config: configPda,
          supportedMint: supportedMintPda,
          merchant: merchantPda,
          order,
          buyer: buyer.publicKey,
          mint,
          buyerTokenAccount: buyerAta,
          escrowTokenAccount: attackerAta, // NOT the order PDA's ATA
          sellerTokenAccount: sellerAta,
          payoutWallet: sellerPayout.publicKey,
          treasuryTokenAccount: treasuryAta,
          treasury: treasury.publicKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      const tx = new Transaction().add(attestation(message)).add(ix);
      // The substituted account is never even consulted. `init` +
      // `associated_token::authority = order` makes Anchor DERIVE the vault
      // address from (order, mint) and create it by CPI, so the CPI references
      // the genuine ATA -- which the attacker did not put in the transaction.
      // The runtime rejects it as a missing account before any constraint on
      // the forged one runs. Asserting the real mechanism rather than a
      // ConstraintAssociated check that never gets the chance to fire.
      await expectError(
        provider.sendAndConfirm(tx, [buyer]),
        "An account required by the instruction is missing"
      );
    });

    it("rejects an order PDA derived from the wrong seed", async () => {
      const orderId = "bad-seed-1";
      const [wrongPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("order"), Buffer.from(keccak_256(Buffer.from("different-id")))],
        program.programId
      );
      const amount = BigInt(10 * UNIT);
      const fee = BigInt(1 * UNIT);
      const expiry = nowSeconds() + 300n;
      const message = quoteMessage(
        orderId,
        buyer.publicKey,
        seller.publicKey,
        mint,
        amount,
        fee,
        expiry
      );

      const ix = await program.methods
        .createOrder(orderId, {
          amount: new BN(amount.toString()),
          feeAmount: new BN(fee.toString()),
          expiry: new BN(expiry.toString()),
        })
        .accounts({
          config: configPda,
          supportedMint: supportedMintPda,
          merchant: merchantPda,
          order: wrongPda,
          buyer: buyer.publicKey,
          mint,
          buyerTokenAccount: buyerAta,
          escrowTokenAccount: getAssociatedTokenAddressSync(mint, wrongPda, true),
          sellerTokenAccount: sellerAta,
          payoutWallet: sellerPayout.publicKey,
          treasuryTokenAccount: treasuryAta,
          treasury: treasury.publicKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      const tx = new Transaction().add(attestation(message)).add(ix);
      await expectError(provider.sendAndConfirm(tx, [buyer]), "ConstraintSeeds");
    });

    it("rejects a buyer token account owned by somebody else", async () => {
      await expectError(
        createOrder({
          orderId: "wrong-source-1",
          payerAta: attackerAta,
        }),
        "InvalidTokenAccountOwner"
      );
    });
  });


  // ---------------------------------------------------------------------
  // The browser's bytes, and wrapped SOL
  // ---------------------------------------------------------------------

  /**
   * Everything above builds transactions with this file's own mirror of the
   * program's wire format. That proves the program is correct; it does not
   * prove the *browser* is, and the browser is what customers use.
   *
   * The browser cannot be imported here. This package pins ts-node 7, whose
   * loader predates `moduleTypes`, so a `.ts` file under a `"type": "module"`
   * package resolves as ESM and the whole suite falls off its CommonJS loader.
   * Pinning a newer ts-node means regenerating a lockfile that is deliberately
   * committed.
   *
   * So the browser emits its bytes into a fixture and this checks them against
   * Anchor's own encoder -- which every passing test in this file has already
   * proven the program accepts. The chain of equality is
   * browser == Anchor client == program, and either half failing names which.
   *
   * The fixture is kept current by the browser's own suite, which fails if it
   * drifts. See `Frontend/scripts/escrow-fixture.ts`.
   */
  describe("browser wire format", () => {
    const fixture = require("./fixtures/browser-create-order.json");
    const fixtureProgram = new PublicKey(fixture.input.programId);
    const pda = (seeds: Buffer[]) =>
      PublicKey.findProgramAddressSync(seeds, fixtureProgram)[0].toBase58();

    it("derives the same addresses the program's own seeds give", () => {
      // Derived against the FIXTURE's program id, not this deployment's, so the
      // check is about the seeds rather than about which program is deployed.
      expect(fixture.derived.config).to.equal(pda([Buffer.from("config")]));
      expect(fixture.derived.supportedMint).to.equal(
        pda([Buffer.from("mint"), NATIVE_MINT.toBuffer()])
      );
      expect(fixture.derived.merchant).to.equal(
        pda([Buffer.from("merchant"), new PublicKey(fixture.input.seller).toBuffer()])
      );
      expect(fixture.derived.order).to.equal(
        pda([Buffer.from("order"), orderIdHash(fixture.input.orderId)])
      );
    });

    it("hashes the order id the way the PDA seed requires", () => {
      expect(fixture.derived.orderIdHash).to.equal(
        orderIdHash(fixture.input.orderId).toString("hex")
      );
    });

    it("builds the message the program rebuilds and compares", () => {
      // A drift here is the nastiest failure in the system: every signature
      // stops verifying on-chain, and the error names the signer rather than
      // the message, so it reads as a wrong key.
      const expected = quoteMessage(
        fixture.input.orderId,
        new PublicKey(fixture.input.buyer),
        new PublicKey(fixture.input.seller),
        NATIVE_MINT,
        BigInt(fixture.input.amount),
        BigInt(fixture.input.feeAmount),
        BigInt(fixture.input.expiry)
      );
      expect(fixture.quoteMessage).to.equal(expected.toString("hex"));
    });

    it("encodes create_order exactly as Anchor's own client does", async () => {
      // Anchor generates this from the IDL, which is generated from the
      // program. If the browser's bytes equal these, the browser is encoding
      // what the program will decode -- discriminator, Borsh string length and
      // all three little-endian integers.
      const ix = await program.methods
        .createOrder(fixture.input.orderId, {
          amount: new BN(fixture.input.amount),
          feeAmount: new BN(fixture.input.feeAmount),
          expiry: new BN(fixture.input.expiry),
        })
        .accounts({
          config: configPda,
          supportedMint: supportedMintPda,
          merchant: merchantPda,
          order: orderPda(fixture.input.orderId),
          buyer: buyer.publicKey,
          mint,
          buyerTokenAccount: buyerAta,
          escrowTokenAccount: getAssociatedTokenAddressSync(
            mint,
            orderPda(fixture.input.orderId),
            true
          ),
          sellerTokenAccount: sellerAta,
          payoutWallet: sellerPayout.publicKey,
          treasuryTokenAccount: treasuryAta,
          treasury: treasury.publicKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      expect(fixture.createOrderData).to.equal(ix.data.toString("hex"));
    });

    it("lists the accounts in the order and with the flags Anchor emits", async () => {
      // Anchor matches accounts positionally. A transposition does not error --
      // it hands the program a different account in a slot whose constraints
      // may happen to pass, which is worse than a crash.
      const ix = await program.methods
        .createOrder(fixture.input.orderId, {
          amount: new BN(fixture.input.amount),
          feeAmount: new BN(fixture.input.feeAmount),
          expiry: new BN(fixture.input.expiry),
        })
        .accounts({
          config: configPda,
          supportedMint: supportedMintPda,
          merchant: merchantPda,
          order: orderPda(fixture.input.orderId),
          buyer: buyer.publicKey,
          mint,
          buyerTokenAccount: buyerAta,
          escrowTokenAccount: getAssociatedTokenAddressSync(
            mint,
            orderPda(fixture.input.orderId),
            true
          ),
          sellerTokenAccount: sellerAta,
          payoutWallet: sellerPayout.publicKey,
          treasuryTokenAccount: treasuryAta,
          treasury: treasury.publicKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();

      // The fixture names different parties, so compare the SHAPE: how many
      // accounts, in what order of signer/writable flags, and that the four
      // fixed program ids land in the same slots.
      expect(fixture.accounts).to.have.length(ix.keys.length);
      expect(fixture.accounts.map((a: any) => [a.isSigner, a.isWritable])).to.deep.equal(
        ix.keys.map((k) => [k.isSigner, k.isWritable])
      );
      for (const slot of [12, 13, 14, 15]) {
        expect(fixture.accounts[slot].pubkey).to.equal(ix.keys[slot].pubkey.toBase58());
      }
    });
  });

  /**
   * Wrapped SOL end to end.
   *
   * The rest of the suite uses a synthetic 6-decimal mint, which is the right
   * choice for exercising the program's logic but says nothing about the
   * currency customers actually pay in. The escrow moves SPL tokens only -- it
   * has no lamport path at all -- so "pay 1.15 SOL" means wrapping it first,
   * and wrapping is the part of the flow with the most ways to be quietly
   * wrong.
   */
  describe("wrapped SOL", () => {
    const amount = 1_150_000_000; // 1.15 SOL
    const fee = 150_000_000;

    let wsolSupportedMintPda: PublicKey;
    let wsolPayoutAta: PublicKey;
    let wsolTreasuryAta: PublicKey;

    before(async () => {
      [wsolSupportedMintPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("mint"), NATIVE_MINT.toBuffer()],
        program.programId
      );

      await program.methods
        .registerMint()
        .accounts({
          config: configPda,
          supportedMint: wsolSupportedMintPda,
          mint: NATIVE_MINT,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([admin])
        .rpc();

      // Neither destination is `init_if_needed` in the program, deliberately:
      // funds must never enter escrow for a seller with nowhere to be paid.
      wsolPayoutAta = (
        await getOrCreateAssociatedTokenAccount(
          connection,
          admin,
          NATIVE_MINT,
          sellerPayout.publicKey
        )
      ).address;
      wsolTreasuryAta = (
        await getOrCreateAssociatedTokenAccount(
          connection,
          admin,
          NATIVE_MINT,
          treasury.publicKey
        )
      ).address;

      await airdrop(buyer.publicKey, 10);
    });

    /** Wrap `lamports` into the buyer's wSOL account, creating it if needed. */
    async function wrap(lamports: number): Promise<PublicKey> {
      const ata = getAssociatedTokenAddressSync(NATIVE_MINT, buyer.publicKey);
      const tx = new Transaction();
      if (!(await connection.getAccountInfo(ata))) {
        tx.add(
          createAssociatedTokenAccountInstruction(
            buyer.publicKey,
            ata,
            buyer.publicKey,
            NATIVE_MINT
          )
        );
      }
      tx.add(
        SystemProgram.transfer({
          fromPubkey: buyer.publicKey,
          toPubkey: ata,
          lamports,
        }),
        // Lamports landing in a native token account do not change its token
        // balance until the token program is told to look. Without this the
        // escrow transfer fails with "insufficient funds" against an account
        // that visibly holds the money.
        createSyncNativeInstruction(ata)
      );
      await provider.sendAndConfirm(tx, [buyer]);
      return ata;
    }

    it("escrows wrapped SOL and pays it out in real lamports", async () => {
      const orderId = "wsol-" + Date.now();
      const buyerWsol = await wrap(amount);

      const expiry = nowSeconds() + 120n;
      const message = quoteMessage(
        orderId,
        buyer.publicKey,
        seller.publicKey,
        NATIVE_MINT,
        BigInt(amount),
        BigInt(fee),
        expiry
      );

      const order = orderPda(orderId);
      await program.methods
        .createOrder(orderId, {
          amount: new BN(amount),
          feeAmount: new BN(fee),
          expiry: new BN(expiry.toString()),
        })
        .accounts({
          config: configPda,
          supportedMint: wsolSupportedMintPda,
          merchant: merchantPda,
          order,
          buyer: buyer.publicKey,
          mint: NATIVE_MINT,
          buyerTokenAccount: buyerWsol,
          escrowTokenAccount: getAssociatedTokenAddressSync(NATIVE_MINT, order, true),
          sellerTokenAccount: wsolPayoutAta,
          payoutWallet: sellerPayout.publicKey,
          treasuryTokenAccount: wsolTreasuryAta,
          treasury: treasury.publicKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([attestation(message)])
        .signers([buyer])
        .rpc();

      const vault = await getAccount(
        connection,
        getAssociatedTokenAddressSync(NATIVE_MINT, order, true)
      );
      expect(vault.amount.toString()).to.equal(amount.toString());

      await program.methods
        .confirmOrder()
        .accounts({
          config: configPda,
          order,
          merchant: merchantPda,
          seller: seller.publicKey,
        })
        .signers([seller])
        .rpc();

      const payoutBefore = (await getAccount(connection, wsolPayoutAta)).amount;
      const treasuryBefore = (await getAccount(connection, wsolTreasuryAta)).amount;

      await program.methods
        .completeOrder()
        .accounts({
          config: configPda,
          order,
          escrowTokenAccount: getAssociatedTokenAddressSync(NATIVE_MINT, order, true),
          sellerTokenAccount: wsolPayoutAta,
          payoutWallet: sellerPayout.publicKey,
          treasuryTokenAccount: wsolTreasuryAta,
          treasury: treasury.publicKey,
          // The vault is closed at settlement and its rent goes back to whoever
          // paid it, which is the buyer.
          buyer: buyer.publicKey,
          authority: seller.publicKey,
          mint: NATIVE_MINT,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([seller])
        .rpc();

      // Real balance deltas, read from the chain. What went in is what came
      // out: nothing is created or lost by the split.
      const payoutAfter = (await getAccount(connection, wsolPayoutAta)).amount;
      const treasuryAfter = (await getAccount(connection, wsolTreasuryAta)).amount;
      expect((payoutAfter - payoutBefore).toString()).to.equal(
        (amount - fee).toString()
      );
      expect((treasuryAfter - treasuryBefore).toString()).to.equal(fee.toString());
    });

    it("rejects a tampered amount, because the signature covers it", async () => {
      // The attestation is genuine; the instruction lies about the figure.
      // This is the attack the signed quote exists to stop.
      const orderId = "wsol-tamper-" + Date.now();
      const buyerWsol = await wrap(amount);
      const expiry = nowSeconds() + 120n;

      const signedFor = quoteMessage(
        orderId,
        buyer.publicKey,
        seller.publicKey,
        NATIVE_MINT,
        BigInt(amount),
        BigInt(fee),
        expiry
      );

      const order = orderPda(orderId);
      await expectError(
        program.methods
          .createOrder(orderId, {
            // A tenth of the price the backend authorised.
            amount: new BN(amount / 10),
            feeAmount: new BN(fee / 10),
            expiry: new BN(expiry.toString()),
          })
          .accounts({
            config: configPda,
            supportedMint: wsolSupportedMintPda,
            merchant: merchantPda,
            order,
            buyer: buyer.publicKey,
            mint: NATIVE_MINT,
            buyerTokenAccount: buyerWsol,
            escrowTokenAccount: getAssociatedTokenAddressSync(NATIVE_MINT, order, true),
            sellerTokenAccount: wsolPayoutAta,
            payoutWallet: sellerPayout.publicKey,
            treasuryTokenAccount: wsolTreasuryAta,
            treasury: treasury.publicKey,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            tokenProgram: TOKEN_PROGRAM_ID,
            associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
          })
          .preInstructions([attestation(signedFor)])
          .signers([buyer])
          .rpc(),
        "QuoteMismatch"
      );
    });
  });
});
