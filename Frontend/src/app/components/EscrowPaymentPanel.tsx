/**
 * Paying an accepted quote into the on-chain escrow.
 *
 * The alternative to this panel is the direct-transfer flow: send tokens to an
 * address we publish, then tell us the transaction hash. That works, but it
 * asks the customer to hand money to a stranger and trust them to deliver. This
 * one hands it to a program instead, and the program will only release it to the
 * registered seller -- or back to the buyer once the timeout passes.
 *
 * ## What happens, in order
 *
 * 1. the backend authorises the already-accepted price, signing it with a key
 *    the program has been told to trust;
 * 2. the client checks everything it can check against the chain *before*
 *    asking for a signature, so a payment that cannot succeed fails with a
 *    sentence rather than a hex error code;
 * 3. the wallet signs one transaction that wraps the SOL, carries the
 *    attestation, and creates the order;
 * 4. the backend reads the order back off the chain and decides whether the
 *    booking is paid.
 *
 * Step 4 is the one that counts. Nothing this component does -- not the
 * pre-flight, not a successful submission, not a transaction signature on
 * screen -- marks anything as paid. Only the backend's own reading of the chain
 * does that, which is why the "paid" badge below comes from the verify response
 * and not from the client having got this far.
 */
import { useCallback, useState } from "react";
import { AlertTriangle, CheckCircle2, ExternalLink, Loader2, ShieldCheck } from "lucide-react";

import {
  authorizeEscrow,
  verifyEscrowDeposit,
  type EscrowDepositResponse,
} from "../lib/backend";
import {
  escrowConnection,
  prepareEscrowDeposit,
  signAndSubmitEscrowDeposit,
  type EscrowAuthorization,
  type SigningProvider,
} from "../lib/escrow/client";
import { formatUnits, solanaProvider, type ConnectedWallet } from "../lib/wallet";
import { PublicKey } from "@solana/web3.js";

type Props = {
  token: string;
  bookingId: string;
  wallet: ConnectedWallet;
  decimals: number;
  tokenSymbol: string;
  /** Told once the backend has confirmed the booking is paid. */
  onSettled: (deposit: EscrowDepositResponse) => void;
};

type Stage =
  | { kind: "idle" }
  | { kind: "authorizing" }
  | { kind: "checking" }
  | { kind: "awaiting-signature" }
  | { kind: "confirming"; signature: string }
  | { kind: "verifying"; signature: string }
  | { kind: "settled"; signature: string; deposit: EscrowDepositResponse }
  | { kind: "failed"; message: string };

/** What the customer is told while each step runs. */
const PROGRESS: Record<string, string> = {
  authorizing: "Authorizing the agreed price…",
  checking: "Checking the escrow program and your balance…",
  "awaiting-signature": "Waiting for you to approve in your wallet…",
  confirming: "Waiting for the network to confirm…",
  verifying: "Verifying the deposit on-chain…",
};

/** Map the backend's snake_case response onto the client's shape. */
function toAuthorization(
  response: Awaited<ReturnType<typeof authorizeEscrow>>,
): EscrowAuthorization {
  return {
    programId: response.program_id,
    rpcUrl: response.rpc_url,
    orderId: response.order_id,
    buyer: response.buyer,
    seller: response.seller,
    payoutWallet: response.payout_wallet,
    treasury: response.treasury,
    mint: response.mint,
    quoteAuthority: response.quote_authority,
    amount: response.amount,
    feeAmount: response.fee_amount,
    expiry: response.expiry,
    signature: response.signature,
  };
}

export function EscrowPaymentPanel({
  token,
  bookingId,
  wallet,
  decimals,
  tokenSymbol,
  onSettled,
}: Props) {
  const [stage, setStage] = useState<Stage>({ kind: "idle" });

  const pay = useCallback(async () => {
    const provider = solanaProvider();
    if (!provider) {
      setStage({
        kind: "failed",
        message: "No Solana wallet is connected. Install or unlock Phantom and try again.",
      });
      return;
    }
    if (!provider.signTransaction && !provider.signAndSendTransaction) {
      setStage({
        kind: "failed",
        message: "This wallet cannot sign transactions, so it cannot pay into escrow.",
      });
      return;
    }

    try {
      setStage({ kind: "authorizing" });
      const authorization = toAuthorization(
        await authorizeEscrow(token, {
          booking_id: bookingId,
          buyer_wallet: wallet.address,
        }),
      );

      // The endpoint the backend chose, never the wallet's own. A wallet set to
      // mainnet while we verify on devnet is the mismatch that makes a payment
      // impossible to confirm, and the server owns the network for that reason.
      const connection = escrowConnection(authorization.rpcUrl);

      setStage({ kind: "checking" });
      const prepared = await prepareEscrowDeposit({
        connection,
        auth: authorization,
        buyer: new PublicKey(wallet.address),
      });

      if (prepared.state === "blocked") {
        // Each reason carries its own sentence. A shortfall is the one case
        // where a number helps, so it gets one.
        const detail =
          prepared.reason === "insufficient-sol" && prepared.shortfallLamports !== undefined
            ? ` You need about ${formatUnits(prepared.shortfallLamports, decimals, 4)} more ${tokenSymbol}.`
            : "";
        setStage({ kind: "failed", message: prepared.message + detail });
        return;
      }

      setStage({ kind: "awaiting-signature" });
      const { signature, orderAccount } = await signAndSubmitEscrowDeposit({
        connection,
        provider: provider as SigningProvider,
        transaction: prepared.transaction,
        lastValidBlockHeight: prepared.lastValidBlockHeight,
        orderAccount: prepared.orderAccount,
      });

      // Submitted and confirmed. Still not paid: that is the backend's call.
      setStage({ kind: "verifying", signature });
      const deposit = await verifyEscrowDeposit(token, {
        booking_id: bookingId,
        order_account: orderAccount,
        deposit_signature: signature,
      });

      setStage({ kind: "settled", signature, deposit });
      onSettled(deposit);
    } catch (err) {
      // A wallet rejection is the commonest path through here and is not an
      // error worth alarming anyone about.
      const raw = err instanceof Error ? err.message : String(err);
      const rejected = /user rejected|declined|denied/i.test(raw);
      setStage({
        kind: "failed",
        message: rejected
          ? "You declined the transaction in your wallet. Nothing was sent."
          : raw || "The escrow payment could not be completed.",
      });
    }
  }, [bookingId, decimals, onSettled, token, tokenSymbol, wallet.address]);

  const busy = !["idle", "settled", "failed"].includes(stage.kind);

  if (stage.kind === "settled") {
    const { deposit, signature } = stage;
    return (
      <div className="space-y-3 rounded-2xl border border-emerald-500/25 bg-emerald-500/10 px-4 py-4">
        <div className="flex items-center gap-2 text-sm text-emerald-200">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>
            {deposit.paid
              ? "Paid into escrow and verified."
              : "Deposit recorded, awaiting verification."}
          </span>
        </div>
        <dl className="space-y-1 text-xs text-emerald-100/80">
          <div className="flex justify-between gap-4">
            <dt>Held in escrow</dt>
            <dd className="font-mono">
              {formatUnits(BigInt(deposit.amount), decimals)} {tokenSymbol}
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt>To the operator on completion</dt>
            <dd className="font-mono">
              {formatUnits(BigInt(deposit.seller_amount), decimals)} {tokenSymbol}
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt>Platform fee</dt>
            <dd className="font-mono">
              {formatUnits(BigInt(deposit.fee_amount), decimals)} {tokenSymbol}
            </dd>
          </div>
        </dl>
        <p className="font-mono text-[11px] break-all text-emerald-100/60">
          <ExternalLink className="mr-1 inline h-3 w-3" />
          {signature}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
      <div className="flex items-start gap-2 text-sm text-slate-200">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
        <p>
          Your payment is held by an on-chain escrow program, not by AeroLedger. It is
          released to the operator when the booking completes, and returns to you if it
          does not.
        </p>
      </div>

      {stage.kind === "failed" && (
        <div className="flex items-start gap-2 rounded-xl border border-rose-500/25 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{stage.message}</span>
        </div>
      )}

      <button
        type="button"
        onClick={pay}
        disabled={busy}
        className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {busy && <Loader2 className="h-4 w-4 animate-spin" />}
        {busy ? PROGRESS[stage.kind] : stage.kind === "failed" ? "Try again" : "Pay into escrow"}
      </button>

      {stage.kind === "awaiting-signature" && (
        <p className="text-xs text-slate-400">
          Check the amount in your wallet before approving. It should match the quoted
          total exactly — the program rejects anything else.
        </p>
      )}
    </div>
  );
}
