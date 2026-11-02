/**
 * Driving an EVM escrow deposit from the browser.
 *
 * The shape matches `client.ts` on the Solana side -- authorise, pre-flight,
 * sign, verify -- and the same sentence applies: nothing here is a security
 * control. The browser is the customer's machine. The contract enforces the
 * rules and the backend decides what was actually paid.
 *
 * ## What is different from Solana, and why
 *
 * There is no transaction to assemble. An EIP-1193 wallet builds its own
 * transaction around the calldata we hand it, picks the gas, and signs. So this
 * module is much smaller: calldata, a value, a chain check, and a wait.
 *
 * The chain check is the one thing EVM needs that Solana does not. A Solana
 * transaction is pinned to a cluster by its blockhash, so a devnet transaction
 * simply cannot land on mainnet. An EVM wallet will happily submit to whatever
 * network it is currently on, and the escrow contract at that address on
 * another chain is either absent or somebody else's. The chain id is inside the
 * EIP-712 domain, so the signature would be rejected -- but by then the
 * customer has paid gas to be told nothing useful.
 */

import {
  callValue,
  encodeCreateOrderCall,
  type EvmQuoteInput,
} from "./evm";

/** The slice of EIP-1193 this module uses. */
export type EvmProvider = {
  request(args: { method: string; params?: unknown[] | object }): Promise<unknown>;
};

/** What `POST /payments/escrow/authorize` returns for an EVM quote. */
export type EvmEscrowAuthorization = {
  chain: "evm";
  contract: string;
  chain_id: number;
  rpc_url: string;
  order_id: string;
  order_hash: string;
  buyer: string;
  seller: string;
  payout_wallet: string;
  treasury: string;
  token: string;
  native: boolean;
  quote_signer: string;
  amount: string;
  fee_amount: string;
  expiry: number;
  signature: string;
  quote_id: string;
};

export type EvmBlockReason =
  | "wallet-mismatch"
  | "authorization-expired"
  | "wrong-network"
  | "insufficient-balance";

export type EvmPreflight =
  | {
      state: "blocked";
      reason: EvmBlockReason;
      message: string;
      /** Set for `wrong-network`, so the caller can offer to switch. */
      chainId?: number;
      /** Set for `insufficient-balance`, in wei. */
      shortfall?: bigint;
    }
  | {
      state: "ready";
      to: string;
      data: string;
      /** Wei to attach. Zero on an ERC-20 route. */
      value: bigint;
      /** The contract's storage key, which the backend verifies against. */
      orderHash: string;
    };

/**
 * Gas held back from the balance check.
 *
 * `createOrder` writes a struct of twelve slots and emits an event, so it is
 * expensive by EVM standards -- on the order of 200,000 gas. At a generous
 * 50 gwei that is 0.01 ETH, and the margin is deliberately loose: a buyer told
 * to top up slightly early is better served than one who signs and then cannot
 * afford the gas.
 *
 * Not an estimate from the node, on purpose. `eth_estimateGas` would revert for
 * every one of the reasons this pre-flight is trying to report *before* the
 * wallet opens, and a revert there gives a worse message than a plain
 * comparison does.
 */
const GAS_HEADROOM_WEI = 10_000_000_000_000_000n;

/**
 * How close to expiry an authorization is refused.
 *
 * Longer than the Solana margin because an EVM transaction waits for a block
 * rather than a slot, and a quote with twenty seconds left will routinely
 * expire while it is still in the mempool.
 */
const EXPIRY_MARGIN_SECONDS = 45n;

function quoteFrom(auth: EvmEscrowAuthorization): EvmQuoteInput {
  return {
    orderId: auth.order_id,
    seller: auth.seller,
    token: auth.token,
    amount: BigInt(auth.amount),
    fee: BigInt(auth.fee_amount),
    expiry: BigInt(auth.expiry),
    signature: auth.signature,
  };
}

function blocked(
  reason: EvmBlockReason,
  message: string,
  extra?: { chainId?: number; shortfall?: bigint },
): EvmPreflight {
  return { state: "blocked", reason, message, ...extra };
}

/** `eth_chainId` returns a hex quantity, not a number. */
async function readChainId(provider: EvmProvider): Promise<number> {
  const raw = (await provider.request({ method: "eth_chainId" })) as string;
  return Number(BigInt(raw));
}

async function readBalance(provider: EvmProvider, address: string): Promise<bigint> {
  const raw = (await provider.request({
    method: "eth_getBalance",
    params: [address, "latest"],
  })) as string;
  return BigInt(raw);
}

export type PrepareEvmParams = {
  provider: EvmProvider;
  auth: EvmEscrowAuthorization;
  /** The wallet currently connected, as the checkout sees it. */
  buyer: string;
  /** Injectable for tests. Unix seconds. */
  now?: () => bigint;
};

/**
 * Check what can be checked, then produce the calldata.
 *
 * The ordering is about diagnosis rather than cost: "you are on the wrong
 * network" and "you need more ETH" are different problems, and a buyer who
 * tops up their wallet when the real issue was the network has been sent to do
 * the wrong thing.
 */
export async function prepareEvmEscrowDeposit(
  params: PrepareEvmParams,
): Promise<EvmPreflight> {
  const { provider, auth, buyer } = params;
  const now = params.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));

  // The buyer's address is inside the signed digest, and it is also what the
  // contract derives the order's storage key from. A different wallet produces
  // a different key and a signature over the wrong one.
  if (buyer.toLowerCase() !== auth.buyer.toLowerCase()) {
    return blocked(
      "wallet-mismatch",
      "This payment was authorized for a different wallet. Reconnect the wallet you started checkout with, or request a new quote.",
    );
  }

  if (BigInt(auth.expiry) <= now() + EXPIRY_MARGIN_SECONDS) {
    return blocked(
      "authorization-expired",
      "This price authorization has expired. Request a new quote to continue.",
    );
  }

  const chainId = await readChainId(provider);
  if (chainId !== auth.chain_id) {
    return blocked(
      "wrong-network",
      "Your wallet is on a different network from the one this payment is for.",
      { chainId: auth.chain_id },
    );
  }

  const quote = quoteFrom(auth);
  const value = callValue(quote, auth.native);

  // Only the native route spends the buyer's coin balance on the amount
  // itself; an ERC-20 route still needs coin for gas.
  const needed = value + GAS_HEADROOM_WEI;
  const balance = await readBalance(provider, buyer);
  if (balance < needed) {
    return blocked(
      "insufficient-balance",
      "This wallet does not hold enough to cover the payment and network fees.",
      { shortfall: needed - balance },
    );
  }

  return {
    state: "ready",
    to: auth.contract,
    data: encodeCreateOrderCall(quote, auth.native),
    value,
    orderHash: auth.order_hash,
  };
}

/**
 * Ask the wallet to switch networks.
 *
 * `4902` is EIP-3085's "this chain is unknown to the wallet", which is a
 * different problem from the user declining: one needs the chain added, the
 * other needs them to say yes. Reported separately so the UI can tell them
 * apart.
 */
export async function switchToChain(
  provider: EvmProvider,
  chainId: number,
): Promise<"switched" | "unknown-chain" | "declined"> {
  try {
    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: `0x${chainId.toString(16)}` }],
    });
    return "switched";
  } catch (err) {
    const code = (err as { code?: number })?.code;
    if (code === 4902) return "unknown-chain";
    return "declined";
  }
}

/**
 * Submit the call and wait for it to be mined.
 *
 * The wallet owns gas estimation and nonce management; handing it only `to`,
 * `data` and `value` is deliberate, because every field we set is a field we
 * could set worse than the wallet would.
 */
export async function submitEvmEscrowDeposit(params: {
  provider: EvmProvider;
  from: string;
  prepared: Extract<EvmPreflight, { state: "ready" }>;
  /** Injectable so tests do not wait on real time. */
  waitMs?: (ms: number) => Promise<void>;
  /** How long to wait for a receipt before giving up. */
  timeoutMs?: number;
}): Promise<{ transactionHash: string; orderHash: string }> {
  const { provider, from, prepared } = params;
  const waitMs =
    params.waitMs ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const timeoutMs = params.timeoutMs ?? 180_000;

  const transactionHash = (await provider.request({
    method: "eth_sendTransaction",
    params: [
      {
        from,
        to: prepared.to,
        data: prepared.data,
        // Hex quantity with no leading zeroes, which is what the RPC expects.
        value: `0x${prepared.value.toString(16)}`,
      },
    ],
  })) as string;

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const receipt = (await provider.request({
      method: "eth_getTransactionReceipt",
      params: [transactionHash],
    })) as { status?: string } | null;

    if (receipt) {
      // A mined transaction can still have reverted, and a reverted one has
      // paid gas and escrowed nothing. Treating "mined" as "paid" would hand
      // the backend an order that does not exist.
      if (receipt.status !== undefined && BigInt(receipt.status) === 0n) {
        throw new Error(
          "The escrow transaction was rejected by the contract. Nothing was charged beyond the network fee.",
        );
      }
      return { transactionHash, orderHash: prepared.orderHash };
    }

    if (Date.now() > deadline) {
      // Not a failure: the transaction may still be pending. The backend will
      // see the order whenever it lands, so the honest answer is "we stopped
      // watching", not "it did not work".
      throw new Error(
        `The transaction has not been mined yet. It may still complete — check your wallet for ${transactionHash}.`,
      );
    }
    await waitMs(2_000);
  }
}
