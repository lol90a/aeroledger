// @vitest-environment node
import { describe, expect, it } from "vitest";

import GOLDEN from "../../../../../contracts/ethereum/test/eip712_golden.json";
import {
  prepareEvmEscrowDeposit,
  submitEvmEscrowDeposit,
  switchToChain,
  type EvmEscrowAuthorization,
  type EvmPreflight,
  type EvmProvider,
} from "./evmClient";

const BUYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const CHAIN_ID = 11155111;
const NOW = 1_700_000_000n;

function authorization(over: Partial<EvmEscrowAuthorization> = {}): EvmEscrowAuthorization {
  const i = GOLDEN.createOrderCalldata.input;
  return {
    chain: "evm",
    contract: CONTRACT,
    chain_id: CHAIN_ID,
    rpc_url: "https://rpc.example",
    order_id: i.orderId,
    order_hash: GOLDEN.getOrder.orderHash,
    buyer: BUYER,
    seller: i.seller,
    payout_wallet: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    treasury: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    token: i.token,
    native: true,
    quote_signer: GOLDEN.input.quoteSigner,
    amount: i.amount,
    fee_amount: i.fee,
    // The golden calldata encodes this exact value, so the comparison tests
    // only mean something if the fixture uses it too.
    expiry: Number(i.expiry),
    signature: i.signature,
    quote_id: "00000000-0000-0000-0000-000000000000",
    ...over,
  };
}

type Scripted = EvmProvider & { calls: { method: string; params?: unknown }[] };

/** A scripted EIP-1193 provider that records what it was asked. */
function provider(
  answers: {
    eth_chainId?: string;
    eth_getBalance?: string;
    receipts?: (unknown | null)[];
  } = {},
): Scripted {
  const receipts = answers.receipts ? [...answers.receipts] : [{ status: "0x1" }];
  const calls: { method: string; params?: unknown }[] = [];
  return {
    calls,
    async request({ method, params }) {
      calls.push({ method, params });
      switch (method) {
        case "eth_chainId":
          return answers.eth_chainId ?? `0x${CHAIN_ID.toString(16)}`;
        case "eth_getBalance":
          // Generous by default: 100 ETH.
          return answers.eth_getBalance ?? `0x${(10n ** 20n).toString(16)}`;
        case "eth_sendTransaction":
          return "0xtxhash";
        case "eth_getTransactionReceipt":
          return receipts.length > 1 ? receipts.shift() : receipts[0];
        default:
          throw new Error(`unexpected method ${method}`);
      }
    },
  };
}

const now = () => NOW;

async function prepare(
  over: Partial<EvmEscrowAuthorization> = {},
  p: Scripted = provider(),
  buyer = BUYER,
): Promise<EvmPreflight> {
  return prepareEvmEscrowDeposit({ provider: p, auth: authorization(over), buyer, now });
}

function reason(result: EvmPreflight): string {
  return result.state === "blocked" ? result.reason : "ready";
}

describe("prepareEvmEscrowDeposit", () => {
  it("produces the calldata the contract expects", async () => {
    const result = await prepare();
    if (result.state !== "ready") throw new Error(`blocked: ${result.reason}`);

    expect(result.data).toBe(GOLDEN.createOrderCalldata.native);
    expect(result.to).toBe(CONTRACT);
    expect(result.orderHash).toBe(GOLDEN.getOrder.orderHash);
  });

  it("attaches the amount as value on a native route", async () => {
    const result = await prepare();
    if (result.state !== "ready") throw new Error("blocked");
    expect(result.value).toBe(BigInt(GOLDEN.createOrderCalldata.input.amount));
  });

  it("attaches nothing on an ERC-20 route and calls the other entry point", async () => {
    // createOrderERC20 is not payable: value sent to it reverts, and the
    // tokens are pulled with transferFrom instead.
    const result = await prepare({ native: false });
    if (result.state !== "ready") throw new Error("blocked");
    expect(result.value).toBe(0n);
    expect(result.data).toBe(GOLDEN.createOrderCalldata.erc20);
  });

  it("blocks a wallet the authorization does not name", async () => {
    // The buyer is inside the signed digest and is what the contract derives
    // the storage key from, so another wallet is a different order entirely.
    const result = await prepare({}, provider(), "0x000000000000000000000000000000000000dEaD");
    expect(reason(result)).toBe("wallet-mismatch");
  });

  it("compares wallets without caring about checksum case", async () => {
    expect(reason(await prepare({}, provider(), BUYER.toLowerCase()))).toBe("ready");
  });

  it("blocks an expired authorization before the wallet opens", async () => {
    expect(reason(await prepare({ expiry: Number(NOW) - 1 }))).toBe("authorization-expired");
  });

  it("blocks one that would expire while the transaction is in flight", async () => {
    // An EVM transaction waits for a block, not a slot, so a quote with
    // seconds left routinely expires in the mempool.
    expect(reason(await prepare({ expiry: Number(NOW) + 10 }))).toBe(
      "authorization-expired",
    );
  });

  it("blocks a wallet on the wrong network and says which to use", async () => {
    // The contract at that address on another chain is absent or somebody
    // else owns it, and the chain id is inside the signed domain either way.
    const result = await prepare({}, provider({ eth_chainId: "0x1" }));
    expect(reason(result)).toBe("wrong-network");
    expect(result.state === "blocked" ? result.chainId : 0).toBe(CHAIN_ID);
  });

  it("blocks a wallet that cannot cover the amount plus gas", async () => {
    // Exactly the amount, with nothing left for gas.
    const balance = BigInt(GOLDEN.createOrderCalldata.input.amount);
    const result = await prepare({}, provider({ eth_getBalance: `0x${balance.toString(16)}` }));
    expect(reason(result)).toBe("insufficient-balance");
    expect(result.state === "blocked" && (result.shortfall ?? 0n) > 0n).toBe(true);
  });

  it("still requires gas on an ERC-20 route, where the amount is not in coin", async () => {
    const result = await prepare({ native: false }, provider({ eth_getBalance: "0x0" }));
    expect(reason(result)).toBe("insufficient-balance");
  });

  it("checks the network before the balance", async () => {
    // A buyer told to top up when the real problem was the network has been
    // sent to do the wrong thing.
    const p = provider({ eth_chainId: "0x1", eth_getBalance: "0x0" });
    expect(reason(await prepare({}, p))).toBe("wrong-network");
    expect(p.calls.some((c) => c.method === "eth_getBalance")).toBe(false);
  });
});

describe("submitEvmEscrowDeposit", () => {
  const ready = {
    state: "ready" as const,
    to: "0xcontract",
    data: "0xdata",
    value: 1_500_000_000_000_000_000n,
    orderHash: "0xhash",
  };

  it("sends the call and returns once it is mined", async () => {
    const p = provider();
    const result = await submitEvmEscrowDeposit({ provider: p, from: BUYER, prepared: ready });

    expect(result.transactionHash).toBe("0xtxhash");
    expect(result.orderHash).toBe("0xhash");

    const sent = p.calls.find((c) => c.method === "eth_sendTransaction");
    const [tx] = sent?.params as Record<string, string | undefined>[];
    if (!tx) throw new Error("no transaction was sent");
    expect(tx.from).toBe(BUYER);
    expect(tx.to).toBe("0xcontract");
    // A hex quantity: not decimal, not zero-padded.
    expect(tx.value).toBe("0x14d1120d7b160000");
    // Gas and nonce are the wallet's business. Every field we set is one we
    // could set worse than it would.
    expect(tx.gas).toBeUndefined();
    expect(tx.nonce).toBeUndefined();
  });

  it("treats a reverted transaction as a failure, not a payment", async () => {
    // A mined transaction can still have reverted, having paid gas and
    // escrowed nothing. Reporting that as paid would hand the backend an
    // order that does not exist.
    const p = provider({ receipts: [{ status: "0x0" }] });
    await expect(
      submitEvmEscrowDeposit({ provider: p, from: BUYER, prepared: ready }),
    ).rejects.toThrow(/rejected by the contract/);
  });

  it("polls until the receipt appears", async () => {
    const p = provider({ receipts: [null, null, { status: "0x1" }] });
    const result = await submitEvmEscrowDeposit({
      provider: p,
      from: BUYER,
      prepared: ready,
      waitMs: async () => {},
    });
    expect(result.transactionHash).toBe("0xtxhash");
  });

  it("gives up without claiming the payment failed", async () => {
    // Still pending is not the same as failed: the backend will see the order
    // whenever it lands.
    const p = provider({ receipts: [null] });
    await expect(
      submitEvmEscrowDeposit({
        provider: p,
        from: BUYER,
        prepared: ready,
        waitMs: async () => {},
        timeoutMs: -1,
      }),
    ).rejects.toThrow(/may still complete/);
  });
});

describe("switchToChain", () => {
  it("reports a successful switch", async () => {
    const p: EvmProvider = {
      async request() {
        return null;
      },
    };
    expect(await switchToChain(p, CHAIN_ID)).toBe("switched");
  });

  it("distinguishes an unknown chain from a declined prompt", async () => {
    // 4902 needs the chain added to the wallet; a decline needs the user to
    // say yes. Reporting the wrong one sends them into the wrong menu.
    const unknown: EvmProvider = {
      async request() {
        throw Object.assign(new Error("unknown"), { code: 4902 });
      },
    };
    const declined: EvmProvider = {
      async request() {
        throw Object.assign(new Error("denied"), { code: 4001 });
      },
    };
    expect(await switchToChain(unknown, CHAIN_ID)).toBe("unknown-chain");
    expect(await switchToChain(declined, CHAIN_ID)).toBe("declined");
  });

  it("asks for the chain id as a hex quantity", async () => {
    let seen: unknown;
    const p: EvmProvider = {
      async request({ params }) {
        seen = params;
        return null;
      },
    };
    await switchToChain(p, CHAIN_ID);
    const [asked] = seen as { chainId: string }[];
    expect(asked?.chainId).toBe("0xaa36a7");
  });
});
