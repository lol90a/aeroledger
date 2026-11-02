# AeroLedger

[![CI](https://github.com/lol90a/aeroledger/actions/workflows/ci.yml/badge.svg)](https://github.com/lol90a/aeroledger/actions/workflows/ci.yml)

A crypto-native commerce platform for private aviation charter and tokenized
luxury assets. A buyer browses a catalogue, books a flight or an asset share, and
pays in cryptocurrency; the backend prices the order itself, verifies the transfer
on-chain, and only then marks the order settled.

The interesting part of this system is not the checkout UI — it is the rule that
**the client never decides what it pays and never decides whether it paid**. Every
amount is computed server-side from an authoritative catalogue price and a recorded
exchange rate, and every settlement is confirmed by reading the chain. The client
contributes one identifier and nothing else: a transaction hash on the direct
path, an order reference on the escrow path — an account address on Solana, a
storage key on EVM. Neither is believed; both are looked up.

---

## How it works

A purchase moves through five server-controlled steps. The client supplies a
booking id and, at the end, a transaction hash. Nothing else it sends affects the
amount.

| Step | Endpoint | What the server does |
|---|---|---|
| 1. Book | `POST /api/bookings` | Reads the catalogue price for the flight or asset. The request body carries no price. |
| 2. Quote | `POST /api/payments/quote` | Converts to crypto using a live rate it fetches and records, with the markup and service fee applied. Returns an expiring quote. |
| 3. Approve | `POST /api/payments/quote/accept` | The client echoes back the exact figures it displayed. If either has moved, the server refuses and returns the new quote rather than charging an amount the user never saw. |
| 4. Initialize | `POST /api/payments/init` | Returns the receiving address, the exact amount in base units, and the network. |
| 5. Confirm | `POST /api/payments/confirm` | Looks the hash up on-chain at finalized commitment, checks the recipient and the amount, and settles only on a match. |

Properties this buys:

- **Amounts are integers in the token's smallest unit** (wei, lamports, satoshis)
  end to end. No float touches a balance comparison.
- **A price change between browsing and paying is surfaced**, not silently applied.
- **A transaction hash settles at most one booking.** Replay is rejected at the
  database level by a unique constraint, not only in application code.
- **Underpaying, paying the wrong address, or inventing a hash all fail**, and the
  error distinguishes *has not settled yet* from *will never settle* — so the UI
  never tells a user to wait for something that cannot happen.
- **The server decides the network.** Chain id (EVM) and RPC endpoint (Solana) are
  served from configuration, so the wallet cannot sign on a different cluster from
  the one the verifier reads. Startup refuses a configuration that mixes mainnet
  and test networks.


### Paying into escrow instead

Steps 4 and 5 above hand money to an address we publish and ask the customer to
trust us with it. A deployment can offer a second route where they do not have
to: the funds go to an on-chain escrow contract that will only release them to
the registered operator, or return them to the buyer once a timeout passes.

There are two escrows, one per ecosystem, and both are wired: an Anchor program
on Solana and a Solidity contract on Ethereum or BSC. Which one settles a
booking comes from the quote the customer accepted, never from anything the
browser asks for.

| Step | Endpoint | What the server does |
|---|---|---|
| 4a. Authorise | `POST /api/payments/escrow/authorize` | Signs the already-accepted price with a key the contract has been told to trust. Short-lived, bound to one buyer wallet, and tagged with the chain that will settle it. |
| — | *(browser)* | Solana: wraps the SOL, carries the signature in a native Ed25519 instruction, and calls `create_order`. EVM: encodes the signed quote into `createOrder` calldata and hands it to an EIP-1193 wallet. Either way, one transaction signed by the buyer. |
| 5a. Verify | `POST /api/payments/escrow/verify` | Reads the order back off the chain and decides whether it settles this booking. |

The backend never builds, signs or submits an escrow transaction. It authorises a
price and checks what happened. Only the buyer's wallet can move the buyer's
tokens, which is what makes this escrow rather than custody.

Three things are worth stating explicitly, because each is a question the design
has to answer and getting any of them wrong is a money bug:

- **The buyer cannot name their own price.** Each contract requires a signature
  from a key it records — `Config.quote_authority` on Solana, `quoteSigner` on
  EVM — over a commitment naming the order, the buyer, the seller, the asset and
  the figures. The private half never leaves the backend process. On EVM that
  commitment is an EIP-712 digest, so it is also bound to one chain id and one
  contract address: a signature authorising a testnet payment cannot authorise
  the same payment on mainnet.
- **Presenting somebody else's escrow order does not pay your booking.** That is
  the attack verification exists for, and it is not a forged account — it is a
  real, correctly funded order that simply belongs elsewhere. The order's own id
  must be the one this booking's quote derives, and every figure and counterparty
  is compared against the accepted quote.
- **A wrapped-SOL account the buyer already had is never closed.** Closing a
  native token account forwards its entire lamport balance to the destination,
  unwrapping whatever was in it. Only an account the payment transaction creates
  is closed again, to return its rent.

#### After the deposit

Everything above is driven by the buyer. Nothing after it is. An order is
confirmed by the seller, completed by the seller or an admin, and refunded by
the seller, an admin, or the buyer themselves once the timeout passes — none of
which goes through this backend, because none of it needs to.

So a sweep re-reads open orders and mirrors what it finds. The case that matters
is a **refund**: the money has gone back to the buyer and the booking is not paid
for, and without the sweep nothing would ever say so.

Two tables, deliberately, because they answer different questions:

| | answers |
|---|---|
| `payments.status` | has the customer settled this booking? |
| `escrow_orders.chain_status` | where is the money right now? |

A refunded order that still reads as a paid booking is the bug that separation
prevents. Every column in `escrow_orders` except the local timestamps is a
mirror of state the chain owns; nothing is written that was not first read back
from a contract-owned account and checked against the quote it claims to settle.

Settlement windows are split into two, on both chains:

```text
t <= settlement_deadline   seller settles or refunds; owner/admin too
t <= timeout_deadline      owner/admin only, arbitrating a late settlement
t >  timeout_deadline      buyer only, exiting unilaterally
```

A single deadline left settlement and the buyer's unilateral exit live at the
same instant, so transaction ordering decided who got the money. Split, at any
moment either settlement is possible or the exit is, never both.

Escrow is opt-in **per chain**: a deployment may escrow Solana, an EVM chain,
both, or neither. `payment_options` reports `escrow_available` per route, so the
checkout never offers a route that would fail. Bitcoin never has one — there is
no contract, and offering it would be offering a payment method that cannot
exist.

#### Configuring it

Each chain is configured independently, and each is all-or-nothing: a partial
configuration refuses to start, because it would issue authorizations the
contract rejects for reasons no error message connects back to a missing
variable.

**Solana** — all five together:

| Variable | What it is |
|---|---|
| `ESCROW_PROGRAM_ID` | The deployed escrow program. |
| `ESCROW_SELLER` | `Merchant.authority` — the seller orders are created against. |
| `ESCROW_PAYOUT_WALLET` | `Merchant.payout_wallet`, snapshotted into each order. |
| `ESCROW_TREASURY` | `Config.treasury`, which receives the platform fee. |
| `ESCROW_QUOTE_AUTHORITY_SEED` | **Secret.** Base58 seed for the signing key. |
| `ESCROW_MINT` | Optional; defaults to wrapped SOL. |

The seller, payout wallet and treasury must already be registered on-chain, and
the payout wallet and treasury must each already have an associated token account
for the mint — the program does not create them, deliberately, so that funds can
never enter escrow for a seller with nowhere to be paid.

**Ethereum / BSC** — all seven together:

| Variable | What it is |
|---|---|
| `ESCROW_EVM_CONTRACT` | The deployed `AeroLedgerEscrow` address. |
| `ESCROW_EVM_CHAIN_ID` | Inside the EIP-712 domain, so a wrong value signs for a different network entirely. |
| `ESCROW_EVM_RPC_URL` | Where the backend reads orders from. |
| `ESCROW_EVM_SELLER` | The registered merchant. |
| `ESCROW_EVM_PAYOUT_WALLET` | Snapshotted into each order at creation. |
| `ESCROW_EVM_TREASURY` | Receives the platform fee. |
| `ESCROW_EVM_QUOTE_SIGNER_KEY` | **Secret.** `0x`-prefixed 32-byte private key. |
| `ESCROW_EVM_TOKEN` | Optional; defaults to the zero address, meaning the native coin. |
| `ESCROW_EVM_BLOCK_TAG` | Optional; defaults to `finalized`. Only lower it for a local chain. |

Reads default to `finalized` on purpose. A re-org can unmake a transaction that
`latest` already reported, and settling a booking on a block that is later
orphaned releases a service against a payment that no longer exists.

Both signing keys are hot keys, rotatable without touching either contract's
admin — which is why both contracts keep the quote signer separate from the
owner. Generate throwaway ones for local work; never reuse a wallet key.

---

## Architecture

The backend follows Clean Architecture, and the dependency rule is enforced rather
than aspired to: `domain/` and `application/` import nothing from the outer layers
and contain no framework types.

```
interfaces/      HTTP handlers, middleware, error mapping      (Actix)
     |
application/     Use cases: create_quote, accept_quote,        (no framework)
     |           init_payment, confirm_payment,
     |           authorize_escrow, verify_escrow_deposit,
     |           reconcile_escrow_orders
domain/          Entities, value objects, repository and       (no framework)
     |           gateway traits — the ports
infrastructure/  Postgres repositories, blockchain gateways,
                 price oracle, config, workers                 (implements the ports)
```

Use cases are generic over the repository and gateway traits, so the direction of
dependency points inward at compile time. Each use case exposes exactly one
`execute`. Traits are kept small — most have one or two methods — so an
implementation is never forced to stub behaviour it does not have.

Two value objects carry most of the safety: `Money` (integer cents, no float
constructor) and `Network` (which realm an endpoint belongs to, used to reject a
deployment pointed at two different networks at once).

### Repository layout

```
src/                        Rust backend
  domain/                   entities, value objects, ports, repository traits
  application/              use cases and DTOs
  infrastructure/           Postgres, blockchain gateways, pricing, config, workers
  interfaces/http/          handlers, middleware, auth
  bin/migrate.rs            standalone migration runner
Frontend/                   React 18 + TypeScript + Vite
  src/app/pages/            routed pages
  src/app/components/       shared components (ui/ is shadcn/ui)
  src/app/lib/              API client, wallet access, cart, presentation helpers
  src/app/lib/escrow/       escrow wire format: PDAs and Borsh (Solana),
                            ABI and EIP-712 calldata (EVM), wrapped SOL
contracts/solana/           Anchor escrow program + TypeScript integration suite
contracts/ethereum/         Solidity escrow contract + Hardhat suite
migrations/                 complete_schema.sql, applied at startup
tests/                      backend integration tests against real Postgres
```

### Stack

**Backend** — Rust 2021, Actix Web 4, `deadpool-postgres`, JWT auth, `reqwest`
blockchain gateways for EVM (Etherscan V2), Solana JSON-RPC and Bitcoin.

**Frontend** — React 18, TypeScript, Vite, React Router, Tailwind, Radix
primitives via shadcn/ui, Motion. Wallets are reached through the injected
EIP-1193 and Solana provider interfaces directly, with no wallet-adapter
dependency tree.

**Contracts** — Anchor 0.29 (Solana) and Solidity 0.8.24 with OpenZeppelin
(EVM). Both implement a buyer/seller/treasury escrow with server-signed price
quotes.

---

## Running it locally

Three processes, in this order.

### 1. Database

```bash
docker compose up -d postgres
```

Dev Postgres, published on host port **5435** so it does not collide with another
instance. The schema is applied by the backend at startup.

### 2. Backend

```bash
cp .env.example .env     # then set DATABASE_URL and a real 32+ character JWT_SECRET
cargo run --bin areo_ledger
```

`--bin areo_ledger` is required: the crate ships two binaries, the server and the
standalone `migrate` runner, so a bare `cargo run` cannot choose.

Migrations run at startup while `RUN_MIGRATIONS=true`. That combination is rejected
when `APP_ENV=production`, where migrations are a deployment step: `cargo run --bin
migrate`.

### 3. Frontend

```bash
cd Frontend
echo "VITE_API_BASE_URL=http://127.0.0.1:8081" > .env
npm install
npm run dev
```

Vite serves on **http://127.0.0.1:3001** with `strictPort`, so it fails loudly
rather than moving to another port and breaking CORS.

### Three values that must agree

A mismatch here is the usual cause of a dead checkout with CORS errors in the
console.

| Value | Set in | Must equal |
|---|---|---|
| `PORT` | root `.env` | the port in `VITE_API_BASE_URL` |
| `VITE_API_BASE_URL` | `Frontend/.env` (not committed) | `http://HOST:PORT` of the backend |
| `FRONTEND_URL` | root `.env` | the Vite origin — it is the CORS allow-list entry |

Check the stack is up:

```bash
curl http://127.0.0.1:8081/api/health
```

---

## Testing

Six suites, every one of them run by CI on every push and pull request.

```bash
# Backend unit tests
cargo test --lib

# Backend integration tests against a real Postgres (not a mock)
docker run -d --name pg-test -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16-alpine
TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres \
  cargo test --test integration_postgres -- --ignored --test-threads=1

# Solana program unit tests
cd contracts/solana && cargo test --lib

# Solana integration tests against a local validator
cd contracts/solana && yarn install --frozen-lockfile && anchor test

# EVM contract tests
cd contracts/ethereum && npm ci && npx hardhat test

# Frontend unit tests, types and production build
cd Frontend && npm test && npx tsc --noEmit && npx vite build
```

The Anchor suite needs an exact toolchain: **Anchor 0.29.0**, **Solana 1.18.26**
and **Node >= 20.18**. Earlier Solana releases ship a rustc too old for the pinned
`solana-program`, and Node 18 is refused by `@solana/codecs-*`. `Cargo.lock` is
committed in lockfile v3 format and `yarn.lock` is committed, so neither set of
dependencies can drift.

The Solana program id in the repository is the Anchor template placeholder. Before
any deploy, generate a real keypair and sync the id — `Anchor.toml` carries the
exact command, and `anchor keys sync` must not be used (it updates only one of the
three `[programs.*]` entries per run).

### Golden vectors

Three independent implementations have to agree about the exact bytes a price
commitment covers: the contract, the backend that signs it, and the browser that
submits it. A disagreement cannot create money — the contract recomputes the
commitment and recovers a different signer — but it makes every payment fail
with an error naming the *key* rather than the *message*, which is a bad
afternoon.

So each side is checked against a vector generated by the contract itself:

```bash
# Solana: the browser's create_order bytes, checked by the Anchor suite against
# Anchor's own encoder.
cd Frontend && npx vite-node scripts/emit-escrow-fixture.ts

# EVM: the order hash, EIP-712 domain, quote digest, a real getOrder response and
# the createOrder calldata — checked by the Rust backend and the browser.
cd contracts/ethereum && npx hardhat run scripts/emit-eip712-golden.js
```

Only needed when a wire format changes. The committed copies are asserted to be
current, so a stale one fails a suite rather than rotting quietly.

---

## Deployment

```bash
cp .env.production.example .env.production   # fill in real values; never commit it
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

`Dockerfile` builds the backend, `Frontend/Dockerfile` and `Frontend/nginx.conf`
build and serve the frontend with an API reverse proxy.

Configuration is validated at startup, and production fails closed: it rejects a
weak or placeholder `JWT_SECRET`, a localhost `FRONTEND_URL`, startup migrations,
manual payment verification, a malformed wallet address for any configured chain,
and any mix of mainnet and test networks.

---

## Status

Stated plainly, because a reader would otherwise reasonably assume otherwise:

- **Direct payment with on-chain verification is the default path everywhere**,
  and the only one on Bitcoin.
- **Both escrows are wired end to end**: the browser builds and signs the
  transaction, and the backend authorises the price and verifies the resulting
  order against the chain. Opt-in per chain, and offered alongside the direct
  transfer, never instead of it.
- **Neither escrow has been deployed to a public network by the author**, and no
  testnet funds have been spent. The Solana one is exercised against a local
  validator on every CI run; the EVM one is exercised against Hardhat.
- **No browser wallet has signed one of these, by the author.** Neither Phantom
  nor MetaMask. Both interfaces are implemented and exercised against scripted
  providers that play the wallet's part, which covers every line on both sides of
  the wallet call and nothing of the extension's own. The bytes those calls carry
  *are* proven: against a real validator for Solana, and byte-for-byte against
  ethers for EVM. What is unproven is the extension's behaviour and the plumbing
  around it.
- **`infrastructure/blockchain/retry.rs`** implements a retrying gateway with a
  circuit breaker. It is tested but not currently constructed in `main.rs`; the
  confirm endpoint is retried by the client instead.
- **SPL-token settlement is unimplemented on the _direct_ Solana path.**
  `confirm_payment` verifies native SOL transfers only, because a half-right
  reading of a token transfer is worse than refusing the route. The escrow path
  is unaffected and in fact moves wrapped SOL — the contract does the accounting
  there, and the backend reads the result rather than parsing a transfer.
- **The frontend's tests cover logic, not rendering.** Base-unit conversion,
  settlement-status mapping, cart identity, JWT handling, and the whole escrow
  wire format on both chains — the quote message, account ordering, Borsh and
  ABI encoding, wrapped-SOL planning, account decoding. There are no component
  or end-to-end tests; rendering is covered by type-checking and a production
  build.
