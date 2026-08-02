# Federation deployment (Phase 7d)

How a validator operator runs their half of the bridge. See
[ADR-0016](adr/0016-federation-signature-exchange.md) for why it is shaped
this way.

## Two processes, one key

Each operator runs **two** processes:

> **Phase 7f:** withdrawals are now marked `Completed` on Solana under an
> M-of-N federation proof, so a relayer starting from an **empty database**
> can tell paid from unpaid by reading chain state
> ([ADR-0018](adr/0018-withdrawal-completion.md)). Completion is
> **irreversible**: there is no un-complete instruction, deliberately.

| process | holds | listens | talks to |
|---|---|---|---|
| `signer-server` | **the** validator ed25519 key **and this operator's single vault key** — the only keys in the deployment | mTLS gRPC | its **own** Solana RPC and its **own** Goldcoin RPC |
| `glc-relayer` | no validator key, no vault key | nothing | Goldcoin RPC, Solana RPC, and every peer's `signer-server` |

The relayer builds, assembles, submits, and pays fees; it cannot authorize
anything. Authority lives only in the signer processes, and only signatures
cross the network. A fully compromised relayer can waste fees and stall
progress — it cannot mint **or move vault funds**, because every signer
independently re-derives what it is asked to sign and refuses anything it did
not derive itself.

> **Phase 7e:** the Goldcoin payout path is now distributed too. The
> operator's Goldcoin node no longer needs enough vault keys to satisfy the
> M-of-N — it holds **one**, in the signer process. See
> [ADR-0017](adr/0017-distributed-payout-signing.md).

Both processes read the same SQLite file. That is deliberate: the signer's
answers come from **this operator's own** chain observations, written by
their own indexer. A signer must never be pointed at a database some other
party populates.

## Certificates

Generate one CA for the federation, and one leaf certificate per process
(both the signer and the relayer need one — the relayer authenticates
itself to peers just as they authenticate to it).

- All leaves must be issued for the **same name**, configured as
  `GLC_FEDERATION_TLS_DOMAIN` and pinned by every relayer. Peers are
  identified by their on-chain key, not by their hostname, so per-host names
  would buy nothing and complicate rotation.
- Only the federation CA is trusted. The public web PKI is not: without
  pinning, any publicly issued certificate for a matching name would be
  accepted at the transport layer.
- Rotating a certificate does **not** change which validator a peer is:
  identity at the application layer is the on-chain ed25519 key. Rotate
  freely; the peer list does not change.

A missing or unreadable certificate file aborts startup. It never degrades
to running without authentication.

## `signer-server` configuration

| variable | meaning |
|---|---|
| `GLC_SIGNER_VALIDATOR_KEYPAIR_PATH` | this validator's ed25519 key. **Singular** — a process holding several federation identities is the topology Phase 7c retired |
| `GLC_SIGNER_LISTEN_ADDR` | `host:port` to serve on |
| `GLC_FEDERATION_CA_CERT_PATH` | the federation CA; client certificates are required against it |
| `GLC_SIGNER_TLS_CERT_PATH` / `GLC_SIGNER_TLS_KEY_PATH` | this process's leaf certificate and key |
| `GLC_DB_PATH` | this operator's own indexer database |
| `GLC_PROGRAM_ID_HEX` | the on-chain program, hex-encoded |
| `GLC_SOLANA_RPC_URL` | for observing the validator epoch |
| `GLC_SOLANA_COMMITMENT` | `processed` \| `confirmed` \| `finalized`; no default, by design |

### Vault signing (Phase 7e) — optional, but all-or-nothing

Set these only if this signer holds a vault key. If `GLC_VAULT_REDEEM_SCRIPT_HEX`
is unset the signer serves mint requests only and **refuses every payout
request**; if it is set, all of the following are required.

| variable | meaning |
|---|---|
| `GLC_VAULT_REDEEM_SCRIPT_HEX` | the vault's redeem script |
| `GLC_SIGNER_VAULT_INDEX` | this signer's position in the vault's ordered signer list |
| `GLC_SIGNER_VAULT_KEY_PATH` | file containing this signer's WIF vault key — **one key** |
| `GLC_SIGNER_GLC_RPC_URL`, `GLC_SIGNER_GLC_RPC_USER`, `GLC_SIGNER_GLC_RPC_PASSWORD` | **this signer's own Goldcoin node**, never the relayer's |

### Completion attestation (Phase 7f)

`GLC_WITHDRAWAL_CONFIRMATION_DEPTH` and `GLC_PROTOCOL_VERSION` enable the
completion arm. Without the depth set, the signer **refuses every completion
request** and logs a warning at startup.

There is deliberately **no separate completion depth** (ADR-0018 Q2): the
depth that governs treating a payout as confirmed locally is the same one
that gates a completion signature. Two knobs could be configured
inconsistently, and the dangerous direction is silent — an operator could
complete on-chain something they do not consider confirmed locally, and
nothing would report the contradiction.

The completion arm uses the **same** Goldcoin node as the payout arm, and
for the same reason: a completion attestation is the last word on whether a
payment happened, so inheriting the requester's view would make the check
circular.

Startup **proves** the key on disk is the key the vault expects at
`GLC_SIGNER_VAULT_INDEX`, and aborts on any mismatch. A misconfigured
operator cannot silently participate — that check is what makes it safe to
keep the identity-to-position mapping in configuration rather than on-chain
(ADR-0017 E1).

> ### The signer's Goldcoin node MUST NOT be the relayer's
>
> This is a **hard requirement**, not a tuning choice (ADR-0017 E2).
>
> A signer validates a payout against its **own** UTXO view. That is the
> only defence that exists: the legacy Goldcoin sighash does **not** commit
> to input amounts, so a signature proves nothing about what an input was
> worth. A signer pointed at the relayer's node inherits the requester's
> view of the chain and the check becomes circular.
>
> The process cannot detect a shared endpoint, so it logs the Goldcoin RPC
> URL at startup. Check it in deployment review.

Startup **fails closed**: it aborts unless every value is present and valid,
the TLS material loads, and the on-chain validator epoch can actually be
read. A signer that has never observed the epoch has nothing meaningful to
compare a request against.

At runtime the epoch is re-polled every 10s. If polling fails for longer
than 60s the view goes stale and **every** request is refused until the link
recovers — a validator that cannot see the chain cannot tell a current epoch
from a superseded one, and must not authorize under a federation revision it
may have fallen behind.

## `glc-relayer` federation configuration

| variable | meaning |
|---|---|
| `GLC_FEDERATION_PEERS` | comma-separated `base58pubkey@uri` |
| `GLC_FEDERATION_CA_CERT_PATH` | the federation CA |
| `GLC_RELAYER_TLS_CERT_PATH` / `GLC_RELAYER_TLS_KEY_PATH` | this relayer's client certificate and key |
| `GLC_FEDERATION_TLS_DOMAIN` | the name peer certificates must be issued for |
| `GLC_FEDERATION_TLS` | set to `off` for loopback/regtest only; logs a warning every start |
| `GLC_VAULT_SIGNER_MAP` | `index:base58pubkey,...` — which validator holds which vault position (Phase 7e) |
| `GLC_RELAYER_VALIDATOR_PUBKEY` | **this** relayer's federation identity (Phase 7g) |
| `GLC_PAYOUT_BUILD_TIMEOUT_SECS` | failover: seconds before a non-designated operator may build (default 120) |
| `GLC_MINT_SUBMIT_TIMEOUT_SECS` | failover: seconds before a non-designated operator may submit a mint (default 60) |

`GLC_VAULT_SIGNER_MAP` is validated against the configured redeem script at
startup and **fails closed**: every vault position must be mapped, no
position may be claimed twice, and no validator may hold two positions. A
gap would make some designated quorum resolve to nobody and look like a
permanent outage; one validator holding two positions would let it satisfy
an M-of-N by itself, which is the entire property the vault exists to
prevent.

The pubkey in each peer entry is the on-chain identity that endpoint must
answer as. A response claiming any other identity is discarded even if its
TLS handshake was perfect, so a compromised endpoint cannot impersonate
another member.

The peer list must not contain this validator's own identity, and must not
contain duplicates. Both are rejected at startup: either would inflate
apparent agreement by counting one party twice.

> **Note:** `GLC_SOLANA_VALIDATOR_KEYPAIR_PATHS` no longer exists. The
> relayer holds no validator key; configuring it with paths to them invited
> operators to place federation key material in the wrong process.

## Running several relayers at once (Phase 7g)

`GLC_RELAYER_VALIDATOR_PUBKEY` states which federation member this relayer
acts as. It is **never derived**, and startup fails closed if it appears in
`GLC_FEDERATION_PEERS` (peers are the *others*) or is absent from
`GLC_VAULT_SIGNER_MAP` (which is what gives this relayer its operator index).

Work is assigned by arithmetic — `index mod N` — so every operator computes
the same answer without exchanging a message. There is no election, no lock,
and no shared database.

**Only the designated operator builds a payout.** Others stay passive: they
do not build and therefore do not reserve UTXOs, then adopt the designated
builder's proposal when asked to sign it — after independently validating
every field against their own state. This is not politeness. Phase 7g
measured two operators building *different* transactions purely because they
observed withdrawals in a different order, and speculative reservation was
the cause ([ADR-0019](adr/0019-multi-relayer-operation.md) §2.1).

If the designated operator is down, the others take over after the failover
window, so one dead operator cannot strand a withdrawal.

> ### Duplicate payouts are NOT harmless
>
> Duplicate *mints* are — the claim PDA's `init` prevents a double-mint and
> only fees are wasted. Duplicate *payouts* are not: Phase 7g measured two
> operators paying the same withdrawal twice. ADR-0014 §10 previously said
> otherwise and has been corrected in place (§10.1).
>
> Three things stop it, in order: Phase 7e's signer check (**primary**),
> Phase 7f's completion plus the discovery filter, and Phase 7g's
> pre-broadcast on-chain status check. The first lives in the *signer*
> process — a different process from the executor that would cause the harm.

## Health and metrics (Phase 7h)

Set `GLC_OPS_LISTEN_ADDR` to expose two read-only endpoints:

| path | purpose |
|---|---|
| `/health` | one line per invariant; **503** when any is breached |
| `/metrics` | Prometheus text exposition |

The relayer **exposes state and pages nobody**. There is no SMTP, PagerDuty,
webhook, or vendor SDK in it, and it holds no alerting credentials. Point
your existing uptime monitoring at `/health` — a breach turns it 503.

> ### Bind it privately
>
> There is **no authentication**, because adding one would mean this process
> holding another secret. The endpoint reveals balances, supply and
> per-state counts. Bind it to a loopback or private interface behind your
> own proxy. The relayer logs the bind address at startup with a warning so
> a mistake is visible in review.
>
> Leaving `GLC_OPS_LISTEN_ADDR` unset is allowed but logged loudly: a bridge
> nobody can observe should not be live.

### The two numbers that must be zero

| metric | meaning |
|---|---|
| `glc_solvency_breach_atomic` | wrapped supply beyond `deposits − payouts`. Measured to have **zero normal slack**, so any value here is real |
| `glc_vault_unexplained_drift_atomic` | vault shortfall that recorded fees do **not** explain |

### The number that grows on purpose

`glc_vault_fee_drift_atomic` tracks `glc_vault_fees_paid_atomic`. ADR-0013 D3
makes the vault absorb payout fees, so the vault sits below the backing bound
by the cumulative fee and **that gap grows with every payout**. It is not a
solvency failure ([ADR-0020](adr/0020-solvency-monitoring-and-fee-drift.md)) —
it is the amount you replenish from an external fee reserve. Watch its slope,
not its existence.

## What a peer's answer means

| outcome | meaning | retry? |
|---|---|---|
| signature | that validator independently derived the same bytes | — |
| **refusal** | that validator's view of the chain **disagrees with yours** | **no** — asking again gets the same answer |
| payout shortfall | a designated signer did not answer | yes, but see below |
| completion shortfall | peers have not yet confirmed the payout at depth | yes — ordinary, not an alarm |
| unavailable | unreachable, timed out, throttled, or answered unusably | yes, next tick |

A refusal is an alarm, not noise. It means two operators' independent views
of the chain have diverged, which is a bug, an outage, or an attack. Falling
short of threshold, by contrast, is an ordinary outcome that the next tick
retries.

**Payouts differ in one important way.** Only the *designated* quorum is
asked, because the Goldcoin txid depends on which quorum signs. If a
designated signer stays unavailable, the payout does **not** silently move to
another signer — it waits until an operator performs an explicit, audited
quorum reassignment (ADR-0015). That is deliberate: substituting a signer
would change the txid, and the txid is what the recovery model reconciles
against.

## Operational bounds

- **per-peer timeout** 5s, **round ceiling** 20s. One slow peer cannot stall
  a mint that the others were ready to authorize.
- **rate limit** 30 burst, 10/s sustained, per peer. The burst allowance
  matters: a relayer catching up after a restart legitimately asks about
  every pending deposit at once.
- Collection **stops as soon as threshold is reached**, and asks **every**
  peer rather than only the first M, so one dead peer does not cost a round.

## Verifying a deployment

The transport is covered end-to-end in
`relayer/tests/federation_transport.rs`, which stands up real servers with
real certificates and proves — by observation, not inspection — that a
client with no certificate, a client certificate from another CA, and a
server certificate from another CA are all rejected, and that a peer
answering as a different validator is discarded despite a valid handshake.

Run it before trusting a change to this path:

```
cd relayer && cargo test --test federation_transport
```

---

# Configuration reference

**Verified against the binaries.** `relayer/tests/deployment_config.rs`
asserts on every CI run that every variable each binary reads appears here,
and that nothing here has stopped being read. Phases 7e–7i added twelve
variables that this document did not mention at all until Phase 7j — an
operator deploying from the previous version got a federation that silently
refused governance actions and vault sweeps.

Every variable is `GLC_`-prefixed. **Required means the process refuses to
start without it** — there are no defaults for anything that carries a
security or economic decision (owner decision U6).

## Shared by every process

These must be **identical across all three binaries and all operators**. A
disagreement here is not a misconfiguration that shows up as an error; it is
two honest operators computing different canonical messages and refusing each
other's proposals.

| variable | meaning |
|---|---|
| `GLC_PROGRAM_ID_HEX` | the bridge program, 32 hex-encoded bytes |
| `GLC_PROTOCOL_VERSION` | bound into every canonical message |
| `GLC_SOLANA_RPC_URL`, `GLC_SOLANA_COMMITMENT` | this operator's own Solana access |
| `GLC_VAULT_REDEEM_SCRIPT_HEX`, `GLC_VAULT_ADDRESS`, `GLC_VAULT_CHANGE_ADDRESS` | the P2SH vault; the address is re-derived from the script and a mismatch is refused at startup |
| `GLC_VAULT_MIN_CONFIRMATIONS`, `GLC_WITHDRAWAL_CONFIRMATION_DEPTH` | how deep is deep enough, on the vault side and the payout side |
| `GLC_WITHDRAWAL_DISCOVERY_COMMITMENT` | must be `finalized`; nothing else is accepted (ADR-0013 D5) |
| `GLC_PAYOUT_FEE_RATE_PER_KB`, `GLC_PAYOUT_DUST_THRESHOLD_ATOMIC`, `GLC_PAYOUT_MAX_INPUTS`, `GLC_PAYOUT_RESERVATION_TIMEOUT_SECS` | payout construction policy; a signer checks an adopted proposal against **its own** copy, so these must match |
| `GLC_FEDERATION_CA_CERT_PATH` | the pinned federation CA |

## `glc-relayer`

Holds no validator key and no vault key.

| variable | required | meaning |
|---|---|---|
| `GLC_DB_PATH` | yes | this operator's own SQLite database |
| `GLC_RPC_URL`, `GLC_RPC_USER`, `GLC_RPC_PASSWORD` | yes | this operator's Goldcoin node |
| `GLC_CONFIRMATION_DEPTH` | yes | deposit confirmation depth |
| `GLC_MAX_REORG_DEPTH` | yes | beyond this the indexer **halts** rather than guessing a fork point; widening it is the only way to clear a halt (runbook §2) |
| `GLC_VALIDATOR_EPOCH` | yes | the epoch this relayer starts from |
| `GLC_WRAPPED_MINT_HEX` | yes | the wrapped-GLC SPL mint |
| `GLC_VAULT_SCRIPT_PUBKEY_HEX`, `GLC_VAULT_SIGNER_MAP` | yes | the vault's script and the validator-to-vault-key mapping |
| `GLC_SOLANA_SUBMITTER_KEYPAIR_PATH` | yes | pays fees only; confers no authority |
| `GLC_RELAYER_VALIDATOR_PUBKEY` | yes | this operator's federation identity, validated against the peer list at startup (ADR-0019 D1) |
| `GLC_FEDERATION_PEERS` | yes | `base58pubkey@uri`, comma-separated; must not contain this operator |
| `GLC_RELAYER_TLS_CERT_PATH`, `GLC_RELAYER_TLS_KEY_PATH`, `GLC_FEDERATION_TLS_DOMAIN` | yes | this process's client identity |
| `GLC_FEDERATION_TLS` | no | `off` disables transport authentication entirely — loopback and regtest only, and loud on purpose |
| `GLC_OPS_LISTEN_ADDR` | no | **unset means health and metrics are not exposed at all.** The endpoint has no authentication; bind it to a private interface |
| `GLC_MAX_DEPOSIT_ATOMIC`, `GLC_ROLLING_WINDOW_CAP_ATOMIC`, `GLC_ROLLING_WINDOW_SECONDS` | no | per-deposit and rolling-window value caps |

## `signer-server`

The only process holding key material.

| variable | required | meaning |
|---|---|---|
| `GLC_SIGNER_VALIDATOR_KEYPAIR_PATH` | yes | **the** validator ed25519 key. Exactly one; there is deliberately no multi-key form |
| `GLC_SIGNER_LISTEN_ADDR` | yes | mTLS gRPC bind address |
| `GLC_SIGNER_TLS_CERT_PATH`, `GLC_SIGNER_TLS_KEY_PATH` | yes | this signer's server identity |
| `GLC_SIGNER_GLC_RPC_URL`, `GLC_SIGNER_GLC_RPC_USER`, `GLC_SIGNER_GLC_RPC_PASSWORD` | yes | **this signer's own** Goldcoin node — never the relayer's (ADR-0017 E2). A signer sharing the requester's node is not checking anything |
| `GLC_SIGNER_VAULT_INDEX`, `GLC_SIGNER_VAULT_KEY_PATH` | yes | this signer's single vault key and its position; the process proves it holds that key before serving (E1) |
| `GLC_DB_PATH` | yes | this operator's own database, written by their own indexer |
| `GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` | no | **unset means every governance request is refused**, so key rotation and supply-cap raises cannot be executed. Written by `glc-admin approve-*` |
| `GLC_SIGNER_SWEEP_APPROVALS_PATH` | no | **unset means every vault sweep is refused.** Written by `glc-admin sweep-approve` |
| `GLC_OPERATOR_INDEX`, `GLC_OPERATOR_COUNT` | no | this operator's place in a multi-operator federation (ADR-0019). Unset means single-operator behaviour |
| `GLC_PAYOUT_BUILD_TIMEOUT_SECS`, `GLC_MINT_SUBMIT_TIMEOUT_SECS` | no | failover windows before a non-designated operator may act |

## `glc-admin`

A one-shot tool. Reads the shared set plus the federation transport
variables, and additionally:

| variable | required for | meaning |
|---|---|---|
| `GLC_ADMIN_KEYPAIR_PATH` | `pause`, `unpause`, `lower-tvl-cap`, `initialize`, `create-wrapped-mint`, `token-metadata` | the **interim single admin key** (custody #7, OPEN — see runbook §9) |
| `GLC_SOLANA_SUBMITTER_KEYPAIR_PATH` | every governance submission | pays fees only |
| `GLC_RPC_URL`, `GLC_RPC_USER`, `GLC_RPC_PASSWORD` | `sweep-execute` | the node that builds and broadcasts the sweep |
| `GLC_DB_PATH` | recovery and sweep commands | this operator's own database |

## The two that are easiest to get wrong

**`GLC_SIGNER_GLC_RPC_URL` must not point at the relayer's node.** Both
processes run on the same host and both need Goldcoin access, so pointing
them at one node is the natural mistake. It defeats ADR-0017 E2: independent
validation is the property that makes a signer's refusal meaningful.

**`GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` and `GLC_SIGNER_SWEEP_APPROVALS_PATH`
are optional and fail closed.** Leaving them unset produces a federation that
starts cleanly, serves deposits and payouts correctly, and cannot rotate its
keys or escape a compromised vault. Nothing complains until the day it
matters. Set them, and keep the files under the same protection as the keys
beside them.

