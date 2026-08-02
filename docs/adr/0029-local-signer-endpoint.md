# ADR-0029: The relayer must be able to reach its own signer

**Status:** accepted
**Date:** 2026-08-02
**Supersedes nothing.** Preserves ADR-0015, ADR-0016, ADR-0017 and ADR-0019.

## 1. The defect

Every payout whose designated signing quorum included this operator stalled
in `Signing` **forever**. The federation collected `threshold - 1` partials,
one short, and because the shortfall was deterministic every retry failed
identically.

It was not an edge case. `designate_quorum` starts a quorum at
`index % signer_count`, and `OperatorAssignment::designated_for` chooses the
builder with the same expression — so **the operator designated to build a
payout is always a member of that payout's own quorum**. On the designated
builder, *every* payout stalled.

Observed on a real three-operator rehearsal, from the relayer's own log:

```
payout partial-signature collection round
    withdrawal_index=0 quorum_attempt=0 summary=1 signed, 0 refused, 1 unavailable
insufficient partial signatures from the designated quorum this tick
    withdrawal_index=0 collected=1 threshold=2 quorum_attempt=0
```

## 2. Root cause

Three correct decisions combined into an incorrect system.

1. **A quorum is designated from the withdrawal index** (ADR-0015), not from
   who is reachable, so the txid is deterministic before any signature
   exists. It contains exactly `threshold` members — no spares.
2. **`GLC_FEDERATION_PEERS` means *the other operators***. `glc-relayer`
   does not merely permit this operator's absence, it **enforces** it
   (`main.rs`): listing yourself among your peers would count one party
   twice and inflate apparent agreement.
3. **The collector resolves each designated signer by looking it up in that
   peer list** (`p2p/collector.rs`), recording anything it cannot find as
   `Unavailable("designated signer is not a configured peer")`.

Nothing connected (1) to (2). The relayer had **no address for its own
signer-server**, even though that process was running on the same host
holding the very vault key the quorum required. The local signer was never
contacted — not refused, not timed out: never asked.

The gap survived review because the two test suites straddled it.
`e2e_deposit_to_payout` proves the whole value path but signs with
`InProcessPayoutCollector`, which holds every vault key in one process and
therefore performs no peer lookup at all. `federation_transport` drives the
real `GrpcCollector` but only ever with remote-only quorums. Neither could
see it.

## 3. Decision

The relayer is configured with `GLC_RELAYER_LOCAL_SIGNER_URI`, the address of
**this operator's own** `signer-server`, and the collector's endpoint set is
`GLC_FEDERATION_PEERS` **plus** that one entry (`identity::with_local_signer`).

`GLC_FEDERATION_PEERS` keeps its meaning exactly. Self remains rejected
there. The local signer is a separate, explicit setting, because the two
answer different questions: *who are the others* and *where is mine*.

**It is required, and startup fails without it.** A relayer that cannot reach
its own signer loses every payout it is designated to build, silently and
permanently. Failing closed converts that into an error message naming the
variable to set.

## 4. What is deliberately unchanged

- **No vault key enters the relayer.** Its own signer is reached over the
  same authenticated gRPC as any peer. The key stays in `signer-server`.
- **mTLS and the pinned CA** apply to the local endpoint like any other.
- **On-chain identity verification** applies: the local endpoint must answer
  as this operator's registered validator key, and a response claiming any
  other identity is discarded (ADR-0016 §6.2).
- **Deterministic quorum assignment** is untouched. The fix changes *who is
  reachable*, never *who is chosen*.
- **No implicit substitution** (ADR-0015). A shortfall still forces an
  explicit, audited reassignment; a reachable but undesignated operator is
  still never asked.
- **`quorum_attempt` semantics** are untouched.
- **ADR-0019 operator assignment** is untouched.

## 5. Rejected alternatives

**Let the relayer hold its own vault key and sign locally.** Fastest, and
wrong: it reintroduces the exact property Phase 7e removed — a relayer able
to produce vault signatures — trading a liveness bug for a custody
regression.

**Permit self in `GLC_FEDERATION_PEERS`.** Overloads one setting with two
meanings and removes a check that catches a real misconfiguration. An
operator listing itself twice would then be counted twice.

**Exclude self from designated quorums.** Changes ADR-0015 determinism and
shrinks the effective signer set, making some quorums unsatisfiable.

**Substitute a reachable signer on shortfall.** Explicitly forbidden by
ADR-0015: the txid depends on which quorum signs.

## 6. Validation

- `rehearsal_three_operator_payout` — three real `signer-server` processes,
  three `goldcoind` nodes (one per signer, ADR-0017 E2), one
  `solana-test-validator`, deposit → mint → burn → discovery → payout →
  completion, over the production `FederationPayoutCollector`. **Fails on the
  unfixed code** with `1 signed, 0 refused, 1 unavailable`; passes after,
  with the local signer recording an ADR-0026 grant.
- `federation_local_signer` — in-process cover for: the builder always being
  in its own quorum; a self-containing quorum being unsatisfiable without a
  local endpoint; a remote-only quorum resolving identically before and
  after; no substitution of an undesignated signer; and the configuration
  rejections (missing endpoint, endpoint shared with a peer, self in the
  peer list, duplicate identity).

## 7. Operational consequence

Every existing operator must set `GLC_RELAYER_LOCAL_SIGNER_URI` before
upgrading, or their relayer will not start. That is the intended behaviour:
starting without it is what caused the outage.
