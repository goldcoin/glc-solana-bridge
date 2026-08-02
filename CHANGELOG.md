# Changelog

Notable changes to the GLC ↔ Solana bridge. Architectural decisions live in
`docs/adr/`; this file records what shipped and when, and links to the ADR
that explains why.

---

## First feature-complete bridge — 2026-08-02

**Milestone: every documented capability of the bridge is now implemented by a
shipped binary.** A user can complete a round trip — deposit native GLC, hold
wrapped GLC in a wallet that displays it by name, burn it, and be paid out —
using only tools in this repository.

> **Feature-complete is not launch-ready.** No federation exists, no external
> security audit has been performed, and the upgrade authority and emergency
> pause are each still a single key. `docs/release-readiness-v1.0.md` §9 states
> the remaining blockers precisely. Nothing here should be read as clearance to
> deploy to mainnet.

### Added in this milestone

- **`glc-wallet`** — the user-facing withdrawal CLI, and the first tool in this
  repository intended for people who do not operate the bridge. Reads the live
  `BridgeConfig`, derives the next `WithdrawalRequest` PDA and the user's
  associated token account, validates the Goldcoin destination *before*
  signing, submits `burn_wrapped`, then polls for the record and verifies it
  matches what was requested. Deliberately separate from `glc-admin`: it holds
  a user's key and can do exactly one thing — burn that user's own tokens.
- **Wallet-visible token metadata** (ADR-0028) — `create_token_metadata` and
  `update_token_metadata` instructions plus the matching `glc-admin` commands,
  so wallets display *Wrapped Goldcoin* / *wGLC* instead of a raw mint address.
  Metaplex rather than Token-2022, because Token-2022 metadata is a mint
  extension and the wrapped mint already exists as classic SPL Token. Both
  operations are admin-only, enforced on chain, and idempotent. The metadata
  URI is supplied by the operator, never compiled into the program, so the
  hosting location can move without a program upgrade.

### The path to feature-complete

Each of these phases was opened because verification found a documented
capability that no shipped tool could actually perform:

| ADR | shipped |
|---|---|
| 0021 | operator tooling `glc-admin`, and authorisation by staged approval |
| 0022 | on-chain operator tooling, and the cross-workspace encoding contract |
| 0023 | the operator runbooks, kept executable rather than aspirational |
| 0024 | launch readiness, and rehearsal as automation |
| 0025 | the offline integrity auditor `glc-audit`, and reorg early warning |
| 0026 | signature-grant audit records |
| 0027 | bootstrap tooling — the bridge previously could not be stood up at all |
| 0028 | wallet-visible token metadata |

Rehearsals written as automated tests found defects review had not: most
significantly, that Goldcoin transactions carry txids in *internal* byte order
while `listunspent` reports *display* order, which would have broken every real
vault sweep.

### Shipped binaries

| binary | audience | purpose |
|---|---|---|
| `glc-relayer` | operator | the relayer daemon |
| `signer-server` | operator | federation signature exchange |
| `glc-admin` | operator | bootstrap, governance, custody, metadata |
| `glc-audit` | operator / auditor | offline integrity audit |
| `glc-wallet` | **user** | withdraw wrapped GLC back to Goldcoin |

### Known limitations at this milestone

- `burn_wrapped` cannot validate the Goldcoin destination on chain — the
  program has no base58 decoder (ADR-0018 D2). A withdrawal to an undecodable
  address is a permanent loss, so `glc-wallet` validates with the same function
  the payout pipeline uses, before signing.
- The Metaplex integration tests require a mainnet-dumped
  `mpl_token_metadata.so`, which is not committed. They self-skip in CI, so CI
  passing is not evidence the metadata encoding is correct; changes to
  `programs/glc-bridge/src/instructions/token_metadata.rs` must be verified
  locally against the real program.

---

## v1.0.0-rc1 — release readiness

`docs/release-readiness-v1.0.md`: the document a security auditor or a new
bridge operator reads first — architecture, ADR index, implemented security
properties, trust assumptions, operational requirements, launch checklist,
rollback, incident response, and post-launch monitoring.

---

## Earlier

Phases 1 through 7 built the bridge itself: the on-chain program, the Goldcoin
indexer, federated M-of-N signing, vault custody, the withdrawal executor, and
multi-relayer operation. See ADR-0001 through ADR-0020 for the decisions and
`docs/architecture.md` for how the pieces fit together.
