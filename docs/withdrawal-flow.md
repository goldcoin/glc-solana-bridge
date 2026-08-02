# Withdrawal flow (wrapped GLC → GLC)

Status: on-chain part implemented in Phase 3; payout side gated on
custody.md.

## For users: `glc-wallet withdraw`

The user-facing entry point. It burns wrapped GLC and creates the
`WithdrawalRequest` the federation pays out from.

```
glc-wallet withdraw \
  --amount-atomic 1500000000 \
  --glc-address <your Goldcoin address> \
  --keypair ~/.config/solana/id.json
```

Amounts are **atomic units**: 1 GLC = 100000000, so the example above
withdraws 15 GLC.

Connection settings come from the environment, using the same names the
bridge itself uses: `GLC_SOLANA_RPC_URL`, `GLC_SOLANA_COMMITMENT`,
`GLC_PROGRAM_ID_HEX`. Everything else — the wrapped mint, the minimum
withdrawal, the next withdrawal index — is read from the on-chain
`BridgeConfig` rather than configured.

### The address is checked first, and that is the point

`burn_wrapped` **cannot validate the Goldcoin address**: the program has no
base58 decoder (ADR-0018 D2), so it stores whatever bytes it is given. A
burn with a malformed or unsupported address therefore succeeds, destroys
the tokens, and creates a withdrawal **no operator can ever pay out** —
there is no un-burn instruction.

`glc-wallet` validates the address with `decode_p2pkh_hash160`, the very
function the payout pipeline uses to decide whether a withdrawal is payable.
Borrowing it rather than re-implementing the rule means the CLI can never
accept a destination the bridge would later refuse. Every check —
paused, minimum, balance, address — runs **before** anything is signed, and
each refusal says "Nothing was burned".

### It verifies rather than assuming

After submitting, the CLI waits for the transaction to confirm, reads the
`WithdrawalRequest` account back, and compares the amount, destination,
requester and index against what was asked for. It prints the withdrawal
index, the PDA, the transaction signature, the amount and the destination.

If the record cannot be read within 30 seconds it says so **without**
claiming the withdrawal failed, and tells the user to check the PDA rather
than re-run — because re-running would burn a second time.

### Concurrency

The withdrawal index comes from `BridgeConfig::withdrawal_count` at
submission time. Two users burning simultaneously race for the same index;
the loser's transaction fails because the account already exists. Nothing is
overwritten, and the CLI tells the loser simply to run the command again.

---

## On-chain (implemented, Phase 3)

`burn_wrapped(amount, glc_address)`:

1. Checks: not paused; `amount > 0` and `≥ min_withdrawal`; `glc_address`
   is 1–64 opaque ASCII bytes (semantic format validation deferred to
   Phase 4 → `goldcoin-rpc-notes.md`); withdrawal counter increments with
   checked arithmetic.
2. Burns `amount` from the caller's associated token account
   (`BurnChecked`).
3. Creates the `WithdrawalRequest` PDA seeded by the monotonic index from
   `BridgeConfig`: `{ index, amount, requester, glc_address,
   requested_at_slot, status: Pending, … }` (180 bytes, ADR-0010).
4. Emits `WithdrawalRequested` — convenience only; the ACCOUNT is the record
   (ADR-0006). Status write-back (`Broadcast`/`Completed`) is deliberately
   not implemented yet; every record stays `Pending` until the payout side
   exists.

Burn-then-record in one atomic instruction: there is no state in which value
was burned without a persistent, queryable payout obligation.

## Off-chain payout (implemented, Phase 6 — ADR-0013)

Regtest only. Production custody is still gated on custody.md #2/#3.

1. Relayers discover `WithdrawalRequest` accounts by scanning program
   accounts at **finalized** commitment (hard requirement, owner decision
   D5). Each account is fully validated: owner, length, PDA re-derivation
   from its own index, canonical bump, non-zero amount, zero-padded ASCII
   address, and a decodable regtest P2PKH destination. Anything malformed is
   refused, never repaired.
2. Vault UTXOs are discovered via `listunspent` and reserved **in the
   relayer's database** — node-side `lockunspent` locks are in-memory and do
   not survive a node restart.
3. A payout is constructed deterministically, then **every output is
   verified before signing**: exact destination script and amount, exact
   vault-owned change, no extra outputs, and exact value conservation.
4. Immediately before signing, the pre-signing guard sequence reloads the
   withdrawal and reservation rows, refuses any already-signed, confirmed or
   completed payout, verifies the reserved inputs still exist and still
   belong to this withdrawal, and recomputes the canonical payout intent
   from persisted fields to compare against the stored commitment. Nothing
   cached is trusted.
5. Signed bytes and their txid are persisted **before** broadcast, so a lost
   response is reconcilable by lookup rather than by re-deriving anything.
6. Broadcast is idempotent: only the identical byte string is ever resent.
7. Completion is recorded at the configured confirmation depth — **off-chain
   only**. `WithdrawalRequest.status` stays `Pending` forever, because no
   status write-back instruction exists (owner decision D1). A future
   threshold-authorized completion instruction can be added without
   redesigning the executor.

## Failure notes

- Solana finality before broadcast: enforced — discovery runs only at
  `finalized` commitment, and any other configured value is a startup error.
- GLC-side reorg after Broadcast: the payout's block is re-checked every
  tick; if it is orphaned the withdrawal returns to `Orphaned` and the
  identical bytes are rebroadcast. `Completed` only at the configured depth.
- Fee bearer: **the vault** (owner decision D3). The payout output is always
  exactly the burned amount, so a fee spike reduces vault change and can at
  worst leave a withdrawal in `AwaitingFunds` — it can never reduce what the
  user receives, and never pays out more than `amount`.
