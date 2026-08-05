# ADR-0030: `glc-admin` must confirm what it submits

**Status:** accepted
**Date:** 2026-08-03
**Supersedes nothing.** Preserves ADR-0021, ADR-0022, ADR-0027.

## 1. The defect

Every state-changing `glc-admin` command reported success for a transaction
it had never observed land. `submit` called `send_transaction` — which
returns as soon as an RPC node *accepts* a transaction for processing — then
printed the signature and returned `Ok(())`. The process exited `0`.

Acceptance is not inclusion. An accepted transaction can still fail to land:
its blockhash expires, the leader drops it, the slot is skipped. Nothing in
`glc-admin` distinguished any of those from success.

Found by running the documented bootstrap sequence (`runbooks.md` §14
steps 1–2) exactly as written, back to back, against a real
`solana-test-validator`:

```
$ glc-admin initialize --validators ... --threshold 2 ...
initialize submitted
  signature: 3rd6aW1qyZhiVBBVWJpXsLEirFNM3dkapps7k1g9LMoQfmsSCuSNVHUBjsr4v6qdbZjdD2HDGK2z6MHoaRfaRe8o
### initialize exit: 0

$ glc-admin create-wrapped-mint --mint-keypair ...
Error: the bridge config account does not exist at 9siQq2LWkyCsabNX1xyT6JFXmTWYjj2c4L8dGztEe9NF — run `initialize`
### create-wrapped-mint exit: 1
```

`initialize` had worked. Seconds later `show-config` printed the fully
populated account. `create-wrapped-mint` had simply read it before
`initialize` landed — and `initialize` had already claimed success.

## 2. Why the bootstrap race is the mild consequence

The documented launch sequence failing is loud, immediate, and happens once.

`glc-admin pause` is the dangerous case. It printed a signature and exited
`0` whether or not the pause ever took effect, and `runbooks.md` §3 tells an
operator facing a solvency breach to **pause first** and then work the rest
of the procedure believing minting has stopped. A dropped pause is
indistinguishable from an engaged circuit breaker, and every further mint
enlarges the breach the operator thinks they just stopped.

The same shape applies to `lower-tvl-cap` (incident response), to the
governance commands (an operator waits out a timelock on a proposal that was
never queued), and to `transfer-admin`/`accept-admin` (custody handover
believed complete while the old key still governs).

`glc-wallet` already got this right — it polls for the withdrawal record and
its comments state the exact semantics, because reporting success for an
irreversible burn without reading it back was recognised as unacceptable
there. `glc-admin` never received the same treatment.

## 3. Decision

`glc-admin` waits for every transaction it sends, and reports only what it
has observed.

**A confirmation primitive in the RPC abstraction, not a sleep.** Two methods
are added to `SolanaRpc`:

- `get_signature_status` — `None` (not yet at this commitment),
  `Some(Ok(()))` (confirmed and succeeded), or `Some(Err(reason))` (confirmed
  and **failed on chain**). The three are deliberately distinct; collapsing
  any pair is how an unconfirmed transaction gets reported as a success. The
  observed status is checked against the *requested* commitment via
  `satisfies_commitment`, so a `processed` sighting never satisfies a
  `finalized` requirement.
- `is_blockhash_valid` — what makes the wait **bounded**. A transaction whose
  blockhash can no longer be used will never confirm, so the failure is
  reported at once rather than waited out.

`solana::confirm::confirm_transaction` polls status, and on each miss asks
whether the transaction can still land. The deadline is only a backstop for
an RPC that answers nothing at all.

**A fixed sleep was rejected.** Too short reports a false failure for a
transaction that lands a moment later; too long stalls every command by its
worst case. Neither tells the operator which happened.

**The expiry path re-checks status before declaring failure.** The blockhash
read happens after the status read, so the transaction may confirm in
between. Reporting a completed `pause` as a failure is the wrong direction to
be wrong in.

**Postconditions are read back where a cheap read exists.** Confirmation
proves the transaction executed; it does not prove the operator got the state
they meant. `initialize` asserts the config account is readable, `pause`
asserts `paused`, `lower-tvl-cap` asserts the new ceiling, the governance
commands assert the queued action appeared or is gone, and the admin handover
asserts the nomination and the acceptance. This is the launch checklist's
"read every value back" made executable rather than advisory.

**Failures name everything an operator needs**: the signature, the action,
the commitment that was required, the reason, and whether the postcondition
was observed — and they are distinguished:

| outcome | what it means | retry? |
|---|---|---|
| `Rejected` | landed, runtime refused it; instruction did **not** take effect | no — same result |
| `Expired` | can never land; nothing took effect | yes, safe |
| `TimedOut` | outcome **UNKNOWN** | read state back first |
| `Rpc` | fate undetermined | read state back first |

## 4. What is deliberately unchanged

- **The daemons keep fire-and-forget submission.** `orchestrator` (mint) and
  `completion` reconcile against on-chain account state on later ticks and
  self-heal; blocking their tick loops on confirmation would stall unrelated
  work for no gain. The distinction is that `glc-admin` is a one-shot tool
  whose exit code *is* the report — there is no later tick to correct it.
- **`glc-wallet` is untouched.** It already verifies by postcondition.
- **`sweep-execute` is untouched.** It broadcasts a *Goldcoin* transaction,
  not a Solana one, and has its own confirmation model (§5).
- **No new dependency.** `satisfies_commitment` is reached through the
  existing `solana-client` surface rather than adding
  `solana-transaction-status` to a `deny.toml` already strained by the Solana
  stack.
- **The audit log still records the attempt before the outcome.** An action
  that was attempted and then failed belongs in the trail; a second record
  now states whether it took effect.

## 5. Known remaining gap

`sweep-execute` broadcasts to Goldcoin and reports the txid. It checks
whether the transaction is already in a block, but does not wait for
confirmation. It is out of scope here — a Goldcoin broadcast has different
failure modes from a Solana submission, and mixing the two into one change
would make neither reviewable. Recorded rather than silently left.

## 6. Validation

- `tests/admin_confirmation.rs` — the confirmation primitive against an RPC
  behaving as a real cluster does in each failure mode: never confirms
  (the original defect's exact shape), rejected on chain, blockhash expired,
  confirmed after a delay, confirmed in the race window as the blockhash
  expires, and RPC failure. Also asserts every failure names the signature.
- The bootstrap sequence itself, run back to back with no waits against a
  real `solana-test-validator`, on the pre-fix and post-fix binaries:

  | | `initialize` | `create-wrapped-mint` |
  |---|---|---|
  | before | exit 0, "submitted" | **exit 1**, "the bridge config account does not exist" |
  | after | exit 0, CONFIRMED + verified | exit 0, CONFIRMED + verified |
