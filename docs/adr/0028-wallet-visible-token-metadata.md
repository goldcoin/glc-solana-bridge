# ADR-0028: Wallet-visible token metadata

- Status: **Accepted** (owner request, 2026-08-01).
- Delivers: wrapped GLC displaying as **Wrapped Goldcoin (wGLC)** in wallets.

---

## 1. The decision: Metaplex, and it was not a preference

The requirement was to add metadata **without creating a new mint**. That
single constraint decides it.

**Token-2022 metadata is a mint extension.** It lives inside the mint account
and only exists on a mint owned by the Token-2022 program. The wrapped-GLC
mint is a **classic SPL Token** mint (owner decision U5, ADR-0009). Adding a
Token-2022 extension to it is not possible — not difficult, impossible. It
would mean creating a new mint under a different program: a new address, a
new authority, and every existing token account invalidated. That is a
different token, not a metadata change.

**Metaplex Token Metadata stores metadata in a separate PDA** derived from
the mint (`["metadata", metaplex_program, mint]`). The mint account, its
authority, its decimals, its supply and its address are untouched. It is the
only option compatible with the mint we already have.

Had the mint been Token-2022, the reverse would be true: the extension would
be preferable, because it removes a third-party program from the trust
surface entirely. It is not, so this is settled by history rather than taste.

## 2. Why this required an on-chain instruction

`CreateMetadataAccountV3` requires the **mint authority to sign**. The
wrapped mint's authority is a data-less PDA with no keypair anywhere
(ADR-0004) — no off-chain tool can produce that signature.

So metadata creation must be a CPI made by the bridge program itself under
`invoke_signed`. There is no `glc-admin`-only version of this feature.

**Timing matters, and it is favourable.** Nothing is deployed, so adding an
instruction costs nothing. Post-launch the same change would require
exercising the single-key upgrade authority (custody #5, still open), which
`remaining-before-launch.md` names as the largest single point of failure. If
this feature is wanted at all, now is materially cheaper than later.

## 3. What is deliberately fixed in the program

| choice | why |
|---|---|
| **Name and symbol are program constants**, not instruction arguments | an operator cannot typo them, and what wallets will display is verifiable by reading the program rather than by trusting whoever ran the command |
| **URI is an argument, defaulted in the relayer** | it points at hosted JSON for a logo, which is deployment-specific and may legitimately move. Held as a **relayer** constant (`WRAPPED_GLC_URI`), not a program one: if it were welded into the program, changing it would require a program upgrade and therefore the single-key upgrade authority (custody #5). As a default it still cannot be typo'd. Bounded at 200 bytes so an over-long value fails with our error rather than an opaque CPI failure |
| **Update authority is the mint-authority PDA** | a future change then requires this program, not whoever holds a loose keypair. Consistent with the rest of the system, where no single key changes bridge state |
| **`is_mutable = true`** | a URI may need to move. The authority above is what makes that safe |
| **Decimals are absent** | Metaplex metadata carries no decimals field; wallets read them from the mint, which already says 8. There is no second copy to disagree |

## 4. Idempotence

The instruction returns `Ok` without writing when the metadata account
already exists. `glc-admin token-metadata` then reads the account back and
checks name, symbol, mint and update authority in both branches.

The check is "does metadata exist", **not** "does it match the arguments" — a
second run with a different URI leaves the existing account alone rather than
silently rewriting what wallets are already displaying. Changing metadata
after the fact should be a deliberate, separate act, not a side effect of
re-running a create command.

That combination is what lets an operator run this to *verify* rather than to
gamble, at any time, without knowing whether it was done before.

## 5. Verified against the real Metaplex program

The instruction data is hand-encoded Borsh for a third party's instruction: a
variant byte, three length-prefixed strings, a `u16`, and five `Option` tags.
Nothing about getting that wrong is visible from reading it, and a mock would
have agreed with whatever was written — the self-consistent-fixture trap that
produced the Phase 7j sweep defect.

So `programs/glc-bridge/tests/token_metadata.rs` loads the **real Metaplex
program**, dumped from mainnet, into litesvm. Ten tests cover creation,
idempotence, admin gating, wrong-mint and wrong-PDA rejection, the URI cap,
and — the requirement this design is shaped by — that the mint account is
**byte-identical** afterwards.

**The suite self-skips and CI does not run it.** The repository excludes
`**/*.so`, so the fixture is not committed. Fetch it with:

```
solana program dump -u m metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s \
  programs/glc-bridge/tests/fixtures/mpl_token_metadata.so
```

A green CI run is not evidence these passed — the same caveat the rehearsal
suites carry, and it applies to the most novel encoding in the change.

## 6. Mutation testing, and a harness that lied again

Nine mutants (`docs/experiments/token-metadata-mutants.py`); all killed.

The first run reported **0 killed, 9 survived** — a uniform result that was a
harness bug, not a code result. The detection logic counted
`test result: ok` lines against a fixed threshold; adding a second test
binary to one command raised the baseline, so a failing first command still
cleared it.

That is the **fourth** distinct harness misreport in this project, and the
first caused by editing the harness itself. Detection now uses **exit codes**
rather than counting output lines, which removes the whole class.

The recurring lesson is worth stating once more: a suspiciously uniform
mutation result is evidence about the harness, not about the code.

## 7. What this does not change

Mint address, mint authority, freeze authority (`None`, custody #6), PDA
seeds and layouts, every existing account, and every security assumption. A
test asserts the mint account is byte-identical after the operation.

The bridge gains one admin-gated instruction that writes an account owned by
a third-party program. Metaplex is now in the trust surface for *display
only*: a compromised or buggy Metaplex cannot mint, move or freeze anything —
at worst wallets show a wrong name. That should be stated to auditors rather
than left implicit.

## 7.1 The URI is write-once, and it currently 404s

Idempotence is by *existence*, not by *contents* (§4), so the URI is fixed at
creation and there is no update instruction. That makes the hosting a
**prerequisite**, not a follow-up.

Verified 2026-08-01: the canonical
`https://goldcoinproject.org/assets/wglc.json` and its `wglc.png` both return
**404**. The host answers 200 at the root, so this is missing files rather
than a wrong domain.

Running `token-metadata` before those files exist writes a URI that wallets
cannot resolve, permanently absent a program upgrade. The runbook states the
ordering; this records why it is load-bearing rather than tidy.

## 9. Updating, added before launch

`create_token_metadata` alone left the URI effectively write-once (§7.1),
because idempotence is by *existence* rather than contents. Moving the
hosting would then have required a metadata-update instruction — i.e. a
program upgrade, i.e. the single-key upgrade authority (custody #5).

`update_token_metadata` closes that, while nothing is deployed and adding
instructions is free.

| property | how |
|---|---|
| admin-only | same `bridge_config.admin` constraint as creation |
| touches only metadata | the instruction **takes no mint account**, so it structurally cannot alter the mint, its decimals or its authorities |
| belongs to our mint | the PDA is re-derived **and** the mint recorded inside the metadata account is compared — defence in depth against a future Metaplex seed change |
| must already exist | absent metadata is `MetadataNotFound`, a different mistake from a failed create |
| idempotent | identical name, symbol and URI write nothing and make **no CPI** |
| authority preserved | `update_authority` and `is_mutable` are sent as Borsh `None`, so neither moves |

Name and symbol became arguments here while remaining program constants at
creation. That asymmetry is deliberate: creation must be right by
construction and unable to be typo'd, whereas a rename is an explicit
decision someone is making on purpose.

A consequence worth stating: `glc-admin token-metadata`'s verification now
reports a name/symbol difference as a **notice** rather than a fault, since
an intentional rename must not look like an alarm. The mint and the update
authority remain hard failures — those are security properties, not display.

### 9.1 Two vacuous tests, found by mutation testing

Four mutants survived the first run of the update suite, and two shared a
root cause worth recording: **comparing account bytes cannot detect a
redundant write**, because writing identical values produces identical
bytes. The idempotence test passed with the idempotence check removed.

Compute units looked like the fix but litesvm reports a flat figure. The
observable that works is the **transaction logs**: a CPI leaves a Metaplex
`invoke [2]` line and an early return does not.

The other two were a test asserting only `is_err()` — which passed when our
check was removed because Metaplex failed downstream for its own reasons,
so it now asserts the specific error — and a defence-in-depth check
unreachable by construction, now exercised by fabricating a metadata account
with the correct PDA but a wrong stored mint.

## 8. What this ADR does not decide

- Who publishes the metadata JSON and image, or when.
- Whether to ever make the metadata immutable (`is_mutable` stays true).
- Whether to make the metadata immutable later.
- Anything about the token's listing, logo artwork, or exchange integration.
