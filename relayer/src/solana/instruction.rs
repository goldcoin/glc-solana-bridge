//! Hand-built `mint_wrapped` instruction encoding (owner decision R1,
//! ADR-0012): discriminator + Borsh-encoded args + raw account metas, with
//! **no dependency on the on-chain `glc-bridge` crate**. This keeps the
//! relayer workspace genuinely independent of anchor-lang, matching
//! ADR-0001's isolation intent, and mirrors this codebase's established
//! preference for hand-rolled encodings over trusting an external shape
//! (the same choice already made for the Goldcoin RPC client, ADR-0011).
//!
//! Every seed byte string and account order below is a verbatim copy of
//! `programs/glc-bridge/src/constants.rs` and
//! `programs/glc-bridge/src/instructions/mint_wrapped.rs` — this is the
//! single place that copy must be kept in sync if the on-chain program's
//! accounts or seeds ever change.

use sha2::{Digest, Sha256};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::sysvar;

/// Verbatim copies of `programs/glc-bridge/src/constants.rs`.
pub const SEED_BRIDGE_CONFIG: &[u8] = b"bridge_config";
pub const SEED_VALIDATOR_SET: &[u8] = b"validator_set";
pub const SEED_MINT_AUTHORITY: &[u8] = b"mint_authority";
pub const SEED_DEPOSIT_CLAIM: &[u8] = b"deposit_claim";
pub const SEED_GOVERNANCE_ACTION: &[u8] = b"governance_action";

/// SPL Token program id (classic, not Token-2022 — owner decision U5,
/// Phase 2). Sourced from the `spl-token` crate's own constant rather than
/// a hand-typed base58 string, to eliminate any risk of a transcription
/// error in a 44-character address.
pub const TOKEN_PROGRAM_ID: Pubkey = spl_token::ID;
/// The Instructions sysvar address the on-chain program pins against,
/// sourced from `solana-sdk` directly for the same reason.
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = sysvar::instructions::ID;

pub fn bridge_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_BRIDGE_CONFIG], program_id)
}

pub fn validator_set_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_VALIDATOR_SET], program_id)
}

pub fn mint_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_MINT_AUTHORITY], program_id)
}

pub fn deposit_claim_pda(program_id: &Pubkey, txid: &[u8; 32], vout: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SEED_DEPOSIT_CLAIM, txid.as_slice(), &vout.to_le_bytes()],
        program_id,
    )
}

/// The 8-byte Anchor instruction discriminator: `sha256("global:<name>")[..8]`
/// — the exact convention this codebase already relies on elsewhere (e.g.
/// `relayer/tests/regtest_indexer.rs`'s discriminator computation from
/// Phase 4).
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

#[allow(clippy::too_many_arguments)]
pub struct MintWrappedAccounts {
    pub submitter: Pubkey,
    pub bridge_config: Pubkey,
    pub validator_set: Pubkey,
    pub deposit_claim: Pubkey,
    pub wrapped_mint: Pubkey,
    pub mint_authority: Pubkey,
    pub recipient: Pubkey,
    pub recipient_token_account: Pubkey,
}

/// Builds the `mint_wrapped` instruction. Account order and mutability
/// flags are a verbatim copy of the on-chain `MintWrapped` accounts struct
/// (see module docs) — this must be kept in sync by hand since there is no
/// generated IDL dependency to enforce it automatically.
pub fn mint_wrapped_instruction(
    program_id: &Pubkey,
    accounts: &MintWrappedAccounts,
    txid: [u8; 32],
    vout: u32,
    amount: u64,
    epoch: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 4 + 8 + 8);
    data.extend_from_slice(&anchor_discriminator("mint_wrapped"));
    data.extend_from_slice(&txid);
    data.extend_from_slice(&vout.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&epoch.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(accounts.submitter, true),
            AccountMeta::new_readonly(accounts.bridge_config, false),
            AccountMeta::new_readonly(accounts.validator_set, false),
            AccountMeta::new(accounts.deposit_claim, false),
            AccountMeta::new(accounts.wrapped_mint, false),
            AccountMeta::new_readonly(accounts.mint_authority, false),
            AccountMeta::new_readonly(accounts.recipient, false),
            AccountMeta::new(accounts.recipient_token_account, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

/// The accounts `complete_withdrawal` reads and writes (Phase 7f,
/// ADR-0018). Five, versus `mint_wrapped`'s eleven — which is why the
/// completion transaction fits two more signatures.
pub struct CompleteWithdrawalAccounts {
    /// Pays fees only; confers no authority (the federation proof does).
    pub submitter: Pubkey,
    pub bridge_config: Pubkey,
    pub validator_set: Pubkey,
    pub withdrawal: Pubkey,
}

/// Derives a withdrawal record's PDA. Mirrors the on-chain seeds exactly.
pub fn withdrawal_pda(program_id: &Pubkey, index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"withdrawal", &index.to_le_bytes()], program_id)
}

/// Hand-builds the `complete_withdrawal` instruction.
///
/// Hand-built rather than generated, like every other instruction here:
/// owner decision R1 keeps this workspace free of `anchor-lang` (ADR-0012).
pub fn complete_withdrawal_instruction(
    program_id: &Pubkey,
    accounts: &CompleteWithdrawalAccounts,
    index: u64,
    payout_txid: [u8; 32],
    payout_height: u64,
    epoch: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 8 + 32 + 8 + 8);
    data.extend_from_slice(&anchor_discriminator("complete_withdrawal"));
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&payout_txid);
    data.extend_from_slice(&payout_height.to_le_bytes());
    data.extend_from_slice(&epoch.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(accounts.submitter, true),
            AccountMeta::new_readonly(accounts.bridge_config, false),
            AccountMeta::new_readonly(accounts.validator_set, false),
            AccountMeta::new(accounts.withdrawal, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
        ],
        data,
    }
}

/// The destination commitment bound into a completion message (ADR-0018 D2):
/// `sha256` over the withdrawal's Goldcoin address **exactly as the on-chain
/// account stores it**.
///
/// Hashing the stored bytes rather than a decoded `hash160` is what lets the
/// program stay ignorant of address formats — so this must hash the same
/// bytes, never a re-encoded or normalised form.
pub fn destination_commitment(glc_address_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(glc_address_bytes).into()
}

// ---------------------------------------------------------------------------
// Admin and governance instructions (Phase 7i-1)
// ---------------------------------------------------------------------------
//
// These existed on-chain since Phases 7a and 7h-0 and had **no caller
// outside the program's own tests**: `set_paused`, the supply-cap controls
// and the whole rotation lifecycle could not be invoked by any shipped
// tool. Runbooks for emergency pause, TVL breach, key rotation and the
// compromise response therefore described procedures nobody could carry
// out. These builders, plus `glc-admin`, are what make them real.
//
// Account order and mutability below are verbatim copies of the builders in
// `programs/glc-bridge/tests/common/mod.rs`, which Anchor generates from the
// on-chain accounts structs. `admin_governance_encoding.rs` in that suite
// pins the same bytes this module produces, so a rename or reorder on either
// side breaks a test rather than a deployment.

pub fn governance_action_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_GOVERNANCE_ACTION], program_id)
}

/// The two accounts every admin-only instruction takes.
fn admin_config_metas(admin: &Pubkey, program_id: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(*admin, true),
        AccountMeta::new(bridge_config_pda(program_id).0, false),
    ]
}

/// `set_paused` — the admin-only circuit breaker.
///
/// The program rejects a no-op (pausing an already-paused bridge), so an
/// operator who is unsure of the current state must read it rather than
/// issue this blindly.
pub fn set_paused_instruction(program_id: &Pubkey, admin: &Pubkey, paused: bool) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&anchor_discriminator("set_paused"));
    // Borsh encodes a bool as one byte, 0 or 1.
    data.push(u8::from(paused));
    Instruction {
        program_id: *program_id,
        accounts: admin_config_metas(admin, program_id),
        data,
    }
}

/// `lower_wrapped_supply_cap` — admin-only, immediate, and only downward
/// (ADR-0014 §11.1). Reducing exposure is incident response; raising it is a
/// federation decision behind a threshold and a timelock.
pub fn lower_supply_cap_instruction(
    program_id: &Pubkey,
    admin: &Pubkey,
    new_max: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&anchor_discriminator("lower_wrapped_supply_cap"));
    data.extend_from_slice(&new_max.to_le_bytes());
    Instruction {
        program_id: *program_id,
        accounts: admin_config_metas(admin, program_id),
        data,
    }
}

/// The accounts a governance *proposal* takes. The proposer pays rent and
/// confers no authority — the federation proof in the preceding ed25519
/// instruction is the only authorization (owner decision U7).
fn propose_metas(proposer: &Pubkey, program_id: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*proposer, true),
        AccountMeta::new_readonly(bridge_config_pda(program_id).0, false),
        AccountMeta::new_readonly(validator_set_pda(program_id).0, false),
        AccountMeta::new(governance_action_pda(program_id).0, false),
        AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ]
}

/// The accounts an *execution* takes. Permissionless: the threshold proof at
/// proposal time was the authorization, and rent is refunded to whoever
/// submits.
fn execute_metas(
    executor: &Pubkey,
    program_id: &Pubkey,
    config_writable: bool,
) -> Vec<AccountMeta> {
    let config = bridge_config_pda(program_id).0;
    vec![
        AccountMeta::new(*executor, true),
        // A rotation writes the validator set and only reads the config; a
        // cap raise is the other way round. Getting this backwards is a
        // runtime failure, not a compile error, which is why both orders are
        // pinned by tests.
        if config_writable {
            AccountMeta::new(config, false)
        } else {
            AccountMeta::new_readonly(config, false)
        },
        if config_writable {
            AccountMeta::new_readonly(validator_set_pda(program_id).0, false)
        } else {
            AccountMeta::new(validator_set_pda(program_id).0, false)
        },
        AccountMeta::new(governance_action_pda(program_id).0, false),
    ]
}

/// `propose_validator_rotation` — queues a rotation behind the timelock.
///
/// Must be preceded in the same transaction by the ed25519 verification
/// instruction carrying M validator signatures over the canonical rotation
/// message (ADR-0010).
pub fn propose_rotation_instruction(
    program_id: &Pubkey,
    proposer: &Pubkey,
    validators: &[Pubkey],
    threshold: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 4 + validators.len() * 32 + 1);
    data.extend_from_slice(&anchor_discriminator("propose_validator_rotation"));
    // Borsh encodes a Vec as a u32 length prefix followed by the elements.
    data.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        data.extend_from_slice(v.as_ref());
    }
    data.push(threshold);
    Instruction {
        program_id: *program_id,
        accounts: propose_metas(proposer, program_id),
        data,
    }
}

/// `execute_validator_rotation` — applies a queued rotation once its
/// timelock has elapsed.
pub fn execute_rotation_instruction(program_id: &Pubkey, executor: &Pubkey) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: execute_metas(executor, program_id, false),
        data: anchor_discriminator("execute_validator_rotation").to_vec(),
    }
}

/// `cancel_validator_rotation` — cancels the pending action under a **fresh**
/// M-of-N proof. Also preceded by an ed25519 verification instruction.
pub fn cancel_rotation_instruction(program_id: &Pubkey, canceller: &Pubkey) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*canceller, true),
            AccountMeta::new_readonly(bridge_config_pda(program_id).0, false),
            AccountMeta::new_readonly(validator_set_pda(program_id).0, false),
            AccountMeta::new(governance_action_pda(program_id).0, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
        ],
        data: anchor_discriminator("cancel_validator_rotation").to_vec(),
    }
}

/// `propose_wrapped_supply_cap_raise` — queues a cap increase under the same
/// threshold-and-timelock path a rotation takes (ADR-0014 §11.1).
pub fn propose_cap_raise_instruction(
    program_id: &Pubkey,
    proposer: &Pubkey,
    new_max: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&anchor_discriminator("propose_wrapped_supply_cap_raise"));
    data.extend_from_slice(&new_max.to_le_bytes());
    Instruction {
        program_id: *program_id,
        accounts: propose_metas(proposer, program_id),
        data,
    }
}

/// `execute_wrapped_supply_cap_raise` — applies a queued increase once its
/// timelock has elapsed. The program re-checks the ceiling at execution.
pub fn execute_cap_raise_instruction(program_id: &Pubkey, executor: &Pubkey) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: execute_metas(executor, program_id, true),
        data: anchor_discriminator("execute_wrapped_supply_cap_raise").to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Bootstrap (Phase 7m)
// ---------------------------------------------------------------------------
//
// `initialize` and `create_wrapped_mint` had **no caller outside the
// program's own tests** — the bridge could not be stood up at all with the
// shipped binaries, which made step 3 of the documented launch sequence
// impossible. `transfer_admin`/`accept_admin` were in the same state, and
// they are how custody #5 hands the admin key to a multisig.
//
// Account order and mutability are verbatim copies of the Anchor-generated
// builders in `programs/glc-bridge/tests/common/mod.rs`, pinned on both
// sides by `admin_governance_encoding.rs` and this module's tests.

/// The `ProgramData` account the upgradeable loader keeps for a program.
/// `initialize` reads it to prove the caller is the upgrade authority.
pub fn program_data_address(program_id: &Pubkey) -> Pubkey {
    #[allow(deprecated)]
    Pubkey::find_program_address(
        &[program_id.as_ref()],
        &solana_sdk::bpf_loader_upgradeable::id(),
    )
    .0
}

/// `initialize` — creates the bridge config and the validator set.
///
/// Every parameter here is a launch-time security decision with **no
/// default** (owner decision U6): the program rejects a zero timelock and a
/// zero supply cap outright rather than inventing a value.
#[allow(clippy::too_many_arguments)]
pub fn initialize_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    validators: &[Pubkey],
    threshold: u8,
    min_deposit: u64,
    min_withdrawal: u64,
    governance_timelock_seconds: i64,
    max_wrapped_supply: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 4 + validators.len() * 32 + 1 + 8 * 4);
    data.extend_from_slice(&anchor_discriminator("initialize"));
    data.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        data.extend_from_slice(v.as_ref());
    }
    data.push(threshold);
    data.extend_from_slice(&min_deposit.to_le_bytes());
    data.extend_from_slice(&min_withdrawal.to_le_bytes());
    data.extend_from_slice(&governance_timelock_seconds.to_le_bytes());
    data.extend_from_slice(&max_wrapped_supply.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(bridge_config_pda(program_id).0, false),
            AccountMeta::new(validator_set_pda(program_id).0, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(program_data_address(program_id), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

/// `create_wrapped_mint` — one-time creation of the wrapped-GLC SPL mint.
///
/// The mint account is a **signer**: it is created by this instruction, so
/// the caller must hold its keypair for exactly this one transaction and
/// never again. Mint authority becomes the program's PDA and freeze
/// authority is `None` (custody #6, ADR-0009).
pub fn create_wrapped_mint_instruction(
    program_id: &Pubkey,
    admin: &Pubkey,
    wrapped_mint: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(bridge_config_pda(program_id).0, false),
            AccountMeta::new_readonly(mint_authority_pda(program_id).0, false),
            AccountMeta::new(*wrapped_mint, true),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: anchor_discriminator("create_wrapped_mint").to_vec(),
    }
}

/// `transfer_admin` — step 1 of the two-step handover (custody #5).
///
/// Two steps exist so a typoed key cannot brick governance: nothing changes
/// until the named key proves it exists by signing `accept_admin`.
pub fn transfer_admin_instruction(
    program_id: &Pubkey,
    admin: &Pubkey,
    new_admin: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&anchor_discriminator("transfer_admin"));
    data.extend_from_slice(new_admin.as_ref());
    Instruction {
        program_id: *program_id,
        accounts: admin_config_metas(admin, program_id),
        data,
    }
}

/// `accept_admin` — step 2, signed by the incoming admin.
pub fn accept_admin_instruction(program_id: &Pubkey, new_admin: &Pubkey) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*new_admin, true),
            AccountMeta::new(bridge_config_pda(program_id).0, false),
        ],
        data: anchor_discriminator("accept_admin").to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Wallet-visible token metadata (ADR-0028)
// ---------------------------------------------------------------------------

/// The Metaplex Token Metadata program, pinned to the same constant the
/// on-chain program address-checks.
pub const TOKEN_METADATA_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

/// What wallets will display. Constants on both sides so the two cannot
/// drift; the on-chain program is what actually writes them.
pub const WRAPPED_GLC_NAME: &str = "Wrapped Goldcoin";
pub const WRAPPED_GLC_SYMBOL: &str = "wGLC";

/// The canonical metadata URI: hosted JSON carrying the token's `image` and
/// display fields.
///
/// A **relayer constant, not a program constant** — deliberately. Name and
/// symbol are welded into the program because they must never change and an
/// operator must not be able to typo them. A URI is different: hosting can
/// legitimately move, and if it were a program constant, changing it would
/// require a program upgrade — which means exercising the single-key upgrade
/// authority (custody #5), the largest single point of failure in the
/// system. Keeping it here makes it the default an operator gets for free
/// while leaving `--uri` able to override it.
pub const WRAPPED_GLC_URI: &str = "https://goldcoinproject.org/assets/wglc.json";

/// Metaplex's metadata PDA for a mint: `["metadata", program, mint]`,
/// derived under the **Metaplex** program, not ours.
pub fn token_metadata_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"metadata",
            TOKEN_METADATA_PROGRAM_ID.as_ref(),
            mint.as_ref(),
        ],
        &TOKEN_METADATA_PROGRAM_ID,
    )
}

/// `create_token_metadata` — creates the wrapped mint's Metaplex metadata.
///
/// Idempotent on chain: the program returns `Ok` without writing if the
/// metadata account already exists, so re-running is how an operator
/// verifies rather than gambles.
pub fn create_token_metadata_instruction(
    program_id: &Pubkey,
    admin: &Pubkey,
    wrapped_mint: &Pubkey,
    uri: &str,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 4 + uri.len());
    data.extend_from_slice(&anchor_discriminator("create_token_metadata"));
    // Borsh string: u32 length prefix, then bytes.
    data.extend_from_slice(&(uri.len() as u32).to_le_bytes());
    data.extend_from_slice(uri.as_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new_readonly(bridge_config_pda(program_id).0, false),
            AccountMeta::new_readonly(mint_authority_pda(program_id).0, false),
            AccountMeta::new_readonly(*wrapped_mint, false),
            AccountMeta::new(token_metadata_pda(wrapped_mint).0, false),
            AccountMeta::new_readonly(TOKEN_METADATA_PROGRAM_ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
        ],
        data,
    }
}

/// `update_token_metadata` — changes the displayed name, symbol and URI.
///
/// Exists so the hosting URL can move **without a program upgrade**, which
/// would otherwise mean exercising the single-key upgrade authority
/// (custody #5). Takes no mint account, so it cannot alter the mint.
pub fn update_token_metadata_instruction(
    program_id: &Pubkey,
    admin: &Pubkey,
    wrapped_mint: &Pubkey,
    name: &str,
    symbol: &str,
    uri: &str,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 12 + name.len() + symbol.len() + uri.len());
    data.extend_from_slice(&anchor_discriminator("update_token_metadata"));
    for s in [name, symbol, uri] {
        data.extend_from_slice(&(s.len() as u32).to_le_bytes());
        data.extend_from_slice(s.as_bytes());
    }
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new_readonly(bridge_config_pda(program_id).0, false),
            AccountMeta::new_readonly(mint_authority_pda(program_id).0, false),
            AccountMeta::new(token_metadata_pda(wrapped_mint).0, false),
            AccountMeta::new_readonly(TOKEN_METADATA_PROGRAM_ID, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_matches_the_anchor_convention_used_elsewhere_in_this_repo() {
        // Cross-checked against the exact formula
        // relayer/tests/regtest_indexer.rs (Phase 4) used for the OLD
        // mint_wrapped_testonly discriminator: sha256("global:<name>")[..8].
        let d = anchor_discriminator("mint_wrapped");
        let expected = Sha256::digest(b"global:mint_wrapped");
        assert_eq!(d, expected[..8]);
    }

    #[test]
    fn instruction_data_layout_is_discriminator_then_borsh_args() {
        let program_id = Pubkey::new_unique();
        let accounts = MintWrappedAccounts {
            submitter: Pubkey::new_unique(),
            bridge_config: Pubkey::new_unique(),
            validator_set: Pubkey::new_unique(),
            deposit_claim: Pubkey::new_unique(),
            wrapped_mint: Pubkey::new_unique(),
            mint_authority: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            recipient_token_account: Pubkey::new_unique(),
        };
        let txid = [0xAB; 32];
        let ix = mint_wrapped_instruction(&program_id, &accounts, txid, 3, 50_000, 7);
        assert_eq!(ix.data.len(), 8 + 32 + 4 + 8 + 8);
        assert_eq!(&ix.data[8..40], &txid);
        assert_eq!(&ix.data[40..44], &3u32.to_le_bytes());
        assert_eq!(&ix.data[44..52], &50_000u64.to_le_bytes());
        assert_eq!(&ix.data[52..60], &7u64.to_le_bytes());
    }

    #[test]
    fn account_order_and_mutability_matches_onchain_struct() {
        let program_id = Pubkey::new_unique();
        let accounts = MintWrappedAccounts {
            submitter: Pubkey::new_unique(),
            bridge_config: Pubkey::new_unique(),
            validator_set: Pubkey::new_unique(),
            deposit_claim: Pubkey::new_unique(),
            wrapped_mint: Pubkey::new_unique(),
            mint_authority: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            recipient_token_account: Pubkey::new_unique(),
        };
        let ix = mint_wrapped_instruction(&program_id, &accounts, [0; 32], 0, 1, 0);
        assert_eq!(ix.accounts.len(), 11);
        let expect = [
            (accounts.submitter, true, true),
            (accounts.bridge_config, false, false),
            (accounts.validator_set, false, false),
            (accounts.deposit_claim, false, true),
            (accounts.wrapped_mint, false, true),
            (accounts.mint_authority, false, false),
            (accounts.recipient, false, false),
            (accounts.recipient_token_account, false, true),
            (INSTRUCTIONS_SYSVAR_ID, false, false),
            (TOKEN_PROGRAM_ID, false, false),
            (system_program::id(), false, false),
        ];
        for (i, (pubkey, is_signer, is_writable)) in expect.into_iter().enumerate() {
            assert_eq!(ix.accounts[i].pubkey, pubkey, "account {i} pubkey");
            assert_eq!(ix.accounts[i].is_signer, is_signer, "account {i} is_signer");
            assert_eq!(
                ix.accounts[i].is_writable, is_writable,
                "account {i} is_writable"
            );
        }
    }

    #[test]
    fn pda_derivations_are_deterministic() {
        let program_id = Pubkey::new_unique();
        assert_eq!(
            bridge_config_pda(&program_id),
            bridge_config_pda(&program_id)
        );
        assert_eq!(
            validator_set_pda(&program_id),
            validator_set_pda(&program_id)
        );
        assert_eq!(
            mint_authority_pda(&program_id),
            mint_authority_pda(&program_id)
        );
        let txid = [1u8; 32];
        assert_eq!(
            deposit_claim_pda(&program_id, &txid, 5),
            deposit_claim_pda(&program_id, &txid, 5)
        );
        assert_ne!(
            deposit_claim_pda(&program_id, &txid, 5).0,
            deposit_claim_pda(&program_id, &txid, 6).0,
            "different vout must derive a different claim PDA"
        );
    }

    // --- admin and governance (Phase 7i-1) ---------------------------------
    //
    // Each of these pins the SAME literal spec that
    // `programs/glc-bridge/tests/admin_governance_encoding.rs` asserts
    // Anchor generates. Those two files are the only link between the two
    // workspaces (ADR-0001 forbids a code dependency), so a change on
    // either side must break one of them.

    fn shape(ix: &Instruction) -> Vec<(Pubkey, bool, bool)> {
        ix.accounts
            .iter()
            .map(|m| (m.pubkey, m.is_signer, m.is_writable))
            .collect()
    }

    #[test]
    fn every_seed_is_pinned_to_its_literal_bytes() {
        // A seed that drifts derives a DIFFERENT PDA, so every instruction
        // built here would address an account the program never touches —
        // silent, and visible only against a live cluster. A surviving
        // mutant found this test missing: changing the governance seed broke
        // nothing.
        assert_eq!(SEED_BRIDGE_CONFIG, b"bridge_config");
        assert_eq!(SEED_VALIDATOR_SET, b"validator_set");
        assert_eq!(SEED_MINT_AUTHORITY, b"mint_authority");
        assert_eq!(SEED_DEPOSIT_CLAIM, b"deposit_claim");
        assert_eq!(SEED_GOVERNANCE_ACTION, b"governance_action");
    }

    #[test]
    fn set_paused_is_discriminator_then_one_borsh_bool() {
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let ix = set_paused_instruction(&program_id, &admin, true);
        assert_eq!(&ix.data[..8], &anchor_discriminator("set_paused"));
        assert_eq!(ix.data.len(), 9);
        assert_eq!(ix.data[8], 1);
        assert_eq!(
            set_paused_instruction(&program_id, &admin, false).data[8],
            0,
            "the argument must actually reach the wire"
        );
        // The admin signs but is not written to; the config is the reverse.
        assert_eq!(
            shape(&ix),
            vec![
                (admin, true, false),
                (bridge_config_pda(&program_id).0, false, true)
            ]
        );
    }

    #[test]
    fn lower_supply_cap_is_discriminator_then_a_u64() {
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let ix = lower_supply_cap_instruction(&program_id, &admin, 21_000_000_000_000);
        assert_eq!(
            &ix.data[..8],
            &anchor_discriminator("lower_wrapped_supply_cap")
        );
        assert_eq!(&ix.data[8..16], &21_000_000_000_000u64.to_le_bytes());
        assert_eq!(ix.data.len(), 16);
        assert_eq!(shape(&ix).len(), 2);
    }

    #[test]
    fn propose_rotation_encodes_a_borsh_vec_then_the_threshold() {
        let program_id = Pubkey::new_unique();
        let proposer = Pubkey::new_unique();
        let validators = vec![Pubkey::new_unique(), Pubkey::new_unique()];
        let ix = propose_rotation_instruction(&program_id, &proposer, &validators, 2);

        assert_eq!(
            &ix.data[..8],
            &anchor_discriminator("propose_validator_rotation")
        );
        assert_eq!(&ix.data[8..12], &2u32.to_le_bytes(), "Vec length prefix");
        assert_eq!(&ix.data[12..44], validators[0].as_ref());
        assert_eq!(&ix.data[44..76], validators[1].as_ref());
        assert_eq!(ix.data[76], 2, "the threshold follows the vector");
        assert_eq!(ix.data.len(), 77);

        assert_eq!(
            shape(&ix),
            vec![
                (proposer, true, true),
                (bridge_config_pda(&program_id).0, false, false),
                (validator_set_pda(&program_id).0, false, false),
                (governance_action_pda(&program_id).0, false, true),
                (INSTRUCTIONS_SYSVAR_ID, false, false),
                (system_program::id(), false, false),
            ]
        );
    }

    #[test]
    fn validator_order_is_preserved_because_it_fixes_the_bitmask_index() {
        // Two proposals differing only in ordering are genuinely different
        // proposals (shared::governance::rotation_params), so the encoding
        // must not sort or dedupe.
        let program_id = Pubkey::new_unique();
        let p = Pubkey::new_unique();
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let ab = propose_rotation_instruction(&program_id, &p, &[a, b], 1);
        let ba = propose_rotation_instruction(&program_id, &p, &[b, a], 1);
        assert_ne!(ab.data, ba.data);
        assert_eq!(&ab.data[12..44], a.as_ref());
        assert_eq!(&ba.data[12..44], b.as_ref());
    }

    #[test]
    fn the_two_execute_paths_have_mirror_image_writability() {
        // A rotation writes the validator set and reads the config; a cap
        // raise is the other way round. Getting this backwards fails only at
        // runtime, on a real cluster, mid-incident.
        let program_id = Pubkey::new_unique();
        let executor = Pubkey::new_unique();
        let config = bridge_config_pda(&program_id).0;
        let vset = validator_set_pda(&program_id).0;
        let action = governance_action_pda(&program_id).0;

        assert_eq!(
            shape(&execute_rotation_instruction(&program_id, &executor)),
            vec![
                (executor, true, true),
                (config, false, false),
                (vset, false, true),
                (action, false, true),
            ]
        );
        assert_eq!(
            shape(&execute_cap_raise_instruction(&program_id, &executor)),
            vec![
                (executor, true, true),
                (config, false, true),
                (vset, false, false),
                (action, false, true),
            ]
        );
    }

    #[test]
    fn the_execute_instructions_carry_a_bare_discriminator() {
        let program_id = Pubkey::new_unique();
        let e = Pubkey::new_unique();
        assert_eq!(
            execute_rotation_instruction(&program_id, &e).data,
            anchor_discriminator("execute_validator_rotation").to_vec()
        );
        assert_eq!(
            execute_cap_raise_instruction(&program_id, &e).data,
            anchor_discriminator("execute_wrapped_supply_cap_raise").to_vec()
        );
    }

    #[test]
    fn cancel_reads_the_sysvar_and_takes_no_system_program() {
        // Cancellation needs a FRESH federation proof, so it reads the
        // sysvar; it creates nothing, so a copy-paste of the propose metas
        // would wrongly add a system program.
        let program_id = Pubkey::new_unique();
        let canceller = Pubkey::new_unique();
        let ix = cancel_rotation_instruction(&program_id, &canceller);
        assert_eq!(
            ix.data,
            anchor_discriminator("cancel_validator_rotation").to_vec()
        );
        assert_eq!(
            shape(&ix),
            vec![
                (canceller, true, true),
                (bridge_config_pda(&program_id).0, false, false),
                (validator_set_pda(&program_id).0, false, false),
                (governance_action_pda(&program_id).0, false, true),
                (INSTRUCTIONS_SYSVAR_ID, false, false),
            ]
        );
        assert!(
            !ix.accounts.iter().any(|m| m.pubkey == system_program::id()),
            "cancel creates no account and must not take the system program"
        );
    }

    #[test]
    fn both_proposals_take_the_same_accounts() {
        let program_id = Pubkey::new_unique();
        let p = Pubkey::new_unique();
        assert_eq!(
            shape(&propose_rotation_instruction(&program_id, &p, &[], 1)),
            shape(&propose_cap_raise_instruction(&program_id, &p, 1))
        );
    }

    #[test]
    fn the_governance_action_pda_is_a_singleton_per_program() {
        // One seed, no discriminating input: the program relies on `init`
        // failing when an action is already pending, so a backlog can never
        // be queued.
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        assert_ne!(governance_action_pda(&a).0, governance_action_pda(&b).0);
        assert_eq!(governance_action_pda(&a).0, governance_action_pda(&a).0);
    }

    // --- bootstrap (Phase 7m) ---------------------------------------------

    #[test]
    fn initialize_encodes_its_arguments_in_declaration_order() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let validators = vec![Pubkey::new_unique(), Pubkey::new_unique()];
        let ix = initialize_instruction(
            &program_id,
            &authority,
            &validators,
            2,
            1_000,
            2_000,
            3_600,
            77,
        );
        assert_eq!(&ix.data[..8], &anchor_discriminator("initialize"));
        assert_eq!(&ix.data[8..12], &2u32.to_le_bytes());
        assert_eq!(&ix.data[12..44], validators[0].as_ref());
        assert_eq!(&ix.data[44..76], validators[1].as_ref());
        assert_eq!(ix.data[76], 2);
        assert_eq!(&ix.data[77..85], &1_000u64.to_le_bytes());
        assert_eq!(&ix.data[85..93], &2_000u64.to_le_bytes());
        assert_eq!(&ix.data[93..101], &3_600i64.to_le_bytes());
        assert_eq!(&ix.data[101..109], &77u64.to_le_bytes());
        assert_eq!(ix.data.len(), 109);

        assert_eq!(
            shape(&ix),
            vec![
                (authority, true, true),
                (bridge_config_pda(&program_id).0, false, true),
                (validator_set_pda(&program_id).0, false, true),
                (program_id, false, false),
                (program_data_address(&program_id), false, false),
                (system_program::id(), false, false),
            ]
        );
    }

    #[test]
    fn initialize_preserves_validator_order() {
        // Order fixes each validator's bitmask index for the whole life of
        // the federation, so the bootstrap must not sort.
        let program_id = Pubkey::new_unique();
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let k = Pubkey::new_unique();
        let ab = initialize_instruction(&program_id, &k, &[a, b], 1, 0, 0, 1, 1);
        let ba = initialize_instruction(&program_id, &k, &[b, a], 1, 0, 0, 1, 1);
        assert_ne!(ab.data, ba.data);
        assert_eq!(&ab.data[12..44], a.as_ref());
    }

    #[test]
    fn create_wrapped_mint_requires_the_mint_itself_to_sign() {
        // The mint account is created by this instruction; marking it
        // non-signing fails only against a live cluster.
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let ix = create_wrapped_mint_instruction(&program_id, &admin, &mint);
        assert_eq!(
            ix.data,
            anchor_discriminator("create_wrapped_mint").to_vec()
        );
        assert_eq!(
            shape(&ix),
            vec![
                (admin, true, true),
                (bridge_config_pda(&program_id).0, false, true),
                (mint_authority_pda(&program_id).0, false, false),
                (mint, true, true),
                (TOKEN_PROGRAM_ID, false, false),
                (system_program::id(), false, false),
            ]
        );
    }

    #[test]
    fn the_admin_handover_is_signed_by_each_side_in_turn() {
        // Two steps so a typoed key cannot brick governance: the outgoing
        // admin names the successor, and nothing changes until the successor
        // proves it exists by signing.
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let new_admin = Pubkey::new_unique();

        let t = transfer_admin_instruction(&program_id, &admin, &new_admin);
        assert_eq!(&t.data[..8], &anchor_discriminator("transfer_admin"));
        assert_eq!(&t.data[8..40], new_admin.as_ref());
        assert_eq!(t.data.len(), 40);
        assert_eq!(
            shape(&t)[0],
            (admin, true, false),
            "the OUTGOING admin signs"
        );

        let a = accept_admin_instruction(&program_id, &new_admin);
        assert_eq!(a.data, anchor_discriminator("accept_admin").to_vec());
        assert_eq!(
            shape(&a)[0],
            (new_admin, true, false),
            "the INCOMING admin signs"
        );
    }

    #[test]
    fn the_program_data_address_is_derived_from_the_upgradeable_loader() {
        // `initialize` reads it to prove the caller is the upgrade
        // authority; deriving it from the wrong program id would make every
        // bootstrap fail with an opaque constraint error.
        let program_id = Pubkey::new_unique();
        #[allow(deprecated)]
        let expected = Pubkey::find_program_address(
            &[program_id.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        )
        .0;
        assert_eq!(program_data_address(&program_id), expected);
    }

    // --- token metadata (ADR-0028) -----------------------------------------

    #[test]
    fn create_token_metadata_encodes_a_borsh_string() {
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let ix = create_token_metadata_instruction(&program_id, &admin, &mint, "abc");

        assert_eq!(
            &ix.data[..8],
            &anchor_discriminator("create_token_metadata")
        );
        assert_eq!(&ix.data[8..12], &3u32.to_le_bytes());
        assert_eq!(&ix.data[12..15], b"abc");
        assert_eq!(ix.data.len(), 15);

        assert_eq!(
            shape(&ix),
            vec![
                (admin, true, true),
                (bridge_config_pda(&program_id).0, false, false),
                (mint_authority_pda(&program_id).0, false, false),
                (mint, false, false),
                (token_metadata_pda(&mint).0, false, true),
                (TOKEN_METADATA_PROGRAM_ID, false, false),
                (system_program::id(), false, false),
                (sysvar::rent::ID, false, false),
            ]
        );
    }

    #[test]
    fn an_empty_uri_encodes_as_a_zero_length_string() {
        // The default: metadata with a name and symbol but no hosted JSON.
        let program_id = Pubkey::new_unique();
        let ix = create_token_metadata_instruction(
            &program_id,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            "",
        );
        assert_eq!(&ix.data[8..12], &0u32.to_le_bytes());
        assert_eq!(ix.data.len(), 12);
    }

    #[test]
    fn the_metadata_pda_is_derived_under_metaplex_not_under_us() {
        // The seeds belong to Metaplex; deriving under our program id would
        // produce an address Metaplex rejects.
        let mint = Pubkey::new_unique();
        let ours = Pubkey::new_unique();
        let expected = Pubkey::find_program_address(
            &[
                b"metadata",
                TOKEN_METADATA_PROGRAM_ID.as_ref(),
                mint.as_ref(),
            ],
            &TOKEN_METADATA_PROGRAM_ID,
        )
        .0;
        assert_eq!(token_metadata_pda(&mint).0, expected);
        assert_ne!(
            token_metadata_pda(&mint).0,
            Pubkey::find_program_address(
                &[
                    b"metadata",
                    TOKEN_METADATA_PROGRAM_ID.as_ref(),
                    mint.as_ref()
                ],
                &ours
            )
            .0
        );
    }

    #[test]
    fn the_canonical_metadata_uri_is_pinned_and_is_json() {
        // The default an operator gets without typing anything. It is a
        // relayer constant rather than a program one so that moving the
        // hosting never requires a program upgrade.
        assert_eq!(
            WRAPPED_GLC_URI,
            "https://goldcoinproject.org/assets/wglc.json"
        );
        assert!(
            WRAPPED_GLC_URI.starts_with("https://"),
            "wallets fetch this; plain http would be downgraded or blocked"
        );
        assert!(
            WRAPPED_GLC_URI.ends_with(".json"),
            "the URI points at the metadata JSON, not directly at the image"
        );
        assert!(
            WRAPPED_GLC_URI.len() <= 200,
            "the on-chain instruction caps the URI at 200 bytes"
        );
    }

    #[test]
    fn the_metaplex_id_and_display_strings_are_pinned() {
        // These are what wallets show and what the on-chain program writes;
        // both sides hold the same constants so they cannot drift.
        assert_eq!(
            TOKEN_METADATA_PROGRAM_ID.to_string(),
            "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
        );
        assert_eq!(WRAPPED_GLC_NAME, "Wrapped Goldcoin");
        assert_eq!(WRAPPED_GLC_SYMBOL, "wGLC");
    }

    #[test]
    fn update_token_metadata_encodes_three_borsh_strings_in_order() {
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let ix = update_token_metadata_instruction(
            &program_id,
            &admin,
            &mint,
            "Wrapped Goldcoin",
            "wGLC",
            "https://x/a.json",
        );

        assert_eq!(
            &ix.data[..8],
            &anchor_discriminator("update_token_metadata")
        );
        let mut off = 8;
        for expected in ["Wrapped Goldcoin", "wGLC", "https://x/a.json"] {
            let len = u32::from_le_bytes(ix.data[off..off + 4].try_into().unwrap()) as usize;
            assert_eq!(len, expected.len());
            assert_eq!(&ix.data[off + 4..off + 4 + len], expected.as_bytes());
            off += 4 + len;
        }
        assert_eq!(ix.data.len(), off, "no trailing bytes");
    }

    #[test]
    fn an_update_takes_no_mint_account_at_all() {
        // The structural guarantee behind "the mint is unchanged": the
        // instruction has no mint to alter.
        let program_id = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let ix = update_token_metadata_instruction(
            &program_id,
            &Pubkey::new_unique(),
            &mint,
            "n",
            "s",
            "u",
        );
        assert!(
            !ix.accounts.iter().any(|m| m.pubkey == mint),
            "the mint must not appear among the accounts"
        );
        assert_eq!(
            shape(&ix)
                .iter()
                .filter(|(_, _, writable)| *writable)
                .count(),
            1,
            "only the metadata account is writable"
        );
    }

    #[test]
    fn an_update_writes_only_the_metadata_account() {
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let ix = update_token_metadata_instruction(&program_id, &admin, &mint, "n", "s", "u");
        assert_eq!(
            shape(&ix),
            vec![
                (admin, true, false),
                (bridge_config_pda(&program_id).0, false, false),
                (mint_authority_pda(&program_id).0, false, false),
                (token_metadata_pda(&mint).0, false, true),
                (TOKEN_METADATA_PROGRAM_ID, false, false),
            ]
        );
    }

    #[test]
    fn create_and_update_target_the_same_metadata_account() {
        // If these diverged, an update would silently edit an account no
        // wallet is reading.
        let program_id = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let c = create_token_metadata_instruction(&program_id, &admin, &mint, "u");
        let u = update_token_metadata_instruction(&program_id, &admin, &mint, "n", "s", "u");
        let c_meta = c
            .accounts
            .iter()
            .find(|m| m.is_writable && m.pubkey != admin);
        let u_meta = u.accounts.iter().find(|m| m.is_writable);
        assert_eq!(c_meta.unwrap().pubkey, u_meta.unwrap().pubkey);
    }
}
