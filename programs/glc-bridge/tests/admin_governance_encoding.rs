//! Pins the wire encoding of every admin and governance instruction
//! (Phase 7i-1).
//!
//! # Why this file exists
//!
//! ADR-0001 keeps the relayer in its own workspace with **no dependency on
//! `anchor-lang` or on this program crate**, so `relayer/src/solana/
//! instruction.rs` hand-builds discriminators and account metas. That is a
//! deliberate isolation choice, and its cost is that nothing mechanically
//! links the two sides: a renamed instruction or a reordered accounts struct
//! would compile cleanly on both and fail only at runtime, against a real
//! deployment, during an incident.
//!
//! So both sides are pinned to the same literal spec instead. Here, Anchor's
//! *generated* encoding is asserted to equal the formula the relayer
//! implements; in the relayer, `solana::instruction`'s tests assert its
//! builders produce the same. Renaming an instruction or reordering an
//! accounts struct now breaks a test on this side; changing the relayer's
//! copy breaks one on that side.
//!
//! The instructions covered here are exactly those that had **no caller
//! outside this test suite** before Phase 7i-1: `set_paused`, the supply-cap
//! controls, and the rotation lifecycle.

mod common;

use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::pubkey::Pubkey;
use anchor_lang::InstructionData;

use common::*;

/// The relayer's `anchor_discriminator`, reimplemented here so the two are
/// compared rather than shared.
fn discriminator(name: &str) -> [u8; 8] {
    let h = hash(format!("global:{name}").as_bytes()).to_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// `(pubkey, is_signer, is_writable)` — the shape the relayer's tests pin.
fn shape(ix: &anchor_lang::solana_program::instruction::Instruction) -> Vec<(Pubkey, bool, bool)> {
    ix.accounts
        .iter()
        .map(|m| (m.pubkey, m.is_signer, m.is_writable))
        .collect()
}

#[test]
fn set_paused_encoding_is_discriminator_then_one_borsh_bool() {
    let admin = Pubkey::new_unique();
    let ix = set_paused_ix(&admin, true);

    assert_eq!(&ix.data[..8], &discriminator("set_paused"));
    assert_eq!(ix.data.len(), 9, "8-byte discriminator + one bool byte");
    assert_eq!(ix.data[8], 1, "true encodes as 1");
    assert_eq!(
        set_paused_ix(&admin, false).data[8],
        0,
        "false encodes as 0"
    );

    // The admin signs but is not written to; the config is written to but
    // does not sign. Swapping these silently would produce a transaction the
    // runtime rejects only once it reaches a real cluster.
    assert_eq!(
        shape(&ix),
        vec![(admin, true, false), (config_pda(), false, true)]
    );
}

#[test]
fn lower_supply_cap_encoding_is_discriminator_then_a_u64() {
    let admin = Pubkey::new_unique();
    let ix = lower_cap_ix(&admin, 21_000_000_000_000);

    assert_eq!(&ix.data[..8], &discriminator("lower_wrapped_supply_cap"));
    assert_eq!(ix.data.len(), 16);
    assert_eq!(&ix.data[8..16], &21_000_000_000_000u64.to_le_bytes());
    assert_eq!(
        shape(&ix),
        vec![(admin, true, false), (config_pda(), false, true)]
    );
}

#[test]
fn propose_rotation_encoding_is_a_borsh_vec_then_the_threshold() {
    let proposer = Pubkey::new_unique();
    let validators = vec![Pubkey::new_unique(), Pubkey::new_unique()];
    let ix = propose_rotation_ix(&proposer, validators.clone(), 2);

    assert_eq!(&ix.data[..8], &discriminator("propose_validator_rotation"));
    // Borsh: u32 length prefix, then the elements, then the trailing u8.
    assert_eq!(&ix.data[8..12], &2u32.to_le_bytes());
    assert_eq!(&ix.data[12..44], validators[0].as_ref());
    assert_eq!(&ix.data[44..76], validators[1].as_ref());
    assert_eq!(ix.data[76], 2, "threshold follows the vector");
    assert_eq!(ix.data.len(), 77);

    assert_eq!(
        shape(&ix),
        vec![
            (proposer, true, true),
            (config_pda(), false, false),
            (validator_set_pda(), false, false),
            (governance_action_pda(), false, true),
            (
                anchor_lang::solana_program::sysvar::instructions::ID,
                false,
                false
            ),
            (solana_sdk::system_program::id(), false, false),
        ]
    );
}

#[test]
fn execute_rotation_writes_the_validator_set_and_only_reads_the_config() {
    // The mirror image of the cap raise below. Getting the two backwards is
    // a runtime failure rather than a compile error, so both are pinned.
    let executor = Pubkey::new_unique();
    let ix = execute_rotation_ix(&executor);

    assert_eq!(
        ix.data,
        discriminator("execute_validator_rotation").to_vec()
    );
    assert_eq!(
        shape(&ix),
        vec![
            (executor, true, true),
            (config_pda(), false, false),
            (validator_set_pda(), false, true),
            (governance_action_pda(), false, true),
        ]
    );
}

#[test]
fn execute_cap_raise_writes_the_config_and_only_reads_the_validator_set() {
    let executor = Pubkey::new_unique();
    let ix = execute_cap_raise_ix(&executor);

    assert_eq!(
        ix.data,
        discriminator("execute_wrapped_supply_cap_raise").to_vec()
    );
    assert_eq!(
        shape(&ix),
        vec![
            (executor, true, true),
            (config_pda(), false, true),
            (validator_set_pda(), false, false),
            (governance_action_pda(), false, true),
        ]
    );
}

#[test]
fn cancel_rotation_carries_the_instructions_sysvar_and_no_system_program() {
    // Cancellation needs a FRESH federation proof, so it reads the sysvar;
    // it creates nothing, so it takes no system program. A copy-paste from
    // the propose path would add one and fail.
    let canceller = Pubkey::new_unique();
    let ix = cancel_rotation_ix(&canceller);

    assert_eq!(ix.data, discriminator("cancel_validator_rotation").to_vec());
    assert_eq!(
        shape(&ix),
        vec![
            (canceller, true, true),
            (config_pda(), false, false),
            (validator_set_pda(), false, false),
            (governance_action_pda(), false, true),
            (
                anchor_lang::solana_program::sysvar::instructions::ID,
                false,
                false
            ),
        ]
    );
}

#[test]
fn propose_cap_raise_shares_the_proposal_account_shape() {
    let proposer = Pubkey::new_unique();
    let ix = propose_cap_raise_ix(&proposer, 42);

    assert_eq!(
        &ix.data[..8],
        &discriminator("propose_wrapped_supply_cap_raise")
    );
    assert_eq!(&ix.data[8..16], &42u64.to_le_bytes());
    assert_eq!(ix.data.len(), 16);
    assert_eq!(
        shape(&ix),
        shape(&propose_rotation_ix(&proposer, vec![], 1)),
        "both proposals take the same accounts in the same order"
    );
}

#[test]
fn the_governance_action_pda_uses_the_seed_the_relayer_copies() {
    assert_eq!(
        governance_action_pda(),
        Pubkey::find_program_address(&[b"governance_action"], &glc_bridge::ID).0
    );
}

#[test]
fn anchor_generates_exactly_the_discriminators_the_relayer_computes() {
    // The whole cross-workspace link in one assertion: if an instruction is
    // renamed on this side, its discriminator changes and the relayer's
    // hand-computed copy stops matching. This catches it here.
    for (name, data) in [
        (
            "set_paused",
            glc_bridge::instruction::SetPaused { paused: true }.data(),
        ),
        (
            "lower_wrapped_supply_cap",
            glc_bridge::instruction::LowerWrappedSupplyCap { new_max: 1 }.data(),
        ),
        (
            "propose_validator_rotation",
            glc_bridge::instruction::ProposeValidatorRotation {
                validators: vec![],
                threshold: 1,
            }
            .data(),
        ),
        (
            "execute_validator_rotation",
            glc_bridge::instruction::ExecuteValidatorRotation {}.data(),
        ),
        (
            "cancel_validator_rotation",
            glc_bridge::instruction::CancelValidatorRotation {}.data(),
        ),
        (
            "propose_wrapped_supply_cap_raise",
            glc_bridge::instruction::ProposeWrappedSupplyCapRaise { new_max: 1 }.data(),
        ),
        (
            "execute_wrapped_supply_cap_raise",
            glc_bridge::instruction::ExecuteWrappedSupplyCapRaise {}.data(),
        ),
    ] {
        assert_eq!(
            &data[..8],
            &discriminator(name),
            "anchor's discriminator for {name} is not sha256(\"global:{name}\")[..8]"
        );
    }
}

#[test]
fn accounts_structs_have_not_grown_or_shrunk() {
    // A field added to an accounts struct changes the meta count and would
    // otherwise surface as an obscure runtime error in the relayer.
    let k = Pubkey::new_unique();
    assert_eq!(set_paused_ix(&k, true).accounts.len(), 2);
    assert_eq!(lower_cap_ix(&k, 1).accounts.len(), 2);
    assert_eq!(propose_rotation_ix(&k, vec![], 1).accounts.len(), 6);
    assert_eq!(propose_cap_raise_ix(&k, 1).accounts.len(), 6);
    assert_eq!(execute_rotation_ix(&k).accounts.len(), 4);
    assert_eq!(execute_cap_raise_ix(&k).accounts.len(), 4);
    assert_eq!(cancel_rotation_ix(&k).accounts.len(), 5);
}

// ---------------------------------------------------------------------------
// Account layout the relayer hand-decodes
// ---------------------------------------------------------------------------

/// The byte offsets `relayer/src/solana/rpc.rs::decode_pending_action` reads,
/// asserted against what Anchor actually serialises.
///
/// This matters more than it looks. A cancellation's canonical message
/// commits to the pending action's `eta` (`shared::governance::cancel_params`),
/// so an offset that is wrong by one byte produces a signature the program
/// rejects — after the entire federation has been asked to make it.
#[test]
fn pending_governance_action_serialises_at_the_offsets_the_relayer_reads() {
    use anchor_lang::AccountSerialize;

    let validators = vec![Pubkey::new_unique(), Pubkey::new_unique()];
    let action = glc_bridge::state::PendingGovernanceAction {
        action: 0x03,
        proposed_under_epoch: 9,
        eta: 1_800_000_000,
        threshold: 2,
        validators: validators.clone(),
        bump: 0xFE,
        proposed_max_wrapped_supply: 0,
        reserved: [0u8; 24],
    };
    let mut data = Vec::new();
    action.try_serialize(&mut data).unwrap();

    let body = &data[8..]; // skip the Anchor discriminator
    assert_eq!(body[0], 0x03, "action at body[0]");
    assert_eq!(&body[1..9], &9u64.to_le_bytes(), "epoch at body[1..9]");
    assert_eq!(
        &body[9..17],
        &1_800_000_000i64.to_le_bytes(),
        "eta at body[9..17]"
    );
    assert_eq!(body[17], 2, "threshold at body[17]");
    assert_eq!(
        &body[18..22],
        &2u32.to_le_bytes(),
        "validators length prefix at body[18..22]"
    );
    assert_eq!(&body[22..54], validators[0].as_ref());
    assert_eq!(&body[54..86], validators[1].as_ref());
    assert_eq!(body[86], 0xFE, "bump follows the validator list");
    assert_eq!(
        &body[87..95],
        &0u64.to_le_bytes(),
        "proposed_max_wrapped_supply follows the bump"
    );
}

#[test]
fn a_cap_raise_shifts_the_supply_field_because_its_validator_list_is_empty() {
    // The reason the relayer decodes this field at a computed offset rather
    // than a fixed one: with no validators, it lands 64 bytes earlier.
    use anchor_lang::AccountSerialize;

    let action = glc_bridge::state::PendingGovernanceAction {
        action: 0x05,
        proposed_under_epoch: 4,
        eta: 123,
        threshold: 0,
        validators: vec![],
        bump: 0xFE,
        proposed_max_wrapped_supply: 21_000_000_000_000,
        reserved: [0u8; 24],
    };
    let mut data = Vec::new();
    action.try_serialize(&mut data).unwrap();

    let body = &data[8..];
    assert_eq!(&body[18..22], &0u32.to_le_bytes(), "empty validator list");
    assert_eq!(body[22], 0xFE, "bump immediately follows");
    assert_eq!(
        &body[23..31],
        &21_000_000_000_000u64.to_le_bytes(),
        "the supply ceiling sits 64 bytes earlier than for a 2-validator rotation"
    );
}

// ---------------------------------------------------------------------------
// Bootstrap encoding (Phase 7m)
// ---------------------------------------------------------------------------
//
// `initialize`, `create_wrapped_mint`, `transfer_admin` and `accept_admin`
// had no shipped caller at all until Phase 7m — the bridge could not be
// stood up with the released binaries. Now that `glc-admin` builds them by
// hand, they need the same cross-workspace pin as everything else.

#[test]
fn initialize_encodes_its_arguments_in_declaration_order() {
    let authority = Pubkey::new_unique();
    let program_data = Pubkey::new_unique();
    let validators = vec![Pubkey::new_unique(), Pubkey::new_unique()];
    let ix = initialize_ix_with_cap(&authority, program_data, validators.clone(), 2, 77);

    assert_eq!(&ix.data[..8], &discriminator("initialize"));
    assert_eq!(&ix.data[8..12], &2u32.to_le_bytes(), "Vec length prefix");
    assert_eq!(&ix.data[12..44], validators[0].as_ref());
    assert_eq!(&ix.data[44..76], validators[1].as_ref());
    assert_eq!(ix.data[76], 2, "threshold");
    // min_deposit, min_withdrawal, governance_timelock_seconds,
    // max_wrapped_supply — the order the relayer must reproduce exactly.
    assert_eq!(&ix.data[77..85], &1_000u64.to_le_bytes());
    assert_eq!(&ix.data[85..93], &2_000u64.to_le_bytes());
    assert_eq!(&ix.data[93..101], &DEFAULT_TEST_TIMELOCK.to_le_bytes());
    assert_eq!(&ix.data[101..109], &77u64.to_le_bytes());
    assert_eq!(ix.data.len(), 109);

    assert_eq!(
        shape(&ix),
        vec![
            (authority, true, true),
            (config_pda(), false, true),
            (validator_set_pda(), false, true),
            (glc_bridge::ID, false, false),
            (program_data, false, false),
            (solana_sdk::system_program::id(), false, false),
        ]
    );
}

#[test]
fn create_wrapped_mint_requires_the_mint_itself_to_sign() {
    // The account is created by this instruction, so the caller must hold
    // its keypair for exactly this one transaction. A builder that marked it
    // read-only or non-signing would fail only against a live cluster.
    let admin = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let ix = create_wrapped_mint_ix(&admin, &mint);

    assert_eq!(ix.data, discriminator("create_wrapped_mint").to_vec());
    assert_eq!(
        shape(&ix),
        vec![
            (admin, true, true),
            (config_pda(), false, true),
            (mint_authority_pda(), false, false),
            (mint, true, true),
            (anchor_spl::token::spl_token::ID, false, false),
            (solana_sdk::system_program::id(), false, false),
        ]
    );
}

#[test]
fn transfer_admin_encodes_the_incoming_key() {
    let admin = Pubkey::new_unique();
    let new_admin = Pubkey::new_unique();
    let ix = transfer_admin_ix(&admin, new_admin);

    assert_eq!(&ix.data[..8], &discriminator("transfer_admin"));
    assert_eq!(&ix.data[8..40], new_admin.as_ref());
    assert_eq!(ix.data.len(), 40);
    assert_eq!(
        shape(&ix),
        vec![(admin, true, false), (config_pda(), false, true)]
    );
}

#[test]
fn accept_admin_is_signed_by_the_incoming_key_not_the_outgoing_one() {
    // The whole point of the two-step handover: nothing changes until the
    // named key proves it exists.
    let new_admin = Pubkey::new_unique();
    let ix = accept_admin_ix(&new_admin);

    assert_eq!(ix.data, discriminator("accept_admin").to_vec());
    assert_eq!(
        shape(&ix),
        vec![(new_admin, true, false), (config_pda(), false, true)]
    );
}

#[test]
fn bridge_config_serialises_at_the_offsets_the_relayer_reads() {
    use anchor_lang::AccountSerialize;

    // `pending_admin: Option<Pubkey>` is a one-byte Borsh tag followed by the
    // value only when set, so every later field moves by 32 bytes depending
    // on whether a handover is in flight. Both shapes are pinned, because
    // reading from fixed offsets would return wrong numbers exactly while an
    // operator is mid-handover and checking.
    for pending in [None, Some(Pubkey::new_unique())] {
        let cfg = glc_bridge::state::BridgeConfig {
            protocol_version: 1,
            admin: Pubkey::new_unique(),
            pending_admin: pending,
            paused: true,
            withdrawal_count: 9,
            min_deposit: 1_000,
            min_withdrawal: 2_000,
            bump: 0xFD,
            wrapped_mint: Pubkey::new_unique(),
            mint_authority_bump: 0xFE,
            governance_timelock_seconds: 3_600,
            max_wrapped_supply: 21_000_000_000_000,
            reserved: [0u8; 15],
        };
        let mut data = Vec::new();
        cfg.try_serialize(&mut data).unwrap();
        let body = &data[8..];

        assert_eq!(body[0], 1, "protocol_version at body[0]");
        assert_eq!(&body[1..33], cfg.admin.as_ref());
        let mut off = match pending {
            None => {
                assert_eq!(body[33], 0, "absent Option is a zero tag with no value");
                34
            }
            Some(p) => {
                assert_eq!(body[33], 1, "present Option is a one tag");
                assert_eq!(&body[34..66], p.as_ref());
                66
            }
        };
        assert_eq!(body[off], 1, "paused");
        off += 1;
        assert_eq!(&body[off..off + 8], &9u64.to_le_bytes());
        off += 8;
        assert_eq!(&body[off..off + 8], &1_000u64.to_le_bytes());
        off += 8;
        assert_eq!(&body[off..off + 8], &2_000u64.to_le_bytes());
        off += 8;
        assert_eq!(body[off], 0xFD, "bump");
        off += 1;
        assert_eq!(&body[off..off + 32], cfg.wrapped_mint.as_ref());
        off += 32;
        assert_eq!(body[off], 0xFE, "mint_authority_bump");
        off += 1;
        assert_eq!(&body[off..off + 8], &3_600i64.to_le_bytes());
        off += 8;
        assert_eq!(&body[off..off + 8], &21_000_000_000_000u64.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Token metadata encoding (ADR-0028)
// ---------------------------------------------------------------------------

#[test]
fn create_token_metadata_encodes_a_borsh_string() {
    use anchor_lang::ToAccountMetas;

    let admin = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let metaplex: Pubkey =
        anchor_lang::solana_program::pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
    let metadata =
        Pubkey::find_program_address(&[b"metadata", metaplex.as_ref(), mint.as_ref()], &metaplex).0;

    let ix = anchor_lang::solana_program::instruction::Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::CreateTokenMetadata {
            admin,
            bridge_config: config_pda(),
            mint_authority: mint_authority_pda(),
            wrapped_mint: mint,
            metadata,
            token_metadata_program: metaplex,
            system_program: solana_sdk::system_program::id(),
            rent: anchor_lang::solana_program::sysvar::rent::ID,
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::CreateTokenMetadata {
            uri: "abc".to_string(),
        }
        .data(),
    };

    assert_eq!(&ix.data[..8], &discriminator("create_token_metadata"));
    assert_eq!(&ix.data[8..12], &3u32.to_le_bytes(), "Borsh string length");
    assert_eq!(&ix.data[12..15], b"abc");
    assert_eq!(ix.data.len(), 15);

    assert_eq!(
        shape(&ix),
        vec![
            (admin, true, true),
            (config_pda(), false, false),
            (mint_authority_pda(), false, false),
            (mint, false, false),
            (metadata, false, true),
            (metaplex, false, false),
            (solana_sdk::system_program::id(), false, false),
            (anchor_lang::solana_program::sysvar::rent::ID, false, false),
        ]
    );
}

#[test]
fn the_metadata_name_and_symbol_are_program_constants() {
    // Constants rather than instruction arguments: an operator cannot typo
    // them, and what wallets will show is verifiable by reading the program.
    assert_eq!(
        glc_bridge::instructions::token_metadata::WRAPPED_GLC_NAME,
        "Wrapped Goldcoin"
    );
    assert_eq!(
        glc_bridge::instructions::token_metadata::WRAPPED_GLC_SYMBOL,
        "wGLC"
    );
}
