//! Wallet-visible metadata, exercised against the **real** Metaplex Token
//! Metadata program (ADR-0028).
//!
//! # Why the real program and not a mock
//!
//! The instruction data is hand-encoded Borsh for a third party's
//! instruction: a variant byte, three length-prefixed strings, a `u16`, and
//! five `Option` tags. Nothing about getting that wrong is visible from
//! reading it, and a mock would agree with whatever I wrote — the same
//! self-consistent-fixture trap that produced the Phase 7j sweep defect.
//!
//! So `tests/fixtures/mpl_token_metadata.so` is the program dumped from
//! mainnet, loaded into litesvm. If the encoding is wrong, Metaplex rejects
//! it here.
//!
//! # These tests self-skip, and CI therefore does not run them
//!
//! The repository excludes `**/*.so`, so the fixture is not committed. Fetch
//! it once:
//!
//! ```text
//! mkdir -p programs/glc-bridge/tests/fixtures
//! solana program dump -u m metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s \
//!   programs/glc-bridge/tests/fixtures/mpl_token_metadata.so
//! ```
//!
//! **A green CI run is not evidence that these passed** — the same caveat
//! the rehearsal suites carry. Run them deliberately before trusting a
//! change to the metadata encoding.

mod common;

use anchor_lang::solana_program::pubkey::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use litesvm::LiteSVM;
use solana_sdk::instruction::Instruction;
use solana_sdk::signature::{Keypair, Signer};

use common::*;

const METAPLEX: Pubkey =
    anchor_lang::solana_program::pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

/// `None` when the fixture has not been fetched, so the suite skips rather
/// than failing on a machine that simply has not run `solana program dump`.
fn metaplex_bytes() -> Option<Vec<u8>> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mpl_token_metadata.so"
    );
    std::fs::read(p).ok()
}

fn metadata_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"metadata", METAPLEX.as_ref(), mint.as_ref()], &METAPLEX).0
}

fn update_metadata_ix(
    admin: &Pubkey,
    mint: &Pubkey,
    name: &str,
    symbol: &str,
    uri: &str,
) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::UpdateTokenMetadata {
            admin: *admin,
            bridge_config: config_pda(),
            mint_authority: mint_authority_pda(),
            metadata: metadata_pda(mint),
            token_metadata_program: METAPLEX,
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::UpdateTokenMetadata {
            name: name.to_string(),
            symbol: symbol.to_string(),
            uri: uri.to_string(),
        }
        .data(),
    }
}

fn create_metadata_ix(admin: &Pubkey, mint: &Pubkey, uri: &str) -> Instruction {
    Instruction {
        program_id: glc_bridge::ID,
        accounts: glc_bridge::accounts::CreateTokenMetadata {
            admin: *admin,
            bridge_config: config_pda(),
            mint_authority: mint_authority_pda(),
            wrapped_mint: *mint,
            metadata: metadata_pda(mint),
            token_metadata_program: METAPLEX,
            system_program: solana_sdk::system_program::id(),
            rent: anchor_lang::solana_program::sysvar::rent::ID,
        }
        .to_account_metas(None),
        data: glc_bridge::instruction::CreateTokenMetadata {
            uri: uri.to_string(),
        }
        .data(),
    }
}

/// An initialized bridge with a wrapped mint, plus the real Metaplex
/// program loaded.
fn setup_with_metaplex(authority: &Keypair) -> Option<(LiteSVM, Pubkey)> {
    let bytes = metaplex_bytes()?;
    let (mut svm, mint) = setup_with_mint(authority, 3, 2);
    svm.add_program(METAPLEX, &bytes);
    Some((svm, mint))
}

/// Skips with an actionable message when the fixture is absent.
macro_rules! svm_or_skip {
    ($authority:expr) => {
        match setup_with_metaplex($authority) {
            Some(v) => v,
            None => {
                eprintln!(
                    "SKIP: fetch the Metaplex fixture first —\n  \
                     solana program dump -u m {} \\\n    \
                     programs/glc-bridge/tests/fixtures/mpl_token_metadata.so",
                    METAPLEX
                );
                return;
            }
        }
    };
}

/// Metaplex stores: key(1) update_authority(32) mint(32) then name, symbol,
/// uri as u32-length-prefixed strings, each padded to a fixed capacity.
fn read_metadata(svm: &LiteSVM, mint: &Pubkey) -> (String, String, String, Pubkey) {
    let acct = svm
        .get_account(&metadata_pda(mint))
        .expect("metadata account exists");
    let d = &acct.data;
    let update_authority = Pubkey::try_from(&d[1..33]).unwrap();
    let mut off = 65; // key + update_authority + mint
    let mut take = || {
        let len = u32::from_le_bytes(d[off..off + 4].try_into().unwrap()) as usize;
        let s = String::from_utf8_lossy(&d[off + 4..off + 4 + len])
            .trim_end_matches('\0')
            .to_string();
        off += 4 + len;
        s
    };
    let name = take();
    let symbol = take();
    let uri = take();
    (name, symbol, uri, update_authority)
}

#[test]
fn metadata_is_created_with_the_name_and_symbol_wallets_will_show() {
    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);

    send(
        &mut svm,
        create_metadata_ix(
            &authority.pubkey(),
            &mint,
            "https://example.invalid/wglc.json",
        ),
        &authority,
        &[],
    )
    .expect("the real Metaplex program accepts our hand-encoded instruction");

    let (name, symbol, uri, update_authority) = read_metadata(&svm, &mint);
    assert_eq!(name, "Wrapped Goldcoin");
    assert_eq!(symbol, "wGLC");
    assert_eq!(uri, "https://example.invalid/wglc.json");
    assert_eq!(
        update_authority,
        mint_authority_pda(),
        "update authority must be the program's PDA, not a loose keypair — a future \
         change then requires this program rather than whoever holds a key"
    );
}

#[test]
fn creating_metadata_twice_is_a_no_op_rather_than_a_failure() {
    // Idempotence is the point: an operator unsure whether a previous
    // attempt landed must be able to re-run this to VERIFY, not to gamble.
    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);

    send(
        &mut svm,
        create_metadata_ix(&authority.pubkey(), &mint, "u"),
        &authority,
        &[],
    )
    .unwrap();
    let before = svm.get_account(&metadata_pda(&mint)).unwrap().data;

    svm.expire_blockhash();
    send(
        &mut svm,
        create_metadata_ix(&authority.pubkey(), &mint, "u"),
        &authority,
        &[],
    )
    .expect("a second run must succeed");

    let after = svm.get_account(&metadata_pda(&mint)).unwrap().data;
    assert_eq!(before, after, "the second run must not rewrite anything");
}

#[test]
fn a_second_run_with_a_different_uri_still_does_not_rewrite() {
    // The idempotence check is "does metadata exist", not "does it match".
    // A run with different arguments must not silently overwrite what
    // wallets are already displaying.
    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);

    send(
        &mut svm,
        create_metadata_ix(&authority.pubkey(), &mint, "first"),
        &authority,
        &[],
    )
    .unwrap();
    svm.expire_blockhash();
    send(
        &mut svm,
        create_metadata_ix(&authority.pubkey(), &mint, "second"),
        &authority,
        &[],
    )
    .unwrap();

    let (_, _, uri, _) = read_metadata(&svm, &mint);
    assert_eq!(uri, "first", "an existing metadata account is left alone");
}

#[test]
fn only_the_admin_may_create_metadata() {
    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 10_000_000_000).unwrap();

    assert!(
        send(
            &mut svm,
            create_metadata_ix(&intruder.pubkey(), &mint, "u"),
            &intruder,
            &[],
        )
        .is_err(),
        "metadata writes a user-visible name; it is admin-gated"
    );
}

#[test]
fn metadata_cannot_be_attached_to_a_different_mint() {
    // The constraint that stops this program being used to name someone
    // else's token with the federation's authority.
    let authority = Keypair::new();
    let (mut svm, _mint) = svm_or_skip!(&authority);
    let other = Pubkey::new_unique();

    assert!(
        send(
            &mut svm,
            create_metadata_ix(&authority.pubkey(), &other, "u"),
            &authority,
            &[],
        )
        .is_err(),
        "only the mint recorded in bridge_config may be given metadata"
    );
}

#[test]
fn a_metadata_account_that_is_not_the_derived_pda_is_refused() {
    // Metaplex derives and checks this too; refusing here means the failure
    // names the problem instead of surfacing as an opaque CPI error.
    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);

    let mut ix = create_metadata_ix(&authority.pubkey(), &mint, "u");
    ix.accounts[4].pubkey = Pubkey::new_unique(); // metadata
    assert!(send(&mut svm, ix, &authority, &[]).is_err());
}

#[test]
fn an_over_long_uri_is_refused_with_our_error_not_a_cpi_failure() {
    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);

    assert!(
        send(
            &mut svm,
            create_metadata_ix(&authority.pubkey(), &mint, &"x".repeat(201)),
            &authority,
            &[],
        )
        .is_err(),
        "the length cap is checked before the CPI so the error is legible"
    );
}

#[test]
fn metadata_creation_does_not_touch_the_mint() {
    // The requirement this whole design is shaped by: the mint address, its
    // authority, its decimals and its supply must be exactly as they were.
    use anchor_lang::solana_program::program_pack::Pack;

    let authority = Keypair::new();
    let (mut svm, mint) = svm_or_skip!(&authority);
    let before = svm.get_account(&mint).unwrap();
    let before_state = anchor_spl::token::spl_token::state::Mint::unpack(&before.data).unwrap();

    send(
        &mut svm,
        create_metadata_ix(&authority.pubkey(), &mint, "u"),
        &authority,
        &[],
    )
    .unwrap();

    let after = svm.get_account(&mint).unwrap();
    let after_state = anchor_spl::token::spl_token::state::Mint::unpack(&after.data).unwrap();

    assert_eq!(
        before.data, after.data,
        "the mint account is byte-identical"
    );
    assert_eq!(after_state.decimals, 8, "decimals still come from the mint");
    assert_eq!(
        after_state.mint_authority, before_state.mint_authority,
        "mint authority unchanged"
    );
    assert!(
        after_state.freeze_authority.is_none(),
        "freeze authority is still None (custody #6)"
    );
    assert_eq!(after_state.supply, before_state.supply);
}

#[test]
fn the_derived_metadata_pda_matches_metaplexs_own_derivation() {
    // Pins the seeds. A wrong derivation would produce an account Metaplex
    // rejects, but only once someone ran it against the real program.
    let mint = Pubkey::new_unique();
    let (expected, _) =
        Pubkey::find_program_address(&[b"metadata", METAPLEX.as_ref(), mint.as_ref()], &METAPLEX);
    assert_eq!(metadata_pda(&mint), expected);
}

#[test]
fn the_metaplex_program_id_is_the_mainnet_one() {
    // Address-pinned in the program so it can never CPI into an impostor.
    assert_eq!(
        glc_bridge::instructions::token_metadata::TOKEN_METADATA_PROGRAM_ID,
        METAPLEX
    );
    assert_eq!(
        glc_bridge::instructions::token_metadata::WRAPPED_GLC_NAME,
        "Wrapped Goldcoin"
    );
    assert_eq!(
        glc_bridge::instructions::token_metadata::WRAPPED_GLC_SYMBOL,
        "wGLC"
    );
}

// ---------------------------------------------------------------------------
// Updating (ADR-0028 §9)
// ---------------------------------------------------------------------------

/// Creates metadata, then returns the fixture ready to update.
fn created(authority: &Keypair) -> Option<(LiteSVM, Pubkey)> {
    let (mut svm, mint) = setup_with_metaplex(authority)?;
    send(
        &mut svm,
        create_metadata_ix(&authority.pubkey(), &mint, "https://old.invalid/a.json"),
        authority,
        &[],
    )
    .unwrap();
    svm.expire_blockhash();
    Some((svm, mint))
}

macro_rules! created_or_skip {
    ($a:expr) => {
        match created($a) {
            Some(v) => v,
            None => {
                eprintln!("SKIP: Metaplex fixture absent");
                return;
            }
        }
    };
}

#[test]
fn an_update_changes_the_name_symbol_and_uri_wallets_display() {
    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);

    send(
        &mut svm,
        update_metadata_ix(
            &authority.pubkey(),
            &mint,
            "Wrapped Goldcoin",
            "wGLC",
            "https://goldcoinproject.org/assets/wglc.json",
        ),
        &authority,
        &[],
    )
    .expect("the real Metaplex program accepts our update encoding");

    let (name, symbol, uri, update_authority) = read_metadata(&svm, &mint);
    assert_eq!(name, "Wrapped Goldcoin");
    assert_eq!(symbol, "wGLC");
    assert_eq!(uri, "https://goldcoinproject.org/assets/wglc.json");
    assert_eq!(
        update_authority,
        mint_authority_pda(),
        "the update must NOT hand authority to anyone — it stays with the PDA"
    );
}

#[test]
fn the_uri_can_be_changed_without_touching_the_name() {
    // The reason this instruction exists: moving the hosting must not
    // require a program upgrade, and must not disturb what wallets show.
    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);
    let (before_name, before_symbol, _, _) = read_metadata(&svm, &mint);

    send(
        &mut svm,
        update_metadata_ix(
            &authority.pubkey(),
            &mint,
            &before_name,
            &before_symbol,
            "https://cdn.example.invalid/moved.json",
        ),
        &authority,
        &[],
    )
    .unwrap();

    let (name, symbol, uri, _) = read_metadata(&svm, &mint);
    assert_eq!(name, before_name);
    assert_eq!(symbol, before_symbol);
    assert_eq!(uri, "https://cdn.example.invalid/moved.json");
}

#[test]
fn repeating_an_update_with_identical_values_makes_no_cpi() {
    // Comparing account bytes cannot prove this: writing the SAME values
    // produces the same bytes, so a no-op and a redundant rewrite look
    // identical on disk. Mutation testing found the byte-comparison version
    // of this test vacuous — removing the idempotence check did not fail it.
    //
    // The logs can tell them apart: a CPI leaves a Metaplex `invoke [2]`
    // line, an early return leaves our own message and no invoke.
    // (Compute units do not work here — litesvm reports a flat figure.)
    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);

    let ix = || {
        update_metadata_ix(
            &authority.pubkey(),
            &mint,
            "Wrapped Goldcoin",
            "wGLC",
            "https://same.invalid/a.json",
        )
    };
    let first = send(&mut svm, ix(), &authority, &[]).unwrap();
    let after_first = svm.get_account(&metadata_pda(&mint)).unwrap().data;

    svm.expire_blockhash();
    let second = send(&mut svm, ix(), &authority, &[]).expect("a repeat must succeed");
    let after_second = svm.get_account(&metadata_pda(&mint)).unwrap().data;

    eprintln!(
        "SECOND LOGS:
{}",
        second.logs.join(
            "
"
        )
    );
    assert_eq!(after_first, after_second, "the account is unchanged");
    assert!(
        second.compute_units_consumed * 2 < first.compute_units_consumed,
        "the repeat must skip the CPI entirely: first {} CU, second {} CU",
        first.compute_units_consumed,
        second.compute_units_consumed
    );
}

#[test]
fn only_the_admin_may_update_metadata() {
    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);
    let intruder = Keypair::new();
    svm.airdrop(&intruder.pubkey(), 10_000_000_000).unwrap();

    assert!(
        send(
            &mut svm,
            update_metadata_ix(&intruder.pubkey(), &mint, "Evil", "EVL", "u"),
            &intruder,
            &[],
        )
        .is_err(),
        "renaming the token is admin-gated"
    );
}

#[test]
fn updating_metadata_that_does_not_exist_is_refused() {
    // A different mistake from a failed create, and it says so rather than
    // surfacing as an opaque CPI error.
    let authority = Keypair::new();
    let (mut svm, mint) = match setup_with_metaplex(&authority) {
        Some(v) => v,
        None => {
            eprintln!("SKIP: Metaplex fixture absent");
            return;
        }
    };
    let err = send(
        &mut svm,
        update_metadata_ix(&authority.pubkey(), &mint, "Wrapped Goldcoin", "wGLC", "u"),
        &authority,
        &[],
    )
    .expect_err("there is nothing to update before create_token_metadata has run");

    // Assert it is OUR refusal, not Metaplex failing downstream for its own
    // reasons. Without this the test passes even with the existence check
    // removed — found by mutation testing.
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.contains("MetadataNotFound"),
        "expected our MetadataNotFound error, got:\n{logs}"
    );
}

#[test]
fn an_update_checks_the_mint_recorded_inside_the_metadata_account() {
    // Defence in depth beyond the PDA check: if Metaplex ever changed its
    // seed scheme, deriving the "right" address could point at another
    // token's metadata. Fabricate exactly that — correct PDA, wrong stored
    // mint — which cannot occur naturally and so is the only way to reach
    // the check.
    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);

    let pda = metadata_pda(&mint);
    let mut acct = svm.get_account(&pda).unwrap();
    // The mint sits at offset 33..65: key(1) + update_authority(32).
    acct.data[33..65].copy_from_slice(Pubkey::new_unique().as_ref());
    svm.set_account(pda, acct).unwrap();

    assert!(
        send(
            &mut svm,
            update_metadata_ix(&authority.pubkey(), &mint, "Wrapped Goldcoin", "wGLC", "u"),
            &authority,
            &[],
        )
        .is_err(),
        "metadata naming a different mint must not be editable by this bridge"
    );
}

#[test]
fn an_update_cannot_be_pointed_at_another_tokens_metadata() {
    let authority = Keypair::new();
    let (mut svm, _mint) = created_or_skip!(&authority);
    let other = Pubkey::new_unique();

    assert!(
        send(
            &mut svm,
            update_metadata_ix(&authority.pubkey(), &other, "Wrapped Goldcoin", "wGLC", "u"),
            &authority,
            &[],
        )
        .is_err(),
        "only the metadata of the configured wrapped mint may be updated"
    );
}

#[test]
fn over_long_values_are_refused_with_our_errors() {
    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);

    for (n, s, u) in [
        ("x".repeat(33), "wGLC".to_string(), "u".to_string()),
        (
            "Wrapped Goldcoin".to_string(),
            "x".repeat(11),
            "u".to_string(),
        ),
        (
            "Wrapped Goldcoin".to_string(),
            "wGLC".to_string(),
            "x".repeat(201),
        ),
        (String::new(), "wGLC".to_string(), "u".to_string()),
        (
            "Wrapped Goldcoin".to_string(),
            String::new(),
            "u".to_string(),
        ),
    ] {
        svm.expire_blockhash();
        assert!(
            send(
                &mut svm,
                update_metadata_ix(&authority.pubkey(), &mint, &n, &s, &u),
                &authority,
                &[],
            )
            .is_err(),
            "name={} symbol={} uri_len={} must be refused",
            n.len(),
            s.len(),
            u.len()
        );
    }
}

#[test]
fn an_update_does_not_touch_the_mint() {
    // The requirement the whole design is shaped by. This instruction takes
    // no mint account at all, so it could not alter one if it tried.
    use anchor_lang::solana_program::program_pack::Pack;

    let authority = Keypair::new();
    let (mut svm, mint) = created_or_skip!(&authority);
    let before = svm.get_account(&mint).unwrap();

    send(
        &mut svm,
        update_metadata_ix(&authority.pubkey(), &mint, "Renamed", "RNM", "u"),
        &authority,
        &[],
    )
    .unwrap();

    let after = svm.get_account(&mint).unwrap();
    assert_eq!(
        before.data, after.data,
        "the mint account is byte-identical"
    );
    let state = anchor_spl::token::spl_token::state::Mint::unpack(&after.data).unwrap();
    assert_eq!(state.decimals, 8);
    assert!(state.freeze_authority.is_none(), "custody #6 unchanged");
}
