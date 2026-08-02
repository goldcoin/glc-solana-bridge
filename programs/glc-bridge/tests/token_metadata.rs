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
