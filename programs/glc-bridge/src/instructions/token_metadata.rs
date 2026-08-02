//! Wallet-visible metadata for the wrapped-GLC mint (ADR-0028).
//!
//! # Why Metaplex and not Token-2022
//!
//! Token-2022's metadata is a **mint extension**: it lives inside the mint
//! account and only exists on a mint owned by the Token-2022 program. The
//! wrapped-GLC mint is a **classic SPL Token** mint (owner decision U5,
//! ADR-0009), so using it would mean creating a new mint under a different
//! program — a new mint address, new authority, and every existing token
//! account invalidated. That is not a metadata change, it is a different
//! token.
//!
//! Metaplex Token Metadata stores metadata in a **separate PDA derived from
//! the mint**. Nothing about the mint account, its authority, its decimals
//! or its address changes. That is the only option compatible with keeping
//! the mint we already have.
//!
//! # Why this has to be an on-chain instruction
//!
//! `CreateMetadataAccountV3` requires the **mint authority to sign**. The
//! wrapped mint's authority is a data-less PDA with no keypair anywhere
//! (ADR-0004) — so no off-chain tool can produce that signature, and this
//! must be a CPI made by the program itself under `invoke_signed`.
//!
//! # Decimals
//!
//! Deliberately not set here: Metaplex metadata carries no decimals field.
//! Wallets read decimals from the mint, which already says 8
//! (`WRAPPED_GLC_DECIMALS`). There is no second copy to disagree.
//!
//! # What this does not touch
//!
//! Mint address, mint authority, freeze authority (`None`, custody #6), PDA
//! seeds, and every existing account layout are unchanged. The instruction
//! is purely additive.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;

use crate::constants::{SEED_BRIDGE_CONFIG, SEED_MINT_AUTHORITY};
use crate::errors::BridgeError;
use crate::state::BridgeConfig;

/// The Metaplex Token Metadata program.
///
/// Pinned as a constant and checked by address, so this program can never be
/// induced to CPI into something else wearing that role.
pub const TOKEN_METADATA_PROGRAM_ID: Pubkey =
    anchor_lang::solana_program::pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

/// The name and symbol wallets will display.
///
/// Program constants rather than instruction arguments: an operator cannot
/// typo them, and anyone can verify what will be written by reading this
/// file rather than by trusting whoever ran the command.
pub const WRAPPED_GLC_NAME: &str = "Wrapped Goldcoin";
pub const WRAPPED_GLC_SYMBOL: &str = "wGLC";

/// Metaplex caps these; exceeding them fails inside the CPI with an error
/// that says nothing useful, so they are checked here where the message can.
const MAX_URI_LEN: usize = 200;

/// `CreateMetadataAccountV3` is variant 33 of the Metaplex instruction enum.
/// Borsh encodes an enum variant as a single leading byte.
const IX_CREATE_METADATA_ACCOUNT_V3: u8 = 33;

#[derive(Accounts)]
pub struct CreateTokenMetadata<'info> {
    /// Pays the metadata account's rent. Admin-gated for the same reason
    /// `create_wrapped_mint` is: it spends the admin's lamports and writes a
    /// user-visible name.
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.admin == admin.key() @ BridgeError::UnauthorizedAdmin
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    /// CHECK: data-less PDA, address fully constrained by seeds. Signs the
    /// CPI as the mint authority (ADR-0004).
    #[account(seeds = [SEED_MINT_AUTHORITY], bump = bridge_config.mint_authority_bump)]
    pub mint_authority: UncheckedAccount<'info>,

    /// CHECK: must be exactly the mint this bridge already created. Compared
    /// against `bridge_config.wrapped_mint`, so metadata can never be
    /// attached to some other mint.
    #[account(constraint = wrapped_mint.key() == bridge_config.wrapped_mint @ BridgeError::MintNotConfigured)]
    pub wrapped_mint: UncheckedAccount<'info>,

    /// CHECK: the Metaplex metadata PDA. Its address is verified here and
    /// again by Metaplex itself, which derives it from the mint.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: address-pinned to the Metaplex program.
    #[account(address = TOKEN_METADATA_PROGRAM_ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    /// CHECK: the rent sysvar, address-pinned; Metaplex reads it.
    #[account(address = anchor_lang::solana_program::sysvar::rent::ID)]
    pub rent: UncheckedAccount<'info>,
}

/// Creates the wrapped mint's Metaplex metadata, or does nothing if it
/// already exists.
///
/// **Idempotent by design.** Re-running is the normal way to confirm the
/// metadata is present: an operator who is unsure whether a previous attempt
/// landed should be able to run this again without risk, and without having
/// to reason about partial state.
pub fn create_token_metadata(ctx: Context<CreateTokenMetadata>, uri: String) -> Result<()> {
    require!(
        ctx.accounts.bridge_config.wrapped_mint != Pubkey::default(),
        BridgeError::MintNotConfigured
    );
    require!(uri.len() <= MAX_URI_LEN, BridgeError::UriTooLong);

    // The metadata PDA is Metaplex's, not ours: ["metadata", program, mint].
    let (expected, _bump) = Pubkey::find_program_address(
        &[
            b"metadata",
            TOKEN_METADATA_PROGRAM_ID.as_ref(),
            ctx.accounts.wrapped_mint.key().as_ref(),
        ],
        &TOKEN_METADATA_PROGRAM_ID,
    );
    require_keys_eq!(
        ctx.accounts.metadata.key(),
        expected,
        BridgeError::InvalidMetadataAccount
    );

    // Idempotence: an initialized metadata account already owned by Metaplex
    // means the work is done. Returning Ok rather than erroring is what lets
    // an operator re-run this to VERIFY rather than to gamble.
    let already = {
        let info = ctx.accounts.metadata.to_account_info();
        info.owner == &TOKEN_METADATA_PROGRAM_ID && !info.data_is_empty()
    };
    if already {
        msg!("token metadata already exists; nothing to do");
        return Ok(());
    }

    // Borsh: variant byte, then DataV2, then is_mutable, then
    // collection_details. Strings are u32-length-prefixed; each Option is a
    // single 0 byte when absent.
    let mut data = Vec::with_capacity(64 + uri.len());
    data.push(IX_CREATE_METADATA_ACCOUNT_V3);
    push_str(&mut data, WRAPPED_GLC_NAME);
    push_str(&mut data, WRAPPED_GLC_SYMBOL);
    push_str(&mut data, &uri);
    data.extend_from_slice(&0u16.to_le_bytes()); // seller_fee_basis_points
    data.push(0); // creators: None
    data.push(0); // collection: None
    data.push(0); // uses: None
    data.push(1); // is_mutable: true
    data.push(0); // collection_details: None

    let ix = Instruction {
        program_id: TOKEN_METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(ctx.accounts.metadata.key(), false),
            AccountMeta::new_readonly(ctx.accounts.wrapped_mint.key(), false),
            // The mint authority signs — the whole reason this is a CPI.
            AccountMeta::new_readonly(ctx.accounts.mint_authority.key(), true),
            AccountMeta::new(ctx.accounts.admin.key(), true),
            // Update authority: the mint-authority PDA, so future changes
            // require this program rather than any loose keypair. Not a
            // signer for creation.
            AccountMeta::new_readonly(ctx.accounts.mint_authority.key(), false),
            AccountMeta::new_readonly(ctx.accounts.system_program.key(), false),
            AccountMeta::new_readonly(ctx.accounts.rent.key(), false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            ctx.accounts.metadata.to_account_info(),
            ctx.accounts.wrapped_mint.to_account_info(),
            ctx.accounts.mint_authority.to_account_info(),
            ctx.accounts.admin.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
            ctx.accounts.rent.to_account_info(),
            ctx.accounts.token_metadata_program.to_account_info(),
        ],
        &[&[
            SEED_MINT_AUTHORITY,
            &[ctx.accounts.bridge_config.mint_authority_bump],
        ]],
    )?;

    msg!(
        "created token metadata: {} ({})",
        WRAPPED_GLC_NAME,
        WRAPPED_GLC_SYMBOL
    );
    Ok(())
}

/// Borsh string: u32 little-endian length, then the bytes.
fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}
