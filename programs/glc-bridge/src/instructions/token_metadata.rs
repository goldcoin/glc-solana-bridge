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
const MAX_NAME_LEN: usize = 32;
const MAX_SYMBOL_LEN: usize = 10;

/// Offsets inside a Metaplex `Metadata` account: `key(1) update_authority(32)
/// mint(32)`, then `name`, `symbol` and `uri` as length-prefixed strings.
///
/// Read on chain so an update can verify the account really belongs to this
/// bridge's mint, and so identical values can be detected without writing.
const METADATA_MINT_OFFSET: usize = 33;
const METADATA_STRINGS_OFFSET: usize = 65;

/// `CreateMetadataAccountV3` is variant 33 of the Metaplex instruction enum.
/// Borsh encodes an enum variant as a single leading byte.
const IX_CREATE_METADATA_ACCOUNT_V3: u8 = 33;
/// `UpdateMetadataAccountV2` is variant 15.
const IX_UPDATE_METADATA_ACCOUNT_V2: u8 = 15;

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

// ---------------------------------------------------------------------------
// Updating
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct UpdateTokenMetadata<'info> {
    /// Admin-gated, like creation: this changes what every wallet displays.
    pub admin: Signer<'info>,

    #[account(
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.admin == admin.key() @ BridgeError::UnauthorizedAdmin
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    /// CHECK: data-less PDA; signs the CPI as the metadata's update
    /// authority, which is what `create_token_metadata` set it to.
    #[account(seeds = [SEED_MINT_AUTHORITY], bump = bridge_config.mint_authority_bump)]
    pub mint_authority: UncheckedAccount<'info>,

    /// CHECK: verified below against `bridge_config.wrapped_mint` AND
    /// against the mint recorded inside the metadata account itself.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: address-pinned to the Metaplex program.
    #[account(address = TOKEN_METADATA_PROGRAM_ID)]
    pub token_metadata_program: UncheckedAccount<'info>,
}

/// Changes the wrapped mint's displayed name, symbol and URI.
///
/// # What this deliberately cannot do
///
/// It updates **only** the Metaplex metadata account. The mint address, its
/// decimals, its mint authority, its freeze authority (`None`, custody #6),
/// every PDA and every protocol rule are untouched — this instruction takes
/// no mint account at all, so it could not alter one if it tried.
///
/// It also never changes the metadata's own update authority or its
/// mutability: those stay with the mint-authority PDA, so the ability to
/// rename remains inside this program rather than moving to a loose keypair.
///
/// # Idempotent
///
/// If the stored name, symbol and URI already equal the requested ones,
/// nothing is written and no CPI is made. Re-running is therefore how an
/// operator confirms a rename landed, not a second write.
pub fn update_token_metadata(
    ctx: Context<UpdateTokenMetadata>,
    name: String,
    symbol: String,
    uri: String,
) -> Result<()> {
    require!(
        !name.is_empty() && name.len() <= MAX_NAME_LEN,
        BridgeError::NameTooLong
    );
    require!(
        !symbol.is_empty() && symbol.len() <= MAX_SYMBOL_LEN,
        BridgeError::SymbolTooLong
    );
    require!(uri.len() <= MAX_URI_LEN, BridgeError::UriTooLong);

    let mint = ctx.accounts.bridge_config.wrapped_mint;
    require!(mint != Pubkey::default(), BridgeError::MintNotConfigured);

    // The metadata PDA must be the one Metaplex derives for OUR mint.
    let (expected, _bump) = Pubkey::find_program_address(
        &[
            b"metadata",
            TOKEN_METADATA_PROGRAM_ID.as_ref(),
            mint.as_ref(),
        ],
        &TOKEN_METADATA_PROGRAM_ID,
    );
    require_keys_eq!(
        ctx.accounts.metadata.key(),
        expected,
        BridgeError::InvalidMetadataAccount
    );

    // It must already exist. Updating something that was never created is a
    // different mistake from a failed create, and says so.
    let info = ctx.accounts.metadata.to_account_info();
    require!(
        info.owner == &TOKEN_METADATA_PROGRAM_ID && !info.data_is_empty(),
        BridgeError::MetadataNotFound
    );

    {
        let data = info.try_borrow_data()?;

        // Belt and braces: the account also records its own mint. Checking
        // it as well as the PDA means a future change to Metaplex's seed
        // scheme cannot silently let us edit another token's metadata.
        let stored_mint = data
            .get(METADATA_MINT_OFFSET..METADATA_MINT_OFFSET + 32)
            .ok_or(BridgeError::InvalidMetadataAccount)?;
        require!(
            stored_mint == mint.as_ref(),
            BridgeError::InvalidMetadataAccount
        );

        // Idempotence: identical values mean there is nothing to write.
        if let Some((n, s, u)) = read_metadata_strings(&data) {
            if n == name && s == symbol && u == uri {
                msg!("token metadata already matches; nothing to do");
                return Ok(());
            }
        }
    }

    // Borsh: variant, Option<DataV2>=Some, DataV2, then three absent
    // Options — update_authority, primary_sale_happened, is_mutable. Leaving
    // those absent is what keeps authority and mutability where they are.
    let mut data = Vec::with_capacity(64 + name.len() + symbol.len() + uri.len());
    data.push(IX_UPDATE_METADATA_ACCOUNT_V2);
    data.push(1); // data: Some(DataV2)
    push_str(&mut data, &name);
    push_str(&mut data, &symbol);
    push_str(&mut data, &uri);
    data.extend_from_slice(&0u16.to_le_bytes()); // seller_fee_basis_points
    data.push(0); // creators: None
    data.push(0); // collection: None
    data.push(0); // uses: None
    data.push(0); // update_authority: None — unchanged
    data.push(0); // primary_sale_happened: None
    data.push(0); // is_mutable: None — unchanged

    let ix = Instruction {
        program_id: TOKEN_METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(ctx.accounts.metadata.key(), false),
            AccountMeta::new_readonly(ctx.accounts.mint_authority.key(), true),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            ctx.accounts.metadata.to_account_info(),
            ctx.accounts.mint_authority.to_account_info(),
            ctx.accounts.token_metadata_program.to_account_info(),
        ],
        &[&[
            SEED_MINT_AUTHORITY,
            &[ctx.accounts.bridge_config.mint_authority_bump],
        ]],
    )?;

    msg!("updated token metadata: {} ({})", name, symbol);
    Ok(())
}

/// Reads `(name, symbol, uri)` out of a Metaplex metadata account.
///
/// Metaplex pads each string to a fixed capacity with NUL bytes, so the
/// stored value must be trimmed before comparison — otherwise an unchanged
/// name would never compare equal and every update would rewrite.
fn read_metadata_strings(data: &[u8]) -> Option<(String, String, String)> {
    let mut off = METADATA_STRINGS_OFFSET;
    let mut take = || -> Option<String> {
        let len = u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?) as usize;
        let raw = data.get(off + 4..off + 4 + len)?;
        off += 4 + len;
        Some(
            core::str::from_utf8(raw)
                .ok()?
                .trim_end_matches('\0')
                .to_string(),
        )
    };
    Some((take()?, take()?, take()?))
}
