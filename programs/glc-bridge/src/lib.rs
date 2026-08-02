//! # glc-bridge — Solana side of the Goldcoin federated bridge
//!
//! **Phase 1: bridge state and governance.** [`state::BridgeConfig`] and
//! [`state::ValidatorSet`] PDAs, upgrade-authority-gated initialization
//! (ADR-0008), pause circuit breaker, epoch-tracked validator-set rotation
//! (ADR-0007), and two-step admin handover. No value moves in this phase:
//! the wrapped mint, deposits, and withdrawals land in Phases 2–3.
//!
//! ## Instruction set
//! - [`initialize`](glc_bridge::initialize) — create the two state PDAs;
//!   only the program upgrade authority may call, exactly once. (Phase 1)
//! - [`set_paused`](glc_bridge::set_paused),
//!   [`propose_validator_rotation`](glc_bridge::propose_validator_rotation),
//!   [`transfer_admin`](glc_bridge::transfer_admin) /
//!   [`accept_admin`](glc_bridge::accept_admin) — admin-gated governance.
//!   (Phase 1)
//! - `mint_wrapped` — verify an M-of-N aggregated federation proof for a
//!   deposit identified by Goldcoin `(txid, vout)`, create the per-claim
//!   [`state::DepositClaim`] PDA (replay guard), mint 1:1. (Phases 2–3)
//! - `burn_wrapped` — burn wrapped GLC and create a persistent
//!   [`state::WithdrawalRequest`] PDA; events are emitted as a convenience
//!   but the account record is authoritative. (Phase 3)

use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;
pub mod validation;
pub mod verification;

use instructions::*;

declare_id!("77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq");

#[program]
pub mod glc_bridge {
    use super::*;

    /// One-time creation of [`state::BridgeConfig`] and
    /// [`state::ValidatorSet`]. Caller must be the program upgrade authority
    /// and becomes the initial admin.
    pub fn initialize(
        ctx: Context<Initialize>,
        validators: Vec<Pubkey>,
        threshold: u8,
        min_deposit: u64,
        min_withdrawal: u64,
        governance_timelock_seconds: i64,
        max_wrapped_supply: u64,
    ) -> Result<()> {
        instructions::initialize(
            ctx,
            validators,
            threshold,
            min_deposit,
            min_withdrawal,
            governance_timelock_seconds,
            max_wrapped_supply,
        )
    }

    /// Admin-only circuit breaker for the value-moving paths (Phase 2+).
    pub fn set_paused(ctx: Context<AdminConfig>, paused: bool) -> Result<()> {
        instructions::set_paused(ctx, paused)
    }

    /// Queues a validator-set rotation behind the governance timelock,
    /// authorized by an M-of-N federation proof (Phase 7a, ADR-0014).
    /// Replaces the deleted admin-gated `update_validator_set`.
    pub fn propose_validator_rotation(
        ctx: Context<ProposeGovernanceAction>,
        validators: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        instructions::propose_validator_rotation(ctx, validators, threshold)
    }

    /// Applies a queued rotation once its timelock has elapsed.
    /// Permissionless: the threshold proof at proposal time was the
    /// authorization.
    pub fn execute_validator_rotation(ctx: Context<ExecuteGovernanceAction>) -> Result<()> {
        instructions::execute_validator_rotation(ctx)
    }

    /// Cancels the pending governance action; requires a fresh M-of-N proof.
    pub fn cancel_validator_rotation(ctx: Context<CancelGovernanceAction>) -> Result<()> {
        instructions::cancel_validator_rotation(ctx)
    }

    /// Admin-only step 1 of the two-step admin handover.
    pub fn transfer_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
        instructions::transfer_admin(ctx, new_admin)
    }

    /// Step 2 of the handover; only the pending admin may call.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        instructions::accept_admin(ctx)
    }

    /// One-time creation of the wrapped-GLC SPL mint; admin-only. Mint
    /// authority is the mint-authority PDA, freeze authority is None
    /// (custody #6, ADR-0009).
    pub fn create_wrapped_mint(ctx: Context<CreateWrappedMint>) -> Result<()> {
        instructions::create_wrapped_mint(ctx)
    }

    /// Mints wrapped GLC 1:1 for a confirmed Goldcoin deposit, authorized by
    /// an M-of-N federation proof carried in a preceding ed25519
    /// verification instruction (ADR-0010). Any fee payer may submit.
    pub fn mint_wrapped(
        ctx: Context<MintWrapped>,
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        epoch: u64,
    ) -> Result<()> {
        instructions::mint_wrapped(ctx, txid, vout, amount, epoch)
    }

    /// Burns wrapped GLC and atomically records the payout obligation as a
    /// persistent [`state::WithdrawalRequest`] (ADR-0006).
    pub fn burn_wrapped(
        ctx: Context<BurnWrapped>,
        amount: u64,
        glc_address: Vec<u8>,
    ) -> Result<()> {
        instructions::burn_wrapped(ctx, amount, glc_address)
    }

    /// LOWERS the wrapped-supply cap immediately (Phase 7h-0). Admin-only,
    /// and only downward: reducing exposure is incident response, raising it
    /// is a federation decision.
    pub fn lower_wrapped_supply_cap(ctx: Context<AdminConfig>, new_max: u64) -> Result<()> {
        instructions::lower_wrapped_supply_cap(ctx, new_max)
    }

    /// Queues a wrapped-supply cap INCREASE behind the governance timelock,
    /// under the same M-of-N proof a validator rotation requires.
    pub fn propose_wrapped_supply_cap_raise(
        ctx: Context<ProposeGovernanceAction>,
        new_max: u64,
    ) -> Result<()> {
        instructions::propose_wrapped_supply_cap_raise(ctx, new_max)
    }

    /// Applies a queued cap increase once its timelock has elapsed.
    pub fn execute_wrapped_supply_cap_raise(ctx: Context<ExecuteCapRaise>) -> Result<()> {
        instructions::execute_wrapped_supply_cap_raise(ctx)
    }

    /// Creates wallet-visible Metaplex metadata for the wrapped mint
    /// (ADR-0028). Admin-only, idempotent, and additive: the mint address,
    /// its authority and its decimals are untouched.
    pub fn create_token_metadata(ctx: Context<CreateTokenMetadata>, uri: String) -> Result<()> {
        instructions::create_token_metadata(ctx, uri)
    }

    /// Records, under an M-of-N federation proof, that a withdrawal was paid
    /// on Goldcoin (Phase 7f, ADR-0018). Terminal and irreversible.
    pub fn complete_withdrawal(
        ctx: Context<CompleteWithdrawal>,
        index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
        epoch: u64,
    ) -> Result<()> {
        instructions::complete_withdrawal(ctx, index, payout_txid, payout_height, epoch)
    }
}
