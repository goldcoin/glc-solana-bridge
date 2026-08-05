//! Solana side (Phase 5, ADR-0012).
//!
//! - `config` — validated Solana-side configuration (RPC URL, program id,
//!   keypair paths, commitment level — no silent default, owner decision R3).
//! - `instruction` — hand-built `mint_wrapped` instruction encoding and PDA
//!   derivation; no dependency on the on-chain `glc-bridge` crate (owner
//!   decision R1).
//! - `rpc` — thin Solana JSON-RPC client wrapper (a trait for mockability,
//!   plus the real `solana-client`-backed implementation).
//! - `confirm` — bounded wait for a submitted transaction to actually land
//!   (ADR-0030). Submission is not inclusion; `glc-admin` reported success
//!   for transactions it had never observed confirm.
//!
//! Withdrawal-side watching (`WithdrawalRequest` account scanning) remains
//! future work — Phase 5 is deposit-mint only, per the approved objective.

pub mod config;
pub mod confirm;
pub mod epoch;
pub mod instruction;
pub mod rpc;
