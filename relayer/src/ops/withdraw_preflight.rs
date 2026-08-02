//! What `glc-wallet` checks before it burns anything.
//!
//! # Why this is the most important code in the CLI
//!
//! `burn_wrapped` **cannot validate the Goldcoin destination**. The program
//! has no base58 decoder — it stores the bytes it is given (ADR-0018 D2).
//! The burn therefore succeeds whatever the user typed, and the resulting
//! `WithdrawalRequest` is permanent and irreversible: there is no un-burn
//! instruction, and the payout pipeline will refuse to build a payout for a
//! destination it cannot decode.
//!
//! A typo in an address is a permanent loss of the burned amount. Every
//! check here exists to make that impossible to reach by accident, and each
//! runs **before** the transaction is signed.
//!
//! # The validator is borrowed, not reimplemented
//!
//! Address validity is decided by [`decode_p2pkh_hash160`] — the same
//! function `withdrawal::discovery` calls when it decides whether a
//! withdrawal is payable. Re-implementing the rule here would let the two
//! drift, and the direction that matters is the dangerous one: accepting
//! something the pipeline will later refuse.

use thiserror::Error;

use crate::withdrawal::address::{decode_p2pkh_hash160, AddressError};

/// Why a withdrawal was refused before anything was signed.
///
/// Messages are written for someone who has never read this codebase: they
/// say what is wrong, what the number was, and what to do.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WithdrawRefusal {
    #[error(
        "the bridge is paused, so withdrawals are not being accepted right now.\n\
         Nothing was burned. Try again once the operators have unpaused it."
    )]
    BridgePaused,

    #[error(
        "the amount must be greater than zero.\n\
         Amounts are in atomic units: 1 GLC = 100000000, so --amount-atomic 100000000 is 1 GLC."
    )]
    ZeroAmount,

    #[error(
        "the amount {amount} is below this bridge's minimum withdrawal of {minimum}.\n\
         Nothing was burned. In GLC that minimum is about {:.8}.",
        as_glc(*.minimum)
    )]
    BelowMinimum { amount: u64, minimum: u64 },

    #[error(
        "you have {balance} atomic units of wrapped GLC but tried to withdraw {amount}.\n\
         Nothing was burned. In GLC you hold about {:.8} and asked for {:.8}.",
        as_glc(*.balance),
        as_glc(*.amount)
    )]
    InsufficientBalance { balance: u64, amount: u64 },

    #[error(
        "no wrapped-GLC token account was found for your key.\n\
         That usually means this key has never received wrapped GLC. Nothing was burned."
    )]
    NoTokenAccount,

    #[error(
        "the Goldcoin address {address:?} is not valid ({reason}).\n\
         Nothing was burned — and that matters: the bridge cannot check the address on chain, \
         so burning to a bad address would destroy the tokens permanently. Check the address \
         and try again."
    )]
    InvalidAddress { address: String, reason: String },

    #[error(
        "this bridge has no wrapped-GLC mint yet, so there is nothing to withdraw.\n\
         The bridge has not finished being set up."
    )]
    MintNotConfigured,
}

/// Everything the CLI reads before deciding, gathered in one place so the
/// decision itself is pure and testable without a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawContext {
    pub paused: bool,
    pub min_withdrawal: u64,
    pub mint_configured: bool,
    /// `None` when the user has no token account at all — distinct from a
    /// zero balance, and the advice differs.
    pub balance: Option<u64>,
}

const ATOMIC_PER_GLC: f64 = 100_000_000.0;

/// Decides whether this withdrawal may proceed.
///
/// Order is deliberate: conditions that are nothing to do with the user come
/// first (paused, un-configured bridge), then the request itself, then the
/// address. Someone whose bridge is paused should be told that, not told
/// their address is malformed.
pub fn check(
    ctx: &WithdrawContext,
    amount: u64,
    glc_address: &str,
) -> Result<[u8; 20], WithdrawRefusal> {
    if !ctx.mint_configured {
        return Err(WithdrawRefusal::MintNotConfigured);
    }
    if ctx.paused {
        return Err(WithdrawRefusal::BridgePaused);
    }
    if amount == 0 {
        return Err(WithdrawRefusal::ZeroAmount);
    }
    if amount < ctx.min_withdrawal {
        return Err(WithdrawRefusal::BelowMinimum {
            amount,
            minimum: ctx.min_withdrawal,
        });
    }
    let balance = ctx.balance.ok_or(WithdrawRefusal::NoTokenAccount)?;
    if balance < amount {
        return Err(WithdrawRefusal::InsufficientBalance { balance, amount });
    }

    // Last, and the one that cannot be undone if it is wrong.
    decode_p2pkh_hash160(glc_address).map_err(|e: AddressError| WithdrawRefusal::InvalidAddress {
        address: glc_address.to_string(),
        reason: e.to_string(),
    })
}

/// Renders atomic units as GLC, for display only.
pub fn as_glc(atomic: u64) -> f64 {
    atomic as f64 / ATOMIC_PER_GLC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::address::encode_p2pkh;

    fn ok_ctx() -> WithdrawContext {
        WithdrawContext {
            paused: false,
            min_withdrawal: 1_000,
            mint_configured: true,
            balance: Some(50_00000000),
        }
    }

    fn good_address() -> String {
        encode_p2pkh(&[0x11; 20])
    }

    #[test]
    fn a_sound_withdrawal_returns_the_decoded_destination() {
        let h = check(&ok_ctx(), 10_00000000, &good_address()).unwrap();
        assert_eq!(h, [0x11; 20]);
    }

    #[test]
    fn a_malformed_address_is_refused_and_the_message_says_why_it_matters() {
        // The single most important refusal in the CLI: the chain cannot
        // check this, so reaching the burn with a bad address is permanent.
        let err = check(&ok_ctx(), 10_00000000, "not-an-address").unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, WithdrawRefusal::InvalidAddress { .. }));
        assert!(text.contains("Nothing was burned"), "{text}");
        assert!(
            text.contains("permanently"),
            "the message must say why this check exists: {text}"
        );
    }

    #[test]
    fn an_address_with_a_bad_checksum_is_refused() {
        // The case a typo actually produces — base58 is checksummed
        // precisely so a mistyped character is caught.
        let mut a: Vec<char> = good_address().chars().collect();
        a[5] = if a[5] == 'A' { 'B' } else { 'A' };
        let typo: String = a.into_iter().collect();
        assert!(matches!(
            check(&ok_ctx(), 1_000, &typo).unwrap_err(),
            WithdrawRefusal::InvalidAddress { .. }
        ));
    }

    #[test]
    fn an_address_the_payout_pipeline_would_reject_is_rejected_here_too() {
        // A P2SH (vault-style) address decodes as base58check but is not a
        // payable destination. Accepting it here would let a user burn into
        // a withdrawal the executor can never build.
        use crate::withdrawal::address::base58check_encode;
        let p2sh = base58check_encode(0x3a, &[0x22; 20]);
        assert!(matches!(
            check(&ok_ctx(), 1_000, &p2sh).unwrap_err(),
            WithdrawRefusal::InvalidAddress { .. }
        ));
    }

    #[test]
    fn a_paused_bridge_is_reported_before_anything_about_the_request() {
        // Someone whose bridge is paused should be told that, not told
        // their address is malformed.
        let ctx = WithdrawContext {
            paused: true,
            ..ok_ctx()
        };
        assert_eq!(
            check(&ctx, 0, "garbage").unwrap_err(),
            WithdrawRefusal::BridgePaused
        );
    }

    #[test]
    fn an_unconfigured_mint_is_reported_first_of_all() {
        let ctx = WithdrawContext {
            mint_configured: false,
            paused: true,
            ..ok_ctx()
        };
        assert_eq!(
            check(&ctx, 1_000, &good_address()).unwrap_err(),
            WithdrawRefusal::MintNotConfigured
        );
    }

    #[test]
    fn zero_is_refused_with_the_unit_explained() {
        let err = check(&ok_ctx(), 0, &good_address()).unwrap_err();
        assert_eq!(err, WithdrawRefusal::ZeroAmount);
        assert!(
            err.to_string().contains("100000000"),
            "a beginner needs the unit spelled out: {err}"
        );
    }

    #[test]
    fn below_the_minimum_is_refused_and_states_the_minimum() {
        let err = check(&ok_ctx(), 999, &good_address()).unwrap_err();
        assert!(matches!(err, WithdrawRefusal::BelowMinimum { .. }));
        assert!(err.to_string().contains("1000"), "{err}");
    }

    #[test]
    fn exactly_the_minimum_is_allowed() {
        // Off-by-one here would refuse a legitimate withdrawal.
        assert!(check(&ok_ctx(), 1_000, &good_address()).is_ok());
    }

    #[test]
    fn spending_the_whole_balance_is_allowed() {
        assert!(check(&ok_ctx(), 50_00000000, &good_address()).is_ok());
    }

    #[test]
    fn one_atom_more_than_the_balance_is_refused_with_both_numbers() {
        let err = check(&ok_ctx(), 50_00000001, &good_address()).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, WithdrawRefusal::InsufficientBalance { .. }));
        assert!(
            text.contains("5000000000") && text.contains("5000000001"),
            "{text}"
        );
        assert!(text.contains("Nothing was burned"), "{text}");
    }

    #[test]
    fn having_no_token_account_is_distinct_from_having_zero() {
        // Different causes, different advice: one means "you never received
        // any", the other means "you spent them".
        let none = WithdrawContext {
            balance: None,
            ..ok_ctx()
        };
        assert_eq!(
            check(&none, 1_000, &good_address()).unwrap_err(),
            WithdrawRefusal::NoTokenAccount
        );

        let zero = WithdrawContext {
            balance: Some(0),
            ..ok_ctx()
        };
        assert!(matches!(
            check(&zero, 1_000, &good_address()).unwrap_err(),
            WithdrawRefusal::InsufficientBalance { .. }
        ));
    }

    #[test]
    fn every_refusal_tells_a_beginner_what_to_do() {
        // These are read by people who have never seen this codebase.
        for err in [
            WithdrawRefusal::BridgePaused,
            WithdrawRefusal::ZeroAmount,
            WithdrawRefusal::BelowMinimum {
                amount: 1,
                minimum: 2,
            },
            WithdrawRefusal::InsufficientBalance {
                balance: 1,
                amount: 2,
            },
            WithdrawRefusal::NoTokenAccount,
            WithdrawRefusal::InvalidAddress {
                address: "x".into(),
                reason: "bad".into(),
            },
            WithdrawRefusal::MintNotConfigured,
        ] {
            let t = err.to_string();
            assert!(t.len() > 40, "too terse to act on: {t}");
            assert!(
                t.contains('\n'),
                "each refusal explains as well as states: {t}"
            );
        }
    }

    #[test]
    fn atomic_units_render_as_glc_for_display() {
        assert!((as_glc(100_000_000) - 1.0).abs() < f64::EPSILON);
        assert!((as_glc(150_000_000) - 1.5).abs() < f64::EPSILON);
        assert_eq!(as_glc(0), 0.0);
    }
}
