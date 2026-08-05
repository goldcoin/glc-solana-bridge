//! Bounded transaction confirmation (ADR-0030).
//!
//! # Why this exists
//!
//! `glc-admin` submitted every state-changing transaction with
//! `send_transaction` — which returns as soon as an RPC node accepts the
//! transaction for processing — and then printed a signature and exited `0`.
//! Acceptance is not inclusion. A transaction can be accepted and then never
//! land: its blockhash expires, the leader drops it, the slot is skipped.
//!
//! Two consequences, and the second is the dangerous one:
//!
//! - the documented bootstrap sequence (runbooks §14) raced against itself —
//!   `create-wrapped-mint` run straight after `initialize` reported *"the
//!   bridge config account does not exist"*, because it read the account
//!   before `initialize` had landed;
//! - `glc-admin pause` printed success whether or not the pause ever took
//!   effect. Runbooks §3 tells an operator to pause first and then act on
//!   that belief during a solvency breach. A dropped pause is indistinguishable
//!   from an engaged circuit breaker, and every further mint enlarges the
//!   breach the operator thinks they just stopped.
//!
//! # Why polling, and why it terminates
//!
//! There is no push notification for "this transaction landed", so the status
//! is polled. What makes the wait *bounded* is not the clock but
//! [`SolanaRpc::is_blockhash_valid`]: once a transaction's blockhash can no
//! longer be used, that transaction can never confirm, so waiting longer is
//! pointless and the failure is reported immediately. The deadline is only a
//! backstop for an RPC that never answers.
//!
//! A fixed sleep would be the wrong fix twice over — too short and it reports
//! a false failure for a transaction that lands a moment later, too long and
//! it stalls every command by its worst case.

use std::time::Duration;

use solana_sdk::hash::Hash;
use solana_sdk::signature::Signature;

use super::rpc::{SolanaRpc, SolanaRpcError};

/// How long to wait, and how often to ask.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmPolicy {
    /// Backstop for an RPC that never reports the transaction either way.
    /// Expiry normally ends the wait long before this.
    pub deadline: Duration,
    pub poll_interval: Duration,
}

impl Default for ConfirmPolicy {
    fn default() -> Self {
        // A legacy blockhash is valid for 150 slots — roughly 60s — so a
        // transaction that has neither confirmed nor expired by 90s is
        // already anomalous. The deadline exists for the RPC that answers
        // nothing at all, not for ordinary slowness.
        ConfirmPolicy {
            deadline: Duration::from_secs(90),
            poll_interval: Duration::from_millis(500),
        }
    }
}

/// Why a transaction could not be confirmed.
///
/// These are kept distinct because an operator's next move differs for each:
/// a rejection is a bug or a stale precondition and re-running will fail the
/// same way; an expiry is safe to retry immediately; a timeout means the
/// cluster's view is unknown and the postcondition must be read before
/// anything is retried.
#[derive(Debug, thiserror::Error)]
pub enum ConfirmFailure {
    /// The transaction landed and the runtime rejected it. The instruction
    /// did **not** take effect.
    #[error("transaction {signature} was rejected on chain: {reason}")]
    Rejected {
        signature: Signature,
        reason: String,
    },

    /// The blockhash expired without the transaction confirming. It can never
    /// confirm, and nothing it would have done has happened.
    #[error(
        "transaction {signature} expired before it confirmed (its blockhash is no longer \
         valid); nothing it would have done has taken effect"
    )]
    Expired { signature: Signature },

    /// Neither confirmed nor expired within the deadline. Unlike the other
    /// two this leaves the outcome genuinely **unknown**.
    #[error(
        "transaction {signature} was neither confirmed nor expired within {waited:?}; its \
         outcome is UNKNOWN — read the on-chain state back before retrying"
    )]
    TimedOut {
        signature: Signature,
        waited: Duration,
    },

    #[error("could not determine the fate of transaction {signature}: {source}")]
    Rpc {
        signature: Signature,
        #[source]
        source: SolanaRpcError,
    },
}

/// Waits until `signature` has demonstrably confirmed at the RPC's commitment,
/// demonstrably failed, or demonstrably can never land.
///
/// Never returns `Ok` on a transaction it has not actually observed succeed.
pub async fn confirm_transaction<R: SolanaRpc>(
    rpc: &R,
    signature: &Signature,
    blockhash: &Hash,
    policy: ConfirmPolicy,
) -> Result<(), ConfirmFailure> {
    let started = std::time::Instant::now();

    loop {
        match rpc.get_signature_status(signature).await {
            Ok(Some(Ok(()))) => return Ok(()),
            Ok(Some(Err(reason))) => {
                return Err(ConfirmFailure::Rejected {
                    signature: *signature,
                    reason,
                })
            }
            Ok(None) => {}
            Err(source) => {
                return Err(ConfirmFailure::Rpc {
                    signature: *signature,
                    source,
                })
            }
        }

        // Not confirmed yet. Can it still land at all?
        let still_landable =
            rpc.is_blockhash_valid(blockhash)
                .await
                .map_err(|source| ConfirmFailure::Rpc {
                    signature: *signature,
                    source,
                })?;

        if !still_landable {
            // The blockhash read happens after the status read, so the
            // transaction may have confirmed in between. Declaring expiry on
            // the strength of the earlier read would report a completed
            // action as a failure — and for `pause` that is the wrong
            // direction to be wrong in. Ask once more before giving up.
            return match rpc.get_signature_status(signature).await {
                Ok(Some(Ok(()))) => Ok(()),
                Ok(Some(Err(reason))) => Err(ConfirmFailure::Rejected {
                    signature: *signature,
                    reason,
                }),
                Ok(None) => Err(ConfirmFailure::Expired {
                    signature: *signature,
                }),
                Err(source) => Err(ConfirmFailure::Rpc {
                    signature: *signature,
                    source,
                }),
            };
        }

        let waited = started.elapsed();
        if waited >= policy.deadline {
            return Err(ConfirmFailure::TimedOut {
                signature: *signature,
                waited,
            });
        }

        tokio::time::sleep(policy.poll_interval).await;
    }
}
