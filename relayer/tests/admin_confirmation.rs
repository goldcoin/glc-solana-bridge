//! Regression suite for ADR-0030: a submitted transaction is not a confirmed
//! transaction.
//!
//! # The defect these tests lock down
//!
//! `glc-admin` submitted every state-changing transaction with
//! `send_transaction` — which returns once an RPC node has *accepted* the
//! transaction — and then printed a signature and exited `0`. Acceptance is
//! not inclusion.
//!
//! Observed on a real `solana-test-validator` during the three-operator
//! rehearsal, running the documented bootstrap sequence from
//! `docs/runbooks.md` §14 exactly as written:
//!
//! ```text
//! $ glc-admin initialize --validators ... --threshold 2 ...
//! initialize submitted
//!   signature: 3rd6aW1qyZhiVBBVWJpXsLEirFNM3dkapps7k1g9LMoQfmsSCuSNVHUBjsr4v6qdbZjdD2HDGK2z6MHoaRfaRe8o
//! $ glc-admin create-wrapped-mint --mint-keypair ...
//! Error: the bridge config account does not exist at 9siQq2... — run `initialize`
//! ```
//!
//! Seconds later `show-config` printed the fully-populated config: the
//! account was fine, `create-wrapped-mint` had simply read it before
//! `initialize` landed.
//!
//! The bootstrap race is the visible symptom. The dangerous one is
//! `glc-admin pause`, which reported success whether or not the pause ever
//! took effect — and `runbooks.md` §3 tells an operator to pause first and
//! then act on that belief while a solvency breach is live.
//!
//! # What is asserted
//!
//! [`confirm_transaction`] is the primitive `glc-admin` now waits on. Each
//! test drives it against an RPC that behaves the way a real cluster does in
//! one specific failure mode, and asserts the outcome is reported rather than
//! papered over. The `never_confirms` case is the exact shape of the original
//! defect: under the old code that path printed success.

use std::sync::Mutex;
use std::time::Duration;

use solana_sdk::account::Account;
use solana_sdk::commitment_config::CommitmentLevel;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;

use glc_relayer::solana::confirm::{confirm_transaction, ConfirmFailure, ConfirmPolicy};
use glc_relayer::solana::rpc::{SolanaRpc, SolanaRpcError};

/// What the cluster will report for the one signature under test.
#[derive(Clone)]
enum Fate {
    /// Never appears in a status response — the shape of a dropped
    /// transaction, and of the original defect.
    NeverConfirms,
    /// Lands and the runtime rejects it. The instruction did not take effect.
    Rejected(String),
    /// Confirms on the Nth poll, having been invisible before that.
    ConfirmsAfter(usize),
    /// The RPC itself fails.
    RpcError,
}

struct MockRpc {
    fate: Fate,
    /// Whether the transaction's blockhash is still usable. `false` is how a
    /// real cluster says "this can never land now".
    blockhash_valid: Mutex<bool>,
    status_calls: Mutex<usize>,
}

impl MockRpc {
    fn new(fate: Fate) -> Self {
        MockRpc {
            fate,
            blockhash_valid: Mutex::new(true),
            status_calls: Mutex::new(0),
        }
    }
    fn expire_blockhash(&self) {
        *self.blockhash_valid.lock().unwrap() = false;
    }
    fn status_calls(&self) -> usize {
        *self.status_calls.lock().unwrap()
    }
}

impl SolanaRpc for MockRpc {
    async fn get_account(&self, _: &Pubkey) -> Result<Option<Account>, SolanaRpcError> {
        unreachable!("not exercised by the confirmation suite")
    }
    async fn get_latest_blockhash(&self) -> Result<Hash, SolanaRpcError> {
        Ok(Hash::default())
    }
    async fn send_transaction(&self, _: &Transaction) -> Result<Signature, SolanaRpcError> {
        Ok(Signature::default())
    }
    async fn get_signature_status(
        &self,
        _: &Signature,
    ) -> Result<Option<Result<(), String>>, SolanaRpcError> {
        let n = {
            let mut c = self.status_calls.lock().unwrap();
            *c += 1;
            *c
        };
        match &self.fate {
            Fate::NeverConfirms => Ok(None),
            Fate::Rejected(reason) => Ok(Some(Err(reason.clone()))),
            Fate::ConfirmsAfter(k) => {
                if n >= *k {
                    Ok(Some(Ok(())))
                } else {
                    Ok(None)
                }
            }
            Fate::RpcError => Err(SolanaRpcError::Transport("mock: RPC unreachable".into())),
        }
    }
    async fn is_blockhash_valid(&self, _: &Hash) -> Result<bool, SolanaRpcError> {
        Ok(*self.blockhash_valid.lock().unwrap())
    }
    async fn get_program_accounts_sized(
        &self,
        _: &Pubkey,
        _: u64,
        _: CommitmentLevel,
    ) -> Result<Vec<(Pubkey, Account)>, SolanaRpcError> {
        unreachable!("not exercised by the confirmation suite")
    }
}

fn fast() -> ConfirmPolicy {
    ConfirmPolicy {
        deadline: Duration::from_millis(300),
        poll_interval: Duration::from_millis(10),
    }
}

/// The original defect, in its exact shape: the transaction is accepted and
/// then never lands.
///
/// Under the old fire-and-forget `submit`, this path printed a signature and
/// exited `0`. It must now be an error — an operator who pauses during a
/// solvency breach has to be told the pause did not take.
#[tokio::test]
async fn a_transaction_that_never_confirms_is_reported_not_assumed_successful() {
    let rpc = MockRpc::new(Fate::NeverConfirms);
    let err = confirm_transaction(&rpc, &Signature::default(), &Hash::default(), fast())
        .await
        .expect_err("a transaction that never confirms must never be reported as success");

    assert!(
        matches!(err, ConfirmFailure::TimedOut { .. }),
        "expected a timeout, got {err:?}"
    );
    // The outcome is genuinely unknown here, and the message must say so
    // rather than implying the action failed cleanly.
    assert!(
        err.to_string().contains("UNKNOWN"),
        "a timeout leaves the outcome unknown and must say so: {err}"
    );
    assert!(
        rpc.status_calls() > 1,
        "confirmation must actually poll, not check once and give up"
    );
}

/// A transaction that lands and is rejected by the runtime. The instruction
/// did not take effect, and the reason must survive to the operator.
#[tokio::test]
async fn a_rejected_transaction_is_reported_with_the_runtime_reason() {
    let rpc = MockRpc::new(Fate::Rejected("custom program error: 0x1771".into()));
    let err = confirm_transaction(&rpc, &Signature::default(), &Hash::default(), fast())
        .await
        .expect_err("a rejected transaction is not a success");

    match err {
        ConfirmFailure::Rejected { ref reason, .. } => {
            assert!(
                reason.contains("0x1771"),
                "the on-chain reason must reach the operator: {reason}"
            );
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

/// The blockhash expires while the transaction is still unseen. It can never
/// land, so this is reported immediately rather than waited out — and it is
/// reported as *expired*, which unlike a timeout means nothing happened.
#[tokio::test]
async fn an_expired_blockhash_ends_the_wait_and_reports_that_nothing_took_effect() {
    let rpc = MockRpc::new(Fate::NeverConfirms);
    rpc.expire_blockhash();

    let started = std::time::Instant::now();
    let err = confirm_transaction(
        &rpc,
        &Signature::default(),
        &Hash::default(),
        // A deadline far longer than the test should take: if expiry is not
        // detected, this fails by timing out instead, which is the point.
        ConfirmPolicy {
            deadline: Duration::from_secs(30),
            poll_interval: Duration::from_millis(10),
        },
    )
    .await
    .expect_err("an expired transaction never confirms");

    assert!(
        matches!(err, ConfirmFailure::Expired { .. }),
        "expected Expired, got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "expiry must end the wait promptly rather than burning the whole deadline"
    );
    assert!(
        err.to_string()
            .contains("nothing it would have done has taken effect"),
        "an expiry is safe to retry and the message must say so: {err}"
    );
}

/// The race between the status read and the blockhash read: the transaction
/// confirms in the gap. Declaring expiry on the strength of the earlier read
/// would report a completed `pause` as a failure, which is the wrong
/// direction to be wrong in.
#[tokio::test]
async fn a_transaction_that_lands_as_its_blockhash_expires_is_reported_successful() {
    // Confirms on the second status call. The first call returns None, the
    // blockhash is then found expired, and the re-check must catch it.
    let rpc = MockRpc::new(Fate::ConfirmsAfter(2));
    rpc.expire_blockhash();

    confirm_transaction(&rpc, &Signature::default(), &Hash::default(), fast())
        .await
        .expect("a transaction that did land must not be reported as expired");

    assert_eq!(
        rpc.status_calls(),
        2,
        "the expiry path must re-check status before declaring failure"
    );
}

/// The ordinary case: not visible immediately, confirms shortly after. This
/// is why the fix cannot be "read the state back once" — the wait has to
/// tolerate the normal propagation delay that caused the bootstrap race.
#[tokio::test]
async fn a_transaction_that_confirms_after_a_delay_succeeds() {
    let rpc = MockRpc::new(Fate::ConfirmsAfter(3));

    confirm_transaction(&rpc, &Signature::default(), &Hash::default(), fast())
        .await
        .expect("a transaction that confirms on a later poll is a success");

    assert!(
        rpc.status_calls() >= 3,
        "the wait must keep asking until the cluster answers"
    );
}

/// An RPC that cannot answer is not evidence of success either.
#[tokio::test]
async fn an_rpc_failure_during_confirmation_is_surfaced_not_swallowed() {
    let rpc = MockRpc::new(Fate::RpcError);
    let err = confirm_transaction(&rpc, &Signature::default(), &Hash::default(), fast())
        .await
        .expect_err("an unreachable RPC cannot confirm anything");

    assert!(
        matches!(err, ConfirmFailure::Rpc { .. }),
        "expected an Rpc failure, got {err:?}"
    );
}

/// Every failure names the signature, so an operator can look the
/// transaction up rather than reconstructing which one it was.
#[tokio::test]
async fn every_confirmation_failure_names_the_signature() {
    for fate in [
        Fate::NeverConfirms,
        Fate::Rejected("boom".into()),
        Fate::RpcError,
    ] {
        let rpc = MockRpc::new(fate);
        let err = confirm_transaction(&rpc, &Signature::default(), &Hash::default(), fast())
            .await
            .expect_err("these fates are all failures");
        assert!(
            err.to_string().contains(&Signature::default().to_string()),
            "the signature must appear in the error an operator reads: {err}"
        );
    }
}
