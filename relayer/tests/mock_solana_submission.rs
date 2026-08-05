//! Mock-Solana-RPC integration tests for the Phase 5 orchestrator
//! (ADR-0012): the tick loop that reloads-and-recomputes, signs,
//! aggregates, threshold-checks, and submits `mint_wrapped`, tying
//! `glc::db` + `signer` + `solana` together.
//!
//! Every test here uses [`MockRpc`] — an in-memory, call-counting
//! [`SolanaRpc`] implementation — never a real Solana node. Real-node
//! end-to-end coverage lives in `tests/local_validator_e2e.rs`.
//!
//! A real SQLite *file* (never `:memory:`) is used throughout, because
//! several tests need a second, independent connection into the same
//! database — either to mutate a field out from under the orchestrator
//! (the reload-and-recompute mismatch tests) or to open a second
//! `Orchestrator` instance against the same file (the restart tests).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::transaction::Transaction;

use glc_relayer::glc::db::{Db, DbError, DepositState, NewBlock, NewCandidate, NewClaimArtifact};
use glc_relayer::glc::deposit::build_claim_message;
use glc_relayer::orchestrator::Orchestrator;
use glc_relayer::p2p::collector::InProcessCollector;
use glc_relayer::solana::instruction;
use glc_relayer::solana::rpc::{SolanaRpc, SolanaRpcError};

// ---------------------------------------------------------------------
// MockRpc
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum MockErrorKind {
    Method,
}

#[derive(Default)]
struct MockState {
    accounts: HashMap<Pubkey, Account>,
    send_transaction_calls: u32,
    get_account_calls: u32,
    queried_pubkeys: Vec<Pubkey>,
    /// Leading `get_account` calls that should fail with a transient
    /// `Transport` error before falling through to the real accounts map —
    /// simulates a flaky endpoint that recovers within the bounded retry
    /// budget (`INNER_RETRY_ATTEMPTS` in `orchestrator.rs`).
    get_account_transport_failures: u32,
    /// If set, `send_transaction` returns this error instead of a
    /// synthetic success signature, once `send_transaction_transport_failures`
    /// (if any) has been exhausted.
    send_transaction_error: Option<MockErrorKind>,
    /// Leading `send_transaction` calls that fail with a transient
    /// `Transport` error before the call is allowed to succeed.
    send_transaction_transport_failures: u32,
}

#[derive(Clone, Default)]
struct MockRpc(Arc<Mutex<MockState>>);

impl MockRpc {
    fn new() -> Self {
        MockRpc::default()
    }

    fn insert_account(&self, pubkey: Pubkey, owner: Pubkey, data: Vec<u8>) {
        self.0.lock().unwrap().accounts.insert(
            pubkey,
            Account {
                lamports: 1_000_000,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    fn send_transaction_calls(&self) -> u32 {
        self.0.lock().unwrap().send_transaction_calls
    }

    fn get_account_calls(&self) -> u32 {
        self.0.lock().unwrap().get_account_calls
    }

    /// Every pubkey `get_account` has been asked about, in call order.
    /// Lets a test prove precisely which stage of `process_one` was (or was
    /// never) reached.
    fn queried_pubkeys(&self) -> Vec<Pubkey> {
        self.0.lock().unwrap().queried_pubkeys.clone()
    }

    fn set_get_account_transport_failures(&self, n: u32) {
        self.0.lock().unwrap().get_account_transport_failures = n;
    }

    fn set_send_transaction_error(&self, kind: MockErrorKind) {
        self.0.lock().unwrap().send_transaction_error = Some(kind);
    }

    fn set_send_transaction_transport_failures(&self, n: u32) {
        self.0.lock().unwrap().send_transaction_transport_failures = n;
    }
}

impl SolanaRpc for MockRpc {
    async fn get_account(&self, pubkey: &Pubkey) -> Result<Option<Account>, SolanaRpcError> {
        let mut state = self.0.lock().unwrap();
        state.get_account_calls += 1;
        state.queried_pubkeys.push(*pubkey);
        if state.get_account_transport_failures > 0 {
            state.get_account_transport_failures -= 1;
            return Err(SolanaRpcError::Transport("mock: transient blip".into()));
        }
        Ok(state.accounts.get(pubkey).cloned())
    }

    async fn get_program_accounts_sized(
        &self,
        program_id: &Pubkey,
        data_len: u64,
        _commitment: solana_sdk::commitment_config::CommitmentLevel,
    ) -> Result<Vec<(Pubkey, Account)>, SolanaRpcError> {
        let state = self.0.lock().unwrap();
        Ok(state
            .accounts
            .iter()
            .filter(|(_, a)| a.owner == *program_id && a.data.len() as u64 == data_len)
            .map(|(k, a)| (*k, a.clone()))
            .collect())
    }

    async fn get_latest_blockhash(&self) -> Result<Hash, SolanaRpcError> {
        Ok(Hash::default())
    }

    async fn send_transaction(&self, _tx: &Transaction) -> Result<Signature, SolanaRpcError> {
        let mut state = self.0.lock().unwrap();
        state.send_transaction_calls += 1;
        if state.send_transaction_transport_failures > 0 {
            state.send_transaction_transport_failures -= 1;
            return Err(SolanaRpcError::Transport("mock: transient blip".into()));
        }
        match state.send_transaction_error {
            Some(MockErrorKind::Method) => Err(SolanaRpcError::Method("mock: rejected".into())),
            None => Ok(Signature::default()),
        }
    }
    async fn get_signature_status(
        &self,
        _: &Signature,
    ) -> Result<Option<Result<(), String>>, SolanaRpcError> {
        // The orchestrator reconciles against on-chain account state rather
        // than signature status, so nothing in this suite reaches here.
        unreachable!("the mint orchestrator does not confirm by signature")
    }
    async fn is_blockhash_valid(&self, _: &solana_sdk::hash::Hash) -> Result<bool, SolanaRpcError> {
        unreachable!("the mint orchestrator does not confirm by signature")
    }
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// A self-consistent, correctly-derived `ReadyForSignature` deposit — the
/// fixture every test starts from. Built entirely through `Db`'s public
/// API (this is a separate test binary from `glc::db`'s own unit tests,
/// so it cannot reach that module's private `#[cfg(test)]` helper).
#[allow(dead_code)]
struct Fixture {
    program_id: Pubkey,
    wrapped_mint: Pubkey,
    txid: [u8; 32],
    vout: u32,
    amount_atomic: u64,
    recipient: Pubkey,
    validator_epoch: u64,
    deposit_id: i64,
}

fn seed_ready_deposit(db: &mut Db) -> Fixture {
    let program_id = Pubkey::new_unique();
    let wrapped_mint = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let txid = [0xAA; 32];
    let vout: u32 = 2;
    let amount_atomic: u64 = 75_000;
    let validator_epoch: u64 = 3;
    let protocol_version: u8 = 1;

    let block = NewBlock {
        height: 1,
        hash: [0x11; 32],
        prev_hash: [0u8; 32],
        block_time: 0,
        indexed_at: 0,
    };
    let candidate = NewCandidate {
        txid,
        vout: vout as i64,
        amount_atomic,
        recipient: recipient.to_bytes(),
        block_height: 1,
        block_hash: [0x11; 32],
        raw_tx_hex: "deadbeef".to_string(),
        discovered_at: 0,
        initial_state: DepositState::Candidate,
        failure_reason: None,
    };
    let ids = db.ingest_block(&block, &[candidate]).unwrap();
    let deposit_id = ids[0];

    let message = build_claim_message(
        protocol_version,
        &program_id.to_bytes(),
        validator_epoch,
        &txid,
        vout,
        amount_atomic,
        &recipient.to_bytes(),
        &wrapped_mint.to_bytes(),
    );
    let message_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(message).into()
    };
    let artifact = NewClaimArtifact {
        deposit_id,
        canonical_message: message,
        message_hash,
        protocol_version,
        validator_epoch,
        program_id: program_id.to_bytes(),
        wrapped_mint: wrapped_mint.to_bytes(),
        created_at: 0,
    };
    db.transition_state(deposit_id, DepositState::Confirming, 1, None, None)
        .unwrap();
    db.transition_state(
        deposit_id,
        DepositState::ReadyForSignature,
        2,
        None,
        Some(&artifact),
    )
    .unwrap();

    Fixture {
        program_id,
        wrapped_mint,
        txid,
        vout,
        amount_atomic,
        recipient,
        validator_epoch,
        deposit_id,
    }
}

/// A second, entirely healthy `ReadyForSignature` deposit sharing the
/// first's deployment parameters (program id / wrapped mint / epoch) but
/// with its own `(txid, vout)`, so it derives a distinct claim PDA.
fn seed_second_ready_deposit(db: &mut Db, base: &Fixture) -> i64 {
    let txid = [0xBB; 32];
    let vout: u32 = 0;
    let amount_atomic: u64 = 42_000;
    let recipient = Pubkey::new_unique();
    let protocol_version: u8 = 1;

    let block = NewBlock {
        height: 2,
        hash: [0x22; 32],
        prev_hash: [0x11; 32],
        block_time: 0,
        indexed_at: 0,
    };
    let candidate = NewCandidate {
        txid,
        vout: vout as i64,
        amount_atomic,
        recipient: recipient.to_bytes(),
        block_height: 2,
        block_hash: [0x22; 32],
        raw_tx_hex: "cafebabe".to_string(),
        discovered_at: 0,
        initial_state: DepositState::Candidate,
        failure_reason: None,
    };
    let ids = db.ingest_block(&block, &[candidate]).unwrap();
    let deposit_id = ids[0];

    let message = build_claim_message(
        protocol_version,
        &base.program_id.to_bytes(),
        base.validator_epoch,
        &txid,
        vout,
        amount_atomic,
        &recipient.to_bytes(),
        &base.wrapped_mint.to_bytes(),
    );
    let message_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(message).into()
    };
    let artifact = NewClaimArtifact {
        deposit_id,
        canonical_message: message,
        message_hash,
        protocol_version,
        validator_epoch: base.validator_epoch,
        program_id: base.program_id.to_bytes(),
        wrapped_mint: base.wrapped_mint.to_bytes(),
        created_at: 0,
    };
    db.transition_state(deposit_id, DepositState::Confirming, 1, None, None)
        .unwrap();
    db.transition_state(
        deposit_id,
        DepositState::ReadyForSignature,
        2,
        None,
        Some(&artifact),
    )
    .unwrap();
    deposit_id
}

/// Manual Borsh encoding of a `ValidatorSet` account body, matching
/// `solana::rpc::decode_validator_set`'s expected layout exactly.
fn validator_set_account_data(epoch: u64, threshold: u8, validators: &[Pubkey]) -> Vec<u8> {
    let mut data = vec![0u8; 8]; // discriminator (contents irrelevant to the decoder)
    data.extend_from_slice(&epoch.to_le_bytes());
    data.push(threshold);
    data.push(0); // bump (unused)
    data.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        data.extend_from_slice(v.as_ref());
    }
    data.extend_from_slice(&[0u8; 32]); // reserved
    data
}

/// Opens a completely independent raw connection to the same SQLite file
/// and mutates one field out from under the orchestrator — simulating
/// database corruption/tampering between `ReadyForSignature` and signing,
/// exactly what the reload-and-recompute safeguard must catch.
fn mutate_raw(db_path: &Path, sql: &str, params: &[&dyn rusqlite::ToSql]) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute(sql, params).unwrap();
}

#[allow(dead_code)]
struct Harness {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    rpc: MockRpc,
    fixture: Fixture,
    submitter: Keypair,
    validator_keys: Vec<Keypair>,
    threshold: u8,
}

/// Builds a fresh database file with one `ReadyForSignature` deposit and a
/// funded `ValidatorSet` account, ready for an `Orchestrator` to tick
/// against. `validator_key_count` lets threshold-not-met tests hand the
/// orchestrator fewer keys than the on-chain threshold requires.
fn build_harness(validator_key_count: usize, threshold: u8) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relayer.sqlite3");
    let mut db = Db::open(&db_path).unwrap();
    let fixture = seed_ready_deposit(&mut db);
    drop(db);

    let validator_keys: Vec<Keypair> = (0..validator_key_count).map(|_| Keypair::new()).collect();
    let all_validators: Vec<Pubkey> = validator_keys.iter().map(|k| k.pubkey()).collect();

    let rpc = MockRpc::new();
    let (validator_set_pda, _) = instruction::validator_set_pda(&fixture.program_id);
    rpc.insert_account(
        validator_set_pda,
        fixture.program_id,
        validator_set_account_data(fixture.validator_epoch, threshold, &all_validators),
    );

    Harness {
        _dir: dir,
        db_path,
        rpc,
        fixture,
        submitter: Keypair::new(),
        validator_keys,
        threshold,
    }
}

impl Harness {
    fn orchestrator(&self) -> Orchestrator<MockRpc, InProcessCollector> {
        let db = Db::open(&self.db_path).unwrap();
        Orchestrator::new(
            db,
            self.rpc.clone(),
            self.fixture.program_id,
            Keypair::try_from(self.submitter.to_bytes().as_slice()).unwrap(),
            InProcessCollector::new(
                self.validator_keys
                    .iter()
                    .map(|k| Keypair::try_from(k.to_bytes().as_slice()).unwrap())
                    .collect(),
            ),
        )
    }

    fn claim_pda(&self) -> Pubkey {
        instruction::deposit_claim_pda(
            &self.fixture.program_id,
            &self.fixture.txid,
            self.fixture.vout,
        )
        .0
    }

    fn deposit_state(&self) -> DepositState {
        let db = Db::open(&self.db_path).unwrap();
        db.get_by_id(self.fixture.deposit_id)
            .unwrap()
            .unwrap()
            .state
    }
}

// ---------------------------------------------------------------------
// Happy path / idempotency / restart-safety
// ---------------------------------------------------------------------

#[tokio::test]
async fn happy_path_submits_then_reconciles_to_minted_on_next_tick() {
    let h = build_harness(3, 2);
    let mut orch = h.orchestrator();

    let report = orch.tick().await.unwrap();
    assert_eq!(report.submitted, 1);
    assert_eq!(h.deposit_state(), DepositState::Submitted);
    assert_eq!(h.rpc.send_transaction_calls(), 1, "exactly one submission");

    // Simulate the transaction landing on-chain before the next tick.
    h.rpc
        .insert_account(h.claim_pda(), h.fixture.program_id, vec![]);

    let report = orch.tick().await.unwrap();
    assert_eq!(report.minted, 1);
    assert_eq!(h.deposit_state(), DepositState::Minted);
    assert_eq!(
        h.rpc.send_transaction_calls(),
        1,
        "reconciliation must never resubmit — never double mint"
    );
}

#[tokio::test]
async fn claim_pda_already_present_reconciles_directly_without_signing_or_submitting() {
    let h = build_harness(3, 2);
    // Simulate another relayer instance having already minted this
    // deposit before this orchestrator ever sees it.
    h.rpc
        .insert_account(h.claim_pda(), h.fixture.program_id, vec![]);
    let mut orch = h.orchestrator();

    let report = orch.tick().await.unwrap();
    assert_eq!(report.minted, 1);
    assert_eq!(h.deposit_state(), DepositState::Minted);
    assert_eq!(
        h.rpc.send_transaction_calls(),
        0,
        "an already-minted deposit must never trigger a submission"
    );
}

#[tokio::test]
async fn restart_mid_flight_reconciles_a_submitted_row_to_minted_without_resubmitting() {
    let h = build_harness(3, 2);
    {
        // Simulate a prior process instance that submitted, then crashed
        // before it ever observed confirmation.
        let mut db = Db::open(&h.db_path).unwrap();
        db.mark_submitted(h.fixture.deposit_id, "deadbeefsig", 10)
            .unwrap();
    }
    assert_eq!(h.deposit_state(), DepositState::Submitted);
    // The in-flight transaction did land, unbeknownst to the restarted process.
    h.rpc
        .insert_account(h.claim_pda(), h.fixture.program_id, vec![]);

    // A brand new Orchestrator instance, as after a real restart.
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();

    assert_eq!(report.minted, 1);
    assert_eq!(h.deposit_state(), DepositState::Minted);
    assert_eq!(
        h.rpc.send_transaction_calls(),
        0,
        "restart-safety: a Submitted row must reconcile via PDA existence, never re-sign/resubmit"
    );
}

#[tokio::test]
async fn restart_mid_flight_without_confirmation_yet_resubmits_safely_next_tick() {
    let h = build_harness(3, 2);
    {
        let mut db = Db::open(&h.db_path).unwrap();
        db.mark_submitted(h.fixture.deposit_id, "deadbeefsig", 10)
            .unwrap();
    }
    // No claim PDA yet — the prior transaction is still in flight (or was
    // dropped). A `Submitted` row without a confirmed claim PDA is
    // resubmitted just like a fresh `ReadyForSignature` one: this is safe
    // (never double-mints) purely because the on-chain claim PDA's `init`
    // constraint makes at most one submission ever successfully create it,
    // regardless of how many duplicate transactions are in flight — and is
    // what makes a dropped/expired in-flight transaction self-healing
    // rather than stuck forever.
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();

    assert_eq!(report.submitted, 1);
    assert_eq!(report.minted, 0);
    assert_eq!(h.deposit_state(), DepositState::Submitted);
    assert_eq!(
        h.rpc.send_transaction_calls(),
        1,
        "resubmission is expected and safe here — the claim PDA's on-chain init constraint is what actually prevents a double mint"
    );
}

// ---------------------------------------------------------------------
// Threshold
// ---------------------------------------------------------------------

#[tokio::test]
async fn insufficient_unique_signatures_never_submits_and_retries_next_tick() {
    // Threshold is 2, but the orchestrator is only configured with 1 of
    // the on-chain validator set's keys.
    let mut h = build_harness(2, 2);
    h.validator_keys.truncate(1);
    let mut orch = h.orchestrator();

    let report = orch.tick().await.unwrap();
    assert_eq!(report.insufficient, 1);
    assert_eq!(h.deposit_state(), DepositState::ReadyForSignature);
    assert_eq!(
        h.rpc.send_transaction_calls(),
        0,
        "below threshold: no transaction may ever be sent"
    );
}

// ---------------------------------------------------------------------
// RPC retry-class split
// ---------------------------------------------------------------------

#[tokio::test]
async fn transient_transport_blip_is_retried_within_budget_and_succeeds() {
    let h = build_harness(3, 2);
    // The very first get_account call (reconciliation's claim-PDA check)
    // fails once transiently, then must succeed on retry.
    h.rpc.set_get_account_transport_failures(1);
    let mut orch = h.orchestrator();

    let report = orch.tick().await.unwrap();
    assert_eq!(report.submitted, 1);
    assert!(
        h.rpc.get_account_calls() >= 2,
        "must have retried at least once"
    );
}

#[tokio::test]
async fn send_transaction_transient_blip_is_retried_within_budget_and_succeeds() {
    let h = build_harness(3, 2);
    h.rpc.set_send_transaction_transport_failures(1);
    let mut orch = h.orchestrator();

    let report = orch.tick().await.unwrap();
    assert_eq!(report.submitted, 1);
    assert!(
        h.rpc.send_transaction_calls() >= 2,
        "must have retried the submission at least once"
    );
}

#[tokio::test]
async fn send_transaction_transport_failure_exhausting_budget_is_node_unavailable() {
    let h = build_harness(3, 2);
    // More failures than the bounded inner-retry budget absorbs.
    h.rpc.set_send_transaction_transport_failures(10);
    let mut orch = h.orchestrator();

    let err = orch.tick().await.unwrap_err();
    assert!(matches!(
        err,
        glc_relayer::orchestrator::OrchestratorError::NodeUnavailable(_)
    ));
    assert_eq!(h.deposit_state(), DepositState::ReadyForSignature);
}

#[tokio::test]
async fn non_retriable_method_error_propagates_without_submitting() {
    let h = build_harness(3, 2);
    h.rpc.set_send_transaction_error(MockErrorKind::Method);
    let mut orch = h.orchestrator();

    let err = orch.tick().await.unwrap_err();
    assert!(matches!(
        err,
        glc_relayer::orchestrator::OrchestratorError::Rpc(_)
    ));
    assert_eq!(h.deposit_state(), DepositState::ReadyForSignature);
}

// ---------------------------------------------------------------------
// Reload-and-recompute mismatch detection (owner security requirement)
// ---------------------------------------------------------------------
//
// Each test seeds a genuinely self-consistent ReadyForSignature deposit,
// then — via a totally independent raw connection to the same file —
// mutates exactly one field the canonical message is built from (or one
// of the two stored commitment fields themselves), simulating drift or
// corruption after ReadyForSignature but before signing. In every case:
// no signature may be produced, `send_transaction` must never be called,
// and the deposit must land in the distinct `IntegrityHalted` state (never
// `Failed`), auditable via `deposit_state_log`.

fn assert_halted_without_submission(
    h: &Harness,
    orch_report: glc_relayer::orchestrator::TickReport,
) {
    assert_eq!(orch_report.halted, 1);
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);
    assert_eq!(
        h.rpc.send_transaction_calls(),
        0,
        "a detected mismatch must never result in a submission"
    );
}

#[tokio::test]
async fn mismatch_txid_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET txid = ?1, txid_hex = ?2 WHERE id = ?3",
        &[&vec![0xFFu8; 32], &"ff".repeat(32), &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_vout_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET vout = vout + 1 WHERE id = ?1",
        &[&h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_amount_atomic_halts_without_submitting() {
    let h = build_harness(3, 2);
    let bumped = (h.fixture.amount_atomic + 1).to_le_bytes().to_vec();
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
        &[&bumped, &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_recipient_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET recipient = ?1 WHERE id = ?2",
        &[&vec![0xEEu8; 32], &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_protocol_version_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE claim_artifacts SET protocol_version = 9 WHERE deposit_id = ?1",
        &[&h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_validator_epoch_halts_without_submitting() {
    let h = build_harness(3, 2);
    let bumped = (h.fixture.validator_epoch + 1).to_le_bytes().to_vec();
    mutate_raw(
        &h.db_path,
        "UPDATE claim_artifacts SET validator_epoch = ?1 WHERE deposit_id = ?2",
        &[&bumped, &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_program_id_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE claim_artifacts SET program_id = ?1 WHERE deposit_id = ?2",
        &[&vec![0xDDu8; 32], &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_wrapped_mint_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE claim_artifacts SET wrapped_mint = ?1 WHERE deposit_id = ?2",
        &[&vec![0xCCu8; 32], &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_stored_canonical_message_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE claim_artifacts SET canonical_message = ?1 WHERE deposit_id = ?2",
        &[&vec![0x00u8; 166], &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

#[tokio::test]
async fn mismatch_stored_message_hash_halts_without_submitting() {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE claim_artifacts SET message_hash = ?1 WHERE deposit_id = ?2",
        &[&vec![0x99u8; 32], &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_halted_without_submission(&h, report);
}

// ---------------------------------------------------------------------
// IntegrityHalted is terminal until explicit operator intervention
// ---------------------------------------------------------------------
//
// These tests pin the halt's *terminality*, not just its detection. The
// key structural fact they lean on: the claim-PDA `get_account` call is
// unconditionally the FIRST statement in `Orchestrator::process_one`. So
// if the `get_account` call count does not increase across a tick, then
// `process_one` was never entered for that deposit at all — which means
// `signer::sign_with_all` was categorically unreachable and no validator
// signature over any message could possibly have been produced. That is a
// stronger guarantee than merely observing that nothing was submitted.

/// Drives a deposit into `IntegrityHalted` and returns the harness plus
/// the RPC call counts recorded at the moment it halted.
async fn halted_harness() -> (Harness, u32, u32) {
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
        &[
            &(h.fixture.amount_atomic + 1).to_le_bytes().to_vec(),
            &h.fixture.deposit_id,
        ],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_eq!(report.halted, 1);
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);
    let get_calls = h.rpc.get_account_calls();
    let send_calls = h.rpc.send_transaction_calls();
    assert_eq!(send_calls, 0, "the halting tick itself must not submit");
    (h, get_calls, send_calls)
}

#[tokio::test]
async fn integrity_halted_is_never_retried_on_subsequent_ticks() {
    let (h, get_calls_at_halt, _) = halted_harness().await;
    let mut orch = h.orchestrator();

    for tick in 0..5 {
        let report = orch.tick().await.unwrap();
        assert_eq!(
            (
                report.minted,
                report.submitted,
                report.insufficient,
                report.halted
            ),
            (0, 0, 0, 0),
            "tick {tick}: a halted deposit must not be picked up at all"
        );
    }

    assert_eq!(
        h.rpc.get_account_calls(),
        get_calls_at_halt,
        "process_one was never entered again — so signing was unreachable and \
         no validator signature was generated"
    );
    assert_eq!(
        h.rpc.send_transaction_calls(),
        0,
        "send_transaction must never be invoked for a halted deposit"
    );
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);
}

#[tokio::test]
async fn restarting_the_relayer_does_not_resume_a_halted_deposit() {
    let (h, get_calls_at_halt, _) = halted_harness().await;

    // Three independent "process restarts": a brand new Orchestrator over a
    // brand new Db connection to the same file, exactly as after a crash or
    // a deliberate restart.
    for restart in 0..3 {
        let mut orch = h.orchestrator();
        let report = orch.tick().await.unwrap();
        assert_eq!(
            (
                report.minted,
                report.submitted,
                report.insufficient,
                report.halted
            ),
            (0, 0, 0, 0),
            "restart {restart}: a fresh process must not resume a halted deposit"
        );
    }

    assert_eq!(
        h.rpc.get_account_calls(),
        get_calls_at_halt,
        "no restart may re-enter process_one — signing stays unreachable across restarts"
    );
    assert_eq!(h.rpc.send_transaction_calls(), 0);
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);
}

#[tokio::test]
async fn halted_deposit_stays_halted_even_once_the_anomaly_is_repaired() {
    // Repairing the underlying data is NOT an exit: the state machine does
    // not re-open a halt just because the drift went away (which is exactly
    // what an attacker who could write to the database would attempt).
    let (h, get_calls_at_halt, _) = halted_harness().await;
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
        &[
            &h.fixture.amount_atomic.to_le_bytes().to_vec(),
            &h.fixture.deposit_id,
        ],
    );

    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();

    assert_eq!(
        (
            report.minted,
            report.submitted,
            report.insufficient,
            report.halted
        ),
        (0, 0, 0, 0),
        "repairing the data must not silently un-halt the deposit"
    );
    assert_eq!(h.rpc.get_account_calls(), get_calls_at_halt);
    assert_eq!(h.rpc.send_transaction_calls(), 0);
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);
}

#[tokio::test]
async fn explicit_operator_recovery_is_the_only_thing_that_resumes_processing() {
    let (h, get_calls_at_halt, _) = halted_harness().await;

    // Repair the underlying anomaly...
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET amount_atomic = ?1 WHERE id = ?2",
        &[
            &h.fixture.amount_atomic.to_le_bytes().to_vec(),
            &h.fixture.deposit_id,
        ],
    );
    // ...which on its own still changes nothing (asserted above); only the
    // explicit administrative procedure re-admits the deposit.
    {
        let mut db = Db::open(&h.db_path).unwrap();
        db.operator_clear_integrity_halt(
            h.fixture.deposit_id,
            DepositState::ReadyForSignature,
            "investigated: confirmed benign, field restored from backup",
            9_000,
        )
        .unwrap();
    }
    assert_eq!(h.deposit_state(), DepositState::ReadyForSignature);

    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();

    assert_eq!(
        report.submitted, 1,
        "after recovery, normal processing resumes"
    );
    assert!(
        h.rpc.get_account_calls() > get_calls_at_halt,
        "process_one is entered again only after the operator acted"
    );
    assert_eq!(h.rpc.send_transaction_calls(), 1);
    assert_eq!(h.deposit_state(), DepositState::Submitted);
}

#[tokio::test]
async fn halting_tick_never_reaches_the_validator_set_or_signing_stage() {
    // Complements the call-count argument with a positive one: the ONLY
    // account ever queried during a halting tick is the claim PDA. The
    // ValidatorSet fetch sits immediately after `sign_with_all` in
    // `process_one`, so its absence confirms execution stopped at the
    // safeguard, before any aggregation work.
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET recipient = ?1 WHERE id = ?2",
        &[&vec![0xEEu8; 32], &h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    let report = orch.tick().await.unwrap();
    assert_eq!(report.halted, 1);

    let (validator_set_pda, _) = instruction::validator_set_pda(&h.fixture.program_id);
    let queried = h.rpc.queried_pubkeys();
    assert_eq!(
        queried,
        vec![h.claim_pda()],
        "only the claim PDA was ever queried"
    );
    assert!(
        !queried.contains(&validator_set_pda),
        "the ValidatorSet was never fetched — aggregation was never reached"
    );
    assert_eq!(h.rpc.send_transaction_calls(), 0);
}

#[tokio::test]
async fn a_halted_deposit_does_not_block_other_healthy_deposits() {
    // Terminality must be per-deposit, not a global stall: a halted row
    // must not prevent the rest of the queue from being processed.
    let h = build_harness(3, 2);
    mutate_raw(
        &h.db_path,
        "UPDATE deposit_candidates SET vout = vout + 1 WHERE id = ?1",
        &[&h.fixture.deposit_id],
    );
    let mut orch = h.orchestrator();
    assert_eq!(orch.tick().await.unwrap().halted, 1);
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);

    // A second, entirely healthy deposit arrives afterwards.
    let second_id = {
        let mut db = Db::open(&h.db_path).unwrap();
        seed_second_ready_deposit(&mut db, &h.fixture)
    };
    let report = orch.tick().await.unwrap();

    assert_eq!(report.submitted, 1, "the healthy deposit is processed");
    assert_eq!(report.halted, 0, "the halted one is not re-examined");
    let second_state = Db::open(&h.db_path)
        .unwrap()
        .get_by_id(second_id)
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(second_state, DepositState::Submitted);
    assert_eq!(h.deposit_state(), DepositState::IntegrityHalted);
}

// ---------------------------------------------------------------------
// operator_clear_integrity_halt cannot be abused
// ---------------------------------------------------------------------
//
// The recovery procedure is the single sanctioned exit from a security
// halt, which makes it the most attractive thing in the codebase to
// misuse: if it could touch a Submitted or Minted deposit, it would be a
// way to re-open a completed mint; if it could rewrite the audit trail, it
// would be a way to erase evidence of the anomaly that triggered the halt.
// This test proves it can do neither.

/// One row of a deposit's audit trail: `(id, from_state, to_state, at,
/// reason)`, ordered by insertion. Compared wholesale to prove history is
/// only ever appended to.
type AuditRow = (i64, Option<String>, String, i64, Option<String>);

fn audit_trail(db_path: &Path, deposit_id: i64) -> Vec<AuditRow> {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, from_state, to_state, at, reason FROM deposit_state_log
             WHERE deposit_id = ?1 ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map([deposit_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

fn assert_not_integrity_halted(err: &DbError, expect_deposit: i64, expect_found: &str) {
    match err {
        DbError::NotIntegrityHalted { deposit_id, found } => {
            assert_eq!(*deposit_id, expect_deposit);
            assert_eq!(
                found.as_str(),
                expect_found,
                "the refusal must name the state actually found"
            );
        }
        other => panic!("expected NotIntegrityHalted, got: {other}"),
    }
}

#[tokio::test]
async fn operator_recovery_cannot_reopen_completed_deposits_or_rewrite_history() {
    // -- 1. A deposit driven through the REAL pipeline to Submitted is
    //       not recoverable, even with a perfectly plausible note.
    let h = build_harness(3, 2);
    let mut orch = h.orchestrator();
    orch.tick().await.unwrap();
    assert_eq!(h.deposit_state(), DepositState::Submitted);
    let submitted_trail = audit_trail(&h.db_path, h.fixture.deposit_id);

    {
        let mut db = Db::open(&h.db_path).unwrap();
        let err = db
            .operator_clear_integrity_halt(
                h.fixture.deposit_id,
                DepositState::ReadyForSignature,
                "in flight too long, forcing a resend",
                1_000,
            )
            .unwrap_err();
        assert_not_integrity_halted(&err, h.fixture.deposit_id, "Submitted");
    }
    assert_eq!(
        h.deposit_state(),
        DepositState::Submitted,
        "a refused recovery must not move an in-flight deposit"
    );

    // -- 2. Once the claim PDA lands and the deposit reconciles to Minted,
    //       it is likewise untouchable — for every permitted target state.
    h.rpc
        .insert_account(h.claim_pda(), h.fixture.program_id, vec![]);
    orch.tick().await.unwrap();
    assert_eq!(h.deposit_state(), DepositState::Minted);

    {
        let mut db = Db::open(&h.db_path).unwrap();
        for target in [DepositState::ReadyForSignature, DepositState::Failed] {
            let err = db
                .operator_clear_integrity_halt(
                    h.fixture.deposit_id,
                    target,
                    "re-open this deposit for another mint",
                    2_000,
                )
                .unwrap_err();
            assert_not_integrity_halted(&err, h.fixture.deposit_id, "Minted");
        }
    }
    assert_eq!(
        h.deposit_state(),
        DepositState::Minted,
        "a completed deposit stays completed"
    );
    assert_eq!(
        h.rpc.send_transaction_calls(),
        1,
        "no refused recovery may lead to a second submission — never double mint"
    );
    let final_trail = audit_trail(&h.db_path, h.fixture.deposit_id);
    assert_eq!(
        &final_trail[..submitted_trail.len()],
        submitted_trail.as_slice(),
        "refused recoveries never rewrite earlier history"
    );

    // -- 3. A healthy, never-halted deposit is not recoverable either:
    //       this is not a general-purpose "force any state" backdoor.
    let h2 = build_harness(3, 2);
    {
        let mut db = Db::open(&h2.db_path).unwrap();
        let err = db
            .operator_clear_integrity_halt(
                h2.fixture.deposit_id,
                DepositState::Failed,
                "retire this deposit",
                3_000,
            )
            .unwrap_err();
        assert_not_integrity_halted(&err, h2.fixture.deposit_id, "ReadyForSignature");
    }
    assert_eq!(h2.deposit_state(), DepositState::ReadyForSignature);

    // -- 4. On a genuinely halted deposit, an anonymous recovery is
    //       refused and leaves absolutely no trace.
    let (h3, _, _) = halted_harness().await;
    let before = audit_trail(&h3.db_path, h3.fixture.deposit_id);
    assert!(
        before.iter().any(|row| row.2 == "IntegrityHalted"),
        "the halt itself is on record before any recovery is attempted"
    );

    {
        let mut db = Db::open(&h3.db_path).unwrap();
        for anonymous in ["", "   ", "\t\n  "] {
            let err = db
                .operator_clear_integrity_halt(
                    h3.fixture.deposit_id,
                    DepositState::Failed,
                    anonymous,
                    4_000,
                )
                .unwrap_err();
            assert!(
                matches!(&err, DbError::OperatorNoteRequired(d) if *d == h3.fixture.deposit_id),
                "an unattributed recovery must be refused, got: {err}"
            );
        }
    }
    assert_eq!(h3.deposit_state(), DepositState::IntegrityHalted);
    assert_eq!(
        audit_trail(&h3.db_path, h3.fixture.deposit_id),
        before,
        "refused recovery attempts must change nothing at all"
    );

    // -- 5. The sanctioned recovery appends; it never edits or deletes.
    {
        let mut db = Db::open(&h3.db_path).unwrap();
        db.operator_clear_integrity_halt(
            h3.fixture.deposit_id,
            DepositState::Failed,
            "investigated: confirmed disk corruption, retiring deposit",
            5_000,
        )
        .unwrap();
    }
    let after = audit_trail(&h3.db_path, h3.fixture.deposit_id);

    assert_eq!(
        after.len(),
        before.len() + 1,
        "recovery appends exactly one audit row"
    );
    assert_eq!(
        &after[..before.len()],
        before.as_slice(),
        "every pre-existing audit row is preserved byte-for-byte — including the \
         original IntegrityHalted record; history is never rewritten"
    );
    let appended = after.last().unwrap();
    assert_eq!(appended.1.as_deref(), Some("IntegrityHalted"));
    assert_eq!(appended.2, "Failed");
    assert_eq!(appended.3, 5_000, "the recovery is timestamped");
    assert!(
        appended
            .4
            .as_deref()
            .unwrap()
            .starts_with("operator_recovery: "),
        "the recovery is attributed and distinguishable from an ordinary transition"
    );
    assert!(appended.4.as_deref().unwrap().contains("disk corruption"));

    // The halt record is still exactly one row, still present, unchanged.
    let halt_rows: Vec<&AuditRow> = after
        .iter()
        .filter(|row| row.2 == "IntegrityHalted")
        .collect();
    assert_eq!(
        halt_rows.len(),
        1,
        "the original anomaly record survives recovery, exactly once"
    );
}
