//! The completion submitter's tick loop (Phase 7f, ADR-0018).
//!
//! Uses an in-memory Solana RPC and a controllable attestation collector —
//! never a real node. Real-validator coverage lives in
//! `tests/local_validator_e2e.rs`.
//!
//! The property these are built around: **reconciliation before action**.
//! Completion is terminal on-chain, so a submitter that acted before
//! checking would burn fees discovering what a read would have told it, and
//! would fight other operators' relayers doing the same work.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::transaction::Transaction;

use glc_relayer::glc::db::Db;
use glc_relayer::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, NewPayout, NewWithdrawalRequest, ObservedUtxo,
    VaultUtxo, WithdrawalState,
};
use glc_relayer::solana::epoch::EpochObservation;
use glc_relayer::solana::instruction;
use glc_relayer::solana::rpc::{SolanaRpc, SolanaRpcError};
use glc_relayer::withdrawal::completion::{
    CompletionSignatureCollector, CompletionSubmitter, STATUS_COMPLETED,
};

/// The on-chain `WithdrawalStatus::Completed` discriminant, as a LITERAL.
///
/// Deliberately not the library constant: seeding the fixture from the same
/// value the code compares against would make the test move with any change
/// to it, and the discriminant is a fact about the on-chain program
/// (verified against a live account, ADR-0018 §2.3), not a choice this
/// crate gets to make.
const COMPLETED_ON_CHAIN: u8 = 2;
use glc_relayer::withdrawal::federation::InProcessPayoutCollector;

const INDEX: i64 = 4;
const AMOUNT: u64 = 500_000;
const FEE: u64 = 20_000;
const UTXO_VALUE: u64 = 700_000;
const DEST: [u8; 20] = [0x33; 20];
const CHANGE: [u8; 20] = [0x44; 20];
const EPOCH: u64 = 7;
const THRESHOLD: u8 = 2;
const PAYOUT_TXID_HEX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const PAYOUT_HEIGHT: i64 = 4_242;
const STATUS_OFFSET: usize = 8 + 113;

// ---------------------------------------------------------------------
// Mock Solana RPC
// ---------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    accounts: HashMap<Pubkey, Account>,
    sent: Vec<Transaction>,
}

#[derive(Clone, Default)]
struct MockRpc(Arc<Mutex<MockState>>);

impl MockRpc {
    fn set(&self, key: Pubkey, data: Vec<u8>) {
        self.0.lock().unwrap().accounts.insert(
            key,
            Account {
                lamports: 1,
                data,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    fn sent(&self) -> usize {
        self.0.lock().unwrap().sent.len()
    }
}

impl SolanaRpc for MockRpc {
    async fn get_account(&self, pubkey: &Pubkey) -> Result<Option<Account>, SolanaRpcError> {
        Ok(self.0.lock().unwrap().accounts.get(pubkey).cloned())
    }
    async fn get_latest_blockhash(&self) -> Result<Hash, SolanaRpcError> {
        Ok(Hash::new_unique())
    }
    async fn send_transaction(&self, tx: &Transaction) -> Result<Signature, SolanaRpcError> {
        self.0.lock().unwrap().sent.push(tx.clone());
        Ok(Signature::new_unique())
    }
    async fn get_signature_status(
        &self,
        _: &Signature,
    ) -> Result<Option<Result<(), String>>, SolanaRpcError> {
        // The completion submitter reconciles against on-chain account state,
        // not signature status.
        unreachable!("the completion submitter does not confirm by signature")
    }
    async fn is_blockhash_valid(&self, _: &solana_sdk::hash::Hash) -> Result<bool, SolanaRpcError> {
        unreachable!("the completion submitter does not confirm by signature")
    }
    async fn get_program_accounts_sized(
        &self,
        _: &Pubkey,
        _: u64,
        _: solana_sdk::commitment_config::CommitmentLevel,
    ) -> Result<Vec<(Pubkey, Account)>, SolanaRpcError> {
        Ok(Vec::new())
    }
}

/// Encodes a `ValidatorSet` account body the way the relayer decodes it.
fn validator_set_account(validators: &[Pubkey], threshold: u8, epoch: u64) -> Vec<u8> {
    let mut d = vec![0u8; 8];
    d.extend_from_slice(&epoch.to_le_bytes());
    d.push(threshold);
    d.push(255); // bump
    d.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        d.extend_from_slice(&v.to_bytes());
    }
    d.extend_from_slice(&[0u8; 32]); // reserved
    d
}

/// A withdrawal account body just long enough to carry a status byte.
fn withdrawal_account(status: u8) -> Vec<u8> {
    let mut d = vec![0u8; 180];
    d[STATUS_OFFSET] = status;
    d
}

// ---------------------------------------------------------------------
// Mock attestation collector
// ---------------------------------------------------------------------

#[derive(Clone)]
struct MockCollector {
    keys: Arc<Vec<Keypair>>,
    /// How many of the validators actually answer.
    answering: Arc<Mutex<usize>>,
    calls: Arc<Mutex<usize>>,
}

impl MockCollector {
    fn new(keys: Vec<Keypair>, answering: usize) -> Self {
        MockCollector {
            keys: Arc::new(keys),
            answering: Arc::new(Mutex::new(answering)),
            calls: Arc::new(Mutex::new(0)),
        }
    }
    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl CompletionSignatureCollector for MockCollector {
    async fn collect_completion_signatures(
        &self,
        _epoch: u64,
        _withdrawal_index: u64,
        _payout_txid: [u8; 32],
        _payout_height: u64,
        message: &[u8],
    ) -> Vec<(Pubkey, Signature)> {
        *self.calls.lock().unwrap() += 1;
        let n = *self.answering.lock().unwrap();
        self.keys
            .iter()
            .take(n)
            .map(|k| (k.pubkey(), k.sign_message(message)))
            .collect()
    }
}

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

struct Harness {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    rpc: MockRpc,
    program_id: Pubkey,
    validators: Vec<Keypair>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A locally-completed payout, plus the on-chain accounts the submitter
/// needs. `onchain_status` seeds the withdrawal account.
fn harness(onchain_status: u8) -> Harness {
    let (vault, _) = InProcessPayoutCollector::deterministic_test_vault(3, 2);
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relayer.sqlite");
    let mut db = Db::open(&db_path).unwrap();

    db.observe_withdrawal(&NewWithdrawalRequest {
        withdrawal_index: INDEX,
        pda: [0x55; 32],
        amount_atomic: AMOUNT,
        requester: [0x11; 32],
        glc_address: glc_relayer::withdrawal::address::encode_p2pkh(&DEST),
        glc_address_hash160: DEST,
        requested_at_slot: 100,
        protocol_version: 1,
        observed_at: 1_000,
        observed_at_slot: 100,
    })
    .unwrap();

    let inputs = vec![VaultUtxo {
        txid: [0x66; 32],
        txid_hex: "66".repeat(32),
        vout: 0,
        amount_atomic: UTXO_VALUE,
        script_pubkey_hex: vault.script_pubkey_hex(),
        confirmations: 10,
    }];
    db.sync_vault_utxos(
        &inputs
            .iter()
            .map(|u| ObservedUtxo {
                txid: u.txid,
                vout: u.vout,
                amount_atomic: u.amount_atomic,
                script_pubkey_hex: u.script_pubkey_hex.clone(),
                confirmations: u.confirmations,
            })
            .collect::<Vec<_>>(),
        1,
        1_000,
    )
    .unwrap();
    db.reserve_utxos(INDEX, &inputs, 1_000).unwrap();

    let change = UTXO_VALUE - AMOUNT - FEE;
    let intent = canonical_payout_intent(
        1,
        INDEX,
        &vault.script_hash160,
        &DEST,
        AMOUNT,
        FEE,
        change,
        &CHANGE,
        0,
        &[0, 1],
        &inputs,
    );
    db.create_payout(&NewPayout {
        withdrawal_index: INDEX,
        vault_script_hash: vault.script_hash160,
        quorum_indices: vec![0, 1],
        quorum_attempt: 0,
        commitment_hash: payout_commitment(&intent),
        intent_bytes: intent,
        fee_atomic: FEE,
        payout_atomic: AMOUNT,
        change_atomic: change,
        change_address: Some(glc_relayer::withdrawal::address::encode_p2pkh(&CHANGE)),
        unsigned_tx_hex: "0100000001deadbeef".to_string(),
        inputs,
        built_at: 1_100,
    })
    .unwrap();

    for (state, at) in [
        (WithdrawalState::Validated, 1_010),
        (WithdrawalState::Building, 1_020),
        (WithdrawalState::Signing, 1_030),
    ] {
        db.transition_withdrawal(INDEX, state, at, None).unwrap();
    }
    let mut txid = glc_relayer::glc::hex::decode_exact::<32>(PAYOUT_TXID_HEX).unwrap();
    txid.reverse();
    db.record_signed_payout(INDEX, "0100signed", &txid, 1_040)
        .unwrap();
    db.record_broadcast(INDEX, 1_050).unwrap();
    db.record_confirmations(INDEX, 10, Some(&[0xAA; 32]), Some(PAYOUT_HEIGHT))
        .unwrap();
    db.transition_withdrawal(INDEX, WithdrawalState::Confirming, 1_060, None)
        .unwrap();
    db.complete_payout(INDEX, 1_070).unwrap();

    let program_id = Pubkey::new_unique();
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let rpc = MockRpc::default();
    let (vs_pda, _) = instruction::validator_set_pda(&program_id);
    rpc.set(
        vs_pda,
        validator_set_account(
            &validators.iter().map(|k| k.pubkey()).collect::<Vec<_>>(),
            THRESHOLD,
            EPOCH,
        ),
    );
    let (w_pda, _) = instruction::withdrawal_pda(&program_id, INDEX as u64);
    rpc.set(w_pda, withdrawal_account(onchain_status));

    Harness {
        _dir: dir,
        db_path,
        rpc,
        program_id,
        validators,
    }
}

fn submitter(
    h: &Harness,
    collector: MockCollector,
    epoch_age: i64,
) -> CompletionSubmitter<MockRpc, MockCollector> {
    CompletionSubmitter::new(
        Db::open(&h.db_path).unwrap(),
        h.rpc.clone(),
        collector,
        h.program_id,
        Keypair::new(),
        1,
        Arc::new(EpochObservation::seeded(EPOCH, now() - epoch_age)),
    )
}

fn keys_of(h: &Harness) -> Vec<Keypair> {
    h.validators.iter().map(|k| k.insecure_clone()).collect()
}

// ---------------------------------------------------------------------

#[test]
fn the_status_discriminant_matches_the_on_chain_program() {
    assert_eq!(
        STATUS_COMPLETED, COMPLETED_ON_CHAIN,
        "WithdrawalStatus::Completed is 2 on-chain — verified against a live account"
    );
}

#[tokio::test]
async fn submits_a_completion_once_threshold_attestations_arrive() {
    let h = harness(0); // on-chain: Pending
    let c = MockCollector::new(keys_of(&h), 2);
    let report = submitter(&h, c.clone(), 0).tick().await.unwrap();

    assert_eq!(report.submitted, 1);
    assert_eq!(report.reconciled, 0);
    assert_eq!(h.rpc.sent(), 1, "one completion transaction");

    let db = Db::open(&h.db_path).unwrap();
    assert!(
        db.is_onchain_completed(INDEX).unwrap(),
        "the local row records the on-chain completion"
    );
    assert!(
        db.payouts_awaiting_onchain_completion().unwrap().is_empty(),
        "and it stops being re-examined"
    );
}

#[tokio::test]
async fn a_completion_transaction_carries_the_ed25519_proof_first() {
    // The program reads the proof from the IMMEDIATELY PRECEDING
    // instruction, so ordering is not cosmetic.
    let h = harness(0);
    let c = MockCollector::new(keys_of(&h), 2);
    submitter(&h, c, 0).tick().await.unwrap();

    let sent = h.rpc.0.lock().unwrap().sent[0].clone();
    let ixs = &sent.message.instructions;
    assert_eq!(ixs.len(), 2, "ed25519 proof + complete_withdrawal");
    let programs: Vec<Pubkey> = ixs
        .iter()
        .map(|i| sent.message.account_keys[i.program_id_index as usize])
        .collect();
    assert_eq!(
        programs[0],
        solana_sdk::ed25519_program::ID,
        "the proof must come first"
    );
    assert_eq!(programs[1], h.program_id);
}

#[tokio::test]
async fn an_already_completed_withdrawal_is_reconciled_without_spending_a_fee() {
    // Another operator got there first. Checking before acting is what makes
    // running several relayers safe — and cheap.
    let h = harness(COMPLETED_ON_CHAIN);
    let c = MockCollector::new(keys_of(&h), 2);
    let report = submitter(&h, c.clone(), 0).tick().await.unwrap();

    assert_eq!(report.reconciled, 1);
    assert_eq!(report.submitted, 0);
    assert_eq!(h.rpc.sent(), 0, "no transaction, no fee");
    assert_eq!(
        c.calls(),
        0,
        "and no attestations are collected for work already done"
    );
    assert!(Db::open(&h.db_path)
        .unwrap()
        .is_onchain_completed(INDEX)
        .unwrap());
}

#[tokio::test]
async fn below_threshold_attestations_submit_nothing_and_are_retried() {
    // Peers that have not yet confirmed the payout at depth correctly
    // refuse. That is an ordinary outcome, not an error.
    let h = harness(0);
    let c = MockCollector::new(keys_of(&h), 1);
    let report = submitter(&h, c, 0).tick().await.unwrap();

    assert_eq!(report.insufficient, 1);
    assert_eq!(report.submitted, 0);
    assert_eq!(h.rpc.sent(), 0);

    let db = Db::open(&h.db_path).unwrap();
    assert!(!db.is_onchain_completed(INDEX).unwrap());
    assert_eq!(
        db.payouts_awaiting_onchain_completion().unwrap(),
        vec![INDEX],
        "it stays queued for the next pass"
    );
}

#[tokio::test]
async fn recovers_on_a_later_pass_once_enough_peers_answer() {
    let h = harness(0);
    let c = MockCollector::new(keys_of(&h), 1);
    submitter(&h, c.clone(), 0).tick().await.unwrap();
    assert_eq!(h.rpc.sent(), 0);

    *c.answering.lock().unwrap() = 2;
    let report = submitter(&h, c, 0).tick().await.unwrap();
    assert_eq!(report.submitted, 1);
    assert_eq!(h.rpc.sent(), 1);
}

#[tokio::test]
async fn a_stale_epoch_observation_stops_completion_requests() {
    // A relayer that has lost sight of the validator set must not stamp an
    // epoch it cannot currently confirm onto an irreversible action.
    let h = harness(0);
    let c = MockCollector::new(keys_of(&h), 3);
    let report = submitter(&h, c.clone(), 100_000).tick().await.unwrap();

    assert_eq!(report.submitted, 0);
    assert_eq!(c.calls(), 0, "no attestations are even requested");
    assert_eq!(h.rpc.sent(), 0);
    assert!(!Db::open(&h.db_path)
        .unwrap()
        .is_onchain_completed(INDEX)
        .unwrap());
}

#[tokio::test]
async fn a_missing_on_chain_account_is_skipped_not_submitted() {
    let h = harness(0);
    {
        let (w_pda, _) = instruction::withdrawal_pda(&h.program_id, INDEX as u64);
        h.rpc.0.lock().unwrap().accounts.remove(&w_pda);
    }
    let c = MockCollector::new(keys_of(&h), 3);
    let report = submitter(&h, c.clone(), 0).tick().await.unwrap();

    assert_eq!(report.skipped, 1);
    assert_eq!(report.submitted, 0);
    assert_eq!(c.calls(), 0);
    assert_eq!(h.rpc.sent(), 0);
}

#[tokio::test]
async fn a_payout_that_is_not_locally_completed_is_never_queued() {
    // The queue is drawn from locally-Completed payouts only: a relayer
    // must not ask the federation to declare final something it has not
    // itself finished.
    let h = harness(0);
    {
        let conn = rusqlite::Connection::open(&h.db_path).unwrap();
        conn.execute(
            "UPDATE withdrawal_requests SET state = 'Confirming' WHERE withdrawal_index = ?1",
            rusqlite::params![INDEX],
        )
        .unwrap();
    }
    let db = Db::open(&h.db_path).unwrap();
    assert!(db.payouts_awaiting_onchain_completion().unwrap().is_empty());

    let c = MockCollector::new(keys_of(&h), 3);
    let report = submitter(&h, c.clone(), 0).tick().await.unwrap();
    assert_eq!(report.submitted, 0);
    assert_eq!(c.calls(), 0);
}

#[tokio::test]
async fn the_local_record_is_written_only_after_the_transaction_is_sent() {
    // ADR-0013's ordering discipline, applied here: nothing claims a
    // completion happened before the network has actually seen it.
    let h = harness(0);
    let c = MockCollector::new(keys_of(&h), 2);
    let db_before = Db::open(&h.db_path).unwrap();
    assert!(!db_before.is_onchain_completed(INDEX).unwrap());
    drop(db_before);

    submitter(&h, c, 0).tick().await.unwrap();
    assert_eq!(h.rpc.sent(), 1);
    assert!(Db::open(&h.db_path)
        .unwrap()
        .is_onchain_completed(INDEX)
        .unwrap());
}
