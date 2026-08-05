//! The withdrawal executor tick loop (Phase 6, ADR-0013).
//!
//! # Reconciliation before action, always
//!
//! Like the Phase 5 mint orchestrator, every tick reconciles observable
//! reality BEFORE deciding to act. For a payout the authoritative question
//! is "does our transaction already exist on the Goldcoin chain?", answered
//! by txid lookup — and the txid is durable *before* the first broadcast, so
//! a lost broadcast response is always recoverable.
//!
//! # Never double-pay
//!
//! Four independent layers, in increasing order of authority:
//!
//! 1. the payout table's primary key — one payout row per withdrawal;
//! 2. `UNIQUE(txid, vout)` on committed inputs — an outpoint funds one
//!    payout, ever;
//! 3. the pre-signing guard sequence — refuses to sign anything already
//!    signed, confirmed, or completed, or whose reservation drifted;
//! 4. the Goldcoin UTXO set itself — a spent input cannot be re-spent
//!    (RPC -25), and an identical re-broadcast is a no-op (RPC -27).
//!
//! Only (4) is a true security boundary; (1)–(3) exist so the executor never
//! *tries* something that (4) would have to catch.

use thiserror::Error;

use crate::glc::db::{Db, DbError};
use crate::glc::rpc::{BroadcastOutcome, RpcError};
use crate::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, NewPayout, NewWithdrawalRequest, ObservedUtxo,
    VaultUtxo, WithdrawalState,
};
use crate::withdrawal::address::{decode_p2pkh_hash160, p2pkh_script_hex};
use crate::withdrawal::assignment::OperatorAssignment;
use crate::withdrawal::builder::{
    verify_payout_tx, verify_signing_preserved_outputs, DecodedInput, DecodedOutput, DecodedTx,
    PayoutPlan, VerifyError,
};
use crate::withdrawal::coin::{self, SelectionError};
use crate::withdrawal::config::WithdrawalConfig;
use crate::withdrawal::multisig::{assemble, MultisigError, Transaction};

/// Reads a withdrawal's **on-chain** status (Phase 7g, ADR-0019 D4).
///
/// Consulted immediately before broadcasting. Phase 7g measured two
/// operators paying the same withdrawal twice with nothing in the executor
/// to stop it (ADR-0019 §2.2); this is the guard that closes that gap in the
/// process that would otherwise cause the harm.
///
/// It is **defence in depth, not the primary protection** — Phase 7e's
/// signer check remains that. This cannot catch a payment made but not yet
/// completed on-chain.
#[tonic::async_trait]
pub trait OnChainWithdrawalStatus: Send + Sync {
    /// Whether the withdrawal is already `Completed` on Solana.
    ///
    /// An error must NOT be read as "not completed": the caller treats an
    /// unavailable chain as a reason to wait, never as permission to
    /// broadcast.
    async fn is_completed(&self, withdrawal_index: u64) -> Result<bool, String>;
}

/// Collects **Goldcoin partial signatures** from the designated quorum
/// (Phase 7e, ADR-0017).
///
/// The executor holds **no vault key**: it asks the designated signers, each
/// of which independently rebuilds the transaction from its own UTXO view
/// before signing (`p2p::payout_view`). A trait so the payout pipeline stays
/// testable without a network, mirroring `SignatureCollector` on the mint
/// side.
pub trait PayoutPartialCollector {
    /// Asks exactly the designated signers, identified by their position in
    /// the vault's ordered signer list.
    ///
    /// Returning fewer than threshold is normal and not an error: the caller
    /// retries on a later tick, or the operator reassigns the quorum
    /// explicitly (ADR-0015). Substituting a non-designated signer is never
    /// acceptable, because the txid depends on which quorum signs.
    fn collect_payout_partials(
        &self,
        epoch: u64,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        quorum_indices: &[u8],
    ) -> impl std::future::Future<Output = Vec<crate::withdrawal::multisig::PartialSignature>> + Send;
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("Goldcoin node unavailable: {0}")]
    NodeUnavailable(RpcError),
    #[error("Goldcoin RPC error: {0}")]
    Rpc(RpcError),
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("payout verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("multisig assembly failed: {0}")]
    Assembly(#[from] MultisigError),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalTickReport {
    pub observed: u32,
    pub validated: u32,
    pub awaiting_funds: u32,
    pub built: u32,
    pub signed: u32,
    pub broadcast: u32,
    pub confirming: u32,
    pub completed: u32,
    pub halted: u32,
    pub failed: u32,
    pub orphaned: u32,
}

/// The Goldcoin RPC surface the executor needs. A trait so the whole
/// pipeline is unit-testable against a mock (mirrors `GoldcoinRpc` and
/// `SolanaRpc`).
pub trait PayoutRpc {
    fn list_unspent(
        &self,
        min_conf: i64,
        addresses: &[String],
    ) -> impl std::future::Future<Output = Result<Vec<ObservedUtxo>, RpcError>> + Send;

    fn create_raw_transaction(
        &self,
        inputs: &[(String, i64)],
        outputs: &[(String, u64)],
    ) -> impl std::future::Future<Output = Result<String, RpcError>> + Send;

    fn decode_raw_transaction(
        &self,
        hex: &str,
    ) -> impl std::future::Future<Output = Result<DecodedTx, RpcError>> + Send;

    /// Signs, supplying the previous outputs with their `redeemScript`.
    ///
    /// `prevtxs` is required, not optional: verified against a real node,
    /// the bare `signrawtransaction(hex)` form cannot sign a P2SH multisig
    /// input (ADR-0015). A partial result returns `complete: false`, and a
    /// partial transaction is rejected by the network, so an incomplete
    /// signature can never move funds.
    fn sign_raw_transaction(
        &self,
        hex: &str,
        prevtxs: &[crate::glc::rpc::PrevTx],
    ) -> impl std::future::Future<Output = Result<(String, bool), RpcError>> + Send;

    fn send_raw_transaction(
        &self,
        hex: &str,
    ) -> impl std::future::Future<Output = Result<BroadcastOutcome, RpcError>> + Send;

    /// Confirmations for a txid, or `None` if the node has never seen it.
    /// A mempool-only transaction reports `Some(0)` — matching the verified
    /// Goldcoin quirk that an unconfirmed transaction has no `confirmations`
    /// field at all.
    fn transaction_confirmations(
        &self,
        txid_hex: &str,
    ) -> impl std::future::Future<Output = Result<Option<TxStatus>, RpcError>> + Send;

    /// True when `block_hash` is still on the main chain. A reorged-away
    /// block reports `confirmations == -1` (verified Phase 4 fact).
    fn block_on_main_chain(
        &self,
        block_hash_hex: &str,
    ) -> impl std::future::Future<Output = Result<bool, RpcError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    pub confirmations: i64,
    pub block_hash_hex: Option<String>,
    pub block_height: Option<i64>,
}

pub struct WithdrawalExecutor<R: PayoutRpc, C: PayoutPartialCollector> {
    db: Db,
    rpc: R,
    config: WithdrawalConfig,
    collector: C,
    /// The validator-set epoch stamped onto signing requests, read fresh
    /// each tick from this relayer's own observation.
    epoch: std::sync::Arc<crate::solana::epoch::EpochObservation>,
    /// This relayer's place in the federation (Phase 7g). `None` means a
    /// single-operator deployment: everything is designated to us.
    assignment: Option<OperatorAssignment>,
    /// The pre-broadcast on-chain check (ADR-0019 D4). `None` disables it,
    /// which is only appropriate for tests that have no Solana at all.
    onchain: Option<std::sync::Arc<dyn OnChainWithdrawalStatus>>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl<R: PayoutRpc, C: PayoutPartialCollector> WithdrawalExecutor<R, C> {
    /// Note the absence of any vault key parameter: this process signs
    /// nothing with vault authority (Phase 7e, ADR-0017). It builds,
    /// assembles, and broadcasts; the designated signers sign.
    pub fn new(
        db: Db,
        rpc: R,
        config: WithdrawalConfig,
        collector: C,
        epoch: std::sync::Arc<crate::solana::epoch::EpochObservation>,
    ) -> Self {
        WithdrawalExecutor {
            db,
            rpc,
            config,
            collector,
            epoch,
            assignment: None,
            onchain: None,
        }
    }

    /// Declares this relayer's place in the federation (Phase 7g, ADR-0019).
    ///
    /// Without it the executor behaves as a single operator: designated for
    /// everything, waiting for nobody. That is the correct behaviour for a
    /// one-operator deployment and the historical behaviour for tests.
    pub fn with_assignment(mut self, assignment: OperatorAssignment) -> Self {
        self.assignment = Some(assignment);
        self
    }

    /// Attaches the pre-broadcast on-chain status check (ADR-0019 D4).
    pub fn with_onchain_status(
        mut self,
        status: std::sync::Arc<dyn OnChainWithdrawalStatus>,
    ) -> Self {
        self.onchain = Some(status);
        self
    }

    /// Whether this operator may build a payout for `index` right now.
    ///
    /// ADR-0019 D3: only the designated builder reserves UTXOs, because
    /// speculative reservation by every operator is what made two honest
    /// executors build different transactions (§2.1). Others take over only
    /// after the failover window.
    fn may_build(&self, index: i64, eligible_since: i64) -> bool {
        match &self.assignment {
            None => true,
            Some(a) => a.may_build(index as u64, eligible_since, now_unix()),
        }
    }

    /// The last check before funds move (ADR-0019 D4).
    ///
    /// Returns `true` when broadcasting is safe. An unavailable chain
    /// returns `false` — waiting is always safe, broadcasting on a guess is
    /// not.
    ///
    /// A free function, not a method: holding `&self` across an `.await`
    /// would require `WithdrawalExecutor: Sync`, which it is not
    /// (`rusqlite::Connection`'s statement cache uses a `RefCell`), and
    /// `tokio::spawn` needs the whole future to be `Send`. The same reason
    /// `Orchestrator::call` is a free function.
    async fn safe_to_broadcast(
        onchain: Option<std::sync::Arc<dyn OnChainWithdrawalStatus>>,
        index: i64,
    ) -> bool {
        let Some(status) = onchain else {
            return true;
        };
        match status.is_completed(index as u64).await {
            Ok(false) => true,
            Ok(true) => {
                tracing::error!(
                    withdrawal_index = index,
                    "withdrawal is already Completed on-chain — refusing to broadcast a second \
                     payout for it"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    withdrawal_index = index,
                    error = %e,
                    "could not read on-chain withdrawal status; not broadcasting this tick"
                );
                false
            }
        }
    }

    pub fn db_mut(&mut self) -> &mut Db {
        &mut self.db
    }

    /// Bytes one signed vault input contributes, from the vault this
    /// executor actually spends from.
    ///
    /// Derived, never a constant: the size depends on the threshold and the
    /// redeem script, and a 2-of-3 P2SH multisig input is roughly twice a
    /// P2PKH one. Using the P2PKH figure underpaid every payout by ~39% and
    /// nodes refused to relay them.
    fn vault_input_bytes(&self) -> u64 {
        coin::multisig_input_bytes(
            self.config.vault.threshold,
            self.config.vault.redeem_script.len(),
        )
    }

    /// Records newly discovered withdrawals. Discovery itself (the Solana
    /// `getProgramAccounts` scan at finalized commitment) is the caller's
    /// job; this is the persistence half, kept separate so the Goldcoin-side
    /// pipeline is testable without a Solana node.
    pub fn ingest_discovered(
        &mut self,
        discovered: &[NewWithdrawalRequest],
    ) -> Result<u32, ExecutorError> {
        let mut n = 0;
        for w in discovered {
            if self.db.observe_withdrawal(w)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Refreshes the vault UTXO view from the node.
    pub async fn sync_vault(&mut self) -> Result<(), ExecutorError> {
        let observed = self
            .rpc
            .list_unspent(
                self.config.vault_min_confirmations,
                &[self.config.vault_address.clone()],
            )
            .await
            .map_err(classify)?;
        let present: Vec<[u8; 32]> = observed.iter().map(|u| u.txid).collect();
        self.db
            .sync_vault_utxos(&observed, self.config.vault_min_confirmations, now_unix())?;
        self.db.mark_missing_utxos_spent(&present)?;
        Ok(())
    }

    /// One full pass over every non-terminal withdrawal.
    pub async fn tick(&mut self) -> Result<WithdrawalTickReport, ExecutorError> {
        self.sync_vault().await?;
        self.reclaim_abandoned_reservations()?;

        let mut report = WithdrawalTickReport::default();

        // Reconciliation first: anything already broadcast is resolved by
        // txid lookup before any new work is considered.
        for w in self.db.withdrawals_by_state(WithdrawalState::Broadcast)? {
            self.reconcile_broadcast(w.withdrawal_index, &mut report)
                .await?;
        }
        for w in self.db.withdrawals_by_state(WithdrawalState::Confirming)? {
            self.reconcile_broadcast(w.withdrawal_index, &mut report)
                .await?;
        }
        for w in self.db.withdrawals_by_state(WithdrawalState::Orphaned)? {
            self.rebroadcast(w.withdrawal_index, &mut report).await?;
        }

        // Then forward progress.
        for w in self.db.withdrawals_by_state(WithdrawalState::Observed)? {
            self.validate(w.withdrawal_index, &mut report)?;
        }
        for state in [WithdrawalState::AwaitingFunds, WithdrawalState::Validated] {
            for w in self.db.withdrawals_by_state(state)? {
                // ADR-0019 D3: a non-designated operator stays PASSIVE — it
                // does not build and therefore does not reserve, which is
                // what removes the divergence measured in §2.1. It adopts a
                // proposal when asked to sign one, after verifying it
                // independently (`p2p::payout_view`).
                let eligible_since = self.db.withdrawal_eligible_since(w.withdrawal_index)?;
                if !self.may_build(w.withdrawal_index, eligible_since) {
                    continue;
                }
                self.build(w.withdrawal_index, &mut report).await?;
            }
        }
        for w in self.db.withdrawals_by_state(WithdrawalState::Signing)? {
            self.sign(w.withdrawal_index, &mut report).await?;
        }
        for w in self.db.withdrawals_by_state(WithdrawalState::Broadcast)? {
            // Newly signed rows land here; broadcast them this same tick.
            let p = self.db.get_payout(w.withdrawal_index)?;
            if p.as_ref().is_some_and(|p| p.confirmations == 0) {
                self.rebroadcast(w.withdrawal_index, &mut report).await?;
            }
        }
        Ok(report)
    }

    /// Releases reservations that never reached a payout and have gone stale
    /// (D10). Rows with a payout row are never touched: those inputs are
    /// committed to a specific txid forever.
    fn reclaim_abandoned_reservations(&mut self) -> Result<(), ExecutorError> {
        let cutoff = now_unix() - self.config.reservation_timeout_secs;
        for state in [
            WithdrawalState::Validated,
            WithdrawalState::AwaitingFunds,
            WithdrawalState::Building,
        ] {
            for w in self.db.withdrawals_by_state(state)? {
                if self.db.get_payout(w.withdrawal_index)?.is_some() {
                    continue;
                }
                let reserved = self.db.reserved_utxos(w.withdrawal_index)?;
                if reserved.is_empty() {
                    continue;
                }
                if self.db.reservation_is_stale(w.withdrawal_index, cutoff)? {
                    self.db.release_reservation(w.withdrawal_index)?;
                    tracing::warn!(
                        withdrawal_index = w.withdrawal_index,
                        "released a stale reservation that never reached a payout"
                    );
                }
            }
        }
        Ok(())
    }

    fn validate(
        &mut self,
        index: i64,
        report: &mut WithdrawalTickReport,
    ) -> Result<(), ExecutorError> {
        let w = self
            .db
            .get_withdrawal(index)?
            .ok_or(DbError::WithdrawalNotFound(index))?;

        // The stored address must still decode, and to the stored hash160.
        match decode_p2pkh_hash160(&w.glc_address) {
            Ok(h) if h == w.glc_address_hash160 => {}
            Ok(_) => {
                self.db.transition_withdrawal(
                    index,
                    WithdrawalState::IntegrityHalted,
                    now_unix(),
                    Some("stored address and hash160 disagree"),
                )?;
                report.halted += 1;
                return Ok(());
            }
            Err(e) => {
                self.db.transition_withdrawal(
                    index,
                    WithdrawalState::Failed,
                    now_unix(),
                    Some(&format!("undecodable destination address: {e}")),
                )?;
                report.failed += 1;
                return Ok(());
            }
        }

        // A payout below dust can never be made; that is permanent.
        if w.amount_atomic < self.config.dust_threshold_atomic {
            self.db.transition_withdrawal(
                index,
                WithdrawalState::Failed,
                now_unix(),
                Some("amount is below the dust threshold and can never be paid out"),
            )?;
            report.failed += 1;
            return Ok(());
        }

        self.db
            .transition_withdrawal(index, WithdrawalState::Validated, now_unix(), None)?;
        report.validated += 1;
        Ok(())
    }

    /// Designates which M of the vault's N signers will sign this payout.
    ///
    /// Deterministic by withdrawal index, so every validator independently
    /// derives the same designation without negotiating, and so a replay
    /// produces the same quorum — and therefore the same txid (ADR-0015 §2).
    /// Reassignment when a designated signer is unavailable is explicit and
    /// audited (`Db::reassign_payout_quorum`), never an implicit fallback.
    fn designate_quorum(&self, index: i64) -> Vec<u8> {
        crate::withdrawal::assignment::designate_quorum(
            index,
            self.config.vault.signer_count(),
            self.config.vault.threshold,
        )
    }

    async fn build(
        &mut self,
        index: i64,
        report: &mut WithdrawalTickReport,
    ) -> Result<(), ExecutorError> {
        // A payout row already exists (crash between create_payout and the
        // state transition): adopt it rather than rebuilding.
        if self.db.get_payout(index)?.is_some() {
            self.db
                .transition_withdrawal(index, WithdrawalState::Signing, now_unix(), None)?;
            return Ok(());
        }

        let w = self
            .db
            .get_withdrawal(index)?
            .ok_or(DbError::WithdrawalNotFound(index))?;
        let candidates = self
            .db
            .available_utxos(self.config.vault_min_confirmations)?;

        let selection = match coin::select(
            &candidates,
            w.amount_atomic,
            self.config.fee_rate_per_kb,
            self.config.dust_threshold_atomic,
            self.config.max_inputs_per_payout,
            self.vault_input_bytes(),
        ) {
            Ok(s) => s,
            Err(SelectionError::Insufficient { .. })
            | Err(SelectionError::TooManyInputs { .. }) => {
                if w.state != WithdrawalState::AwaitingFunds {
                    self.db.transition_withdrawal(
                        index,
                        WithdrawalState::AwaitingFunds,
                        now_unix(),
                        Some("insufficient spendable vault funds"),
                    )?;
                }
                report.awaiting_funds += 1;
                return Ok(());
            }
        };

        if w.state == WithdrawalState::AwaitingFunds {
            self.db
                .transition_withdrawal(index, WithdrawalState::Validated, now_unix(), None)?;
        }

        // Reserve first: if this races and loses, no payout is created.
        if let Err(e) = self.db.reserve_utxos(index, &selection.inputs, now_unix()) {
            tracing::warn!(withdrawal_index = index, error = %e, "reservation lost; retrying next tick");
            report.awaiting_funds += 1;
            return Ok(());
        }
        self.db
            .transition_withdrawal(index, WithdrawalState::Building, now_unix(), None)?;

        // Build via the node, then verify what it produced.
        let change_h160 = if selection.change_atomic > 0 {
            Some(self.config.change_hash160)
        } else {
            None
        };
        let mut outputs: Vec<(String, u64)> = vec![(w.glc_address.clone(), w.amount_atomic)];
        if selection.change_atomic > 0 {
            outputs.push((self.config.change_address.clone(), selection.change_atomic));
        }
        let ins: Vec<(String, i64)> = selection
            .inputs
            .iter()
            .map(|u| (u.txid_hex.clone(), u.vout))
            .collect();

        let unsigned_hex = self
            .rpc
            .create_raw_transaction(&ins, &outputs)
            .await
            .map_err(classify)?;
        let decoded = self
            .rpc
            .decode_raw_transaction(&unsigned_hex)
            .await
            .map_err(classify)?;

        let plan = PayoutPlan {
            dest_hash160: w.glc_address_hash160,
            payout_atomic: w.amount_atomic, // D3: exactly the burned amount
            // Change returns to the P2SH vault, so its script is
            // `a914..87`, never the P2PKH shape (ADR-0015).
            change_script_hex: (selection.change_atomic > 0)
                .then(|| self.config.vault.script_pubkey_hex()),
            change_atomic: selection.change_atomic,
            fee_atomic: selection.fee_atomic,
            inputs: selection.inputs.clone(),
        };

        // EVERY output is verified before anything is signed.
        if let Err(e) = verify_payout_tx(&decoded, &plan) {
            tracing::error!(
                withdrawal_index = index,
                error = %e,
                "constructed payout failed output verification — halting, nothing signed"
            );
            self.db.transition_withdrawal(
                index,
                WithdrawalState::IntegrityHalted,
                now_unix(),
                Some(&format!("output verification failed: {e}")),
            )?;
            report.halted += 1;
            return Ok(());
        }

        // ADR-0015: the signing quorum is designated NOW, before any
        // signature exists, so the resulting txid is deterministic and the
        // ADR-0013 persist-txid-before-broadcast model still holds.
        let quorum = self.designate_quorum(index);
        self.config
            .vault
            .validate_quorum(&quorum)
            .map_err(|e| ExecutorError::Rpc(RpcError::Malformed(e.to_string())))?;
        let intent = canonical_payout_intent(
            w.protocol_version,
            index,
            &self.config.vault.script_hash160,
            &w.glc_address_hash160,
            w.amount_atomic,
            selection.fee_atomic,
            selection.change_atomic,
            &change_h160.unwrap_or([0u8; 20]),
            0,
            &quorum,
            &selection.inputs,
        );
        self.db.create_payout(&NewPayout {
            withdrawal_index: index,
            vault_script_hash: self.config.vault.script_hash160,
            quorum_indices: quorum,
            quorum_attempt: 0,
            commitment_hash: payout_commitment(&intent),
            intent_bytes: intent,
            fee_atomic: selection.fee_atomic,
            payout_atomic: w.amount_atomic,
            change_atomic: selection.change_atomic,
            change_address: if selection.change_atomic > 0 {
                Some(self.config.change_address.clone())
            } else {
                None
            },
            unsigned_tx_hex: unsigned_hex,
            inputs: selection.inputs,
            built_at: now_unix(),
        })?;
        self.db
            .transition_withdrawal(index, WithdrawalState::Signing, now_unix(), None)?;
        report.built += 1;
        Ok(())
    }

    /// Collects partial signatures from the designated quorum and assembles
    /// the fully-signed transaction (Phase 7e, ADR-0017).
    ///
    /// This process holds no vault key. Goldcoin 0.17 has no
    /// `combinerawtransaction` and no PSBT, so assembly happens here, in
    /// `withdrawal::multisig`, pinned by a golden vector against real node
    /// output.
    async fn sign(
        &mut self,
        index: i64,
        report: &mut WithdrawalTickReport,
    ) -> Result<(), ExecutorError> {
        // The full pre-signing guard sequence. Anything wrong halts here and
        // nothing is signed.
        let signable = match self.db.verify_and_load_signable_payout(index, now_unix()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    withdrawal_index = index,
                    error = %e,
                    "pre-signing guards refused this payout — NOT signed, NOT broadcast"
                );
                report.halted += 1;
                return Ok(());
            }
        };

        // A relayer whose own view of the validator set has gone stale must
        // not stamp an epoch it cannot currently confirm onto a request.
        if !self.epoch.is_fresh_at(now_unix()) {
            tracing::warn!(
                withdrawal_index = index,
                "validator epoch observation is stale — not requesting signatures this tick"
            );
            return Ok(());
        }

        let partials = self
            .collector
            .collect_payout_partials(
                self.epoch.epoch(),
                index as u64,
                signable.quorum_attempt,
                &signable.intent_bytes,
                &signable.unsigned_tx_hex,
                &signable.quorum_indices,
            )
            .await;

        // Falling short is NORMAL, not an error and not a halt: the tick
        // simply retries, or an operator reassigns the quorum explicitly
        // (ADR-0015). Halting here would strand a withdrawal over an
        // ordinary outage.
        if partials.len() < self.config.vault.threshold {
            tracing::warn!(
                withdrawal_index = index,
                collected = partials.len(),
                threshold = self.config.vault.threshold,
                quorum_attempt = signable.quorum_attempt,
                "insufficient partial signatures from the designated quorum this tick"
            );
            return Ok(());
        }

        let unsigned = Transaction::parse_hex(&signable.unsigned_tx_hex)?;

        // Assembly verifies every partial against its input's sighash,
        // rejects strangers and duplicates, enforces the threshold exactly,
        // and orders signatures by redeem-script position — the
        // consensus-critical invariant (ADR-0017 D2).
        let signed = match assemble(&unsigned, &self.config.vault, &partials) {
            Ok(t) => t,
            Err(e) => {
                // An assembly failure means the collected partials cannot
                // form a spendable transaction. That is an anomaly, not an
                // outage: the signatures verified as coming from designated
                // signers, so something deeper disagrees.
                tracing::error!(
                    withdrawal_index = index,
                    error = %e,
                    "could not assemble a valid scriptSig from the designated quorum — halting"
                );
                self.db.transition_withdrawal(
                    index,
                    WithdrawalState::IntegrityHalted,
                    now_unix(),
                    Some(&format!("multisig assembly failed: {e}")),
                )?;
                report.halted += 1;
                return Ok(());
            }
        };
        let signed_hex = signed.serialize_hex();

        // Cross-check our own serializer against the node's decoder before
        // anything is persisted or broadcast. If our assembly or txid
        // computation were wrong, this is where it surfaces — not after the
        // network has seen it.
        let signed_decoded = self
            .rpc
            .decode_raw_transaction(&signed_hex)
            .await
            .map_err(classify)?;
        if signed_decoded.txid_hex != signed.txid_hex() {
            tracing::error!(
                withdrawal_index = index,
                ours = %signed.txid_hex(),
                node = %signed_decoded.txid_hex,
                "assembled txid disagrees with the node's — halting rather than broadcasting"
            );
            self.db.transition_withdrawal(
                index,
                WithdrawalState::IntegrityHalted,
                now_unix(),
                Some("assembled txid disagrees with the node's decoding"),
            )?;
            report.halted += 1;
            return Ok(());
        }

        let unsigned_decoded = self
            .rpc
            .decode_raw_transaction(&signable.unsigned_tx_hex)
            .await
            .map_err(classify)?;

        // Signing must not have altered outputs or outpoints.
        if let Err(e) = verify_signing_preserved_outputs(&unsigned_decoded, &signed_decoded) {
            self.db.transition_withdrawal(
                index,
                WithdrawalState::IntegrityHalted,
                now_unix(),
                Some(&format!("{e}")),
            )?;
            report.halted += 1;
            return Ok(());
        }

        let txid = crate::glc::hex::decode_exact::<32>(&signed_decoded.txid_hex)
            .map_err(|e| ExecutorError::Rpc(RpcError::Malformed(e.to_string())))?;

        // Durable BEFORE the network sees anything (ADR-0013). RFC6979
        // determinism is what makes this safe under crash: re-collecting
        // from the same quorum reproduces the identical transaction and
        // txid, so a lost broadcast response is always reconcilable.
        self.db
            .record_signed_payout(index, &signed_hex, &txid, now_unix())?;
        report.signed += 1;
        Ok(())
    }

    async fn rebroadcast(
        &mut self,
        index: i64,
        report: &mut WithdrawalTickReport,
    ) -> Result<(), ExecutorError> {
        let Some(p) = self.db.get_payout(index)? else {
            return Ok(());
        };
        let Some(signed) = p.signed_tx_hex.clone() else {
            return Ok(());
        };

        // ADR-0019 D4 — the last check before funds move. Phase 7g measured
        // two operators paying one withdrawal twice with nothing here to
        // stop it (§2.2).
        if !Self::safe_to_broadcast(self.onchain.clone(), index).await {
            return Ok(());
        }

        // Only ever the identical byte string; never a rebuild.
        match self
            .rpc
            .send_raw_transaction(&signed)
            .await
            .map_err(classify)?
        {
            BroadcastOutcome::Accepted { .. } | BroadcastOutcome::AlreadyInChain => {
                self.db.record_broadcast(index, now_unix())?;
                // An orphaned payout re-enters the pipeline at Broadcast —
                // the state machine has no Orphaned -> Confirming edge, and
                // shouldn't: re-confirmation must be observed, not assumed.
                let w = self.db.get_withdrawal(index)?;
                if w.is_some_and(|w| w.state == WithdrawalState::Orphaned) {
                    self.db.transition_withdrawal(
                        index,
                        WithdrawalState::Broadcast,
                        now_unix(),
                        Some("rebroadcast identical bytes after orphaning"),
                    )?;
                }
                report.broadcast += 1;
                // Immediately reconcile so a transaction that is already
                // mined advances in the same tick rather than waiting.
                self.reconcile_broadcast(index, report).await?;
            }
            BroadcastOutcome::MissingInputs => {
                // The inputs are gone. Either our own transaction is already
                // mined (handled by reconciliation) or something else spent
                // them — which we must never paper over by rebuilding.
                tracing::error!(
                    withdrawal_index = index,
                    "broadcast reported missing inputs; reconciling before any further action"
                );
                self.reconcile_broadcast(index, report).await?;
            }
        }
        Ok(())
    }

    /// Resolves a broadcast/confirming payout against chain reality.
    async fn reconcile_broadcast(
        &mut self,
        index: i64,
        report: &mut WithdrawalTickReport,
    ) -> Result<(), ExecutorError> {
        let Some(p) = self.db.get_payout(index)? else {
            return Ok(());
        };
        let Some(txid_hex) = p.txid_hex.clone() else {
            return Ok(());
        };

        let status = self
            .rpc
            .transaction_confirmations(&txid_hex)
            .await
            .map_err(classify)?;

        let Some(status) = status else {
            // The node has never seen it: it was dropped or never landed.
            // Rebroadcasting the identical bytes is safe and idempotent.
            tracing::warn!(
                withdrawal_index = index,
                txid = %txid_hex,
                "payout transaction not known to the node; will rebroadcast identical bytes"
            );
            self.db.transition_withdrawal(
                index,
                WithdrawalState::Orphaned,
                now_unix(),
                Some("payout transaction unknown to the node"),
            )?;
            report.orphaned += 1;
            return Ok(());
        };

        // If it claims a block, that block must still be on the main chain.
        if let Some(bh) = status.block_hash_hex.as_deref() {
            if !self.rpc.block_on_main_chain(bh).await.map_err(classify)? {
                tracing::warn!(
                    withdrawal_index = index,
                    "payout's block was reorged away; reverting to rebroadcast"
                );
                self.db.transition_withdrawal(
                    index,
                    WithdrawalState::Orphaned,
                    now_unix(),
                    Some("payout block orphaned by a reorg"),
                )?;
                report.orphaned += 1;
                return Ok(());
            }
        }

        let block_hash = status
            .block_hash_hex
            .as_deref()
            .and_then(|h| crate::glc::hex::decode_exact::<32>(h).ok());
        self.db.record_confirmations(
            index,
            status.confirmations,
            block_hash.as_ref(),
            status.block_height,
        )?;

        let w = self
            .db
            .get_withdrawal(index)?
            .ok_or(DbError::WithdrawalNotFound(index))?;
        if w.state == WithdrawalState::Broadcast {
            self.db
                .transition_withdrawal(index, WithdrawalState::Confirming, now_unix(), None)?;
        }

        if status.confirmations >= self.config.confirmation_depth {
            self.db.complete_payout(index, now_unix())?;
            tracing::info!(
                withdrawal_index = index,
                txid = %txid_hex,
                confirmations = status.confirmations,
                "payout confirmed at required depth: Completed"
            );
            report.completed += 1;
        } else {
            report.confirming += 1;
        }
        Ok(())
    }
}

/// Helper for tests and callers building output maps.
pub fn expected_output_scripts(dest: &[u8; 20], change: Option<&[u8; 20]>) -> Vec<String> {
    let mut v = vec![p2pkh_script_hex(dest)];
    if let Some(c) = change {
        v.push(p2pkh_script_hex(c));
    }
    v
}

/// Mirrors the two-tier retry classification used by the indexer and the
/// mint orchestrator.
fn classify(e: RpcError) -> ExecutorError {
    if e.is_retriable() {
        ExecutorError::NodeUnavailable(e)
    } else {
        ExecutorError::Rpc(e)
    }
}

/// Convenience re-exports so integration tests can build decoded shapes.
pub use crate::withdrawal::builder::{DecodedInput as TxIn, DecodedOutput as TxOut};

/// Builds a `DecodedTx` from parts — used by the real RPC adapter and by
/// mocks so both produce identical shapes.
pub fn decoded_tx(
    txid_hex: impl Into<String>,
    inputs: Vec<(String, i64)>,
    outputs: Vec<(u64, String)>,
) -> DecodedTx {
    DecodedTx {
        txid_hex: txid_hex.into(),
        inputs: inputs
            .into_iter()
            .map(|(txid_hex, vout)| DecodedInput { txid_hex, vout })
            .collect(),
        outputs: outputs
            .into_iter()
            .map(|(value_atomic, script_pubkey_hex)| DecodedOutput {
                value_atomic,
                script_pubkey_hex,
            })
            .collect(),
    }
}

/// Converts a raw `VaultUtxo` list into the `(txid_hex, vout)` pairs the
/// node's `createrawtransaction` expects.
pub fn outpoints(utxos: &[VaultUtxo]) -> Vec<(String, i64)> {
    utxos.iter().map(|u| (u.txid_hex.clone(), u.vout)).collect()
}
