//! What a validator will sign for a vault sweep (Phase 7i-0).
//!
//! A sweep spends the **entire vault** to an address chosen by a human
//! (ADR-0014 §8.7's compromise response). Nothing on chain says it should
//! happen, so — exactly as with governance ([`super::governance_view`]) —
//! this validator signs only what its own operator staged, and nothing else.
//!
//! # The two independent gates
//!
//! 1. **The operator approved this exact sweep.** The staged commitment
//!    covers the source vault, the destination script, the fee, the swept
//!    amount, and every outpoint and amount being spent. Change any of them
//!    and the commitment changes.
//! 2. **This validator has itself observed every input as vault-owned.**
//!    Input amounts come from this validator's *own* `vault_utxos` rows, not
//!    from the request. An input this validator has never seen as a
//!    confirmed vault output is refused outright, so a proposer cannot make
//!    a signer attest to a spend of something it cannot see.
//!
//! Both are required. Gate 1 without gate 2 would let a proposer hand over a
//! plan whose amounts were invented; gate 2 without gate 1 would let anyone
//! with a transport identity drain the vault to an address of their choosing.
//!
//! # Why this is a separate arm from the payout arm
//!
//! Both produce Goldcoin partial signatures with the same vault key, and
//! that is precisely why they must not share a path. The payout arm's
//! authorisation is "a matching burn exists on Solana"; the sweep arm's is
//! "my operator told me to". Folding them together would mean one code path
//! where the *stronger* condition could be reached through the *weaker*
//! check.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::glc::db::Db;
use crate::glc::rpc::PrevTx;
use crate::glc::withdrawal_db::VaultUtxo;
use crate::withdrawal::coin::fee_for;
use crate::withdrawal::config::WithdrawalConfig;
use crate::withdrawal::multisig::{extract_signatures, MultisigError, Transaction};
use crate::withdrawal::sweep::{verify_sweep_tx, SweepError, SweepPlan, SWEEP_OUTPUT_COUNT};
use crate::withdrawal::vault::MultisigVault;

use super::payout_view::{PartialSigner, PayoutPartial};

/// What a signer authorised, alongside the signatures themselves.
///
/// The amount is carried out of the view deliberately: the audit record for
/// the most dangerous operation in the system must state what left the
/// vault, and only the view knows it. Logging a placeholder there would put
/// a number in an audit trail that is not true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepPartial {
    pub partial: PayoutPartial,
    pub swept_atomic: u64,
    pub inputs: usize,
}

/// How long a staged sweep approval stays usable. Shorter than the
/// governance TTL: a sweep's commitment pins the exact UTXO set, so a stale
/// approval stops matching as soon as the vault receives anything, and a
/// long window buys nothing but risk.
pub const SWEEP_APPROVAL_TTL_SECONDS: i64 = 6 * 60 * 60;

/// A ceiling on the sweep fee, as a multiple of the policy fee for the same
/// shape.
///
/// Not a security boundary — the operator's approval already commits to the
/// exact fee. It is a guard against operator error: approving a plan whose
/// fee field was misread donates vault funds to a miner irreversibly, and
/// that mistake is worth making impossible rather than merely unlikely. A
/// sweep is an incident response, so some headroom over the ordinary rate is
/// allowed for faster confirmation.
pub const MAX_SWEEP_FEE_MULTIPLE: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SweepRefusal {
    #[error("this validator's operator has not approved any sweep")]
    NotApproved,
    #[error("this validator's operator approved a DIFFERENT sweep")]
    DifferentSweepApproved,
    #[error("the sweep approval expired at {expiry}, now {now}")]
    ApprovalExpired { expiry: i64, now: i64 },
    #[error("this validator has already signed a DIFFERENT sweep")]
    AlreadySignedAnother,
    #[error("sweep approval store is unreadable: {0}")]
    StoreUnreadable(String),
    #[error("the proposed sweep transaction is malformed: {0}")]
    Malformed(String),
    #[error(
        "input {index} ({outpoint}) is not an available vault output in this validator's own view"
    )]
    UnknownInput { index: usize, outpoint: String },
    #[error("the proposed sweep does not match its plan: {0}")]
    PlanMismatch(String),
    #[error("the sweep pays a {fee} fee, more than the {ceiling} ceiling for its shape")]
    FeeTooHigh { fee: u64, ceiling: u64 },
    #[error("the sweep output exceeds the value of its inputs")]
    OutputExceedsInputs,
    #[error("signing on this validator's own node failed: {0}")]
    SigningFailed(String),
    #[error("the node returned a malformed partial signature: {0}")]
    MalformedPartial(String),
    #[error("this validator's database is unreadable: {0}")]
    DbUnreadable(String),
}

/// One operator-staged sweep approval.
///
/// At most one is ever in force: a vault has one contents, so two
/// simultaneously-approved sweeps of it would be two attempts to spend the
/// same outputs. Staging a second replaces the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepApproval {
    /// [`SweepPlan::commitment`] — the whole sweep in 32 bytes.
    pub commitment: [u8; 32],
    pub expiry_unix: i64,
    /// Why the operator approved. Recorded for the audit trail; a sweep with
    /// no recorded reason is indistinguishable from an intrusion later.
    pub note: String,
}

impl SweepApproval {
    /// The on-disk form: `hex_commitment expiry note`, one line.
    ///
    /// Plain text for the same reason the governance store is: this file is
    /// meant to be read by a human during an incident, without tooling.
    pub fn to_text(&self) -> String {
        format!(
            "{} {} {}\n",
            crate::glc::hex::encode(&self.commitment),
            self.expiry_unix,
            self.note.replace('\n', " ")
        )
    }

    /// Parses the store, taking the **last** approval in the file.
    ///
    /// Last rather than first so an operator appending a correction gets the
    /// correction, which is the way people actually edit a file under
    /// pressure.
    pub fn from_text(text: &str) -> Result<Option<Self>, SweepRefusal> {
        let mut found = None;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = |what: &str| SweepRefusal::StoreUnreadable(format!("line {}: {what}", n + 1));
            let mut parts = line.splitn(3, ' ');
            let commitment = crate::glc::hex::decode_exact::<32>(
                parts.next().ok_or_else(|| bad("missing commitment"))?,
            )
            .map_err(|_| bad("commitment is not 32 hex bytes"))?;
            let expiry: i64 = parts
                .next()
                .ok_or_else(|| bad("missing expiry"))?
                .parse()
                .map_err(|_| bad("expiry is not an i64"))?;
            found = Some(SweepApproval {
                commitment,
                expiry_unix: expiry,
                note: parts.next().unwrap_or("").to_string(),
            });
        }
        Ok(found)
    }

    /// Reads the store, treating a missing file as **no approval** — the
    /// correct default, since a validator with nothing staged must refuse
    /// every sweep.
    pub fn load(path: &Path) -> Result<Option<Self>, SweepRefusal> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_text(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SweepRefusal::StoreUnreadable(e.to_string())),
        }
    }
}

/// A validator's sweep signing view, over its own database and its own node.
pub struct SweepView<S: PartialSigner> {
    config: WithdrawalConfig,
    vault: MultisigVault,
    vault_signer_index: u8,
    signer: S,
    approvals_path: PathBuf,
    /// What has already been signed, so a retry is idempotent and a second,
    /// conflicting sweep is refused — the same equivocation guard the mint
    /// and governance paths have. Two signed sweeps of one vault are two
    /// conflicting spends of the same outputs.
    signed: std::sync::Mutex<Option<[u8; 32]>>,
}

impl<S: PartialSigner> SweepView<S> {
    /// Fails closed on a signer index outside the vault (ADR-0017 E1): a
    /// mapping that could route a request to the wrong key must be rejected
    /// at construction, not discovered when a sweep fails.
    pub fn new(
        config: WithdrawalConfig,
        vault_signer_index: u8,
        signer: S,
        approvals_path: PathBuf,
    ) -> Result<Self, String> {
        let vault = config.vault.clone();
        if usize::from(vault_signer_index) >= vault.signer_count() {
            return Err(format!(
                "vault signer index {vault_signer_index} is out of range for a {}-signer vault",
                vault.signer_count()
            ));
        }
        Ok(SweepView {
            config,
            vault,
            vault_signer_index,
            signer,
            approvals_path,
            signed: std::sync::Mutex::new(None),
        })
    }

    pub fn vault_pubkey(&self) -> [u8; 33] {
        self.vault.signer_pubkeys[usize::from(self.vault_signer_index)]
    }

    /// Reconstructs the plan a proposed transaction describes, using **this
    /// validator's own** UTXO rows for every input amount.
    ///
    /// The request supplies only the transaction. Everything that determines
    /// value — which outputs are being spent and what they are worth — is
    /// read locally, so a proposer cannot inflate or invent an input.
    fn plan_from_local_view(&self, db: &Db, tx: &Transaction) -> Result<SweepPlan, SweepRefusal> {
        let available = db
            .available_utxos(self.config.vault_min_confirmations)
            .map_err(|e| SweepRefusal::DbUnreadable(e.to_string()))?;

        let mut inputs: Vec<VaultUtxo> = Vec::with_capacity(tx.inputs.len());
        for (i, inp) in tx.inputs.iter().enumerate() {
            let found = available
                .iter()
                // `VaultUtxo::txid` is display order, the transaction's is
                // internal. Comparing them directly made every real sweep
                // fail as UnknownInput (see sweep::internal_txid).
                .find(|u| {
                    crate::withdrawal::sweep::internal_txid(&u.txid) == inp.prev_txid
                        && u.vout as u32 == inp.prev_vout
                })
                .ok_or_else(|| SweepRefusal::UnknownInput {
                    index: i,
                    outpoint: format!(
                        "{}:{}",
                        crate::glc::hex::encode(&crate::withdrawal::sweep::internal_txid(
                            &inp.prev_txid
                        )),
                        inp.prev_vout
                    ),
                })?;
            inputs.push(found.clone());
        }

        if tx.outputs.len() != 1 {
            return Err(SweepRefusal::PlanMismatch(
                SweepError::NotSingleOutput(tx.outputs.len()).to_string(),
            ));
        }
        let out = &tx.outputs[0];
        let total_in: u64 = inputs.iter().map(|u| u.amount_atomic).sum();
        // Derived, never taken from the request: what the vault loses beyond
        // the output is the fee, by definition.
        let fee = total_in
            .checked_sub(out.value)
            .ok_or(SweepRefusal::OutputExceedsInputs)?;

        let ceiling = fee_for(
            inputs.len() as u64,
            SWEEP_OUTPUT_COUNT,
            self.config.fee_rate_per_kb,
            crate::withdrawal::coin::multisig_input_bytes(
                self.vault.threshold,
                self.vault.redeem_script.len(),
            ),
        )
        .saturating_mul(MAX_SWEEP_FEE_MULTIPLE);
        if fee > ceiling {
            return Err(SweepRefusal::FeeTooHigh { fee, ceiling });
        }

        Ok(SweepPlan {
            source_hash160: self.vault.script_hash160,
            // The destination is described by the script the transaction
            // actually pays. There is no separate destination field to
            // disagree with it, which removes a whole class of "the label
            // said one thing and the script said another" failure.
            dest_hash160: dest_hash160_of(&out.script_pubkey),
            dest_script_pubkey: out.script_pubkey.clone(),
            dest_address: String::new(),
            fee_atomic: fee,
            swept_atomic: out.value,
            inputs,
        })
    }

    /// Decides whether to sign, and if so signs on this validator's own node.
    pub async fn sign_sweep(
        &self,
        // `&mut` rather than `&`: `Db` is `Send` but not `Sync` (a `RefCell`
        // in the statement cache), so a shared reference cannot be held
        // across an `.await`. The same reason the payout arm takes one.
        db: &mut Db,
        unsigned_tx_hex: &str,
        protocol_version: u8,
        now_unix: i64,
    ) -> Result<SweepPartial, SweepRefusal> {
        let tx = Transaction::parse_hex(unsigned_tx_hex)
            .map_err(|e: MultisigError| SweepRefusal::Malformed(e.to_string()))?;

        // Gate 2 first: it is answered entirely from local state, so a
        // request naming outputs this validator cannot see never reaches the
        // approval file or the node.
        let plan = self.plan_from_local_view(&*db, &tx)?;
        verify_sweep_tx(&tx, &plan).map_err(|e| SweepRefusal::PlanMismatch(e.to_string()))?;

        // Gate 1: the operator approved this exact sweep.
        let commitment = plan.commitment(protocol_version);
        let approval =
            SweepApproval::load(&self.approvals_path)?.ok_or(SweepRefusal::NotApproved)?;
        if approval.commitment != commitment {
            return Err(SweepRefusal::DifferentSweepApproved);
        }
        if now_unix > approval.expiry_unix {
            return Err(SweepRefusal::ApprovalExpired {
                expiry: approval.expiry_unix,
                now: now_unix,
            });
        }

        // Equivocation guard. A retry of the SAME sweep is free; a second,
        // different sweep of the same vault is two conflicting spends and
        // this validator will not contribute to both.
        {
            let mut signed = self.signed.lock().unwrap();
            match *signed {
                Some(prev) if prev == commitment => {}
                Some(_) => return Err(SweepRefusal::AlreadySignedAnother),
                None => *signed = Some(commitment),
            }
        }

        // prevtxs are built ENTIRELY from local rows, like the payout path:
        // nothing about the inputs comes from the request.
        let prevtxs: Vec<PrevTx> = plan
            .inputs
            .iter()
            .map(|u| PrevTx {
                txid: u.txid_hex.clone(),
                vout: u.vout,
                script_pub_key: u.script_pubkey_hex.clone(),
                redeem_script: self.vault.redeem_script_hex(),
            })
            .collect();

        tracing::warn!(
            inputs = plan.inputs.len(),
            swept_atomic = plan.swept_atomic,
            fee_atomic = plan.fee_atomic,
            note = %approval.note,
            "SIGNING A VAULT SWEEP — this moves the entire vault"
        );

        let partial_hex = self
            .signer
            .sign_partial(unsigned_tx_hex, &prevtxs)
            .await
            .map_err(SweepRefusal::SigningFailed)?;
        let partial = Transaction::parse_hex(&partial_hex)
            .map_err(|e: MultisigError| SweepRefusal::MalformedPartial(e.to_string()))?;
        let signatures = extract_signatures(&partial, &self.vault.redeem_script)
            .map_err(|e| SweepRefusal::MalformedPartial(e.to_string()))?;

        Ok(SweepPartial {
            swept_atomic: plan.swept_atomic,
            inputs: plan.inputs.len(),
            partial: PayoutPartial {
                vault_pubkey: self.vault_pubkey(),
                signatures,
            },
        })
    }
}

/// The hash160 a `scriptPubKey` pays, for P2SH (`a914..87`) and P2PKH
/// (`76a914..88ac`). Anything else yields zeroes, which still commits to the
/// script itself — the script bytes are in the commitment either way, so an
/// unrecognised shape cannot slip past, it merely has no short label.
fn dest_hash160_of(script: &[u8]) -> [u8; 20] {
    let mut h = [0u8; 20];
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        h.copy_from_slice(&script[2..22]);
    } else if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        h.copy_from_slice(&script[3..23]);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::sweep::p2sh_script_pubkey;

    struct NeverCalled;
    impl PartialSigner for NeverCalled {
        async fn sign_partial(&self, _: &str, _: &[PrevTx]) -> Result<String, String> {
            panic!("the node must not be reached for a sweep refused on local state");
        }
    }

    /// Stands in for a node that signs: it returns the transaction with a
    /// `OP_0 <sig> <redeemScript>` scriptSig on every input, the shape
    /// `signrawtransaction` produces for a partial M-of-N spend.
    ///
    /// The bytes are not a real ECDSA signature — this view never verifies
    /// one; that happens during assembly, against the input's sighash. What
    /// is under test here is which requests reach the node at all.
    struct AlwaysSigns {
        redeem_script: Vec<u8>,
    }
    impl PartialSigner for AlwaysSigns {
        async fn sign_partial(&self, hex: &str, _: &[PrevTx]) -> Result<String, String> {
            let mut tx = Transaction::parse_hex(hex).map_err(|e| e.to_string())?;
            for inp in &mut tx.inputs {
                let mut s = vec![0x00, 71];
                s.extend_from_slice(&[0xAB; 71]);
                s.push(0x4c);
                s.push(self.redeem_script.len() as u8);
                s.extend_from_slice(&self.redeem_script);
                inp.script_sig = s;
            }
            Ok(tx.serialize_hex())
        }
    }

    fn vault_of(n: usize, m: usize) -> MultisigVault {
        let keys: Vec<[u8; 33]> = (0..n)
            .map(|i| {
                let mut k = [0u8; 33];
                k[0] = 0x02;
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        MultisigVault::new(m, keys).unwrap()
    }

    fn cfg_of(n: usize, m: usize) -> WithdrawalConfig {
        let v = vault_of(n, m);
        WithdrawalConfig::validate(crate::withdrawal::config::RawWithdrawalConfig {
            vault_redeem_script_hex: v.redeem_script_hex(),
            vault_address: v.address.clone(),
            change_address: v.address.clone(),
            fee_rate_per_kb: 10_000,
            dust_threshold_atomic: 5_400,
            vault_min_confirmations: 1,
            confirmation_depth: 2,
            max_inputs_per_payout: 20,
            reservation_timeout_secs: 900,
            discovery_commitment: "finalized".into(),
            poll_interval_ms: 500,
        })
        .unwrap()
    }

    fn view(dir: &std::path::Path) -> SweepView<NeverCalled> {
        SweepView::new(cfg_of(3, 2), 0, NeverCalled, dir.join("sweep-approvals")).unwrap()
    }

    #[test]
    fn refuses_to_construct_with_a_vault_index_out_of_range() {
        let err = match SweepView::new(
            cfg_of(3, 2),
            3,
            NeverCalled,
            PathBuf::from("/nonexistent/approvals"),
        ) {
            Err(e) => e,
            Ok(_) => panic!("a vault index outside the signer set must be refused"),
        };
        assert!(err.contains("out of range"), "{err}");
    }

    #[test]
    fn an_approval_round_trips_through_its_text_form() {
        let a = SweepApproval {
            commitment: [0x5a; 32],
            expiry_unix: 1_800_000_000,
            note: "vault key suspected compromised, ticket INC-42".into(),
        };
        let back = SweepApproval::from_text(&a.to_text()).unwrap().unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn a_missing_store_means_no_approval_rather_than_an_error() {
        // The fail-closed default: nothing staged, so every sweep is refused
        // — but the signer still starts and still serves everything else.
        assert_eq!(
            SweepApproval::load(std::path::Path::new("/nonexistent/sweep-approvals")).unwrap(),
            None
        );
    }

    #[test]
    fn comments_and_blank_lines_are_tolerated() {
        let text = "# staged 2026-07-30 by kavinda\n\n\
                    5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a 99 why\n";
        let a = SweepApproval::from_text(text).unwrap().unwrap();
        assert_eq!(a.expiry_unix, 99);
        assert_eq!(a.note, "why");
    }

    #[test]
    fn a_corrupt_store_is_an_error_rather_than_silently_empty() {
        // Silently treating a damaged file as "nothing approved" would be
        // safe here, but treating it as an error surfaces the damage before
        // an operator concludes their staging did not take.
        assert!(SweepApproval::from_text("not-hex 1 note").is_err());
        assert!(SweepApproval::from_text("5a5a 1 note").is_err());
        assert!(SweepApproval::from_text(
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a notanumber n"
        )
        .is_err());
    }

    #[test]
    fn a_later_line_supersedes_an_earlier_one() {
        let text = "1111111111111111111111111111111111111111111111111111111111111111 1 first\n\
                    2222222222222222222222222222222222222222222222222222222222222222 2 second\n";
        let a = SweepApproval::from_text(text).unwrap().unwrap();
        assert_eq!(a.commitment, [0x22; 32]);
        assert_eq!(a.note, "second");
    }

    #[test]
    fn the_p2sh_and_p2pkh_destination_shapes_are_recognised() {
        assert_eq!(dest_hash160_of(&p2sh_script_pubkey(&[7u8; 20])), [7u8; 20]);
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[9u8; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(dest_hash160_of(&p2pkh), [9u8; 20]);
    }

    #[test]
    fn an_unrecognised_destination_shape_yields_no_label_but_is_not_an_error() {
        // The script bytes themselves are in the commitment, so an odd shape
        // cannot slip past — it simply has no 20-byte label.
        assert_eq!(dest_hash160_of(&[0x6a]), [0u8; 20]);
    }

    #[tokio::test]
    async fn refuses_a_sweep_of_outputs_this_validator_has_never_seen() {
        // Gate 2, and it must be answered without touching the node: a
        // proposer naming outputs this validator cannot see gets nothing.
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = crate::glc::db::Db::open(&dir.path().join("db.sqlite")).unwrap();

        let tx = Transaction {
            version: 1,
            inputs: vec![crate::withdrawal::multisig::TxInput {
                prev_txid: [0xAB; 32],
                prev_vout: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![crate::withdrawal::multisig::TxOutput {
                value: 100_000,
                script_pubkey: p2sh_script_pubkey(&[0x22; 20]),
            }],
            lock_time: 0,
        };
        let err = v
            .sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SweepRefusal::UnknownInput { index: 0, .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn refuses_a_malformed_transaction_without_reaching_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = crate::glc::db::Db::open(&dir.path().join("db.sqlite")).unwrap();
        let err = v
            .sign_sweep(&mut db, "not hex at all", 1, 1_000)
            .await
            .unwrap_err();
        assert!(matches!(err, SweepRefusal::Malformed(_)), "got {err:?}");
    }

    // --- gate 1: the operator's staged approval -------------------------

    /// A database whose vault holds `amounts`, as this validator's own node
    /// would have reported them.
    fn db_with_vault(dir: &std::path::Path, vault: &MultisigVault, amounts: &[u64]) -> Db {
        use crate::glc::withdrawal_db::ObservedUtxo;
        let mut db = Db::open(&dir.join("db.sqlite")).unwrap();
        let observed: Vec<ObservedUtxo> = amounts
            .iter()
            .enumerate()
            .map(|(i, a)| ObservedUtxo {
                txid: [i as u8 + 1; 32],
                vout: 0,
                amount_atomic: *a,
                script_pubkey_hex: vault.script_pubkey_hex(),
                confirmations: 10,
            })
            .collect();
        db.sync_vault_utxos(&observed, 1, 1_000).unwrap();
        db
    }

    /// The unsigned sweep an operator would build from that vault.
    fn sweep_tx(db: &Db, dest: &[u8; 20], fee: u64) -> (Transaction, Vec<VaultUtxo>) {
        let inputs = db.available_utxos(1).unwrap();
        let total: u64 = inputs.iter().map(|u| u.amount_atomic).sum();
        let tx = Transaction {
            version: 1,
            inputs: inputs
                .iter()
                .map(|u| crate::withdrawal::multisig::TxInput {
                    prev_txid: u.txid,
                    prev_vout: u.vout as u32,
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                })
                .collect(),
            outputs: vec![crate::withdrawal::multisig::TxOutput {
                value: total - fee,
                script_pubkey: p2sh_script_pubkey(dest),
            }],
            lock_time: 0,
        };
        (tx, inputs)
    }

    fn stage(path: &std::path::Path, commitment: [u8; 32], expiry: i64) {
        std::fs::write(
            path,
            SweepApproval {
                commitment,
                expiry_unix: expiry,
                note: "INC-42".into(),
            }
            .to_text(),
        )
        .unwrap();
    }

    /// The commitment for the sweep `tx` describes, as the signer computes it.
    fn commitment_of(v: &SweepView<NeverCalled>, db: &Db, tx: &Transaction) -> [u8; 32] {
        v.plan_from_local_view(db, tx).unwrap().commitment(1)
    }

    #[tokio::test]
    async fn refuses_every_sweep_when_nothing_is_staged() {
        // The fail-closed default. A validator whose operator has said
        // nothing must not help move the vault.
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000, 700_000]);
        let (tx, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        assert_eq!(
            v.sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_000)
                .await
                .unwrap_err(),
            SweepRefusal::NotApproved
        );
    }

    #[tokio::test]
    async fn refuses_a_sweep_to_a_destination_the_operator_did_not_approve() {
        // THE property this module exists for: an approval to sweep to A
        // must not move the vault to B.
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000, 700_000]);

        let (approved, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        stage(
            &dir.path().join("sweep-approvals"),
            commitment_of(&v, &db, &approved),
            9_999,
        );

        let (attacker, _) = sweep_tx(&db, &[0xEE; 20], 2_000);
        assert_eq!(
            v.sign_sweep(&mut db, &attacker.serialize_hex(), 1, 1_000)
                .await
                .unwrap_err(),
            SweepRefusal::DifferentSweepApproved
        );
    }

    #[tokio::test]
    async fn refuses_a_sweep_whose_amount_was_altered_after_approval() {
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000, 700_000]);

        let (approved, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        stage(
            &dir.path().join("sweep-approvals"),
            commitment_of(&v, &db, &approved),
            9_999,
        );

        // Same destination, a larger fee still inside the sanity ceiling —
        // so the approval check is what has to catch it. The difference
        // would go to a miner.
        let (altered, _) = sweep_tx(&db, &[0x22; 20], 5_000);
        assert_eq!(
            v.sign_sweep(&mut db, &altered.serialize_hex(), 1, 1_000)
                .await
                .unwrap_err(),
            SweepRefusal::DifferentSweepApproved
        );
    }

    #[tokio::test]
    async fn refuses_an_expired_approval() {
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000]);
        let (tx, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        stage(
            &dir.path().join("sweep-approvals"),
            commitment_of(&v, &db, &tx),
            1_000,
        );
        assert_eq!(
            v.sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_001)
                .await
                .unwrap_err(),
            SweepRefusal::ApprovalExpired {
                expiry: 1_000,
                now: 1_001
            }
        );
    }

    #[tokio::test]
    async fn revoking_an_approval_takes_effect_without_a_restart() {
        // The file is re-read on every request precisely so an operator can
        // withdraw consent mid-incident.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sweep-approvals");
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000]);
        let (tx, _) = sweep_tx(&db, &[0x22; 20], 2_000);

        stage(&path, commitment_of(&v, &db, &tx), 9_999);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            v.sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_000)
                .await
                .unwrap_err(),
            SweepRefusal::NotApproved
        );
    }

    #[tokio::test]
    async fn an_absurd_fee_is_refused_even_when_it_was_approved() {
        // Defense against operator error, not against an attacker: the
        // approval matched, and the sweep is still refused because the fee
        // is far outside anything the fee policy would produce.
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[10_000_000]);
        let (tx, _) = sweep_tx(&db, &[0x22; 20], 9_000_000);
        let err = v
            .sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SweepRefusal::FeeTooHigh { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_sweep_paying_out_more_than_it_spends_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let mut db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000]);
        let (mut tx, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        tx.outputs[0].value = 900_000;
        assert_eq!(
            v.sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_000)
                .await
                .unwrap_err(),
            SweepRefusal::OutputExceedsInputs
        );
    }

    #[tokio::test]
    async fn a_sweep_with_a_second_output_is_refused() {
        // A "sweep" that leaves change behind leaves value under the key the
        // sweep exists to abandon.
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let vault = vault_of(3, 2);
        let mut db = db_with_vault(dir.path(), &vault, &[500_000]);
        let (mut tx, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        tx.outputs[0].value -= 100_000;
        tx.outputs.push(crate::withdrawal::multisig::TxOutput {
            value: 100_000,
            script_pubkey: crate::glc::hex::decode_vec(&vault.script_pubkey_hex()).unwrap(),
        });
        let err = v
            .sign_sweep(&mut db, &tx.serialize_hex(), 1, 1_000)
            .await
            .unwrap_err();
        assert!(matches!(err, SweepRefusal::PlanMismatch(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn having_signed_one_sweep_it_refuses_a_second_different_one() {
        // Two signed sweeps of one vault are two conflicting spends of the
        // same outputs. Even with a perfectly valid fresh approval, this
        // validator must not contribute to both — the same equivocation
        // guard the mint and governance paths have.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sweep-approvals");
        let vault = vault_of(3, 2);
        let v = SweepView::new(
            cfg_of(3, 2),
            0,
            AlwaysSigns {
                redeem_script: vault.redeem_script.clone(),
            },
            path.clone(),
        )
        .unwrap();
        let mut db = db_with_vault(dir.path(), &vault, &[500_000, 700_000]);

        let (first, _) = sweep_tx(&db, &[0x22; 20], 2_000);
        let first_commitment = v.plan_from_local_view(&db, &first).unwrap().commitment(1);
        stage(&path, first_commitment, 9_999);
        let partial = v
            .sign_sweep(&mut db, &first.serialize_hex(), 1, 1_000)
            .await
            .expect("the staged sweep is signed");
        assert_eq!(
            partial.partial.signatures.len(),
            2,
            "one signature per input"
        );
        assert_eq!(partial.partial.vault_pubkey, vault.signer_pubkeys[0]);
        // The audit record for a sweep must state what actually left the
        // vault, so the view carries it out rather than the service guessing.
        assert_eq!(partial.inputs, 2);
        assert!(partial.swept_atomic > 0);

        // A retry of the SAME sweep stays free.
        v.sign_sweep(&mut db, &first.serialize_hex(), 1, 1_000)
            .await
            .expect("retrying the same sweep is idempotent");

        // The operator now stages a different destination. The approval is
        // valid; the signer has already committed elsewhere.
        let (second, _) = sweep_tx(&db, &[0x44; 20], 2_000);
        let second_commitment = v.plan_from_local_view(&db, &second).unwrap().commitment(1);
        assert_ne!(first_commitment, second_commitment);
        stage(&path, second_commitment, 9_999);
        assert_eq!(
            v.sign_sweep(&mut db, &second.serialize_hex(), 1, 1_000)
                .await
                .unwrap_err(),
            SweepRefusal::AlreadySignedAnother
        );
    }

    #[tokio::test]
    async fn the_local_plan_reads_amounts_from_this_validators_own_rows() {
        // Gate 2's substance: the request carries no amounts at all, so the
        // fee and swept value are whatever this validator's own view says.
        let dir = tempfile::tempdir().unwrap();
        let v = view(dir.path());
        let db = db_with_vault(dir.path(), &vault_of(3, 2), &[500_000, 700_000]);
        let (tx, inputs) = sweep_tx(&db, &[0x22; 20], 2_000);
        let plan = v.plan_from_local_view(&db, &tx).unwrap();
        assert_eq!(plan.total_in(), 1_200_000);
        assert_eq!(plan.fee_atomic, 2_000);
        assert_eq!(plan.swept_atomic, 1_198_000);
        assert_eq!(plan.inputs, inputs);
        assert_eq!(plan.source_hash160, vault_of(3, 2).script_hash160);
    }
}
