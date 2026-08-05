//! Every granted signature leaves a record (ADR-0014 §13.3).
//!
//! # Why this test captures real `tracing` output
//!
//! An audit-logging feature whose tests only check the *formatting helper*
//! would pass with every call site deleted. The thing that matters is that
//! the event is actually emitted on the path that grants the signature, so
//! this installs a subscriber, drives the real `SignerService`, and asserts
//! on what came out.
//!
//! That is also what makes it mutation-testable: removing any one
//! `audit_log::record` call must fail something.

use solana_sdk::signature::Keypair;

mod common;
use common::capture_grants;

use glc_relayer::p2p::audit_log::{Granted, EVENT};
use glc_relayer::p2p::policy::{Action, LocalView, SigningIdentity};
use glc_relayer::p2p::service::pb::GovernanceSignRequest;
use glc_relayer::p2p::service::{mint_request, now_unix, SignerService};

// ---------------------------------------------------------------------------
// A signer whose view derives exactly one message
// ---------------------------------------------------------------------------

const EPOCH: u64 = 11;
const TXID: [u8; 32] = [0xAB; 32];
const VOUT: u32 = 3;
const MESSAGE: &[u8] = b"canonical-message";

struct View;
impl LocalView for View {
    fn observed_epoch(&self) -> u64 {
        EPOCH
    }
    fn view_is_fresh(&self) -> bool {
        true
    }
    fn derive_message(&self, _a: Action, id: &SigningIdentity) -> Option<Vec<u8>> {
        match id {
            SigningIdentity::Deposit { txid, vout } if *txid == TXID && *vout == VOUT => {
                Some(MESSAGE.to_vec())
            }
            _ => None,
        }
    }
}

#[test]
fn granting_a_mint_signature_leaves_a_record() {
    // The gap this closes: before Phase 7l this path logged nothing at all
    // on success, so a validator's exercise of its authority left no local
    // trace.
    let service = SignerService::new(Keypair::new(), View);
    let (result, grants) = capture_grants(|| {
        service.handle(mint_request(vec![1], EPOCH, MESSAGE.to_vec(), TXID, VOUT))
    });
    assert!(result.is_ok());

    assert_eq!(grants.len(), 1, "exactly one audit record per grant");
    let g = &grants[0];
    assert_eq!(g.get("action"), Some("mint"));
    assert_eq!(g.level, "INFO", "an ordinary mint is not an alarm");

    let identity = g.get("identity").expect("the record names what was signed");
    assert!(
        identity.starts_with("abab") && identity.ends_with(":3"),
        "the record must identify the outpoint: {identity}"
    );
    assert!(
        g.get("validator").is_some_and(|v| v.len() == 64),
        "the record must name which validator signed"
    );
}

#[test]
fn a_refused_request_produces_no_grant_record() {
    // A grant record for something that was refused would be worse than no
    // record: it would put a false authorisation in the audit trail.
    let service = SignerService::new(Keypair::new(), View);
    let (result, grants) = capture_grants(|| {
        service.handle(mint_request(vec![1], EPOCH, b"forged".to_vec(), TXID, VOUT))
    });
    assert!(result.is_err());
    assert!(
        grants.is_empty(),
        "a refusal must never be recorded as a grant: {grants:?}"
    );
}

#[test]
fn a_signer_with_no_governance_arm_records_nothing() {
    let service = SignerService::new(Keypair::new(), View);
    let (result, grants) = capture_grants(|| {
        service.handle_governance(GovernanceSignRequest {
            request_id: vec![1],
            epoch: EPOCH,
            action: 3,
            params_commitment: vec![0xAA; 32],
            expiry_unix: now_unix() + 60,
        })
    });
    assert!(result.is_err());
    assert!(grants.is_empty());
}

#[test]
fn a_repeated_request_records_each_grant_it_answers() {
    // A retry returns the SAME signature (the seen-set makes it idempotent),
    // but it is still an occasion on which this validator handed one out.
    // An audit trail that recorded only the first would understate what left
    // the process.
    let service = SignerService::new(Keypair::new(), View);
    let (_, grants) = capture_grants(|| {
        let a = service.handle(mint_request(vec![1], EPOCH, MESSAGE.to_vec(), TXID, VOUT));
        let b = service.handle(mint_request(vec![2], EPOCH, MESSAGE.to_vec(), TXID, VOUT));
        assert_eq!(a.unwrap().signature, b.unwrap().signature);
    });
    assert_eq!(
        grants.len(),
        2,
        "each answered request is an occasion a signature left this process"
    );
}

#[test]
fn the_event_name_is_stable_across_every_action() {
    // One grep must find every grant on every host. The name is part of the
    // operator's log-shipping filters, so it is pinned here as well as in
    // the module's own tests.
    assert_eq!(EVENT, "signature_granted");
    for g in [
        Granted::Mint {
            txid: &TXID,
            vout: 0,
        },
        Granted::Payout {
            withdrawal_index: 1,
            quorum_attempt: 0,
        },
        Granted::Completion {
            withdrawal_index: 1,
            payout_txid: &TXID,
        },
        Granted::Governance {
            action: 3,
            epoch: 1,
        },
        Granted::Sweep {
            inputs: 1,
            swept_atomic: 1,
        },
    ] {
        assert!(!g.action().is_empty());
        assert!(!g.identity().is_empty());
    }
}

#[test]
fn policy_changing_grants_are_recorded_above_routine_traffic() {
    // Mints and payouts happen many times an hour. Governance changes who
    // the federation is; a sweep moves every coin. An operator filtering out
    // routine traffic must still see those two.
    let (_, grants) = capture_grants(|| {
        glc_relayer::p2p::audit_log::record(
            Granted::Governance {
                action: 3,
                epoch: 9,
            },
            &[0x11; 32],
        );
        glc_relayer::p2p::audit_log::record(
            Granted::Sweep {
                inputs: 4,
                swept_atomic: 12_000_000_000,
            },
            &[0x11; 32],
        );
        glc_relayer::p2p::audit_log::record(
            Granted::Payout {
                withdrawal_index: 2,
                quorum_attempt: 0,
            },
            &[0x11; 32],
        );
    });
    assert_eq!(grants.len(), 3);
    assert_eq!(
        grants[0].level, "WARN",
        "governance must not be filtered out"
    );
    assert_eq!(grants[1].level, "WARN", "a sweep must not be filtered out");
    assert_eq!(grants[2].level, "INFO", "a payout is routine");
    assert!(
        grants[1]
            .get("identity")
            .is_some_and(|i| i.contains("12000000000")),
        "a sweep record must state what left the vault: {:?}",
        grants[1]
    );
}

#[test]
fn no_grant_record_carries_signature_bytes() {
    // The authoritative copy lives on chain or in the assembled transaction.
    // A second copy in a log invites someone to treat the log as the source
    // of truth, and bloats the field that actually matters.
    let service = SignerService::new(Keypair::new(), View);
    let (result, grants) = capture_grants(|| {
        service.handle(mint_request(vec![1], EPOCH, MESSAGE.to_vec(), TXID, VOUT))
    });
    let sig = result.unwrap().signature;
    let sig_hex = glc_relayer::glc::hex::encode(&sig);

    for g in &grants {
        for (k, v) in &g.fields {
            assert!(
                !v.contains(&sig_hex),
                "field {k} leaked the signature into the audit log"
            );
            assert!(
                !v.contains("canonical-message"),
                "field {k} leaked the canonical message into the audit log"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The other four grant paths
// ---------------------------------------------------------------------------
//
// Mutation testing found these four call sites entirely uncovered: deleting
// the record from the payout, completion, governance or sweep path broke
// nothing, because only `handle` (mint) was exercised. Testing one
// representative path and assuming the rest is the same mistake this project
// found in Phase 7k's auditor.

#[test]
fn granting_a_governance_signature_leaves_a_notable_record() {
    use glc_relayer::p2p::governance_view::{Approval, ApprovalStore, GovernanceView};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    let commitment = [0xAA; 32];
    let mut store = ApprovalStore::new();
    store.stage(Approval {
        action: 3,
        params_commitment: commitment,
        epoch: EPOCH,
        expiry_unix: now_unix() + 3600,
        note: "REHEARSAL".into(),
    });
    std::fs::write(&path, store.to_text()).unwrap();

    let service = SignerService::new(Keypair::new(), View).with_governance_arm(
        GovernanceView::new(path),
        [0x33; 32],
        1,
    );
    let (result, grants) = capture_grants(|| {
        service.handle_governance(GovernanceSignRequest {
            request_id: vec![1],
            epoch: EPOCH,
            action: 3,
            params_commitment: commitment.to_vec(),
            expiry_unix: now_unix() + 60,
        })
    });
    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].get("action"), Some("governance"));
    assert_eq!(
        grants[0].level, "WARN",
        "changing who the federation is must not be filtered out with routine traffic"
    );
    let id = grants[0].get("identity").unwrap();
    assert!(id.contains("3") && id.contains(&EPOCH.to_string()), "{id}");
}

#[tokio::test]
async fn granting_a_sweep_signature_records_what_left_the_vault() {
    use glc_relayer::glc::db::Db;
    use glc_relayer::glc::rpc::PrevTx;
    use glc_relayer::glc::withdrawal_db::ObservedUtxo;
    use glc_relayer::p2p::payout_view::PartialSigner;
    use glc_relayer::p2p::service::pb::SweepSignRequest;
    use glc_relayer::p2p::sweep_view::{SweepApproval, SweepView};
    use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
    use glc_relayer::withdrawal::multisig::Transaction;
    use glc_relayer::withdrawal::sweep::{p2sh_script_pubkey, plan_sweep, SweepDestination};
    use glc_relayer::withdrawal::vault::MultisigVault;

    struct AlwaysSigns {
        redeem: Vec<u8>,
    }
    impl PartialSigner for AlwaysSigns {
        async fn sign_partial(&self, hex: &str, _: &[PrevTx]) -> Result<String, String> {
            let mut tx = Transaction::parse_hex(hex).map_err(|e| e.to_string())?;
            for inp in &mut tx.inputs {
                let mut sig = vec![0x00, 71];
                sig.extend_from_slice(&[0xAB; 71]);
                sig.push(0x4c);
                sig.push(self.redeem.len() as u8);
                sig.extend_from_slice(&self.redeem);
                inp.script_sig = sig;
            }
            Ok(tx.serialize_hex())
        }
    }

    let keys: Vec<[u8; 33]> = (0..3)
        .map(|i| {
            let mut k = [0u8; 33];
            k[0] = 0x02;
            k[32] = i as u8 + 1;
            k
        })
        .collect();
    let vault = MultisigVault::new(2, keys).unwrap();
    let cfg = WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_redeem_script_hex: vault.redeem_script_hex(),
        vault_address: vault.address.clone(),
        change_address: vault.address.clone(),
        fee_rate_per_kb: 10_000,
        dust_threshold_atomic: 5_400,
        vault_min_confirmations: 1,
        confirmation_depth: 2,
        max_inputs_per_payout: 20,
        reservation_timeout_secs: 900,
        discovery_commitment: "finalized".into(),
        poll_interval_ms: 500,
    })
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let mut db = Db::open(&dir.path().join("db.sqlite")).unwrap();
    db.sync_vault_utxos(
        &[ObservedUtxo {
            txid: [0x77; 32],
            vout: 0,
            amount_atomic: 500_000,
            script_pubkey_hex: vault.script_pubkey_hex(),
            confirmations: 10,
        }],
        1,
        1_000,
    )
    .unwrap();

    let dest = [0x22; 20];
    let plan = plan_sweep(
        vault.script_hash160,
        SweepDestination::p2sh(dest, "Qdest".into()),
        &db.available_utxos(1).unwrap(),
        cfg.fee_rate_per_kb,
        cfg.dust_threshold_atomic,
        cfg.max_inputs_per_payout,
        glc_relayer::withdrawal::coin::multisig_input_bytes(
            vault.threshold,
            vault.redeem_script.len(),
        ),
    )
    .unwrap();

    let tx = Transaction {
        version: 1,
        inputs: plan
            .inputs
            .iter()
            .map(|u| glc_relayer::withdrawal::multisig::TxInput {
                prev_txid: glc_relayer::withdrawal::sweep::internal_txid(&u.txid),
                prev_vout: u.vout as u32,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs: vec![glc_relayer::withdrawal::multisig::TxOutput {
            value: plan.swept_atomic,
            script_pubkey: p2sh_script_pubkey(&dest),
        }],
        lock_time: 0,
    };

    let approvals = dir.path().join("sweep-approvals");
    std::fs::write(
        &approvals,
        SweepApproval {
            commitment: plan.commitment(1),
            expiry_unix: now_unix() + 3600,
            note: "REHEARSAL".into(),
        }
        .to_text(),
    )
    .unwrap();

    let view = SweepView::new(
        cfg,
        0,
        AlwaysSigns {
            redeem: vault.redeem_script.clone(),
        },
        approvals,
    )
    .unwrap();
    let service = SignerService::new(Keypair::new(), View).with_sweep_arm(
        view,
        Db::open(&dir.path().join("db.sqlite")).unwrap(),
        1,
    );

    let (result, grants) = common::capture_grants_async(service.handle_sweep(SweepSignRequest {
        request_id: vec![9],
        epoch: EPOCH,
        unsigned_tx_hex: tx.serialize_hex(),
        expiry_unix: now_unix() + 60,
    }))
    .await;

    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].get("action"), Some("sweep"));
    assert_eq!(grants[0].level, "WARN", "a sweep moves the entire vault");
    let id = grants[0].get("identity").unwrap();
    assert!(
        id.contains(&plan.swept_atomic.to_string()),
        "the record must state what left the vault: {id}"
    );
}
