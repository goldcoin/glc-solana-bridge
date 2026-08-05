//! `glc-admin` — the operator utility (Phase 7i-0).
//!
//! Every recovery and governance procedure in the runbooks is invoked from
//! here. Before this existed, `operator_clear_integrity_halt`,
//! `operator_clear_withdrawal_halt` and `reassign_payout_quorum` were
//! implemented, guarded and audited — and reachable **only from tests**. An
//! operator facing an integrity halt had no supported way to act.
//!
//! A runbook step with no executable form is not a procedure, it is a wish.
//! This binary exists so the Phase 7i runbooks can name real commands.
//!
//! # What it deliberately does not do
//!
//! It holds no validator key, no vault key and no admin key. Recovery
//! commands touch only this operator's own database. Governance and sweep
//! commands *stage an approval* for this operator's own signer. Nothing here
//! can move value or change federation policy on its own.
//!
//! # Every mutating command demands a reason
//!
//! `--note` is mandatory and is recorded in the audit trail. An operator
//! action with no recorded reason is indistinguishable from an intrusion six
//! months later.

use std::path::PathBuf;

use glc_bridge_shared::governance::{
    cancel_params, governance_message, rotation_params, tvl_raise_params, ACTION_CANCEL_ROTATION,
    ACTION_PROPOSE_ROTATION, ACTION_PROPOSE_TVL_RAISE,
};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

use glc_relayer::glc::db::{Db, DepositState};
use glc_relayer::glc::hex;
use glc_relayer::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, WithdrawalState,
};
use glc_relayer::ops::preflight::{can_execute, can_propose, cancel_target, enough_approvals};
use glc_relayer::p2p::governance_view::{Approval, ApprovalStore, APPROVAL_TTL_SECONDS};
use glc_relayer::p2p::sweep_view::{SweepApproval, SWEEP_APPROVAL_TTL_SECONDS};
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::sweep::{plan_sweep, SweepDestination, SweepPlan};

use glc_relayer::p2p::collector::{DesignatedSigner, GrpcCollector};
use glc_relayer::p2p::identity::{parse_peers, TlsMaterial, TlsPaths};
use glc_relayer::signer::aggregate::build_ed25519_instruction;
use glc_relayer::solana::instruction as ix;
use glc_relayer::solana::rpc::{
    decode_bridge_config, decode_pending_action, decode_token_metadata, decode_validator_set,
    BridgeConfigSnapshot, PendingActionSnapshot, RealSolanaRpc, SolanaRpc,
};
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::executor::PayoutRpc;
use glc_relayer::withdrawal::multisig::{assemble, PartialSignature, Transaction};
use solana_sdk::signature::{read_keypair_file, Keypair, Signer as _};

const USAGE: &str = r#"glc-admin — operator utility for recovery, governance and vault sweeps

STATUS
  status                --db PATH

RECOVERY (acts on this operator's own database only)
  clear-deposit-halt    --db PATH --id N --to ReadyForSignature|Failed --note TEXT
  clear-withdrawal-halt --db PATH --index N --to Validated|Failed --note TEXT
  reassign-quorum       --db PATH --index N --quorum a,b --note TEXT

GOVERNANCE (stages an approval for THIS operator's signer)
  approve-rotation      --approvals PATH --epoch N --threshold M --validators A,B,C --note TEXT
  approve-tvl-raise     --approvals PATH --epoch N --new-max ATOMIC --note TEXT
  approve-cancel        --approvals PATH --epoch N --pending-action N --pending-eta N --note TEXT
  list-approvals        --approvals PATH
  revoke-approval       --approvals PATH --action N

BOOTSTRAP (once, at launch -- see docs/launch-checklist.md)
  initialize            --validators A,B,C --threshold M --timelock-secs N
                        --max-supply ATOMIC --min-deposit N --min-withdrawal N --note TEXT
  create-wrapped-mint   --mint-keypair PATH --note TEXT
  token-metadata        [--uri URL] --note TEXT     (create if absent, then verify)
                        default uri: https://goldcoinproject.org/assets/wglc.json
  update-token-metadata [--name TEXT] [--symbol TEXT] [--uri URL] --note TEXT
                        changes what wallets display; omitted values keep
                        their current on-chain value
  show-config

ADMIN HANDOVER (custody #5)
  transfer-admin        --new-admin PUBKEY --note TEXT      (signed by the OUTGOING admin)
  accept-admin          --note TEXT                          (signed by the INCOMING admin)

ON-CHAIN ADMIN (interim single admin key -- see docs/custody.md #7)
  pause                 --note TEXT
  unpause               --note TEXT
  lower-tvl-cap         --new-max ATOMIC --note TEXT

ON-CHAIN GOVERNANCE (collects M signatures from the federation, then submits)
  show-pending
  submit-rotation       --threshold M --validators A,B,C --note TEXT
  submit-tvl-raise      --new-max ATOMIC --note TEXT
  submit-cancel         --note TEXT
  execute-rotation      --note TEXT
  execute-tvl-raise     --note TEXT

VAULT SWEEP (ADR-0014 section 8.7 compromise response)
  sweep-plan            --db PATH --dest-hash160 HEX --dest-address ADDR
  sweep-approve         --db PATH --sweep-approvals PATH --dest-hash160 HEX
                        --dest-address ADDR --commitment HEX --note TEXT
  sweep-revoke          --sweep-approvals PATH
  sweep-execute         --db PATH --dest-hash160 HEX --dest-address ADDR --note TEXT

Staging an approval does NOT perform the action. It tells this operator's own
signer that it may sign that one exact proposal. The action happens only once
M operators have each independently done the same.

Vault configuration is read from the environment, exactly as the relayer and
signer read it (GLC_VAULT_REDEEM_SCRIPT_HEX, GLC_VAULT_ADDRESS, ...), so a
sweep is planned against the same validated vault the pipeline uses."#;

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn require(args: &[String], name: &str) -> String {
    match arg(args, name) {
        Some(v) => v,
        None => {
            eprintln!("error: {name} is required\n");
            usage()
        }
    }
}

fn require_note(args: &[String]) -> String {
    let note = require(args, "--note");
    if note.trim().is_empty() {
        eprintln!("error: --note must not be empty — every operator action is audited");
        std::process::exit(2);
    }
    note
}

fn open_db(args: &[String]) -> anyhow::Result<Db> {
    Ok(Db::open(&PathBuf::from(require(args, "--db")))?)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn commitment_of(params: &[u8]) -> [u8; 32] {
    Sha256::digest(params).into()
}

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is not set"))
}

/// The same validated vault the relayer and signer load, from the same
/// environment. Deliberately not a separate set of flags: a sweep planned
/// against a vault the pipeline does not agree with is a sweep of the wrong
/// vault.
fn withdrawal_config_from_env() -> anyhow::Result<WithdrawalConfig> {
    let raw = RawWithdrawalConfig {
        vault_redeem_script_hex: env_required("GLC_VAULT_REDEEM_SCRIPT_HEX")?,
        vault_address: env_required("GLC_VAULT_ADDRESS")?,
        change_address: env_required("GLC_VAULT_CHANGE_ADDRESS")?,
        fee_rate_per_kb: env_required("GLC_PAYOUT_FEE_RATE_PER_KB")?.parse()?,
        dust_threshold_atomic: env_required("GLC_PAYOUT_DUST_THRESHOLD_ATOMIC")?.parse()?,
        vault_min_confirmations: env_required("GLC_VAULT_MIN_CONFIRMATIONS")?.parse()?,
        confirmation_depth: env_required("GLC_WITHDRAWAL_CONFIRMATION_DEPTH")?.parse()?,
        max_inputs_per_payout: env_required("GLC_PAYOUT_MAX_INPUTS")?.parse()?,
        reservation_timeout_secs: env_required("GLC_PAYOUT_RESERVATION_TIMEOUT_SECS")?.parse()?,
        discovery_commitment: env_required("GLC_WITHDRAWAL_DISCOVERY_COMMITMENT")?,
        poll_interval_ms: 5_000,
    };
    WithdrawalConfig::validate(raw)
        .map_err(|e| anyhow::anyhow!("invalid withdrawal configuration: {e}"))
}

fn protocol_version_from_env() -> anyhow::Result<u8> {
    Ok(env_required("GLC_PROTOCOL_VERSION")?.parse()?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1).map(|s| s.as_str()) else {
        usage()
    };

    match cmd {
        "status" => status(&args),
        "clear-deposit-halt" => clear_deposit_halt(&args),
        "clear-withdrawal-halt" => clear_withdrawal_halt(&args),
        "reassign-quorum" => reassign_quorum(&args),
        "approve-rotation" => approve_rotation(&args),
        "approve-tvl-raise" => approve_tvl_raise(&args),
        "approve-cancel" => approve_cancel(&args),
        "list-approvals" => list_approvals(&args),
        "revoke-approval" => revoke_approval(&args),
        "sweep-plan" => sweep_plan(&args),
        "sweep-approve" => sweep_approve(&args),
        "sweep-revoke" => sweep_revoke(&args),
        "sweep-execute" => sweep_execute(&args).await,
        "pause" => set_paused(&args, true).await,
        "unpause" => set_paused(&args, false).await,
        "lower-tvl-cap" => lower_tvl_cap(&args).await,
        "show-pending" => show_pending(&args).await,
        "show-config" => show_config(&args).await,
        "initialize" => initialize(&args).await,
        "create-wrapped-mint" => create_wrapped_mint(&args).await,
        "token-metadata" => token_metadata(&args).await,
        "update-token-metadata" => update_token_metadata(&args).await,
        "transfer-admin" => transfer_admin(&args).await,
        "accept-admin" => accept_admin(&args).await,
        "submit-rotation" => submit_rotation(&args).await,
        "submit-tvl-raise" => submit_tvl_raise(&args).await,
        "submit-cancel" => submit_cancel(&args).await,
        "execute-rotation" => execute_queued(&args, false).await,
        "execute-tvl-raise" => execute_queued(&args, true).await,
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("error: unknown command {other:?}\n");
            usage()
        }
    }
}

// ------------------------------------------------------------------ status

/// What an operator wants first in an incident: what is stuck, and why.
fn status(args: &[String]) -> anyhow::Result<()> {
    let db = open_db(args)?;

    println!("deposits by state:");
    for (state, n) in db.deposit_counts_by_state()? {
        println!("  {state:<20} {n}");
    }
    println!("\nwithdrawals by state:");
    for (state, n) in db.withdrawal_counts_by_state()? {
        println!("  {state:<20} {n}");
    }
    let (utxo_count, utxo_total) = db.vault_utxo_stats()?;
    println!("\nvault: {utxo_count} available outputs, {utxo_total} atomic units");

    let halted = db.candidates_by_state(DepositState::IntegrityHalted)?;
    if !halted.is_empty() {
        println!("\nHALTED DEPOSITS — each needs an explicit operator decision:");
        for d in &halted {
            println!(
                "  id={} txid={} vout={} amount={}\n    reason: {}",
                d.id,
                d.txid_hex,
                d.vout,
                d.amount_atomic,
                d.failure_reason.as_deref().unwrap_or("(none recorded)")
            );
        }
    }
    let halted_w = db.withdrawals_by_state(WithdrawalState::IntegrityHalted)?;
    if !halted_w.is_empty() {
        println!("\nHALTED WITHDRAWALS:");
        for w in &halted_w {
            println!(
                "  index={} amount={}\n    reason: {}",
                w.withdrawal_index,
                w.amount_atomic,
                w.failure_reason.as_deref().unwrap_or("(none recorded)")
            );
        }
    }
    if halted.is_empty() && halted_w.is_empty() {
        println!("\nno integrity halts");
    }
    Ok(())
}

// ---------------------------------------------------------------- recovery

fn clear_deposit_halt(args: &[String]) -> anyhow::Result<()> {
    let mut db = open_db(args)?;
    let id: i64 = require(args, "--id").parse()?;
    let to = DepositState::parse(&require(args, "--to"))?;
    let note = require_note(args);

    // Show the record before altering it. An operator acting under pressure
    // deserves to see what they are about to change.
    let before = db
        .get_by_id(id)?
        .ok_or_else(|| anyhow::anyhow!("no deposit with id {id}"))?;
    println!(
        "deposit {id}: {} -> {}\n  txid={} vout={} amount={}\n  halt reason: {}",
        before.state.as_str(),
        to.as_str(),
        before.txid_hex,
        before.vout,
        before.amount_atomic,
        before.failure_reason.as_deref().unwrap_or("(none)")
    );

    db.operator_clear_integrity_halt(id, to, &note, now_unix())?;
    println!("cleared. The halt record is preserved; the recovery was appended beside it.");
    Ok(())
}

fn clear_withdrawal_halt(args: &[String]) -> anyhow::Result<()> {
    let mut db = open_db(args)?;
    let index: i64 = require(args, "--index").parse()?;
    let to = WithdrawalState::parse(&require(args, "--to"))?;
    let note = require_note(args);

    let before = db
        .get_withdrawal(index)?
        .ok_or_else(|| anyhow::anyhow!("no withdrawal with index {index}"))?;
    println!(
        "withdrawal {index}: {} -> {}\n  amount={}\n  halt reason: {}",
        before.state.as_str(),
        to.as_str(),
        before.amount_atomic,
        before.failure_reason.as_deref().unwrap_or("(none)")
    );

    db.operator_clear_withdrawal_halt(index, to, &note, now_unix())?;
    println!("cleared. The halt record is preserved.");
    Ok(())
}

/// Re-designates the signing quorum for a payout whose designated signers
/// cannot sign (ADR-0015).
///
/// The new quorum is given explicitly rather than derived: the operator is
/// the one who knows *which* signer is unavailable, and an automatic
/// substitution is exactly what ADR-0015 forbids.
fn reassign_quorum(args: &[String]) -> anyhow::Result<()> {
    let cfg = withdrawal_config_from_env()?;
    let mut db = open_db(args)?;
    let index: i64 = require(args, "--index").parse()?;
    let note = require_note(args);
    let new_quorum: Vec<u8> = require(args, "--quorum")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u8>().map_err(|e| anyhow::anyhow!("{s:?}: {e}")))
        .collect::<anyhow::Result<_>>()?;
    cfg.vault
        .validate_quorum(&new_quorum)
        .map_err(|e| anyhow::anyhow!("the proposed quorum is not valid for this vault: {e}"))?;

    let payout = db
        .get_payout(index)?
        .ok_or_else(|| anyhow::anyhow!("no payout for withdrawal {index}"))?;
    if payout.signed_tx_hex.is_some() {
        // A signed payout has a txid that may already be in a mempool.
        // Re-designating would produce a second, conflicting transaction.
        anyhow::bail!(
            "withdrawal {index} is already signed (txid {}) — rebroadcast it rather than \
             reassigning; reassignment changes the txid",
            payout.txid_hex.as_deref().unwrap_or("unknown")
        );
    }
    let w = db
        .get_withdrawal(index)?
        .ok_or_else(|| anyhow::anyhow!("no withdrawal with index {index}"))?;
    let inputs = db.payout_inputs(index)?;
    let attempt = payout.quorum_attempt + 1;

    println!(
        "withdrawal {index}: attempt {} -> {attempt}\n  quorum {:?} -> {new_quorum:?}\n  \
         payout {} fee {} change {}",
        payout.quorum_attempt,
        payout.quorum_indices,
        payout.payout_atomic,
        payout.fee_atomic,
        payout.change_atomic
    );
    println!(
        "\nNOTE: reassignment changes the payout txid (ADR-0015). Every operator must reassign\n\
         to the same attempt and the same quorum before signatures can be collected."
    );

    // The intent is rebuilt exactly as the executor builds it: same inputs,
    // same amounts, same destination — only the quorum and attempt change.
    // The unsigned transaction is unchanged, because the quorum affects the
    // scriptSig, not the outputs.
    let change_hash160 = if payout.change_atomic > 0 {
        cfg.change_hash160
    } else {
        [0u8; 20]
    };
    let intent = canonical_payout_intent(
        w.protocol_version,
        index,
        &cfg.vault.script_hash160,
        &w.glc_address_hash160,
        payout.payout_atomic,
        payout.fee_atomic,
        payout.change_atomic,
        &change_hash160,
        attempt,
        &new_quorum,
        &inputs,
    );
    let next = db.reassign_payout_quorum(
        index,
        &new_quorum,
        &payout_commitment(&intent),
        &intent,
        &payout.unsigned_tx_hex,
        &note,
        now_unix(),
    )?;
    println!("reassigned to attempt {next}");
    Ok(())
}

// -------------------------------------------------------------- governance

fn stage(args: &[String], approval: Approval) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--approvals"));
    let mut store = ApprovalStore::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    store.stage(approval.clone());
    std::fs::write(&path, store.to_text())?;

    println!(
        "staged approval for action {} under epoch {}\n  commitment: {}\n  expires:    {} (in {} hours)\n  note:       {}",
        approval.action,
        approval.epoch,
        hex::encode(&approval.params_commitment),
        approval.expiry_unix,
        APPROVAL_TTL_SECONDS / 3600,
        approval.note
    );
    println!(
        "\nThis authorises THIS operator's signer to sign that one exact proposal. The action\n\
         takes effect only once M operators have each done the same, and — for rotations and\n\
         raises — the governance timelock has elapsed."
    );
    Ok(())
}

fn approve_rotation(args: &[String]) -> anyhow::Result<()> {
    let epoch: u64 = require(args, "--epoch").parse()?;
    let threshold: u8 = require(args, "--threshold").parse()?;
    let validators: Vec<[u8; 32]> = require(args, "--validators")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Pubkey>()
                .map(|p| p.to_bytes())
                .map_err(|e| anyhow::anyhow!("{s:?} is not a pubkey: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;
    if threshold == 0 || usize::from(threshold) > validators.len() {
        anyhow::bail!(
            "threshold {threshold} is impossible for {} validators",
            validators.len()
        );
    }
    // Order is significant — it fixes each validator's bitmask index — so it
    // is echoed back for the operator to check against the other operators'.
    println!("rotation: threshold {threshold} of {}", validators.len());
    for (i, v) in validators.iter().enumerate() {
        println!("  [{i}] {}", Pubkey::from(*v));
    }
    stage(
        args,
        Approval {
            action: ACTION_PROPOSE_ROTATION,
            params_commitment: commitment_of(&rotation_params(threshold, &validators)),
            epoch,
            expiry_unix: now_unix() + APPROVAL_TTL_SECONDS,
            note: require_note(args),
        },
    )
}

fn approve_tvl_raise(args: &[String]) -> anyhow::Result<()> {
    let epoch: u64 = require(args, "--epoch").parse()?;
    let new_max: u64 = require(args, "--new-max").parse()?;
    if new_max == 0 {
        anyhow::bail!("a wrapped-supply cap of zero is never valid");
    }
    println!("TVL raise: new ceiling {new_max} atomic units");
    stage(
        args,
        Approval {
            action: ACTION_PROPOSE_TVL_RAISE,
            params_commitment: commitment_of(&tvl_raise_params(new_max)),
            epoch,
            expiry_unix: now_unix() + APPROVAL_TTL_SECONDS,
            note: require_note(args),
        },
    )
}

fn approve_cancel(args: &[String]) -> anyhow::Result<()> {
    let epoch: u64 = require(args, "--epoch").parse()?;
    let pending_action: u8 = require(args, "--pending-action").parse()?;
    let pending_eta: i64 = require(args, "--pending-eta").parse()?;
    println!("cancel: pending action {pending_action}, eta {pending_eta}");
    stage(
        args,
        Approval {
            action: ACTION_CANCEL_ROTATION,
            params_commitment: commitment_of(&cancel_params(pending_action, pending_eta)),
            epoch,
            expiry_unix: now_unix() + APPROVAL_TTL_SECONDS,
            note: require_note(args),
        },
    )
}

const GOVERNANCE_ACTIONS: [u8; 3] = [
    ACTION_PROPOSE_ROTATION,
    ACTION_CANCEL_ROTATION,
    ACTION_PROPOSE_TVL_RAISE,
];

fn list_approvals(args: &[String]) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--approvals"));
    let store = ApprovalStore::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    if store.is_empty() {
        println!("no approvals staged — this signer will refuse every governance request");
        return Ok(());
    }
    let now = now_unix();
    for action in GOVERNANCE_ACTIONS {
        if let Some(a) = store.get(action) {
            println!(
                "action {} epoch {} {} commitment {}\n  note: {}",
                a.action,
                a.epoch,
                if now > a.expiry_unix {
                    "EXPIRED"
                } else {
                    "valid"
                },
                hex::encode(&a.params_commitment),
                a.note
            );
        }
    }
    Ok(())
}

fn revoke_approval(args: &[String]) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--approvals"));
    let action: u8 = require(args, "--action").parse()?;
    let store = ApprovalStore::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut kept = ApprovalStore::new();
    for a in GOVERNANCE_ACTIONS {
        if a != action {
            if let Some(existing) = store.get(a) {
                kept.stage(existing.clone());
            }
        }
    }
    std::fs::write(&path, kept.to_text())?;
    // The signer re-reads the file on every request, which is exactly so an
    // operator can withdraw consent mid-incident.
    println!("revoked approval for action {action} — effective immediately, no restart needed");
    Ok(())
}

// ------------------------------------------------------------- vault sweep

/// Builds the sweep an operator is about to approve, from this operator's
/// own UTXO rows.
///
/// Every operator runs this independently. If their commitments differ they
/// are looking at different vault contents and must reconcile *before* any
/// of them approves — which is far better than discovering it when the
/// signatures fail to combine.
fn build_plan(args: &[String], cfg: &WithdrawalConfig, db: &Db) -> anyhow::Result<SweepPlan> {
    let dest_hash160 = hex::decode_exact::<20>(&require(args, "--dest-hash160"))
        .map_err(|e| anyhow::anyhow!("--dest-hash160 is not 20 hex bytes: {e}"))?;
    let dest_address = require(args, "--dest-address");

    let utxos = db.available_utxos(cfg.vault_min_confirmations)?;
    let (all_count, all_total) = db.vault_utxo_stats()?;
    if utxos.len() as u64 != all_count {
        // `available_utxos` excludes reserved outputs. Saying so matters:
        // the sweep would be partial, and an operator who believed it was
        // total would leave funds under the key they meant to abandon.
        println!(
            "WARNING: {} of {all_count} vault outputs are reserved for in-flight payouts and\n\
             will NOT be swept. Release or complete them first for a total sweep.",
            all_count.saturating_sub(utxos.len() as u64)
        );
    }

    let plan = plan_sweep(
        cfg.vault.script_hash160,
        SweepDestination::p2sh(dest_hash160, dest_address),
        &utxos,
        cfg.fee_rate_per_kb,
        cfg.dust_threshold_atomic,
        cfg.max_inputs_per_payout,
    )
    .map_err(|e| anyhow::anyhow!("cannot plan this sweep: {e}"))?;

    println!(
        "sweep of vault {}\n  from:   {} ({} outputs, {} atomic total in vault)\n  to:     {} ({})\n  \
         inputs: {}\n  fee:    {}\n  swept:  {}",
        hex::encode(&cfg.vault.script_hash160),
        cfg.vault.address,
        all_count,
        all_total,
        plan.dest_address,
        hex::encode(&plan.dest_hash160),
        plan.inputs.len(),
        plan.fee_atomic,
        plan.swept_atomic
    );
    for u in &plan.inputs {
        println!("    {}:{} {}", u.txid_hex, u.vout, u.amount_atomic);
    }
    Ok(plan)
}

fn sweep_plan(args: &[String]) -> anyhow::Result<()> {
    let cfg = withdrawal_config_from_env()?;
    let protocol_version = protocol_version_from_env()?;
    let db = open_db(args)?;
    let plan = build_plan(args, &cfg, &db)?;
    println!(
        "\ncommitment: {}\n\nCompare this with every other operator BEFORE approving. Differing\n\
         commitments mean differing views of the vault, not a tooling problem.",
        hex::encode(&plan.commitment(protocol_version))
    );
    Ok(())
}

/// Stages a sweep approval — after re-deriving the plan locally and refusing
/// unless it matches the commitment the operator typed.
///
/// `--commitment` is required and is **checked, not trusted**: it is how an
/// operator states what they believe they are approving, and the check is
/// what catches "the number on my screen is not the number on yours".
fn sweep_approve(args: &[String]) -> anyhow::Result<()> {
    let cfg = withdrawal_config_from_env()?;
    let protocol_version = protocol_version_from_env()?;
    let db = open_db(args)?;
    let note = require_note(args);
    let claimed = hex::decode_exact::<32>(&require(args, "--commitment"))
        .map_err(|e| anyhow::anyhow!("--commitment is not 32 hex bytes: {e}"))?;

    let plan = build_plan(args, &cfg, &db)?;
    let actual = plan.commitment(protocol_version);
    if actual != claimed {
        anyhow::bail!(
            "REFUSING TO STAGE: the sweep this operator can build commits to\n  {}\nbut the \
             approval names\n  {}\nThese are different sweeps. Reconcile the vault view with the \
             other operators before approving.",
            hex::encode(&actual),
            hex::encode(&claimed)
        );
    }

    let path = PathBuf::from(require(args, "--sweep-approvals"));
    let approval = SweepApproval {
        commitment: actual,
        expiry_unix: now_unix() + SWEEP_APPROVAL_TTL_SECONDS,
        note,
    };
    std::fs::write(&path, approval.to_text())?;
    println!(
        "\nSTAGED. This signer will now contribute to that ONE sweep, until {} ({} hours).\n\
         It moves the entire available vault. Revoke with `sweep-revoke` if anything changes.",
        approval.expiry_unix,
        SWEEP_APPROVAL_TTL_SECONDS / 3600
    );
    Ok(())
}

fn sweep_revoke(args: &[String]) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--sweep-approvals"));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no sweep approval was staged");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    println!("sweep approval revoked — effective immediately, no restart needed");
    Ok(())
}

// ------------------------------------------------------- on-chain plumbing

/// Everything a Solana-touching command needs, read from the same
/// environment the relayer uses.
struct Chain {
    rpc: RealSolanaRpc,
    program_id: solana_sdk::pubkey::Pubkey,
    /// Carried so a confirmation failure can report which commitment was
    /// actually asked for, rather than leaving an operator to infer it.
    commitment: solana_sdk::commitment_config::CommitmentLevel,
}

fn chain_from_env() -> anyhow::Result<Chain> {
    let commitment =
        glc_relayer::solana::config::parse_commitment(&env_required("GLC_SOLANA_COMMITMENT")?)
            .map_err(|e| anyhow::anyhow!("invalid GLC_SOLANA_COMMITMENT: {e}"))?;
    let program_id = solana_sdk::pubkey::Pubkey::from(
        hex::decode_exact::<32>(&env_required("GLC_PROGRAM_ID_HEX")?)
            .map_err(|e| anyhow::anyhow!("GLC_PROGRAM_ID_HEX is not 32 hex bytes: {e}"))?,
    );
    Ok(Chain {
        rpc: RealSolanaRpc::new(env_required("GLC_SOLANA_RPC_URL")?, commitment),
        program_id,
        commitment,
    })
}

fn keypair_at(var: &str) -> anyhow::Result<Keypair> {
    let path = env_required(var)?;
    read_keypair_file(&path)
        .map_err(|e| anyhow::anyhow!("could not read the keypair at {path} ({var}): {e}"))
}

/// Signs, sends, and **waits for** one transaction (ADR-0030).
///
/// Returns only once the cluster has been observed to include the
/// transaction at the configured commitment. Submission is not inclusion:
/// before this waited, every command here printed a signature and exited `0`
/// whether or not the transaction ever landed — which made `glc-admin pause`
/// indistinguishable from a pause that silently never happened.
async fn submit(
    chain: &Chain,
    instructions: &[solana_sdk::instruction::Instruction],
    payer: &Keypair,
    what: &str,
    note: &str,
) -> anyhow::Result<()> {
    submit_signed(chain, instructions, payer, &[payer], what, note).await
}

/// As [`submit`], for the one instruction that needs a second signer (the
/// mint account signs its own creation).
async fn submit_signed(
    chain: &Chain,
    instructions: &[solana_sdk::instruction::Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
    what: &str,
    note: &str,
) -> anyhow::Result<()> {
    let blockhash = chain.rpc.get_latest_blockhash().await?;
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        signers,
        blockhash,
    );
    let sig = chain.rpc.send_transaction(&tx).await?;
    // Logged at warn: every command that reaches here is ATTEMPTING to change
    // the bridge's behaviour on-chain, and the note is the audit record of
    // why. It is deliberately logged before the outcome is known — an action
    // that was attempted and then failed still belongs in the trail.
    tracing::warn!(action = what, signature = %sig, %note, "SUBMITTED an on-chain operator action");
    println!("{what} submitted (awaiting confirmation)\n  signature: {sig}\n  note: {note}");

    confirm(chain, &sig, &blockhash, what).await?;
    println!("{what} CONFIRMED at {:?} commitment", chain.commitment);
    Ok(())
}

/// Waits for `sig`, turning any failure into an operator-actionable error.
///
/// Every error names the signature, the action, the commitment that was
/// required, and the reason — an operator reading it in an incident should
/// not have to reconstruct which of those four it was.
async fn confirm(
    chain: &Chain,
    sig: &solana_sdk::signature::Signature,
    blockhash: &solana_sdk::hash::Hash,
    what: &str,
) -> anyhow::Result<()> {
    match glc_relayer::solana::confirm::confirm_transaction(
        &chain.rpc,
        sig,
        blockhash,
        glc_relayer::solana::confirm::ConfirmPolicy::default(),
    )
    .await
    {
        Ok(()) => {
            tracing::warn!(
                action = what,
                signature = %sig,
                commitment = ?chain.commitment,
                "CONFIRMED an on-chain operator action"
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                action = what,
                signature = %sig,
                commitment = ?chain.commitment,
                error = %e,
                "an on-chain operator action did NOT take effect"
            );
            Err(anyhow::anyhow!(
                "{what} did NOT take effect.\n  signature:  {sig}\n  commitment: {:?}\n  \
                 reason:     {e}\n\nThe bridge is in whatever state it was before this command. \
                 Verify with `glc-admin show-config` before retrying.",
                chain.commitment
            ))
        }
    }
}

/// Reads an expected on-chain effect back after confirmation.
///
/// Confirmation proves the transaction executed; it does not prove the
/// operator got the state they meant. Where a command has a cheap read-back,
/// this asserts it — the launch checklist's "read every value back" made
/// executable rather than advisory.
async fn verify_postcondition(
    what: &str,
    description: &str,
    observed: anyhow::Result<bool>,
) -> anyhow::Result<()> {
    match observed {
        Ok(true) => {
            println!("  verified: {description}");
            Ok(())
        }
        Ok(false) => Err(anyhow::anyhow!(
            "{what} confirmed on chain, but the expected result was NOT observed: {description}. \
             This is a contradiction — the transaction succeeded yet the state does not reflect \
             it. Do not retry blindly; inspect with `glc-admin show-config`."
        )),
        Err(e) => Err(anyhow::anyhow!(
            "{what} confirmed on chain, but its result could not be read back ({description}): \
             {e}. The action most likely took effect; confirm with `glc-admin show-config` \
             before retrying."
        )),
    }
}

/// The federation as this operator's node currently sees it.
async fn validator_set(
    chain: &Chain,
) -> anyhow::Result<glc_relayer::solana::rpc::ValidatorSetSnapshot> {
    let (pda, _) = ix::validator_set_pda(&chain.program_id);
    let account = chain
        .rpc
        .get_account(&pda)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the validator set account does not exist at {pda}"))?;
    Ok(decode_validator_set(&account.data)?)
}

async fn pending_action(chain: &Chain) -> anyhow::Result<Option<PendingActionSnapshot>> {
    let (pda, _) = ix::governance_action_pda(&chain.program_id);
    match chain.rpc.get_account(&pda).await? {
        // Anchor closes the account on execute/cancel, so an existing but
        // empty account means "nothing pending", not "corrupt".
        Some(a) if !a.data.is_empty() => Ok(Some(decode_pending_action(&a.data)?)),
        _ => Ok(None),
    }
}

fn collector_from_env() -> anyhow::Result<GrpcCollector> {
    let peers = parse_peers(&env_required("GLC_FEDERATION_PEERS")?, None)?;
    if std::env::var("GLC_FEDERATION_TLS").as_deref() == Ok("off") {
        eprintln!(
            "WARNING: GLC_FEDERATION_TLS=off — federation traffic is UNAUTHENTICATED at the \
             transport layer; acceptable only for loopback or regtest"
        );
        return Ok(GrpcCollector::insecure_without_tls(peers));
    }
    let tls = TlsMaterial::load(&TlsPaths {
        ca: PathBuf::from(env_required("GLC_FEDERATION_CA_CERT_PATH")?),
        cert: PathBuf::from(env_required("GLC_RELAYER_TLS_CERT_PATH")?),
        key: PathBuf::from(env_required("GLC_RELAYER_TLS_KEY_PATH")?),
    })?;
    Ok(GrpcCollector::new(
        peers,
        tls,
        env_required("GLC_FEDERATION_TLS_DOMAIN")?,
    ))
}

// ------------------------------------------------------------ admin actions

/// `pause` / `unpause`.
///
/// # Custody note (docs/custody.md #7, OPEN)
///
/// This is gated by a **single interim admin key**, not by a threshold. One
/// key holder can pause the bridge, and one key holder can unpause it —
/// which also means losing that key removes the circuit breaker entirely.
/// Whether pause should stay single-key and what quorum should unpause is a
/// launch-time governance decision that has not been made; this command
/// implements what the program actually enforces today and says so rather
/// than implying a threshold exists.
async fn set_paused(args: &[String], paused: bool) -> anyhow::Result<()> {
    let note = require_note(args);
    let chain = chain_from_env()?;
    let admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    // The program rejects a no-op, so an operator who issues this blindly
    // gets an obscure error. Read the state and say so plainly instead.
    println!(
        "{} the bridge as admin {}\n  program: {}",
        if paused { "PAUSING" } else { "UNPAUSING" },
        admin.pubkey(),
        chain.program_id
    );
    if !paused {
        println!(
            "\nNOTE: unpausing resumes minting and payouts. Confirm the condition that caused\n\
             the pause is actually resolved — the bridge does not re-check it for you."
        );
    }

    let what = if paused { "pause" } else { "unpause" };
    let instruction = ix::set_paused_instruction(&chain.program_id, &admin.pubkey(), paused);
    submit(&chain, &[instruction], &admin, what, &note).await?;

    // The circuit breaker is the one setting an operator most needs to be
    // true rather than merely submitted (runbooks §3 has them pause and then
    // act on that belief), so it is read back rather than assumed.
    verify_postcondition(
        what,
        &format!(
            "the bridge is now {}",
            if paused { "PAUSED" } else { "LIVE" }
        ),
        bridge_config(&chain).await.map(|c| c.paused == paused),
    )
    .await
}

/// `lower-tvl-cap` — admin-only, immediate, and only downward (ADR-0014
/// §11.1). Raising the cap needs `submit-tvl-raise` and a timelock.
async fn lower_tvl_cap(args: &[String]) -> anyhow::Result<()> {
    let new_max: u64 = require(args, "--new-max").parse()?;
    let note = require_note(args);
    if new_max == 0 {
        anyhow::bail!("a wrapped-supply cap of zero is never valid; the program refuses it");
    }
    let chain = chain_from_env()?;
    let admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;
    println!(
        "LOWERING the wrapped-supply cap to {new_max} atomic units\n  \
         This takes effect immediately and cannot be undone without a threshold-approved,\n  \
         timelocked raise (`submit-tvl-raise`)."
    );
    let instruction = ix::lower_supply_cap_instruction(&chain.program_id, &admin.pubkey(), new_max);
    submit(&chain, &[instruction], &admin, "lower-tvl-cap", &note).await?;

    verify_postcondition(
        "lower-tvl-cap",
        &format!("the wrapped-supply cap is now {new_max} atomic"),
        bridge_config(&chain)
            .await
            .map(|c| c.max_wrapped_supply == new_max),
    )
    .await
}

// ------------------------------------------------------- governance actions

async fn show_pending(_args: &[String]) -> anyhow::Result<()> {
    let chain = chain_from_env()?;
    let Some(p) = pending_action(&chain).await? else {
        println!("no governance action is pending");
        return Ok(());
    };
    let now = now_unix();
    println!(
        "pending governance action\n  action:   {} ({})\n  epoch:    {}\n  eta:      {} ({})",
        p.action,
        match p.action {
            ACTION_PROPOSE_ROTATION => "validator rotation",
            ACTION_PROPOSE_TVL_RAISE => "wrapped-supply cap raise",
            _ => "unrecognised",
        },
        p.proposed_under_epoch,
        p.eta,
        if now >= p.eta {
            "timelock elapsed — executable now".to_string()
        } else {
            format!("{} seconds remaining", p.eta - now)
        }
    );
    if p.action == ACTION_PROPOSE_ROTATION {
        println!("  threshold: {} of {}", p.threshold, p.validators.len());
        for (i, v) in p.validators.iter().enumerate() {
            println!("    [{i}] {v}");
        }
    }
    if p.action == ACTION_PROPOSE_TVL_RAISE {
        println!("  new ceiling: {}", p.proposed_max_wrapped_supply);
    }
    Ok(())
}

/// Collects M governance signatures over `message` and returns the ed25519
/// verification instruction the program will read.
///
/// Refusals here are **ordinary**: a validator whose operator has not staged
/// this exact proposal is behaving as designed (ADR-0021 §4). They are
/// reported so the operator can see who still needs to approve.
async fn collect_governance(
    chain: &Chain,
    action: u8,
    params: &[u8],
) -> anyhow::Result<solana_sdk::instruction::Instruction> {
    let protocol_version = protocol_version_from_env()?;
    let set = validator_set(chain).await?;
    let commitment = commitment_of(params);
    let message = governance_message(
        protocol_version,
        &chain.program_id.to_bytes(),
        set.epoch,
        action,
        &commitment,
    );

    println!(
        "collecting signatures for action {action} under epoch {}\n  commitment: {}\n  need {} of {} validators",
        set.epoch,
        hex::encode(&commitment),
        set.threshold,
        set.validators.len()
    );

    let round = collector_from_env()?
        .collect_governance_signatures(set.epoch, action, &commitment, &message)
        .await;

    for (peer, why) in &round.refused {
        println!("  not approved by {peer}: {why}");
    }
    for (peer, why) in &round.unavailable {
        println!("  unreachable {peer}: {why}");
    }
    let have = round.unique_signers();
    println!("  collected {have} of {} required", set.threshold);
    enough_approvals(have, set.threshold).map_err(|e| {
        anyhow::anyhow!(
            "{e}. Each remaining operator must run the matching `glc-admin approve-*` command."
        )
    })?;
    Ok(build_ed25519_instruction(&round.signatures, &message))
}

async fn submit_rotation(args: &[String]) -> anyhow::Result<()> {
    let threshold: u8 = require(args, "--threshold").parse()?;
    let note = require_note(args);
    let validators: Vec<solana_sdk::pubkey::Pubkey> = require(args, "--validators")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow::anyhow!("{s:?} is not a pubkey: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;
    if threshold == 0 || usize::from(threshold) > validators.len() {
        anyhow::bail!(
            "threshold {threshold} is impossible for {} validators",
            validators.len()
        );
    }
    let chain = chain_from_env()?;
    can_propose(pending_action(&chain).await?.as_ref())
        .map_err(|e| anyhow::anyhow!("{e} (`glc-admin show-pending`)"))?;

    let raw: Vec<[u8; 32]> = validators.iter().map(|v| v.to_bytes()).collect();
    let ed25519 = collect_governance(
        &chain,
        ACTION_PROPOSE_ROTATION,
        &rotation_params(threshold, &raw),
    )
    .await?;

    let payer = keypair_at("GLC_SOLANA_SUBMITTER_KEYPAIR_PATH")?;
    let propose = ix::propose_rotation_instruction(
        &chain.program_id,
        &payer.pubkey(),
        &validators,
        threshold,
    );
    submit(
        &chain,
        &[ed25519, propose],
        &payer,
        "propose-rotation",
        &note,
    )
    .await?;
    verify_postcondition(
        "propose-rotation",
        "the rotation is queued on chain behind the timelock",
        pending_action(&chain).await.map(|p| p.is_some()),
    )
    .await?;
    println!(
        "\nThe rotation is QUEUED behind the governance timelock. Run `glc-admin show-pending`\n\
         for its eta, then `glc-admin execute-rotation` once it has elapsed."
    );
    Ok(())
}

async fn submit_tvl_raise(args: &[String]) -> anyhow::Result<()> {
    let new_max: u64 = require(args, "--new-max").parse()?;
    let note = require_note(args);
    if new_max == 0 {
        anyhow::bail!("a wrapped-supply cap of zero is never valid");
    }
    let chain = chain_from_env()?;
    can_propose(pending_action(&chain).await?.as_ref())
        .map_err(|e| anyhow::anyhow!("{e} (`glc-admin show-pending`)"))?;
    let ed25519 =
        collect_governance(&chain, ACTION_PROPOSE_TVL_RAISE, &tvl_raise_params(new_max)).await?;

    let payer = keypair_at("GLC_SOLANA_SUBMITTER_KEYPAIR_PATH")?;
    let propose = ix::propose_cap_raise_instruction(&chain.program_id, &payer.pubkey(), new_max);
    submit(
        &chain,
        &[ed25519, propose],
        &payer,
        "propose-tvl-raise",
        &note,
    )
    .await?;
    verify_postcondition(
        "propose-tvl-raise",
        "the cap raise is queued on chain behind the timelock",
        pending_action(&chain).await.map(|p| p.is_some()),
    )
    .await?;
    println!(
        "\nThe raise is QUEUED behind the governance timelock. The program re-checks the\n\
         ceiling at execution, so a supply change in the meantime can still refuse it."
    );
    Ok(())
}

/// `submit-cancel` — cancels the pending action under a **fresh** M-of-N proof.
///
/// The cancelled action and its eta are read **from the chain**, never typed
/// by the operator: `cancel_params` commits to both, and a mistyped eta
/// produces a proof the program rejects after the whole federation has been
/// asked to sign it.
async fn submit_cancel(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let chain = chain_from_env()?;
    let pending = pending_action(&chain).await?;
    let (target_action, target_eta) =
        cancel_target(pending.as_ref()).map_err(|e| anyhow::anyhow!("{e} — nothing to cancel"))?;
    let pending = pending.expect("cancel_target succeeded, so an action is pending");

    println!("cancelling the pending action {target_action} with eta {target_eta}");
    println!(
        "  Every operator must have staged this exact cancellation:\n    \
         glc-admin approve-cancel --epoch {} --pending-action {} --pending-eta {} ...",
        pending.proposed_under_epoch, pending.action, pending.eta
    );

    let ed25519 = collect_governance(
        &chain,
        ACTION_CANCEL_ROTATION,
        &cancel_params(target_action, target_eta),
    )
    .await?;

    let payer = keypair_at("GLC_SOLANA_SUBMITTER_KEYPAIR_PATH")?;
    let cancel = ix::cancel_rotation_instruction(&chain.program_id, &payer.pubkey());
    submit(
        &chain,
        &[ed25519, cancel],
        &payer,
        "cancel-governance",
        &note,
    )
    .await?;
    verify_postcondition(
        "cancel-governance",
        "the queued governance action is gone",
        pending_action(&chain).await.map(|p| p.is_none()),
    )
    .await
}

/// `execute-rotation` / `execute-tvl-raise`.
///
/// Permissionless — the threshold proof at proposal time was the
/// authorization — so this needs no signatures, only a fee payer.
async fn execute_queued(args: &[String], cap_raise: bool) -> anyhow::Result<()> {
    let note = require_note(args);
    let chain = chain_from_env()?;
    let pending = pending_action(&chain).await?;
    let expected = if cap_raise {
        ACTION_PROPOSE_TVL_RAISE
    } else {
        ACTION_PROPOSE_ROTATION
    };
    // Every one of these is ALSO enforced on-chain. Checking here buys a
    // clear refusal instead of a failed transaction and an error code to
    // decode mid-incident (ops::preflight).
    can_execute(
        pending.as_ref(),
        expected,
        validator_set(&chain).await?.epoch,
        now_unix(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let payer = keypair_at("GLC_SOLANA_SUBMITTER_KEYPAIR_PATH")?;
    let instruction = if cap_raise {
        ix::execute_cap_raise_instruction(&chain.program_id, &payer.pubkey())
    } else {
        ix::execute_rotation_instruction(&chain.program_id, &payer.pubkey())
    };
    let what = if cap_raise {
        "execute-tvl-raise"
    } else {
        "execute-rotation"
    };
    submit(&chain, &[instruction], &payer, what, &note).await?;

    // Execution closes the governance action account, so "nothing pending"
    // is the observable proof the queued action actually applied.
    verify_postcondition(
        what,
        "the queued governance action is no longer pending",
        pending_action(&chain).await.map(|p| p.is_none()),
    )
    .await
}

// ------------------------------------------------------------- sweep-execute

/// Collects partial signatures for an approved sweep, assembles the
/// transaction, and broadcasts it.
///
/// This operator's own node broadcasts, and this operator's own rows built
/// the plan — but the *authorisation* is M other operators each having
/// staged the same commitment. Assembly verifies every signature against its
/// input's sighash, so a wrong or forged partial fails here rather than at
/// broadcast.
async fn sweep_execute(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let cfg = withdrawal_config_from_env()?;
    let protocol_version = protocol_version_from_env()?;
    let chain = chain_from_env()?;
    let db = open_db(args)?;

    let plan = build_plan(args, &cfg, &db)?;
    let commitment = plan.commitment(protocol_version);
    println!("\ncommitment: {}", hex::encode(&commitment));

    // The transaction is built by this operator's own Goldcoin node, then
    // verified against the plan before anyone is asked to sign it.
    let rpc = goldcoin_rpc_from_env()?;
    let outputs = vec![(plan.dest_address.clone(), plan.swept_atomic)];
    let inputs: Vec<(String, i64)> = plan
        .inputs
        .iter()
        .map(|u| (u.txid_hex.clone(), u.vout))
        .collect();
    let unsigned_hex = rpc.create_raw_transaction(&inputs, &outputs).await?;
    let unsigned = Transaction::parse_hex(&unsigned_hex)
        .map_err(|e| anyhow::anyhow!("the node returned an unparseable transaction: {e}"))?;
    glc_relayer::withdrawal::sweep::verify_sweep_tx(&unsigned, &plan)
        .map_err(|e| anyhow::anyhow!("the node did not build the planned sweep: {e}"))?;

    // Every vault signer is asked; the first `threshold` that answer are the
    // quorum. A sweep is not derived from a withdrawal index, so unlike a
    // payout there is nothing to designate from (ADR-0021 §5.1).
    let set = validator_set(&chain).await?;
    let signers: Vec<DesignatedSigner> = set
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            cfg.vault
                .signer_pubkeys
                .get(i)
                .map(|vault_pubkey| DesignatedSigner {
                    validator_pubkey: *v,
                    vault_pubkey: *vault_pubkey,
                })
        })
        .collect();

    let round = collector_from_env()?
        .collect_sweep_partials(set.epoch, &unsigned_hex, &signers, cfg.vault.threshold)
        .await;
    for (peer, why) in &round.round.refused {
        println!("  not approved by {peer}: {why}");
    }
    for (peer, why) in &round.round.unavailable {
        println!("  unreachable {peer}: {why}");
    }
    enough_approvals(round.partials.len(), cfg.vault.threshold as u8).map_err(|e| {
        anyhow::anyhow!(
            "{e}. Each remaining operator must run `glc-admin sweep-approve` with commitment {}.",
            hex::encode(&commitment)
        )
    })?;

    // Assembly verifies each signature against its input's sighash and
    // orders them by redeem-script position, which consensus enforces
    // (ADR-0017 D2).
    let partials: Vec<PartialSignature> = round.partials;
    let signed = assemble(&unsigned, &cfg.vault, &partials)
        .map_err(|e| anyhow::anyhow!("could not assemble the sweep: {e}"))?;
    let signed_hex = signed.serialize_hex();
    let txid = signed.txid_hex();

    println!("\nassembled sweep {txid}\n  broadcasting...");
    match rpc.send_raw_transaction(&signed_hex).await? {
        glc_relayer::glc::rpc::BroadcastOutcome::Accepted { txid } => {
            println!("BROADCAST. txid {txid}\n  note: {note}");
        }
        glc_relayer::glc::rpc::BroadcastOutcome::AlreadyInChain => {
            println!("already in a block — the sweep had already been broadcast");
        }
        glc_relayer::glc::rpc::BroadcastOutcome::MissingInputs => {
            anyhow::bail!(
                "the node rejected the sweep: its inputs are missing or already spent. The \
                 vault's contents changed since the plan was built; re-plan and re-approve."
            );
        }
    }
    Ok(())
}

/// This operator's own Goldcoin node, wrapped in the same adapter the
/// executor uses so the amount formatting the node demands (decimal GLC to
/// exactly eight places) is done in one place rather than two.
fn goldcoin_rpc_from_env() -> anyhow::Result<RealPayoutRpc> {
    let client =
        glc_relayer::glc::rpc::RpcClient::new(&glc_relayer::glc::config::RpcConfigValidated {
            url: env_required("GLC_RPC_URL")?,
            user: env_required("GLC_RPC_USER")?,
            password: env_required("GLC_RPC_PASSWORD")?,
            connect_timeout_ms: 5_000,
            read_timeout_ms: 30_000,
        })?;
    Ok(RealPayoutRpc::new(client))
}

// ---------------------------------------------------------------- bootstrap

/// `initialize` — stands the bridge up. Runs exactly once, at launch.
///
/// Every parameter is a launch-time security decision with **no default**
/// (owner decision U6). The program refuses a zero timelock and a zero
/// supply cap outright rather than inventing one, and this command refuses
/// them earlier so the operator gets a sentence instead of a program error.
async fn initialize(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let threshold: u8 = require(args, "--threshold").parse()?;
    let timelock: i64 = require(args, "--timelock-secs").parse()?;
    let max_supply: u64 = require(args, "--max-supply").parse()?;
    let min_deposit: u64 = require(args, "--min-deposit").parse()?;
    let min_withdrawal: u64 = require(args, "--min-withdrawal").parse()?;
    let validators: Vec<Pubkey> = require(args, "--validators")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow::anyhow!("{s:?} is not a pubkey: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;

    if threshold == 0 || usize::from(threshold) > validators.len() {
        anyhow::bail!(
            "threshold {threshold} is impossible for {} validators",
            validators.len()
        );
    }
    if timelock <= 0 {
        anyhow::bail!(
            "the governance timelock must be positive — the program refuses zero, because a \
             timelock of zero is no timelock and there is deliberately no default"
        );
    }
    if max_supply == 0 {
        anyhow::bail!(
            "a wrapped-supply cap of zero is never valid: it would have to mean either 'no \
             minting' or 'unlimited', and the second is the exact wrong default for a bound \
             on exposure"
        );
    }

    let chain = chain_from_env()?;
    let authority = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    // Validator ORDER is permanent: it fixes each member's bitmask index for
    // the life of the federation. Echo it back so it is checked before it is
    // committed rather than after.
    println!(
        "INITIALIZING the bridge\n  program:   {}\n  authority: {}\n  threshold: {threshold} of {}\n  \
         timelock:  {timelock}s\n  max supply: {max_supply} atomic\n  min deposit/withdrawal: {min_deposit}/{min_withdrawal}",
        chain.program_id,
        authority.pubkey(),
        validators.len()
    );
    for (i, v) in validators.iter().enumerate() {
        println!("  validator [{i}] {v}");
    }
    println!(
        "\nValidator ORDER is permanent — it fixes each member's bitmask index. Check it now.\n\
         This runs ONCE; the bridge config account cannot be created twice."
    );

    let instruction = ix::initialize_instruction(
        &chain.program_id,
        &authority.pubkey(),
        &validators,
        threshold,
        min_deposit,
        min_withdrawal,
        timelock,
        max_supply,
    );
    submit(&chain, &[instruction], &authority, "initialize", &note).await?;

    // The bootstrap sequence's very next step reads this account. Before
    // confirmation existed, `create-wrapped-mint` run straight afterwards
    // reported "the bridge config account does not exist" (ADR-0030).
    verify_postcondition(
        "initialize",
        "the bridge config account exists and is readable",
        bridge_config(&chain).await.map(|_| true),
    )
    .await?;

    println!("\nNow verify what actually landed: `glc-admin show-config`");
    Ok(())
}

/// `create_wrapped_mint` — one-time creation of the wrapped-GLC SPL mint.
///
/// The mint account signs its own creation, so this needs its keypair for
/// exactly one transaction. Keep it only until the transaction confirms:
/// the mint authority becomes a program PDA and freeze authority is `None`
/// (custody #6), so the keypair confers nothing afterwards and is one more
/// thing to lose.
async fn create_wrapped_mint(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let mint_path = require(args, "--mint-keypair");
    let mint = read_keypair_file(&mint_path)
        .map_err(|e| anyhow::anyhow!("could not read the mint keypair at {mint_path}: {e}"))?;
    let chain = chain_from_env()?;
    let admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    let existing = bridge_config(&chain).await?;
    if existing.mint_is_configured() {
        anyhow::bail!(
            "the wrapped mint is already set to {} — this instruction runs once",
            existing.wrapped_mint
        );
    }

    println!(
        "CREATING the wrapped-GLC mint {}\n  mint authority becomes a program PDA; freeze \
         authority is None (custody #6)",
        mint.pubkey()
    );

    let instruction =
        ix::create_wrapped_mint_instruction(&chain.program_id, &admin.pubkey(), &mint.pubkey());
    submit_signed(
        &chain,
        &[instruction],
        &admin,
        &[&admin, &mint],
        "create-wrapped-mint",
        &note,
    )
    .await?;

    let expected = mint.pubkey();
    verify_postcondition(
        "create-wrapped-mint",
        &format!("the wrapped mint is {expected}"),
        bridge_config(&chain)
            .await
            .map(|c| c.mint_is_configured() && c.wrapped_mint == expected),
    )
    .await?;

    println!(
        "\nThe mint keypair confers nothing from here on. Verify with `glc-admin show-config`."
    );
    Ok(())
}

/// Reads the bridge configuration back — launch step 3.
async fn bridge_config(chain: &Chain) -> anyhow::Result<BridgeConfigSnapshot> {
    let (pda, _) = ix::bridge_config_pda(&chain.program_id);
    let account = chain.rpc.get_account(&pda).await?.ok_or_else(|| {
        anyhow::anyhow!("the bridge config account does not exist at {pda} — run `initialize`")
    })?;
    Ok(decode_bridge_config(&account.data)?)
}

/// `show-config` — what actually landed on chain.
///
/// Launch step 3 requires verifying `initialize` recorded the intended
/// values by reading the accounts back. Every one of them is a security
/// decision with no default, so confirming them is not optional.
async fn show_config(_args: &[String]) -> anyhow::Result<()> {
    let chain = chain_from_env()?;
    let c = bridge_config(&chain).await?;
    let set = validator_set(&chain).await?;

    println!(
        "bridge config ({})\n  protocol version: {}\n  admin:            {}\n  pending admin:    {}\n  \
         paused:           {}\n  wrapped mint:     {}\n  governance timelock: {}s\n  \
         max wrapped supply:  {} atomic\n  min deposit/withdrawal: {}/{}\n  withdrawals so far:  {}",
        chain.program_id,
        c.protocol_version,
        c.admin,
        match c.pending_admin {
            Some(p) => format!("{p} — a handover is IN FLIGHT"),
            None => "none".to_string(),
        },
        if c.paused { "YES" } else { "no" },
        if c.mint_is_configured() {
            c.wrapped_mint.to_string()
        } else {
            "NOT YET CREATED — minting is impossible until `create-wrapped-mint` runs".to_string()
        },
        c.governance_timelock_seconds,
        c.max_wrapped_supply,
        c.min_deposit,
        c.min_withdrawal,
        c.withdrawal_count
    );
    println!(
        "\nvalidator set (epoch {})\n  threshold: {} of {}",
        set.epoch,
        set.threshold,
        set.validators.len()
    );
    for (i, v) in set.validators.iter().enumerate() {
        println!("  [{i}] {v}");
    }
    Ok(())
}

/// `transfer-admin` — step 1 of the handover, signed by the OUTGOING admin.
async fn transfer_admin(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let new_admin: Pubkey = require(args, "--new-admin")
        .parse()
        .map_err(|e| anyhow::anyhow!("--new-admin is not a pubkey: {e}"))?;
    let chain = chain_from_env()?;
    let admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    println!(
        "NOMINATING {new_admin} as admin, replacing {}\n\n\
         Nothing changes until that key signs `glc-admin accept-admin`. That is the point: a\n\
         typoed key cannot brick governance, because a key that does not exist cannot accept.",
        admin.pubkey()
    );
    let instruction =
        ix::transfer_admin_instruction(&chain.program_id, &admin.pubkey(), &new_admin);
    submit(&chain, &[instruction], &admin, "transfer-admin", &note).await?;

    verify_postcondition(
        "transfer-admin",
        &format!("{new_admin} is nominated and the handover is in flight"),
        bridge_config(&chain)
            .await
            .map(|c| c.pending_admin == Some(new_admin)),
    )
    .await
}

/// `accept-admin` — step 2, signed by the INCOMING admin.
async fn accept_admin(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let chain = chain_from_env()?;
    // Deliberately the same variable: the incoming admin runs this command
    // on their own host, with their own key configured as GLC_ADMIN_KEYPAIR_PATH.
    let new_admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    let c = bridge_config(&chain).await?;
    match c.pending_admin {
        None => anyhow::bail!("no admin handover is pending"),
        Some(p) if p != new_admin.pubkey() => anyhow::bail!(
            "the pending admin is {p}, but GLC_ADMIN_KEYPAIR_PATH holds {} — this command must \
             be run by the INCOMING admin",
            new_admin.pubkey()
        ),
        Some(_) => {}
    }

    println!("ACCEPTING the admin role as {}", new_admin.pubkey());
    let instruction = ix::accept_admin_instruction(&chain.program_id, &new_admin.pubkey());
    submit(&chain, &[instruction], &new_admin, "accept-admin", &note).await?;

    verify_postcondition(
        "accept-admin",
        &format!("{} is now the admin", new_admin.pubkey()),
        bridge_config(&chain)
            .await
            .map(|c| c.admin == new_admin.pubkey() && c.pending_admin.is_none()),
    )
    .await
}

/// `token-metadata` — makes the wrapped mint show up in wallets as
/// "Wrapped Goldcoin (wGLC)", and confirms it did (ADR-0028).
///
/// **Create-or-verify, in one command.** If the metadata does not exist it
/// is created; if it does, nothing is written. Either way the account is
/// read back and checked, so running this is how an operator answers "is the
/// token named correctly?" without having to know whether it was done
/// before.
///
/// Decimals are deliberately absent: Metaplex metadata carries none, and
/// wallets read them from the mint, which already says 8. There is no second
/// copy that could disagree.
async fn token_metadata(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    // Defaults to the canonical URI so an operator cannot typo it; `--uri`
    // overrides, and `--uri ""` deliberately writes none.
    let uri = arg(args, "--uri").unwrap_or_else(|| ix::WRAPPED_GLC_URI.to_string());
    let chain = chain_from_env()?;
    let admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    let cfg = bridge_config(&chain).await?;
    if !cfg.mint_is_configured() {
        anyhow::bail!("no wrapped mint exists yet — run `glc-admin create-wrapped-mint` first");
    }
    let mint = cfg.wrapped_mint;
    let (metadata_pda, _) = ix::token_metadata_pda(&mint);

    let existing = chain.rpc.get_account(&metadata_pda).await?;
    if existing.as_ref().is_some_and(|a| !a.data.is_empty()) {
        println!("metadata already exists at {metadata_pda} — nothing to create");
    } else {
        println!(
            "creating token metadata for mint {mint}\n  name:   {}\n  symbol: {}\n  uri:    {}",
            ix::WRAPPED_GLC_NAME,
            ix::WRAPPED_GLC_SYMBOL,
            if uri.is_empty() { "(none)" } else { &uri }
        );
        let instruction =
            ix::create_token_metadata_instruction(&chain.program_id, &admin.pubkey(), &mint, &uri);
        submit(&chain, &[instruction], &admin, "token-metadata", &note).await?;
    }

    // Verify by reading it back, whichever branch we took. A command that
    // reports success without looking is how "it was done months ago"
    // becomes an assumption nobody checked.
    let account = chain
        .rpc
        .get_account(&metadata_pda)
        .await?
        .ok_or_else(|| anyhow::anyhow!("metadata account {metadata_pda} does not exist"))?;
    let m = decode_token_metadata(&account.data)?;

    println!(
        "\nverified on chain ({metadata_pda})\n  name:   {}\n  symbol: {}\n  uri:    {}\n  \
         mint:   {}\n  update authority: {}",
        m.name,
        m.symbol,
        if m.uri.is_empty() { "(none)" } else { &m.uri },
        m.mint,
        m.update_authority
    );

    let (mint_authority, _) = ix::mint_authority_pda(&chain.program_id);
    let mut wrong = Vec::new();
    if m.name != ix::WRAPPED_GLC_NAME {
        wrong.push(format!(
            "name is {:?}, expected {:?}",
            m.name,
            ix::WRAPPED_GLC_NAME
        ));
    }
    if m.symbol != ix::WRAPPED_GLC_SYMBOL {
        wrong.push(format!(
            "symbol is {:?}, expected {:?}",
            m.symbol,
            ix::WRAPPED_GLC_SYMBOL
        ));
    }
    if m.mint != mint {
        wrong.push(format!("metadata names mint {}, not {mint}", m.mint));
    }
    if m.update_authority != mint_authority {
        wrong.push(format!(
            "update authority is {}, not the program's mint-authority PDA {mint_authority}",
            m.update_authority
        ));
    }
    if !wrong.is_empty() {
        anyhow::bail!(
            "the on-chain metadata is NOT what this bridge expects:\n  - {}",
            wrong.join("\n  - ")
        );
    }

    println!(
        "\nOK — wallets will display {} ({}), 8 decimals from the mint.",
        m.name, m.symbol
    );
    Ok(())
}

/// `update-token-metadata` — changes what wallets display (ADR-0028 §9).
///
/// Omitted values keep whatever is on chain, so moving only the hosting URL
/// does not require restating the name and symbol — and cannot change them
/// by accident.
///
/// Idempotent: the program writes nothing when the values already match, so
/// re-running is how an operator confirms a change landed.
async fn update_token_metadata(args: &[String]) -> anyhow::Result<()> {
    let note = require_note(args);
    let chain = chain_from_env()?;
    let admin = keypair_at("GLC_ADMIN_KEYPAIR_PATH")?;

    let cfg = bridge_config(&chain).await?;
    if !cfg.mint_is_configured() {
        anyhow::bail!("no wrapped mint exists yet — run `glc-admin create-wrapped-mint` first");
    }
    let mint = cfg.wrapped_mint;
    let (metadata_pda, _) = ix::token_metadata_pda(&mint);

    let account = chain.rpc.get_account(&metadata_pda).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "there is no token metadata for mint {mint} yet.\n\
             Run `glc-admin token-metadata` to create it before updating it."
        )
    })?;
    let current = decode_token_metadata(&account.data)?;

    // Omitted values keep their current on-chain value, so moving only the
    // URL cannot rename the token by accident.
    let name = arg(args, "--name").unwrap_or_else(|| current.name.clone());
    let symbol = arg(args, "--symbol").unwrap_or_else(|| current.symbol.clone());
    let uri = arg(args, "--uri").unwrap_or_else(|| current.uri.clone());

    if name == current.name && symbol == current.symbol && uri == current.uri {
        println!(
            "token metadata already matches — nothing to change.\n  name:   {}\n  symbol: {}\n  uri:    {}",
            current.name,
            current.symbol,
            if current.uri.is_empty() {
                "(none)"
            } else {
                &current.uri
            }
        );
        return Ok(());
    }

    println!(
        "updating token metadata for mint {mint}\n  name:   {:?} -> {:?}\n  symbol: {:?} -> {:?}\n  uri:    {:?} -> {:?}",
        current.name, name, current.symbol, symbol, current.uri, uri
    );

    let instruction = ix::update_token_metadata_instruction(
        &chain.program_id,
        &admin.pubkey(),
        &mint,
        &name,
        &symbol,
        &uri,
    );
    submit(
        &chain,
        &[instruction],
        &admin,
        "update-token-metadata",
        &note,
    )
    .await?;

    // Read back rather than trusting the signature.
    let account = chain
        .rpc
        .get_account(&metadata_pda)
        .await?
        .ok_or_else(|| anyhow::anyhow!("metadata account {metadata_pda} vanished"))?;
    let after = decode_token_metadata(&account.data)?;
    if after.name != name || after.symbol != symbol || after.uri != uri {
        anyhow::bail!(
            "the update was submitted but the on-chain values do not match:\n  name {:?}, symbol {:?}, uri {:?}",
            after.name,
            after.symbol,
            after.uri
        );
    }
    if after.mint != mint {
        anyhow::bail!("the metadata now names a different mint — report this immediately");
    }

    println!(
        "\nverified on chain — wallets will display {} ({}).\n  uri: {}",
        after.name,
        after.symbol,
        if after.uri.is_empty() {
            "(none)"
        } else {
            &after.uri
        }
    );
    println!(
        "\nWallets and explorers cache metadata; the change may take time to appear.\n\
         The mint, its decimals and its authorities are unchanged."
    );
    Ok(())
}
