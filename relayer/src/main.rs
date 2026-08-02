//! glc-relayer — federated validator daemon.
//!
//! Runs three long-running services against one SQLite file, each on its own
//! task so a stall on one side never blocks the others:
//!
//! 1. the **Goldcoin indexer** (`glc`) — follows the chain, detects vault
//!    deposits, tracks confirmations, and freezes canonical claim artifacts
//!    at `ReadyForSignature` (Phase 4);
//! 2. the **mint orchestrator** (`orchestrator`) — collects federation
//!    signatures and submits `mint_wrapped` (Phase 5, ADR-0012);
//! 3. the **withdrawal executor** (`withdrawal`) — pays out on Goldcoin
//!    (Phase 6, ADR-0013).
//!
//! # This process holds no validator key
//!
//! It signs nothing with a federation identity. Signatures are requested
//! from `signer-server` peers over mutually authenticated TLS, each of which
//! independently re-derives the message from its own chain observations
//! before signing (ADR-0016). The submitter keypair pays transaction fees
//! and confers no authority whatsoever (owner decision R4).
//!
//! A fully compromised relayer can therefore waste fees and stall progress,
//! but cannot mint or move value.
//!
//! All configuration — including RPC credentials — comes from the
//! environment, never from a committed file (see `.gitignore` and
//! docs/goldcoin-rpc-notes.md). Every value is validated strictly at
//! startup (`glc::config::IndexerConfig::validate`); the process refuses to
//! run on a misconfiguration rather than guessing.

use std::path::PathBuf;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::read_keypair_file;

use glc_relayer::glc;
use glc_relayer::glc::config::{
    IndexerConfig, RawIndexerConfig, RollingWindow, RpcConfig, ValueCaps,
};
use glc_relayer::glc::db::Db;
use glc_relayer::glc::indexer::{Indexer, TickOutcome};
use glc_relayer::glc::rpc::RpcClient;
use glc_relayer::ops::collector::OpsCollector;
use glc_relayer::ops::health;
use glc_relayer::orchestrator::{Orchestrator, OrchestratorError};
use glc_relayer::p2p::collector::GrpcCollector;
use glc_relayer::p2p::identity::{parse_peers, TlsMaterial, TlsPaths};
use glc_relayer::solana::config::{RawSolanaConfig, SolanaConfig};
use glc_relayer::solana::epoch::{observe_epoch, run_epoch_refresher, EpochObservation};
use glc_relayer::solana::rpc::RealSolanaRpc;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::assignment::OperatorAssignment;
use glc_relayer::withdrawal::completion::{CompletionError, CompletionSubmitter};
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::discovery;
use glc_relayer::withdrawal::executor::{ExecutorError, WithdrawalExecutor};
use glc_relayer::withdrawal::federation::{
    FederationCompletionCollector, FederationPayoutCollector, VaultSignerMap,
};
use glc_relayer::withdrawal::status::SolanaWithdrawalStatus;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is not set"))
}

fn env_optional_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{name} must be a u64: {e}")),
        Err(_) => Ok(default),
    }
}

fn env_required_u64(name: &str) -> anyhow::Result<u64> {
    env_required(name)?
        .parse()
        .map_err(|e| anyhow::anyhow!("{name} must be a u64: {e}"))
}

fn env_required_u32(name: &str) -> anyhow::Result<u32> {
    env_required(name)?
        .parse()
        .map_err(|e| anyhow::anyhow!("{name} must be a u32: {e}"))
}

/// Assembles [`RawIndexerConfig`] from environment variables. Kept separate
/// from `main` so its (extensive) env-var contract is easy to find and unit
/// test independently of process I/O.
fn config_from_env() -> anyhow::Result<IndexerConfig> {
    let max_deposit_atomic = match std::env::var("GLC_MAX_DEPOSIT_ATOMIC") {
        Ok(v) => Some(
            v.parse::<u64>()
                .map_err(|e| anyhow::anyhow!("GLC_MAX_DEPOSIT_ATOMIC must be a u64: {e}"))?,
        ),
        Err(_) => None,
    };
    let rolling_window = match (
        std::env::var("GLC_ROLLING_WINDOW_SECONDS").ok(),
        std::env::var("GLC_ROLLING_WINDOW_CAP_ATOMIC").ok(),
    ) {
        (Some(w), Some(c)) => Some(RollingWindow {
            window_seconds: w
                .parse()
                .map_err(|e| anyhow::anyhow!("GLC_ROLLING_WINDOW_SECONDS must be a u64: {e}"))?,
            cap_atomic: c
                .parse()
                .map_err(|e| anyhow::anyhow!("GLC_ROLLING_WINDOW_CAP_ATOMIC must be a u64: {e}"))?,
        }),
        (None, None) => None,
        _ => {
            return Err(anyhow::anyhow!(
                "GLC_ROLLING_WINDOW_SECONDS and GLC_ROLLING_WINDOW_CAP_ATOMIC must be set together"
            ))
        }
    };

    let raw = RawIndexerConfig {
        rpc: RpcConfig {
            url: env_required("GLC_RPC_URL")?,
            user: env_required("GLC_RPC_USER")?,
            password: env_required("GLC_RPC_PASSWORD")?,
            connect_timeout_ms: env_optional_u64("GLC_RPC_CONNECT_TIMEOUT_MS", 5_000)?,
            read_timeout_ms: env_optional_u64("GLC_RPC_READ_TIMEOUT_MS", 30_000)?,
        },
        db_path: PathBuf::from(env_required("GLC_DB_PATH")?),
        vault_script_pubkey_hex: env_required("GLC_VAULT_SCRIPT_PUBKEY_HEX")?,
        // No built-in production default (owner decision U6): Goldcoin's
        // safe confirmation depth and reorg-halt bound are open security/ops
        // decisions (docs/threat-model.md), never silently assumed here.
        confirmation_depth: env_required_u32("GLC_CONFIRMATION_DEPTH")?,
        max_reorg_depth: env_required_u32("GLC_MAX_REORG_DEPTH")?,
        // 0 = disabled, consistent with the on-chain min_deposit convention;
        // the on-chain check remains the final enforcement either way (U3).
        min_deposit_atomic: env_optional_u64("GLC_MIN_DEPOSIT_ATOMIC", 0)?,
        value_caps: ValueCaps {
            max_deposit_atomic,
            rolling_window,
        },
        protocol_version: env_required("GLC_PROTOCOL_VERSION")?
            .parse()
            .map_err(|e| anyhow::anyhow!("GLC_PROTOCOL_VERSION must be a u8: {e}"))?,
        program_id_hex: env_required("GLC_PROGRAM_ID_HEX")?,
        validator_epoch: env_required_u64("GLC_VALIDATOR_EPOCH")?,
        wrapped_mint_hex: env_required("GLC_WRAPPED_MINT_HEX")?,
        node_unavailable_retry_interval_ms: env_optional_u64(
            "GLC_NODE_UNAVAILABLE_RETRY_INTERVAL_MS",
            5_000,
        )?,
        poll_interval_ms: env_optional_u64("GLC_POLL_INTERVAL_MS", 1_000)?,
    };

    IndexerConfig::validate(raw).map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))
}

/// Assembles [`SolanaConfig`] (Phase 5, ADR-0012) from environment
/// variables. `program_id_bytes` comes from the already-validated
/// `GLC_PROGRAM_ID_HEX` (Phase 4) rather than a second, independently
/// configured value — the on-chain program targeted by a submitted
/// transaction must always be identical to the one embedded in the claim
/// message, and reusing the single parsed source eliminates any chance of
/// the two drifting apart.
fn solana_config_from_env(program_id_bytes: [u8; 32]) -> anyhow::Result<SolanaConfig> {
    let raw = RawSolanaConfig {
        rpc_url: env_required("GLC_SOLANA_RPC_URL")?,
        program_id: Pubkey::from(program_id_bytes).to_string(),
        submitter_keypair_path: PathBuf::from(env_required("GLC_SOLANA_SUBMITTER_KEYPAIR_PATH")?),
        // No built-in default (owner decision R3): the confirmation
        // commitment level must be explicit in configuration.
        commitment: env_required("GLC_SOLANA_COMMITMENT")?,
        poll_interval_ms: env_optional_u64("GLC_SOLANA_POLL_INTERVAL_MS", 2_000)?,
    };

    SolanaConfig::validate(raw).map_err(|e| anyhow::anyhow!("invalid Solana configuration: {e}"))
}

/// Assembles [`WithdrawalConfig`] (Phase 6, ADR-0013) from environment
/// variables. Nothing here has a silent default: the fee rate (D4), the
/// confirmation depth (D7) and the discovery commitment (D5) must all be
/// stated explicitly, and the commitment must be exactly `finalized`.
fn withdrawal_config_from_env() -> anyhow::Result<WithdrawalConfig> {
    let raw = RawWithdrawalConfig {
        vault_redeem_script_hex: env_required("GLC_VAULT_REDEEM_SCRIPT_HEX")?,
        vault_address: env_required("GLC_VAULT_ADDRESS")?,
        change_address: env_required("GLC_VAULT_CHANGE_ADDRESS")?,
        fee_rate_per_kb: env_required_u64("GLC_PAYOUT_FEE_RATE_PER_KB")?,
        dust_threshold_atomic: env_required_u64("GLC_PAYOUT_DUST_THRESHOLD_ATOMIC")?,
        vault_min_confirmations: env_required_u64("GLC_VAULT_MIN_CONFIRMATIONS")? as i64,
        confirmation_depth: env_required_u64("GLC_WITHDRAWAL_CONFIRMATION_DEPTH")? as i64,
        max_inputs_per_payout: env_required_u64("GLC_PAYOUT_MAX_INPUTS")? as usize,
        reservation_timeout_secs: env_required_u64("GLC_PAYOUT_RESERVATION_TIMEOUT_SECS")? as i64,
        discovery_commitment: env_required("GLC_WITHDRAWAL_DISCOVERY_COMMITMENT")?,
        poll_interval_ms: env_optional_u64("GLC_WITHDRAWAL_POLL_INTERVAL_MS", 5_000)?,
    };
    WithdrawalConfig::validate(raw)
        .map_err(|e| anyhow::anyhow!("invalid withdrawal configuration: {e}"))
}

/// The withdrawal executor's tick loop (Phase 6), the third long-running
/// service alongside the indexer and the mint orchestrator.
///
/// Discovery and execution share one task on purpose: the executor is
/// single-threaded by design (owner decision D8), so scanning Solana and
/// driving payouts are strictly sequential and no two ticks can ever
/// overlap on the same vault.
#[allow(clippy::too_many_arguments)]
async fn run_withdrawal_loop(
    mut executor: WithdrawalExecutor<RealPayoutRpc, FederationPayoutCollector>,
    solana_rpc: RealSolanaRpc,
    program_id: Pubkey,
    config: WithdrawalConfig,
    poll_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("withdrawal loop: shutdown signal received, exiting");
                return Ok(());
            }
            result = withdrawal_tick(&mut executor, &solana_rpc, &program_id, &config) => {
                match result {
                    Ok(()) => tokio::time::sleep(poll_interval).await,
                    Err(WithdrawalTickError::Executor(ExecutorError::Db(e))) => {
                        tracing::error!(error = %e, "withdrawal database error — exiting");
                        return Err(e.into());
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "withdrawal tick failed; retrying next tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum WithdrawalTickError {
    #[error("withdrawal discovery failed: {0}")]
    Discovery(#[from] glc_relayer::solana::rpc::SolanaRpcError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
}

/// One discovery + execution pass. A discovery failure is NOT fatal and does
/// not skip execution of already-known withdrawals: a Solana outage must not
/// strand payouts that were discovered before it started.
async fn withdrawal_tick(
    executor: &mut WithdrawalExecutor<RealPayoutRpc, FederationPayoutCollector>,
    solana_rpc: &RealSolanaRpc,
    program_id: &Pubkey,
    config: &WithdrawalConfig,
) -> Result<(), WithdrawalTickError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match discovery::scan_withdrawals(solana_rpc, program_id, config.discovery_commitment, now, 0)
        .await
    {
        Ok(found) => {
            let n = executor.ingest_discovered(&found)?;
            if n > 0 {
                tracing::info!(new_withdrawals = n, "observed new withdrawal requests");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "withdrawal discovery failed; continuing with known work");
        }
    }

    let report = executor.tick().await?;
    if report.completed > 0 || report.signed > 0 || report.halted > 0 || report.failed > 0 {
        tracing::info!(
            validated = report.validated,
            awaiting_funds = report.awaiting_funds,
            built = report.built,
            signed = report.signed,
            broadcast = report.broadcast,
            confirming = report.confirming,
            completed = report.completed,
            halted = report.halted,
            failed = report.failed,
            orphaned = report.orphaned,
            "withdrawal tick"
        );
    }
    Ok(())
}

/// The completion service's tick loop (Phase 7f, ADR-0018).
///
/// Falling short of threshold is an ordinary outcome here, not an error:
/// peers that have not yet confirmed the payout at the required depth
/// correctly refuse, and the next pass tries again.
async fn run_completion_loop(
    mut submitter: CompletionSubmitter<RealSolanaRpc, FederationCompletionCollector>,
    poll_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("completion loop: shutdown signal received, exiting");
                return Ok(());
            }
            result = submitter.tick() => {
                match result {
                    Ok(report) => {
                        if report.submitted > 0 || report.reconciled > 0 || report.skipped > 0 {
                            tracing::info!(
                                submitted = report.submitted,
                                reconciled = report.reconciled,
                                insufficient = report.insufficient,
                                skipped = report.skipped,
                                "completion tick"
                            );
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(CompletionError::Db(e)) => {
                        tracing::error!(error = %e, "completion database error — exiting");
                        return Err(e.into());
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "completion tick failed; retrying next tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }
    }
}

/// Builds the peer collector from configuration (Phase 7d).
///
/// `GLC_FEDERATION_PEERS` is comma-separated `base58pubkey@uri`: the pubkey
/// is the on-chain validator identity the endpoint must answer as, checked
/// on every response, so a compromised endpoint cannot impersonate another
/// federation member even with a valid certificate.
///
/// TLS is **required unless explicitly disabled**. `GLC_FEDERATION_TLS=off`
/// exists for loopback and regtest, and is loud on purpose: without it a
/// relayer talks to its signers in plaintext, with no transport
/// authentication at all.
/// Whether `who` appears in a raw `GLC_FEDERATION_PEERS` string.
fn peers_contain(raw: &str, who: &Pubkey) -> bool {
    parse_peers(raw, None)
        .map(|ps| ps.iter().any(|p| p.validator_pubkey == *who))
        .unwrap_or(false)
}

fn collector_from_env(own_identity: &Pubkey) -> anyhow::Result<GrpcCollector> {
    // The other operators, plus this one's OWN signer-server.
    //
    // `GLC_FEDERATION_PEERS` deliberately excludes self, but a payout quorum
    // is designated from the withdrawal index and therefore routinely
    // includes this operator — always, in fact, for the payout it is
    // designated to build. Without an address for its own signer the relayer
    // can never reach threshold on those. See `with_local_signer`.
    let peers = parse_peers(&env_required("GLC_FEDERATION_PEERS")?, Some(own_identity))?;
    let peers = glc_relayer::p2p::identity::with_local_signer(
        peers,
        *own_identity,
        &std::env::var("GLC_RELAYER_LOCAL_SIGNER_URI").unwrap_or_default(),
    )?;

    if std::env::var("GLC_FEDERATION_TLS").as_deref() == Ok("off") {
        tracing::warn!(
            peer_count = peers.len(),
            "GLC_FEDERATION_TLS=off — federation traffic is UNAUTHENTICATED at the transport \
             layer; acceptable only for loopback or regtest"
        );
        return Ok(GrpcCollector::insecure_without_tls(peers));
    }

    let tls = TlsMaterial::load(&TlsPaths {
        ca: PathBuf::from(env_required("GLC_FEDERATION_CA_CERT_PATH")?),
        cert: PathBuf::from(env_required("GLC_RELAYER_TLS_CERT_PATH")?),
        key: PathBuf::from(env_required("GLC_RELAYER_TLS_KEY_PATH")?),
    })?;
    // Pinned by configuration rather than derived from each peer's URI: a
    // peer must present a certificate for the federation's name, not merely
    // for a hostname it happens to control.
    let domain = env_required("GLC_FEDERATION_TLS_DOMAIN")?;
    tracing::info!(
        peer_count = peers.len(),
        tls_domain = %domain,
        "federation transport: mutual TLS against the pinned federation CA"
    );
    Ok(GrpcCollector::new(peers, tls, domain))
}

/// The Goldcoin indexer's tick loop (Phase 4), run as an independent task
/// alongside the orchestrator's so a stall or restart of one side never
/// blocks the other.
async fn run_indexer_loop(
    mut indexer: Indexer<RpcClient>,
    poll_interval: Duration,
    unavailable_interval: Duration,
    status: std::sync::Arc<glc_relayer::ops::indexer_status::IndexerStatus>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("indexer loop: shutdown signal received, exiting");
                return Ok(());
            }
            result = indexer.tick() => {
                match result {
                    Ok(TickOutcome::Progressed { blocks_indexed, reorg }) => {
                        status.record_tick(now_unix());
                        if let Some(r) = reorg {
                            // §13.1 (5): published so an operator sees a
                            // chain trending toward max_reorg_depth before
                            // the indexer halts on it.
                            let depth = r.old_tip_height - r.fork_height;
                            status.record_reorg(depth);
                            tracing::warn!(
                                fork_height = r.fork_height,
                                old_tip_height = r.old_tip_height,
                                orphaned_count = r.orphaned_count,
                                depth,
                                "reorg detected and rolled back"
                            );
                        }
                        if blocks_indexed > 0 {
                            tracing::info!(blocks_indexed, "indexed new blocks");
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    Ok(TickOutcome::Halted { attempted_depth }) => {
                        // Published so /health reports it. Before this the
                        // halt was a single log line and the endpoint kept
                        // returning 200 while nothing was being indexed.
                        status.record_halt(attempted_depth);
                        tracing::error!(
                            attempted_depth,
                            "reorg deeper than max_reorg_depth: indexer halted, manual intervention required"
                        );
                        // Process stays alive (for liveness probes/orchestration)
                        // but performs no further indexing work.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                    Err(glc::indexer::IndexerError::NodeUnavailable(e)) => {
                        tracing::warn!(error = %e, "Goldcoin node unavailable, retrying");
                        tokio::time::sleep(unavailable_interval).await;
                    }
                    Err(glc::indexer::IndexerError::Rpc(e)) => {
                        tracing::error!(error = %e, "Goldcoin RPC method error this tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(glc::indexer::IndexerError::Db(e)) => {
                        tracing::error!(error = %e, "indexer database error — exiting");
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

/// The Phase 5 mint pipeline's tick loop, run independently of the indexer
/// so Solana RPC outages never stall Goldcoin chain-following and vice
/// versa. Both loops read/write the same SQLite file through their own
/// connection (`Db::open` enables WAL mode + a busy timeout for exactly
/// this overlap).
async fn run_orchestrator_loop(
    mut orchestrator: Orchestrator<RealSolanaRpc, GrpcCollector>,
    poll_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("orchestrator loop: shutdown signal received, exiting");
                return Ok(());
            }
            result = orchestrator.tick() => {
                match result {
                    Ok(report) => {
                        if report.minted > 0 || report.submitted > 0 || report.halted > 0 {
                            tracing::info!(
                                minted = report.minted,
                                submitted = report.submitted,
                                insufficient = report.insufficient,
                                halted = report.halted,
                                "orchestrator tick"
                            );
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(OrchestratorError::NodeUnavailable(e)) => {
                        tracing::warn!(error = %e, "Solana node unavailable, retrying");
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(OrchestratorError::Db(e)) => {
                        tracing::error!(error = %e, "orchestrator database error — exiting");
                        return Err(e.into());
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "orchestrator error this tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = config_from_env()?;
    tracing::info!(
        confirmation_depth = config.confirmation_depth,
        max_reorg_depth = config.max_reorg_depth,
        min_deposit_atomic = config.min_deposit_atomic,
        "glc-relayer: starting Goldcoin indexer"
    );

    let db = Db::open(&config.db_path)?;
    tracing::info!(schema_version = db.schema_version()?, "database ready");
    let rpc_for_payouts = config.rpc.clone();
    let rpc = RpcClient::new(&config.rpc)?;
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let unavailable_interval = Duration::from_millis(config.node_unavailable_retry_interval_ms);
    let program_id_bytes = config.program_id;
    let config_protocol_version = config.protocol_version;
    let wrapped_mint_pubkey = Pubkey::from(config.wrapped_mint);
    let db_path = config.db_path.clone();
    let indexer = Indexer::new(rpc, db, config);

    let solana_config = solana_config_from_env(program_id_bytes)?;
    tracing::info!(
        program_id = %solana_config.program_id,
        commitment = ?solana_config.commitment,
        "glc-relayer: starting Solana mint orchestrator (ADR-0012)"
    );
    // A second, independent connection to the same SQLite file (Db::open
    // enables WAL mode + a busy timeout for exactly this overlap) — the
    // indexer and orchestrator loops run concurrently and must not share
    // one connection across two tasks.
    let orchestrator_db = Db::open(&db_path)?;
    let submitter = read_keypair_file(&solana_config.submitter_keypair_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read submitter keypair {}: {e}",
            solana_config.submitter_keypair_path.display()
        )
    })?;
    // Phase 7g (ADR-0019 D1): this relayer's own federation identity, stated
    // EXPLICITLY and never derived. It decides who acts first, and inferring
    // it from the shape of another setting is how two configurations drift
    // apart without anyone noticing. It is also which signer the collector
    // must be able to reach locally, so it is read before the collector.
    let relayer_identity: Pubkey = env_required("GLC_RELAYER_VALIDATOR_PUBKEY")?
        .parse()
        .map_err(|e| anyhow::anyhow!("GLC_RELAYER_VALIDATOR_PUBKEY is not a pubkey: {e}"))?;
    // Phase 7c/7d (ADR-0016): this process holds NO validator key.
    // Signatures are requested from `signer-server` peers over mutually
    // authenticated TLS, each of which independently re-derives the message
    // before signing. Only signatures cross the network.
    let collector = collector_from_env(&relayer_identity)?;
    let solana_rpc = RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment);
    let orchestrator_poll_interval = Duration::from_millis(solana_config.poll_interval_ms);
    let orchestrator = Orchestrator::new(
        orchestrator_db,
        solana_rpc,
        solana_config.program_id,
        submitter,
        collector,
    );

    // Third service: the Goldcoin withdrawal executor (Phase 6, ADR-0013).
    let withdrawal_config = withdrawal_config_from_env()?;
    tracing::info!(
        vault_address = %withdrawal_config.vault_address,
        confirmation_depth = withdrawal_config.confirmation_depth,
        fee_rate_per_kb = withdrawal_config.fee_rate_per_kb,
        "glc-relayer: starting Goldcoin withdrawal executor (regtest custody — ADR-0013)"
    );
    let withdrawal_poll_interval = Duration::from_millis(withdrawal_config.poll_interval_ms);
    let payout_rpc = RealPayoutRpc::new(RpcClient::new(&rpc_for_payouts)?);

    // Phase 7e (ADR-0017): this process holds NO vault key either. Payout
    // signatures are collected from the designated quorum and assembled
    // here, because Goldcoin 0.17 has no combinerawtransaction and no PSBT.
    //
    // The vault-signer map is validated against the configured redeem script
    // and FAILS CLOSED (E1): every position must map to exactly one
    // validator, and no validator may hold two positions.
    let vault_signer_map = VaultSignerMap::parse(
        &env_required("GLC_VAULT_SIGNER_MAP")?,
        &withdrawal_config.vault,
    )?;

    // Fails closed both ways: we must not be listed among our own peers, and
    // we must appear in the vault signer map — that map is what gives us an
    // operator index at all.
    let peers_raw = env_required("GLC_FEDERATION_PEERS")?;
    if peers_contain(&peers_raw, &relayer_identity) {
        return Err(anyhow::anyhow!(
            "GLC_RELAYER_VALIDATOR_PUBKEY {relayer_identity} appears in GLC_FEDERATION_PEERS; \
             peers are the OTHER operators"
        ));
    }
    let operator_index = vault_signer_map
        .index_of(&relayer_identity)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "GLC_RELAYER_VALIDATOR_PUBKEY {relayer_identity} does not appear in \
                 GLC_VAULT_SIGNER_MAP — refusing to start without an operator index"
            )
        })?;
    let assignment = OperatorAssignment::new(
        operator_index as usize,
        vault_signer_map.len(),
        env_optional_u64("GLC_PAYOUT_BUILD_TIMEOUT_SECS", 120)? as i64,
        env_optional_u64("GLC_MINT_SUBMIT_TIMEOUT_SECS", 60)? as i64,
    )?;
    tracing::info!(
        validator = %relayer_identity,
        operator_index,
        operator_count = vault_signer_map.len(),
        "relayer identity validated against the federation configuration"
    );
    tracing::info!(
        vault_signers = vault_signer_map.len(),
        threshold = withdrawal_config.vault.threshold,
        "vault signer map validated against the configured redeem script"
    );

    // The epoch this relayer stamps onto signing requests — its OWN
    // observation, refreshed in the background and never a configured
    // constant. Startup blocks on a first successful read.
    let epoch_rpc = RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment);
    let first_epoch = observe_epoch(&epoch_rpc, &solana_config.program_id)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to start without a first observation of the validator epoch: {e}"
            )
        })?;
    let epoch_observation = std::sync::Arc::new(EpochObservation::seeded(first_epoch, now_unix()));
    tracing::info!(observed_epoch = first_epoch, "validator epoch observed");

    let payout_collector = FederationPayoutCollector::new(
        collector_from_env(&relayer_identity)?,
        withdrawal_config.vault.clone(),
        vault_signer_map,
        operator_index as u32,
    );
    let withdrawal_executor = WithdrawalExecutor::new(
        Db::open(&db_path)?,
        payout_rpc,
        withdrawal_config.clone(),
        payout_collector,
        std::sync::Arc::clone(&epoch_observation),
    )
    .with_assignment(assignment)
    // ADR-0019 D4: the last check before funds move.
    .with_onchain_status(std::sync::Arc::new(SolanaWithdrawalStatus::new(
        RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment),
        solana_config.program_id,
    )));
    let discovery_rpc = RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment);

    // Fourth service: recording completed payouts on Solana (Phase 7f,
    // ADR-0018). Runs on its own tick so a Solana outage never stalls
    // Goldcoin payouts, and vice versa.
    let completion_submitter = CompletionSubmitter::new(
        Db::open(&db_path)?,
        RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment),
        FederationCompletionCollector::new(collector_from_env(&relayer_identity)?),
        solana_config.program_id,
        read_keypair_file(&solana_config.submitter_keypair_path).map_err(|e| {
            anyhow::anyhow!("failed to read submitter keypair for completions: {e}")
        })?,
        config_protocol_version,
        std::sync::Arc::clone(&epoch_observation),
    );

    // Fifth service: the operator-facing health and metrics endpoint
    // (Phase 7h, ADR-0014 §13). It EXPOSES state and never pages anyone —
    // no alerting credentials live in this process (owner decision H2).
    //
    // Optional so a deployment can run without it, but logged loudly when
    // absent: a bridge nobody can observe is not one that should be live.
    let ops_addr: Option<std::net::SocketAddr> = match std::env::var("GLC_OPS_LISTEN_ADDR") {
        Ok(a) => Some(
            a.parse()
                .map_err(|e| anyhow::anyhow!("GLC_OPS_LISTEN_ADDR must be host:port: {e}"))?,
        ),
        Err(_) => {
            tracing::warn!(
                "GLC_OPS_LISTEN_ADDR is not set — health and metrics are NOT being exposed"
            );
            None
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let epoch_task = tokio::spawn(run_epoch_refresher(
        RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment),
        solana_config.program_id,
        std::sync::Arc::clone(&epoch_observation),
        shutdown_rx.clone(),
    ));
    let indexer_status = std::sync::Arc::new(glc_relayer::ops::indexer_status::IndexerStatus::new(
        now_unix(),
    ));
    let mut indexer_task = tokio::spawn(run_indexer_loop(
        indexer,
        poll_interval,
        unavailable_interval,
        std::sync::Arc::clone(&indexer_status),
        shutdown_rx.clone(),
    ));
    let mut orchestrator_task = tokio::spawn(run_orchestrator_loop(
        orchestrator,
        orchestrator_poll_interval,
        shutdown_rx.clone(),
    ));
    let ops_task = ops_addr.map(|addr| {
        tracing::warn!(
            %addr,
            "health and metrics endpoint has NO authentication — bind it to a private \
             interface, never a public one"
        );
        let collector = OpsCollector::new(
            db_path.clone(),
            RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment),
            RealPayoutRpc::new(RpcClient::new(&rpc_for_payouts).expect("goldcoin rpc")),
            wrapped_mint_pubkey,
            withdrawal_config.vault_address.clone(),
            withdrawal_config.vault_min_confirmations,
            std::sync::Arc::clone(&epoch_observation),
        )
        .with_indexer_status(std::sync::Arc::clone(&indexer_status));
        tokio::spawn(health::serve(
            addr,
            std::sync::Arc::new(collector),
            shutdown_rx.clone(),
        ))
    });

    let mut completion_task = tokio::spawn(run_completion_loop(
        completion_submitter,
        withdrawal_poll_interval,
        shutdown_rx.clone(),
    ));
    let mut withdrawal_task = tokio::spawn(run_withdrawal_loop(
        withdrawal_executor,
        discovery_rpc,
        solana_config.program_id,
        withdrawal_config,
        withdrawal_poll_interval,
        shutdown_rx,
    ));

    // Either an operator-requested shutdown or an unexpected exit from
    // either loop (e.g. a fatal database error) stops the other loop and
    // ends the process — a stuck task must never be left running silently
    // after its sibling has already exited.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received, stopping all three services");
            let _ = shutdown_tx.send(true);
            let (i, o, w) = tokio::join!(indexer_task, orchestrator_task, withdrawal_task);
            let _ = tokio::join!(epoch_task, completion_task);
            if let Some(t) = ops_task {
                let _ = t.await;
            }
            i??;
            o??;
            w??;
        }
        result = &mut indexer_task => {
            tracing::error!("indexer loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(orchestrator_task, withdrawal_task, completion_task);
            let _ = epoch_task.await;
            result??;
        }
        result = &mut orchestrator_task => {
            tracing::error!("orchestrator loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(indexer_task, withdrawal_task, completion_task);
            let _ = epoch_task.await;
            result??;
        }
        result = &mut completion_task => {
            tracing::error!("completion loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(indexer_task, orchestrator_task, withdrawal_task);
            let _ = epoch_task.await;
            result??;
        }
        result = &mut withdrawal_task => {
            tracing::error!("withdrawal loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(indexer_task, orchestrator_task, completion_task);
            let _ = epoch_task.await;
            result??;
        }
    }
    Ok(())
}
