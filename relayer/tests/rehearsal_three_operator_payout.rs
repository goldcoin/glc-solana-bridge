//! The **three-operator** round trip, over the real federation transport.
//!
//! ```text
//! real Goldcoin deposit  ->  indexer  ->  claim artifact
//!   ->  mint orchestrator  ->  real SPL mint on a real solana-test-validator
//!   ->  burn_wrapped       ->  real WithdrawalRequest PDA
//!   ->  withdrawal discovery + executor
//!   ->  payout partials collected from THREE REAL signer-server processes
//!   ->  real Goldcoin payout arriving at a real address
//! ```
//!
//! # Why this exists alongside `e2e_deposit_to_payout`
//!
//! That test proves the *value path*, but it signs payouts with
//! [`InProcessPayoutCollector`] — the test-only collector that holds every
//! vault key in one process. It therefore never performs a **peer lookup**,
//! and a whole class of federation-wiring defects is invisible to it.
//!
//! This rig replaces exactly one component — the payout collector — with the
//! production [`FederationPayoutCollector`] over a real mTLS `GrpcCollector`,
//! and stands up the topology a real deployment has:
//!
//! - three `goldcoind -regtest` nodes, one per signer, sharing a chain
//!   (ADR-0017 E2: a signer that checks against the requester's node is not
//!   checking anything);
//! - three **real `signer-server` processes**, each holding exactly one vault
//!   key, behind real certificates issued by a real test CA;
//! - one relayer, operator 0, whose peer list contains only the *other* two
//!   operators — which `main.rs` does not merely permit but **enforces**.
//!
//! Nothing in the value path or the signing path is mocked.
//!
//! Skipped (not failed) unless `GOLDCOIND_BIN`, `GOLDCOIN_CLI_BIN`, the
//! compiled program, the `signer-server` binary, and `solana-test-validator`
//! are all available.

use std::collections::BTreeMap;
use std::io::Write as _;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient as BlockingRpcClient;
#[allow(deprecated)]
use solana_sdk::bpf_loader_upgradeable;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::transaction::Transaction;

use glc_relayer::glc;
use glc_relayer::glc::config::{
    IndexerConfig, RawIndexerConfig, RpcConfig, RpcConfigValidated, ValueCaps,
};
use glc_relayer::glc::db::{Db, DepositState};
use glc_relayer::glc::indexer::Indexer;
use glc_relayer::glc::rpc::RpcClient as GlcRpcClient;
use glc_relayer::glc::withdrawal_db::WithdrawalState;
use glc_relayer::orchestrator::Orchestrator;
use glc_relayer::p2p::collector::{GrpcCollector, InProcessCollector};
use glc_relayer::p2p::identity::{PeerEndpoint, TlsMaterial};
use glc_relayer::p2p::service::now_unix;
use glc_relayer::solana::epoch::EpochObservation;
use glc_relayer::solana::instruction as glc_ix;
use glc_relayer::solana::rpc::RealSolanaRpc;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::assignment::OperatorAssignment;
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::discovery;
use glc_relayer::withdrawal::executor::WithdrawalExecutor;
use glc_relayer::withdrawal::federation::{
    FederationPayoutCollector, InProcessPayoutCollector, VaultSignerMap,
};

const DECLARED_PROGRAM_ID: &str = "77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq";

/// The name every federation certificate is issued for, and the one the
/// relayer pins.
const FEDERATION_DOMAIN: &str = "signer.glc-federation.test";

// =====================================================================
// Environment gating
// =====================================================================

fn goldcoind_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIND_BIN").map(PathBuf::from)
}
fn goldcoin_cli_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIN_CLI_BIN").map(PathBuf::from)
}
fn program_so() -> Option<PathBuf> {
    let p = std::env::var("GLC_BRIDGE_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../target/deploy/glc_bridge.so"));
    p.exists().then_some(p)
}
/// The **real** `signer-server` binary, beside the test executable.
///
/// Deliberately the shipped artifact rather than an in-process tonic server:
/// this rig is about what a deployment actually runs.
fn signer_server_bin() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // .../target/debug/deps/<test>-<hash> -> .../target/debug/signer-server
    let dir = exe.parent()?.parent()?;
    let p = dir.join("signer-server");
    p.exists().then_some(p)
}
fn validator_available() -> bool {
    Command::new("solana-test-validator")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// =====================================================================
// Goldcoin regtest node
// =====================================================================

struct GoldNode {
    child: Child,
    cli: PathBuf,
    datadir: tempfile::TempDir,
    rpc_port: u16,
    p2p_port: u16,
    user: String,
    password: String,
}

impl GoldNode {
    fn start(bin: &Path, cli: &Path) -> Self {
        Self::start_connected(bin, cli, None)
    }

    /// Starts a node, optionally peered to another node's p2p port.
    ///
    /// Each signer must verify against **its own** Goldcoin node (ADR-0017
    /// E2), so this rig runs three. On regtest they only see the same chain
    /// if they are actually connected, hence `-connect`.
    fn start_connected(bin: &Path, cli: &Path, connect_to: Option<u16>) -> Self {
        let datadir = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let p2p_port = free_port();
        let user = "e2e_user".to_string();
        let password = format!("e2e_pw_{}", std::process::id());
        let mut cmd = Command::new(bin);
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", datadir.path().display()))
            .arg("-daemon=0")
            .arg("-printtoconsole=0")
            .arg(format!("-rpcuser={user}"))
            .arg(format!("-rpcpassword={password}"))
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .arg("-rpcbind=127.0.0.1")
            .arg("-rpcallowip=127.0.0.1")
            .arg("-fallbackfee=0.0001")
            .arg("-txindex=1");
        if let Some(peer) = connect_to {
            cmd.arg(format!("-connect=127.0.0.1:{peer}"));
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn goldcoind");
        let n = GoldNode {
            child,
            cli: cli.to_path_buf(),
            datadir,
            rpc_port,
            p2p_port,
            user,
            password,
        };
        for _ in 0..120 {
            if n.try_cli(&["getblockcount"]).is_some() {
                return n;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("goldcoind never became ready");
    }

    fn cli_cmd(&self) -> Command {
        let mut c = Command::new(&self.cli);
        c.arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.path().display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcuser={}", self.user))
            .arg(format!("-rpcpassword={}", self.password));
        c
    }
    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let o = self.cli_cmd().args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
    fn cli(&self, args: &[&str]) -> String {
        let o = self.cli_cmd().args(args).output().expect("goldcoin-cli");
        assert!(
            o.status.success(),
            "goldcoin-cli {:?} failed: {}",
            args,
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap().trim().to_string()
    }
    fn mine(&self, n: u32, to: &str) {
        self.cli(&["generatetoaddress", &n.to_string(), to]);
    }
    /// A real deposit: pays the vault and binds a Solana recipient in a
    /// 32-byte OP_RETURN, exactly the Phase 4 shape.
    fn send_deposit(&self, vault: &str, amount_glc: f64, recipient: &[u8; 32]) -> String {
        let payload = glc::hex::encode(recipient);
        let outputs = format!("{{\"{vault}\":{amount_glc},\"data\":\"{payload}\"}}");
        let raw = self.cli(&["createrawtransaction", "[]", &outputs]);
        let funded: serde_json::Value =
            serde_json::from_str(&self.cli(&["fundrawtransaction", &raw])).unwrap();
        let signed: serde_json::Value = serde_json::from_str(
            &self.cli(&["signrawtransaction", funded["hex"].as_str().unwrap()]),
        )
        .unwrap();
        self.cli(&["sendrawtransaction", signed["hex"].as_str().unwrap()])
    }
    fn rpc_config(&self) -> RpcConfigValidated {
        RpcConfigValidated {
            url: format!("http://127.0.0.1:{}", self.rpc_port),
            user: self.user.clone(),
            password: self.password.clone(),
            connect_timeout_ms: 5_000,
            read_timeout_ms: 30_000,
        }
    }
    fn raw_rpc_config(&self) -> RpcConfig {
        RpcConfig {
            url: format!("http://127.0.0.1:{}", self.rpc_port),
            user: self.user.clone(),
            password: self.password.clone(),
            connect_timeout_ms: 5_000,
            read_timeout_ms: 30_000,
        }
    }
    fn script_pubkey_of(&self, addr: &str) -> String {
        let v: serde_json::Value =
            serde_json::from_str(&self.cli(&["validateaddress", addr])).unwrap();
        v["scriptPubKey"].as_str().unwrap().to_string()
    }
    fn received(&self, addr: &str) -> f64 {
        self.cli(&["getreceivedbyaddress", addr, "1"])
            .parse()
            .unwrap()
    }
}

impl Drop for GoldNode {
    fn drop(&mut self) {
        let _ = self.cli_cmd().arg("stop").output();
        std::thread::sleep(Duration::from_millis(500));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// =====================================================================
// Solana test validator
// =====================================================================

struct SolNode {
    child: Child,
    _ledger: tempfile::TempDir,
    url: String,
}

impl SolNode {
    fn start(so: &Path, program_id: &Pubkey, upgrade_authority: &Pubkey) -> Self {
        let ledger = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let faucet_port = free_port();
        let child = Command::new("solana-test-validator")
            .arg("--reset")
            .arg("--quiet")
            .arg("--ledger")
            .arg(ledger.path())
            .arg("--rpc-port")
            .arg(rpc_port.to_string())
            .arg("--faucet-port")
            .arg(faucet_port.to_string())
            .arg("--bind-address")
            .arg("127.0.0.1")
            .arg("--upgradeable-program")
            .arg(program_id.to_string())
            .arg(so)
            .arg(upgrade_authority.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn solana-test-validator");
        let n = SolNode {
            child,
            _ledger: ledger,
            url: format!("http://127.0.0.1:{rpc_port}"),
        };
        let c = n.client();
        for _ in 0..240 {
            if c.get_health().is_ok() {
                return n;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("solana-test-validator never became healthy");
    }
    fn client(&self) -> BlockingRpcClient {
        BlockingRpcClient::new_with_commitment(self.url.clone(), CommitmentConfig::finalized())
    }
}

impl Drop for SolNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// =====================================================================
// Test PKI — a real CA issuing real leaf certificates
// =====================================================================

struct TestCa {
    ca_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new(common_name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let ca_pem = cert.pem();
        TestCa {
            ca_pem,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn issue(&self, name: &str) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn material_for(&self, name: &str) -> TlsMaterial {
        let (cert_pem, key_pem) = self.issue(name);
        TlsMaterial {
            ca_pem: self.ca_pem.clone().into_bytes(),
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
        }
    }
}

fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    p
}

// =====================================================================
// A real signer-server process
// =====================================================================

/// One operator's signing service: the **shipped binary**, its own Goldcoin
/// node, its own single vault key, behind its own certificate.
struct SignerProc {
    child: Child,
    validator_pubkey: Pubkey,
    endpoint: String,
    log_path: PathBuf,
    _dir: tempfile::TempDir,
}

impl SignerProc {
    /// The log this process wrote, which is the evidence of what it was
    /// actually asked to do.
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn peer(&self) -> PeerEndpoint {
        PeerEndpoint {
            validator_pubkey: self.validator_pubkey,
            uri: self.endpoint.clone(),
        }
    }
}

impl Drop for SignerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Configuration shared by every signer in the federation.
struct SignerCommon {
    program_id: Pubkey,
    solana_url: String,
    vault_address: String,
    vault_redeem_hex: String,
    operator_count: usize,
}

#[allow(clippy::too_many_arguments)]
fn spawn_signer(
    bin: &Path,
    ca: &TestCa,
    common: &SignerCommon,
    index: u8,
    validator_key: &Keypair,
    vault_wif: &str,
    node: &GoldNode,
    db_path: &Path,
) -> SignerProc {
    let dir = tempfile::tempdir().unwrap();
    let material = ca.material_for(FEDERATION_DOMAIN);
    let ca_path = write_file(
        dir.path(),
        "ca.pem",
        &String::from_utf8_lossy(&material.ca_pem),
    );
    let cert_path = write_file(
        dir.path(),
        "cert.pem",
        &String::from_utf8_lossy(&material.cert_pem),
    );
    let key_path = write_file(
        dir.path(),
        "key.pem",
        &String::from_utf8_lossy(&material.key_pem),
    );
    // The validator's ed25519 identity, in the JSON array form
    // `read_keypair_file` expects.
    let kp_path = write_file(
        dir.path(),
        "validator.json",
        &serde_json::to_string(&validator_key.to_bytes().to_vec()).unwrap(),
    );
    // Exactly ONE vault key, as ADR-0017 E1 requires.
    let wif_path = write_file(dir.path(), "vault.wif", vault_wif);
    let log_path = dir.path().join("signer.log");
    let log = std::fs::File::create(&log_path).unwrap();

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");

    let child = Command::new(bin)
        .env("GLC_SIGNER_VALIDATOR_KEYPAIR_PATH", &kp_path)
        .env("GLC_SIGNER_LISTEN_ADDR", &listen)
        .env("GLC_FEDERATION_CA_CERT_PATH", &ca_path)
        .env("GLC_SIGNER_TLS_CERT_PATH", &cert_path)
        .env("GLC_SIGNER_TLS_KEY_PATH", &key_path)
        .env("GLC_SIGNER_VAULT_INDEX", index.to_string())
        .env("GLC_SIGNER_VAULT_KEY_PATH", &wif_path)
        .env(
            "GLC_SIGNER_GLC_RPC_URL",
            format!("http://127.0.0.1:{}", node.rpc_port),
        )
        .env("GLC_SIGNER_GLC_RPC_USER", &node.user)
        .env("GLC_SIGNER_GLC_RPC_PASSWORD", &node.password)
        .env("GLC_SOLANA_RPC_URL", &common.solana_url)
        .env("GLC_SOLANA_COMMITMENT", "confirmed")
        .env(
            "GLC_PROGRAM_ID_HEX",
            glc::hex::encode(&common.program_id.to_bytes()),
        )
        .env("GLC_PROTOCOL_VERSION", "1")
        .env("GLC_DB_PATH", db_path)
        .env("GLC_VAULT_ADDRESS", &common.vault_address)
        .env("GLC_VAULT_CHANGE_ADDRESS", &common.vault_address)
        .env("GLC_VAULT_REDEEM_SCRIPT_HEX", &common.vault_redeem_hex)
        .env("GLC_VAULT_MIN_CONFIRMATIONS", "1")
        .env("GLC_WITHDRAWAL_CONFIRMATION_DEPTH", "2")
        .env("GLC_WITHDRAWAL_DISCOVERY_COMMITMENT", "finalized")
        .env("GLC_PAYOUT_FEE_RATE_PER_KB", "100000")
        .env("GLC_PAYOUT_DUST_THRESHOLD_ATOMIC", "5400")
        .env("GLC_PAYOUT_MAX_INPUTS", "20")
        .env("GLC_PAYOUT_RESERVATION_TIMEOUT_SECS", "900")
        .env("GLC_PAYOUT_BUILD_TIMEOUT_SECS", "120")
        .env("GLC_MINT_SUBMIT_TIMEOUT_SECS", "60")
        .env("GLC_OPERATOR_INDEX", index.to_string())
        .env("GLC_OPERATOR_COUNT", common.operator_count.to_string())
        .env("RUST_LOG", "info")
        // Both streams: which one a signer's subscriber writes to is not
        // this rig's business, and losing the evidence to the wrong pipe is
        // how a test ends up asserting nothing.
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn signer-server");

    let proc = SignerProc {
        child,
        validator_pubkey: validator_key.pubkey(),
        endpoint: format!("https://{listen}"),
        log_path,
        _dir: dir,
    };
    // Wait for it to bind, or surface why it refused to start.
    for _ in 0..160 {
        if std::net::TcpStream::connect(&listen).is_ok() {
            return proc;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "signer {index} never bound {listen}; its log said:\n{}",
        proc.log()
    );
}

/// Waits for an SPL token account to report `expected` atomic units.
///
/// The orchestrator submits at `confirmed` commitment while this client
/// reads at `finalized`, so a freshly-landed mint is briefly invisible here.
/// Polling avoids racing finality rather than weakening the assertion.
fn await_token_balance(c: &BlockingRpcClient, ata: &Pubkey, expected: u64, what: &str) {
    for _ in 0..120 {
        if let Ok(b) = c.get_token_account_balance(ata) {
            if b.amount == expected.to_string() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let actual = c
        .get_token_account_balance(ata)
        .map(|b| b.amount)
        .unwrap_or_else(|e| format!("<error: {e}>"));
    panic!("{what}: expected {expected} atomic units, got {actual}");
}

fn anchor_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    let mut o = [0u8; 8];
    o.copy_from_slice(&h[..8]);
    o
}

fn program_data_pda(pid: &Pubkey) -> Pubkey {
    #[allow(deprecated)]
    Pubkey::find_program_address(&[pid.as_ref()], &bpf_loader_upgradeable::id()).0
}

fn airdrop(c: &BlockingRpcClient, to: &Pubkey, lamports: u64) {
    let sig = c.request_airdrop(to, lamports).expect("airdrop");
    for _ in 0..200 {
        if c.confirm_transaction(&sig).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("airdrop never confirmed");
}

// =====================================================================
// The test
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn three_operator_federation_pays_out_a_real_withdrawal() {
    let (Some(gbin), Some(gcli)) = (goldcoind_bin(), goldcoin_cli_bin()) else {
        eprintln!("skipping rig: GOLDCOIND_BIN / GOLDCOIN_CLI_BIN not set");
        return;
    };
    let Some(so) = program_so() else {
        eprintln!("skipping rig: compiled program not found (run `anchor build`)");
        return;
    };
    let Some(sbin) = signer_server_bin() else {
        eprintln!("skipping rig: signer-server binary not built");
        return;
    };
    if !validator_available() {
        eprintln!("skipping rig: solana-test-validator not on PATH");
        return;
    }

    // EVIDENCE 6: the relayer's own logs, including the collector's round
    // summary ("N signed, N refused, N unavailable") and the reason it
    // recorded for each designated signer.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("glc_relayer=info")),
        )
        .with_test_writer()
        .try_init();

    // ---------- chains up ----------
    // Node 0 is the relayer's own node and the chain's source of truth;
    // nodes 1 and 2 belong to the other two signers and sync from it.
    let gold = GoldNode::start(&gbin, &gcli);
    let gold1 = GoldNode::start_connected(&gbin, &gcli, Some(gold.p2p_port));
    let gold2 = GoldNode::start_connected(&gbin, &gcli, Some(gold.p2p_port));
    let program_id: Pubkey = DECLARED_PROGRAM_ID.parse().unwrap();
    let authority = Keypair::new();
    let sol = SolNode::start(&so, &program_id, &authority.pubkey());
    let sc = sol.client();
    airdrop(&sc, &authority.pubkey(), 20_000_000_000);
    let submitter = Keypair::new();
    airdrop(&sc, &submitter.pubkey(), 20_000_000_000);

    // ---------- Goldcoin: vault + funds ----------
    let miner = gold.cli(&["getnewaddress"]);
    // A real P2SH 2-of-3 vault (Phase 7b, ADR-0015). The deposit side still
    // pays a P2PKH vault output — Phase 4 matches P2PKH only (owner
    // decision U5) — so the deposit vault and the payout vault are distinct
    // addresses, which is also how a real deployment separates them.
    let deposit_vault = gold.cli(&["getnewaddress"]);
    let signers: Vec<String> = (0..3).map(|_| gold.cli(&["getnewaddress"])).collect();
    let pubkeys: Vec<String> = signers
        .iter()
        .map(|a| {
            let v: serde_json::Value =
                serde_json::from_str(&gold.cli(&["validateaddress", a])).unwrap();
            v["pubkey"].as_str().unwrap().to_string()
        })
        .collect();
    let ms: serde_json::Value = serde_json::from_str(&gold.cli(&[
        "createmultisig",
        "2",
        &serde_json::to_string(&pubkeys).unwrap(),
    ]))
    .unwrap();
    let vault = ms["address"].as_str().unwrap().to_string();
    let vault_redeem = ms["redeemScript"].as_str().unwrap().to_string();
    // Phase 7e: the executor holds no vault key. It collects partials from
    // the designated quorum and assembles the scriptSig itself.
    let vault_wifs: Vec<(u8, String)> = signers
        .iter()
        .enumerate()
        .map(|(i, a)| (i as u8, gold.cli(&["dumpprivkey", a])))
        .collect();
    let _ = gold.try_cli(&["importaddress", &vault, "vault", "false"]);
    let _ = gold.try_cli(&[
        "importaddress",
        &vault_redeem,
        "vault-redeem",
        "false",
        "true",
    ]);
    let payout_dest = gold.cli(&["getnewaddress"]);
    gold.mine(130, &miner);
    let vault_script = gold.script_pubkey_of(&deposit_vault);

    // ---------- Solana: initialize + wrapped mint ----------
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let validator_pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let threshold: u8 = 2;
    let (bridge_config, _) = glc_ix::bridge_config_pda(&program_id);
    let (validator_set, _) = glc_ix::validator_set_pda(&program_id);
    let (mint_authority, _) = glc_ix::mint_authority_pda(&program_id);

    let mut init_data = anchor_disc("initialize").to_vec();
    init_data.extend_from_slice(&(validator_pubkeys.len() as u32).to_le_bytes());
    for v in &validator_pubkeys {
        init_data.extend_from_slice(v.as_ref());
    }
    init_data.push(threshold);
    init_data.extend_from_slice(&0u64.to_le_bytes()); // min_deposit
    init_data.extend_from_slice(&0u64.to_le_bytes()); // min_withdrawal

    // Two values with no built-in default, both rejected at zero, so tests
    // state them explicitly: the governance timelock (Phase 7a, ADR-0014)
    // and the wrapped-supply ceiling (Phase 7h-0, ADR-0014 §11.1).
    init_data.extend_from_slice(&3_600i64.to_le_bytes()); // governance_timelock_seconds
    init_data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_wrapped_supply
    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(validator_set, false),
            AccountMeta::new_readonly(program_id, false),
            AccountMeta::new_readonly(program_data_pda(&program_id), false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: init_data,
    };
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&authority.pubkey()),
        &[&authority],
        bh,
    ))
    .expect("initialize");

    let wrapped_mint_kp = Keypair::new();
    let create_mint_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new_readonly(mint_authority, false),
            AccountMeta::new(wrapped_mint_kp.pubkey(), true),
            AccountMeta::new_readonly(spl_token::ID, false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: anchor_disc("create_wrapped_mint").to_vec(),
    };
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[create_mint_ix],
        Some(&authority.pubkey()),
        &[&authority, &wrapped_mint_kp],
        bh,
    ))
    .expect("create_wrapped_mint");
    let wrapped_mint = wrapped_mint_kp.pubkey();

    // The depositor's Solana wallet, and its ATA (must pre-exist).
    let user = Keypair::new();
    airdrop(&sc, &user.pubkey(), 20_000_000_000);
    let user_ata =
        spl_associated_token_account::get_associated_token_address(&user.pubkey(), &wrapped_mint);
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[
            spl_associated_token_account::instruction::create_associated_token_account(
                &authority.pubkey(),
                &user.pubkey(),
                &wrapped_mint,
                &spl_token::ID,
            ),
        ],
        Some(&authority.pubkey()),
        &[&authority],
        bh,
    ))
    .expect("create user ATA");

    // ---------- STEP 1: real Goldcoin deposit ----------
    let deposit_glc = 40.0_f64;
    let deposit_atomic = 40_00000000u64;
    let deposit_txid = gold.send_deposit(&deposit_vault, deposit_glc, &user.pubkey().to_bytes());
    gold.mine(3, &miner);

    // ---------- STEP 2: indexer -> ReadyForSignature ----------
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relayer.sqlite3");
    Db::open(&db_path).unwrap();

    let indexer_config = IndexerConfig::validate(RawIndexerConfig {
        rpc: gold.raw_rpc_config(),
        db_path: db_path.clone(),
        vault_script_pubkey_hex: vault_script.clone(),
        confirmation_depth: 2,
        max_reorg_depth: 10,
        min_deposit_atomic: 0,
        value_caps: ValueCaps {
            max_deposit_atomic: None,
            rolling_window: None,
        },
        protocol_version: 1,
        program_id_hex: glc::hex::encode(&program_id.to_bytes()),
        validator_epoch: 0,
        wrapped_mint_hex: glc::hex::encode(&wrapped_mint.to_bytes()),
        node_unavailable_retry_interval_ms: 500,
        poll_interval_ms: 200,
    })
    .expect("indexer config");

    let mut indexer = Indexer::new(
        GlcRpcClient::new(&gold.rpc_config()).unwrap(),
        Db::open(&db_path).unwrap(),
        indexer_config,
    );
    for _ in 0..20 {
        indexer.tick().await.expect("indexer tick");
        let ready = Db::open(&db_path)
            .unwrap()
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap();
        if !ready.is_empty() {
            break;
        }
        gold.mine(1, &miner);
    }
    let ready = Db::open(&db_path)
        .unwrap()
        .candidates_by_state(DepositState::ReadyForSignature)
        .unwrap();
    assert_eq!(ready.len(), 1, "the real deposit reached ReadyForSignature");
    assert_eq!(ready[0].txid_hex, deposit_txid);
    assert_eq!(ready[0].amount_atomic, deposit_atomic);

    // ---------- STEP 3: mint orchestrator -> real SPL mint ----------
    let mut orch = Orchestrator::new(
        Db::open(&db_path).unwrap(),
        RealSolanaRpc::new(sol.url.clone(), CommitmentLevel::Confirmed),
        program_id,
        Keypair::try_from(submitter.to_bytes().as_slice()).unwrap(),
        // Test-only in-process signing; production wiring uses GrpcCollector
        // and the orchestrator holds no keys (ADR-0016).
        InProcessCollector::new(
            validators
                .iter()
                .map(|k| Keypair::try_from(k.to_bytes().as_slice()).unwrap())
                .collect(),
        ),
    );
    let mut minted = false;
    for _ in 0..40 {
        if orch.tick().await.expect("orchestrator tick").minted > 0 {
            minted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(minted, "deposit was minted on the real validator");

    await_token_balance(
        &sc,
        &user_ata,
        deposit_atomic,
        "user holds exactly the deposited amount in wrapped GLC",
    );

    // ---------- STEP 4: burn_wrapped -> real WithdrawalRequest PDA ----------
    let burn_atomic = 15_00000000u64; // 15 GLC back to Goldcoin
    let (withdrawal_pda, _) = discovery::withdrawal_pda(&program_id, 0);
    let mut burn_data = anchor_disc("burn_wrapped").to_vec();
    burn_data.extend_from_slice(&burn_atomic.to_le_bytes());
    burn_data.extend_from_slice(&(payout_dest.len() as u32).to_le_bytes());
    burn_data.extend_from_slice(payout_dest.as_bytes());
    let burn_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(wrapped_mint, false),
            AccountMeta::new(user_ata, false),
            AccountMeta::new(withdrawal_pda, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: burn_data,
    };
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[burn_ix],
        Some(&user.pubkey()),
        &[&user],
        bh,
    ))
    .expect("burn_wrapped");

    await_token_balance(
        &sc,
        &user_ata,
        deposit_atomic - burn_atomic,
        "wrapped tokens were really burned",
    );

    // ---------- STEP 5: withdrawal discovery over the real validator ----------
    let discovery_rpc = RealSolanaRpc::new(sol.url.clone(), CommitmentLevel::Finalized);
    let mut found = Vec::new();
    for _ in 0..40 {
        found = discovery::scan_withdrawals(
            &discovery_rpc,
            &program_id,
            CommitmentLevel::Finalized,
            1_000,
            0,
        )
        .await
        .expect("scan");
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(found.len(), 1, "the real WithdrawalRequest was discovered");
    assert_eq!(found[0].withdrawal_index, 0);
    assert_eq!(found[0].amount_atomic, burn_atomic);
    assert_eq!(found[0].glc_address, payout_dest);

    // Fund the P2SH payout vault so the executor has spendable inputs.
    gold.cli(&["sendtoaddress", &vault, "60.0"]);
    gold.mine(3, &miner);

    // ---------- the other two operators' nodes ----------
    //
    // Each signer verifies the proposed payout against its OWN node
    // (ADR-0017 E2), so both must have the vault in view and must have
    // caught up to the chain that funded it.
    // Rescan is required, not optional: the vault was funded before these
    // nodes imported it, so without a rescan their wallets never learn about
    // the UTXO and the signer refuses an input it cannot see.
    for n in [&gold1, &gold2] {
        let _ = n.try_cli(&["importaddress", &vault, "vault", "true"]);
        let _ = n.try_cli(&[
            "importaddress",
            &vault_redeem,
            "vault-redeem",
            "true",
            "true",
        ]);
    }
    let tip: i64 = gold.cli(&["getblockcount"]).parse().unwrap();
    for n in [&gold1, &gold2] {
        let mut synced = false;
        for _ in 0..120 {
            if n.try_cli(&["getblockcount"])
                .and_then(|c| c.parse::<i64>().ok())
                .is_some_and(|c| c >= tip)
            {
                synced = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(
            synced,
            "a signer's Goldcoin node never caught up to the chain"
        );
    }

    // ---------- STEP 6: executor -> real Goldcoin payout ----------
    let w_config = WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_redeem_script_hex: vault_redeem.clone(),
        vault_address: vault.clone(),
        change_address: vault.clone(),
        fee_rate_per_kb: 100_000,
        dust_threshold_atomic: 5_400,
        vault_min_confirmations: 1,
        confirmation_depth: 2,
        max_inputs_per_payout: 20,
        reservation_timeout_secs: 900,
        discovery_commitment: "finalized".into(),
        poll_interval_ms: 500,
    })
    .expect("withdrawal config");

    // ---------- the federation: three real signer-server processes ----------
    let ca = TestCa::new("glc-federation-test-ca");
    let common = SignerCommon {
        program_id,
        solana_url: sol.url.clone(),
        vault_address: vault.clone(),
        vault_redeem_hex: vault_redeem.clone(),
        operator_count: 3,
    };
    let signer_nodes = [&gold, &gold1, &gold2];

    // The epoch actually on chain, read the same way a signer reads it.
    // Seeding a different one makes every signer refuse — correctly, under
    // ADR-0016 — which would mask the defect this rig exists to expose.
    let chain_epoch = glc_relayer::solana::epoch::observe_epoch(
        &RealSolanaRpc::new(sol.url.clone(), CommitmentLevel::Confirmed),
        &program_id,
    )
    .await
    .expect("observe the on-chain validator epoch");
    eprintln!("rig: on-chain validator epoch is {chain_epoch}");

    // Each operator runs its own relayer, so each has independently
    // discovered withdrawal 0 from Solana and holds it in its own database
    // — the one its signer-server reads. A signer will not sign a payout for
    // a withdrawal it has never seen (ADR-0017), and that independence is
    // the point: operator 0 asserting the withdrawal exists is not evidence.
    let signer_dbs: Vec<PathBuf> = (0..3)
        .map(|i| {
            // Operator 0's signer shares the relayer's database, because on a
            // real host they are one operator with one `GLC_DB_PATH`. Giving
            // it a separate database would hide the fix behind a state
            // mismatch the deployment does not have.
            let p = if i == 0 {
                db_path.clone()
            } else {
                dir.path().join(format!("operator{i}.sqlite3"))
            };
            let mut db = Db::open(&p).unwrap();
            for w in &found {
                db.observe_withdrawal(w).expect("observe withdrawal");
            }
            p
        })
        .collect();

    let signers: Vec<SignerProc> = (0..3u8)
        .map(|i| {
            spawn_signer(
                &sbin,
                &ca,
                &common,
                i,
                &validators[i as usize],
                &vault_wifs[i as usize].1,
                signer_nodes[i as usize],
                &signer_dbs[i as usize],
            )
        })
        .collect();

    // The passive operators' relayers tick too, which is how withdrawal 0
    // advances out of `Observed` in *their* databases. A signer refuses to
    // sign for a withdrawal its own operator has not yet validated, so
    // without this the rig would prove nothing about the defect under test.
    //
    // They are given a long build window and a non-designated index, so
    // ADR-0019 keeps them from building a competing payout: they validate,
    // and then adopt operator 0's proposal when it arrives.
    for (i, p) in signer_dbs.iter().enumerate().skip(1) {
        let node = signer_nodes[i];
        let mut passive = WithdrawalExecutor::new(
            Db::open(p).unwrap(),
            RealPayoutRpc::new(GlcRpcClient::new(&node.rpc_config()).unwrap()),
            w_config.clone(),
            // A passive operator signs nothing in this rig; its vault key
            // lives in its signer-server, where it belongs.
            InProcessPayoutCollector::from_wifs(w_config.vault.clone(), &[]).unwrap(),
            std::sync::Arc::new(EpochObservation::seeded(chain_epoch, now_unix())),
        )
        .with_assignment(OperatorAssignment::new(i, 3, 3_600, 3_600).unwrap());
        passive.tick().await.expect("passive operator tick");
    }

    // This relayer IS operator 0. `GLC_FEDERATION_PEERS` therefore contains
    // only operators 1 and 2 — `main.rs` refuses to start otherwise — and
    // the relayer's own signer is added separately, exactly as
    // `collector_from_env` now does.
    let peers: Vec<PeerEndpoint> = glc_relayer::p2p::identity::with_local_signer(
        signers[1..].iter().map(|s| s.peer()).collect(),
        validators[0].pubkey(),
        &signers[0].endpoint,
    )
    .expect("local signer endpoint");
    let signer_map_raw = (0..3)
        .map(|i| format!("{i}:{}", validators[i].pubkey()))
        .collect::<Vec<_>>()
        .join(",");
    let vault_signer_map = VaultSignerMap::parse(&signer_map_raw, &w_config.vault)
        .expect("vault signer map must match the vault");

    // EVIDENCE 1 + 2: the quorum this withdrawal designates, and who that is.
    let quorum = glc_relayer::withdrawal::assignment::designate_quorum(
        0,
        w_config.vault.signer_count(),
        w_config.vault.threshold,
    );
    // Who ADR-0019 designates to build withdrawal 0 — asked rather than
    // assumed, since the whole point is that this operator turns out to be
    // a member of the quorum it is building for.
    let builder = OperatorAssignment::new(0, 3, 120, 60)
        .unwrap()
        .designated_for(0);
    eprintln!("EVIDENCE 1: withdrawal 0 designates quorum {quorum:?}");
    eprintln!("EVIDENCE 2: those positions are validators:");
    for i in &quorum {
        eprintln!("    position {i} -> {}", validators[*i as usize].pubkey());
    }
    eprintln!(
        "  this relayer is operator {builder} ({}), and its peer list is:",
        validators[builder].pubkey()
    );
    for p in &peers {
        eprintln!("    {} @ {}", p.validator_pubkey, p.uri);
    }

    let material = ca.material_for(FEDERATION_DOMAIN);
    let make_executor = || {
        let collector = FederationPayoutCollector::new(
            GrpcCollector::new(
                peers.clone(),
                material.clone(),
                FEDERATION_DOMAIN.to_string(),
            ),
            w_config.vault.clone(),
            vault_signer_map.clone(),
            builder as u32,
        );
        WithdrawalExecutor::new(
            Db::open(&db_path).unwrap(),
            RealPayoutRpc::new(GlcRpcClient::new(&gold.rpc_config()).unwrap()),
            w_config.clone(),
            collector,
            // The epoch the SIGNERS observe on chain. Seeding a different
            // one makes every signer refuse — correctly, under ADR-0016 —
            // and would mask the defect this rig exists to expose.
            std::sync::Arc::new(EpochObservation::seeded(chain_epoch, now_unix())),
        )
    };

    let mut exec = make_executor();
    exec.ingest_discovered(&found).expect("ingest");
    exec.tick().await.expect("withdrawal tick");

    // EVIDENCE 3 + 4 + 5: which signer-servers were actually asked.
    //
    // Read from the signer's OWN durable record, not from a guess about its
    // logging. A signer that grants a payout writes an ADR-0026 grant
    // (`event=signature_granted action=payout`); one that declines writes
    // "refused a payout signing request". A signer that was never contacted
    // writes neither — and that distinction is the whole question here.
    let mut asked: BTreeMap<usize, &'static str> = BTreeMap::new();
    for (i, s) in signers.iter().enumerate() {
        let log = s.log();
        let outcome = if log.contains("signature_granted") && log.contains("payout") {
            "GRANTED"
        } else if log.contains("refused a payout signing request") {
            "REFUSED"
        } else {
            "NEVER CONTACTED"
        };
        asked.insert(i, outcome);
        eprintln!(
            "EVIDENCE 3/4: signer {i} ({}) -> {outcome}",
            validators[i].pubkey()
        );
        eprintln!("---- signer {i} log ----\n{}\n---- end ----", log.trim());
    }
    eprintln!("EVIDENCE 5: quorum is {quorum:?}; per-signer outcome {asked:?}");

    let state = Db::open(&db_path)
        .unwrap()
        .get_withdrawal(0)
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(
        state,
        WithdrawalState::Confirming,
        "the payout must be signed by the designated quorum {quorum:?} and broadcast.\n\
         Withdrawal 0 designates quorum {quorum:?}; this relayer is operator {builder}, which is \
         ITSELF a member of that quorum. Signers contacted: {asked:?}.\n\
         If it is stuck in Signing with only one partial collected, the relayer never asked its \
         own signer-server, because a relayer's peer list contains only the OTHER operators."
    );

    gold.mine(3, &miner);
    for _ in 0..10 {
        make_executor().tick().await.expect("withdrawal tick");
        let s = Db::open(&db_path)
            .unwrap()
            .get_withdrawal(0)
            .unwrap()
            .unwrap()
            .state;
        if s == WithdrawalState::Completed {
            break;
        }
        gold.mine(1, &miner);
    }

    // ---------- the round trip is closed ----------
    let final_state = Db::open(&db_path)
        .unwrap()
        .get_withdrawal(0)
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(final_state, WithdrawalState::Completed);

    let received = gold.received(&payout_dest);
    assert!(
        (received - 15.0).abs() < 1e-9,
        "the destination received exactly 15.0 GLC (the burned amount, vault paid the fee); got {received}"
    );

    let payout = Db::open(&db_path).unwrap().get_payout(0).unwrap().unwrap();
    assert_eq!(
        payout.payout_atomic, burn_atomic,
        "payout == burned amount (D3)"
    );
    assert!(payout.fee_atomic > 0, "the vault absorbed a real fee");
    assert!(payout.completed_at.is_some());

    // And exactly one payout exists for that withdrawal — never two.
    let payouts: i64 = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM withdrawal_payouts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(payouts, 1);
}
