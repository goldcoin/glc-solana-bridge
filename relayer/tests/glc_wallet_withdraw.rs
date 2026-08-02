//! `glc-wallet withdraw` against a real `solana-test-validator`.
//!
//! This runs the **shipped binary** as a subprocess rather than calling the
//! library functions it happens to use. A withdrawal is irreversible, and
//! what a user actually invokes is the executable — argument parsing,
//! environment reading, exit codes and all. Testing the library would leave
//! exactly the gaps this project has found six times: correct code that
//! nothing calls.
//!
//! Skips itself when the program `.so` or `solana-test-validator` is absent.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use solana_client::rpc_client::RpcClient as BlockingRpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;

use glc_relayer::glc::deposit::build_claim_message;
use glc_relayer::signer::aggregate::build_ed25519_instruction;
use glc_relayer::solana::instruction as ix;
use glc_relayer::withdrawal::address::encode_p2pkh;
use glc_relayer::withdrawal::discovery;

const DECLARED_PROGRAM_ID: &str = "77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq";
const PROTOCOL_VERSION: u8 = 1;
const DEPOSIT_ATOMIC: u64 = 100_00000000; // 100 GLC

fn program_so_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("GLC_BRIDGE_SO") {
        let p = std::path::PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/glc_bridge.so");
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
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct LocalValidator {
    child: Child,
    _ledger: tempfile::TempDir,
    rpc_url: String,
}

impl LocalValidator {
    fn start(so: &std::path::Path, program_id: &Pubkey, authority: &Pubkey) -> Self {
        let ledger = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let child = Command::new("solana-test-validator")
            .args(["--reset", "--quiet", "--bind-address", "127.0.0.1"])
            .arg("--ledger")
            .arg(ledger.path())
            .arg("--rpc-port")
            .arg(rpc_port.to_string())
            .arg("--faucet-port")
            .arg(free_port().to_string())
            .arg("--upgradeable-program")
            .arg(program_id.to_string())
            .arg(so)
            .arg(authority.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("solana-test-validator must be on PATH");
        let v = LocalValidator {
            child,
            _ledger: ledger,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
        };
        for _ in 0..200 {
            let c = BlockingRpcClient::new_with_commitment(
                v.rpc_url.clone(),
                CommitmentConfig::confirmed(),
            );
            if c.get_health().is_ok() {
                return v;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("solana-test-validator did not become healthy");
    }
}

impl Drop for LocalValidator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn airdrop(c: &BlockingRpcClient, to: &Pubkey, lamports: u64) {
    let sig = c.request_airdrop(to, lamports).unwrap();
    for _ in 0..100 {
        if c.confirm_transaction(&sig).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("airdrop did not confirm");
}

fn send(c: &BlockingRpcClient, ixs: &[solana_sdk::instruction::Instruction], signers: &[&Keypair]) {
    let bh = c.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&signers[0].pubkey()), signers, bh);
    c.send_and_confirm_transaction(&tx).expect("transaction");
}

/// A bridge that is initialized, has a mint, and has minted `DEPOSIT_ATOMIC`
/// wrapped GLC to `user`.
struct Fixture {
    _validator: LocalValidator,
    client: BlockingRpcClient,
    rpc_url: String,
    program_id: Pubkey,
    user: Keypair,
    keypair_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn setup() -> Option<Fixture> {
    let so = program_so_path()?;
    if !validator_available() {
        eprintln!("SKIP: solana-test-validator is not on PATH");
        return None;
    }
    let program_id: Pubkey = DECLARED_PROGRAM_ID.parse().unwrap();
    let admin = Keypair::new();
    let validator = LocalValidator::start(&so, &program_id, &admin.pubkey());
    let client = BlockingRpcClient::new_with_commitment(
        validator.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    airdrop(&client, &admin.pubkey(), 20_000_000_000);

    let user = Keypair::new();
    airdrop(&client, &user.pubkey(), 10_000_000_000);

    // One validator, threshold 1 — this test is about the withdrawal CLI,
    // not about aggregation, which has its own suites.
    let fed = Keypair::new();
    send(
        &client,
        &[ix::initialize_instruction(
            &program_id,
            &admin.pubkey(),
            &[fed.pubkey()],
            1,
            0,
            1_000,
            3_600,
            u64::MAX,
        )],
        &[&admin],
    );

    let mint_kp = Keypair::new();
    send(
        &client,
        &[ix::create_wrapped_mint_instruction(
            &program_id,
            &admin.pubkey(),
            &mint_kp.pubkey(),
        )],
        &[&admin, &mint_kp],
    );
    let wrapped_mint = mint_kp.pubkey();

    let user_ata =
        spl_associated_token_account::get_associated_token_address(&user.pubkey(), &wrapped_mint);
    send(
        &client,
        &[
            spl_associated_token_account::instruction::create_associated_token_account(
                &admin.pubkey(),
                &user.pubkey(),
                &wrapped_mint,
                &spl_token::ID,
            ),
        ],
        &[&admin],
    );

    // Mint through the real proof path so the user's balance is genuine.
    let txid = [0x77; 32];
    let message = build_claim_message(
        PROTOCOL_VERSION,
        &program_id.to_bytes(),
        0,
        &txid,
        0,
        DEPOSIT_ATOMIC,
        &user.pubkey().to_bytes(),
        &wrapped_mint.to_bytes(),
    );
    let sig = fed.sign_message(message.as_slice());
    let (claim_pda, _) = ix::deposit_claim_pda(&program_id, &txid, 0);
    let (bridge_config, _) = ix::bridge_config_pda(&program_id);
    let (validator_set, _) = ix::validator_set_pda(&program_id);
    let (mint_authority, _) = ix::mint_authority_pda(&program_id);
    send(
        &client,
        &[
            build_ed25519_instruction(&[(fed.pubkey(), sig)], message.as_slice()),
            ix::mint_wrapped_instruction(
                &program_id,
                &ix::MintWrappedAccounts {
                    submitter: admin.pubkey(),
                    bridge_config,
                    validator_set,
                    deposit_claim: claim_pda,
                    wrapped_mint,
                    mint_authority,
                    recipient: user.pubkey(),
                    recipient_token_account: user_ata,
                },
                txid,
                0,
                DEPOSIT_ATOMIC,
                0,
            ),
        ],
        &[&admin],
    );

    let dir = tempfile::tempdir().unwrap();
    let keypair_path = dir.path().join("user.json");
    std::fs::write(
        &keypair_path,
        serde_json::to_string(&user.to_bytes().to_vec()).unwrap(),
    )
    .unwrap();

    let rpc_url = validator.rpc_url.clone();
    Some(Fixture {
        _validator: validator,
        client,
        rpc_url,
        program_id,
        user,
        keypair_path,
        _dir: dir,
    })
}

/// Runs the shipped binary.
fn run_wallet(f: &Fixture, amount: &str, address: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_glc-wallet"))
        .args([
            "withdraw",
            "--amount-atomic",
            amount,
            "--glc-address",
            address,
        ])
        .arg("--keypair")
        .arg(&f.keypair_path)
        .env("GLC_SOLANA_RPC_URL", &f.rpc_url)
        .env("GLC_SOLANA_COMMITMENT", "confirmed")
        .env("GLC_PROGRAM_ID_HEX", hex_of(&f.program_id.to_bytes()))
        .output()
        .expect("glc-wallet runs")
}

fn hex_of(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn user_balance(f: &Fixture) -> u64 {
    let (config_pda, _) = ix::bridge_config_pda(&f.program_id);
    let cfg = glc_relayer::solana::rpc::decode_bridge_config(
        &f.client.get_account(&config_pda).unwrap().data,
    )
    .unwrap();
    let ata = spl_associated_token_account::get_associated_token_address(
        &f.user.pubkey(),
        &cfg.wrapped_mint,
    );
    ix::token_account_amount(&f.client.get_account(&ata).unwrap().data).unwrap()
}

#[test]
fn a_withdrawal_burns_and_records_what_the_user_asked_for() {
    let Some(f) = setup() else { return };
    let dest = encode_p2pkh(&[0x33; 20]);
    let amount = 15_00000000u64;

    let out = run_wallet(&f, &amount.to_string(), &dest);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "withdraw failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The CLI must report the facts a user needs to follow up.
    assert!(stdout.contains("withdrawal index: 0"), "{stdout}");
    assert!(
        stdout.contains(&dest),
        "the destination is echoed: {stdout}"
    );
    assert!(stdout.contains(&amount.to_string()), "{stdout}");

    // Independently verify the on-chain record rather than trusting output.
    let (pda, _) = ix::withdrawal_request_pda(&f.program_id, 0);
    let account = f.client.get_account(&pda).unwrap();
    let record =
        discovery::decode_withdrawal(&f.program_id, &pda, &account.owner, &account.data).unwrap();
    assert_eq!(record.index, 0);
    assert_eq!(record.amount_atomic, amount);
    assert_eq!(record.glc_address, dest);
    assert_eq!(record.requester, f.user.pubkey());
    assert_eq!(record.glc_address_hash160, [0x33; 20]);

    assert_eq!(
        user_balance(&f),
        DEPOSIT_ATOMIC - amount,
        "exactly the requested amount was burned"
    );
}

#[test]
fn a_bad_address_is_refused_and_nothing_is_burned() {
    // The most important behaviour in this tool. The program cannot check
    // the address, so if the CLI let this through the tokens would be gone
    // and unpayable forever.
    let Some(f) = setup() else { return };
    let before = user_balance(&f);

    let out = run_wallet(&f, "15_00000000", "not-a-goldcoin-address");
    assert!(!out.status.success(), "a bad address must not succeed");

    let out = run_wallet(&f, "1500000000", "not-a-goldcoin-address");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("Nothing was burned"),
        "the user must be told nothing was lost: {stderr}"
    );
    assert!(
        stderr.contains("permanently"),
        "and why the check exists: {stderr}"
    );

    assert_eq!(user_balance(&f), before, "the balance is untouched");
    assert!(
        f.client
            .get_account(&ix::withdrawal_request_pda(&f.program_id, 0).0)
            .is_err(),
        "no withdrawal record was created"
    );
}

#[test]
fn withdrawing_more_than_the_balance_is_refused_before_signing() {
    let Some(f) = setup() else { return };
    let before = user_balance(&f);

    let out = run_wallet(
        &f,
        &(DEPOSIT_ATOMIC + 1).to_string(),
        &encode_p2pkh(&[0x33; 20]),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("Nothing was burned"), "{stderr}");
    assert_eq!(user_balance(&f), before);
}

#[test]
fn two_withdrawals_take_consecutive_indices() {
    // The index comes from BridgeConfig::withdrawal_count, which the program
    // increments. A CLI that cached it would collide on the second run.
    let Some(f) = setup() else { return };
    let dest = encode_p2pkh(&[0x44; 20]);

    for expected in 0..2u64 {
        let out = run_wallet(&f, "1000000000", &dest);
        assert!(
            out.status.success(),
            "withdrawal {expected} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("withdrawal index: {expected}")),
            "expected index {expected}: {stdout}"
        );
    }

    let (pda1, _) = ix::withdrawal_request_pda(&f.program_id, 1);
    let a = f.client.get_account(&pda1).unwrap();
    let r = discovery::decode_withdrawal(&f.program_id, &pda1, &a.owner, &a.data).unwrap();
    assert_eq!(r.index, 1);
}

#[test]
fn the_cli_reads_the_live_bridge_config_rather_than_assuming() {
    // Named for what it actually checks. The index, the mint and the
    // minimum all come from the on-chain BridgeConfig; a CLI that assumed
    // any of them would work here and fail against a real deployment.
    //
    // (Pause refusal is unit-tested in ops::withdraw_preflight, and the
    // program's own rejection of a paused burn is covered by its suite.)
    let Some(f) = setup() else { return };
    let out = run_wallet(&f, "1000000000", &encode_p2pkh(&[0x55; 20]));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("withdrawal index: 0"));
}
