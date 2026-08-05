//! **Rehearsal: vault compromise response** (Phase 7j).
//!
//! ADR-0014 §8.7 has required since Phase 7 that the compromise response be
//! "rehearsed on testnet, not written and filed". Until this file, it never
//! had been — the sweep was implemented in Phase 7i-0 and verified only
//! against unit fixtures. This runs the *documented procedure* from
//! `docs/runbooks.md` §5 against a real `goldcoind`, and checks what a
//! rehearsal is actually for: that the claims the runbook makes are true.
//!
//! # What is rehearsed here, and what is not
//!
//! **Here:** steps 4–6 of runbook §5 — plan, approve on every operator's
//! signer, collect partials, assemble, broadcast, confirm. Against a real
//! node, real P2SH multisig, real consensus rules.
//!
//! **Not here:** the pause (Solana-side; see `rehearsal_rotation.rs`) and
//! the physical key ceremony (ADR-0014 §8.3), which no test can perform.
//!
//! # Why the signers each get one key
//!
//! Production splits the vault keys across operators, and the whole point of
//! the sweep design is that **M humans each approve**. A rehearsal in which
//! one process holds every key would exercise none of that, so each
//! `SweepView` here is constructed with exactly one vault index and its own
//! approvals file — the same shape `signer-server` builds in production.
//!
//! Skips itself when `GOLDCOIND_BIN` / `GOLDCOIN_CLI_BIN` are unset, exactly
//! like the other real-node suites.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use glc_relayer::glc::config::RpcConfigValidated;
use glc_relayer::glc::db::Db;
use glc_relayer::glc::rpc::{BroadcastOutcome, PrevTx, RpcClient};
use glc_relayer::glc::withdrawal_db::ObservedUtxo;
use glc_relayer::p2p::payout_view::PartialSigner;
use glc_relayer::p2p::sweep_view::{SweepApproval, SweepRefusal, SweepView};
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::multisig::{assemble, PartialSignature, Transaction};
use glc_relayer::withdrawal::sweep::{plan_sweep, SweepDestination, SweepPlan};

const PROTOCOL_VERSION: u8 = 1;

fn goldcoind_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIND_BIN").map(PathBuf::from)
}
fn goldcoin_cli_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIN_CLI_BIN").map(PathBuf::from)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct RegtestNode {
    child: Child,
    cli: PathBuf,
    datadir: tempfile::TempDir,
    rpc_port: u16,
    user: String,
    password: String,
}

impl RegtestNode {
    fn start(goldcoind: &Path, cli: &Path) -> Self {
        let datadir = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let p2p_port = free_port();
        let user = "glc_r_user".to_string();
        let password = format!("glc_r_pw_{}", std::process::id());
        let child = Command::new(goldcoind)
            .arg("-regtest")
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0001")
            .arg(format!("-datadir={}", datadir.path().display()))
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .arg(format!("-rpcuser={user}"))
            .arg(format!("-rpcpassword={password}"))
            .arg("-rpcbind=127.0.0.1")
            .arg("-rpcallowip=127.0.0.1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn goldcoind");
        let node = RegtestNode {
            child,
            cli: cli.to_path_buf(),
            datadir,
            rpc_port,
            user,
            password,
        };
        node.wait_ready();
        node
    }

    fn wait_ready(&self) {
        for _ in 0..200 {
            if self.try_cli(&["getblockchaininfo"]).is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("goldcoind did not become ready");
    }

    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let out = Command::new(&self.cli)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.path().display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcuser={}", self.user))
            .arg(format!("-rpcpassword={}", self.password))
            .args(args)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args)
            .unwrap_or_else(|| panic!("goldcoin-cli {args:?} failed"))
    }

    fn rpc(&self) -> RpcClient {
        RpcClient::new(&RpcConfigValidated {
            url: format!("http://127.0.0.1:{}", self.rpc_port),
            user: self.user.clone(),
            password: self.password.clone(),
            connect_timeout_ms: 5_000,
            read_timeout_ms: 30_000,
        })
        .unwrap()
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One operator's vault key, signing on the node — the production shape,
/// with a single key per signer.
struct OneKeySigner {
    rpc: RpcClient,
    wif: String,
}

impl PartialSigner for OneKeySigner {
    async fn sign_partial(
        &self,
        unsigned_tx_hex: &str,
        prevtxs: &[PrevTx],
    ) -> Result<String, String> {
        self.rpc
            .sign_raw_transaction_with_prevtxs(
                unsigned_tx_hex,
                prevtxs,
                Some(std::slice::from_ref(&self.wif)),
            )
            .await
            .map(|r| r.hex)
            .map_err(|e| e.to_string())
    }
}

/// A 2-of-3 P2SH vault built by the node, funded with `count` mature
/// outputs — the "compromised" vault the rehearsal escapes from.
struct Vault {
    address: String,
    redeem_hex: String,
    hash160: [u8; 20],
    wifs: Vec<String>,
}

fn build_vault(node: &RegtestNode) -> Vault {
    let addrs: Vec<String> = (0..3).map(|_| node.cli(&["getnewaddress"])).collect();
    let pubkeys: Vec<String> = addrs
        .iter()
        .map(|a| {
            let v: serde_json::Value =
                serde_json::from_str(&node.cli(&["validateaddress", a])).unwrap();
            v["pubkey"].as_str().unwrap().to_string()
        })
        .collect();
    let ms: serde_json::Value = serde_json::from_str(&node.cli(&[
        "createmultisig",
        "2",
        &serde_json::to_string(&pubkeys).unwrap(),
    ]))
    .unwrap();
    let address = ms["address"].as_str().unwrap().to_string();
    let redeem_hex = ms["redeemScript"].as_str().unwrap().to_string();
    let wifs: Vec<String> = addrs
        .iter()
        .map(|a| node.cli(&["dumpprivkey", a]))
        .collect();
    let _ = node.try_cli(&["importaddress", &address, "v", "false"]);
    let _ = node.try_cli(&["importaddress", &redeem_hex, "vr", "false", "true"]);

    let hash160 = {
        use glc_relayer::withdrawal::vault::MultisigVault;
        MultisigVault::from_redeem_script_hex(&redeem_hex)
            .unwrap()
            .script_hash160
    };
    Vault {
        address,
        redeem_hex,
        hash160,
        wifs,
    }
}

fn cfg_for(vault: &Vault) -> WithdrawalConfig {
    WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_redeem_script_hex: vault.redeem_hex.clone(),
        vault_address: vault.address.clone(),
        change_address: vault.address.clone(),
        fee_rate_per_kb: 100_000,
        dust_threshold_atomic: 5_400,
        vault_min_confirmations: 1,
        confirmation_depth: 1,
        max_inputs_per_payout: 20,
        reservation_timeout_secs: 900,
        discovery_commitment: "finalized".into(),
        poll_interval_ms: 500,
    })
    .unwrap()
}

/// Mirrors `available_utxos` into this operator's database, as the real
/// reconciliation loop does. The sweep signer reads amounts only from here.
fn sync_vault(db: &mut Db, node: &RegtestNode, vault: &Vault) -> u64 {
    let listed = node.cli(&[
        "listunspent",
        "1",
        "9999999",
        &format!("[\"{}\"]", vault.address),
    ]);
    let rows: serde_json::Value = serde_json::from_str(&listed).unwrap();
    let mut observed = Vec::new();
    let mut total = 0u64;
    for r in rows.as_array().unwrap() {
        // Mirrors `RealPayoutRpc::list_unspent` exactly: the txid is stored
        // in DISPLAY order, as the node reports it. `createrawtransaction`
        // wants that same order, and the conversion to the internal order a
        // transaction carries happens at comparison time
        // (`withdrawal::sweep::internal_txid`).
        let txid_hex = r["txid"].as_str().unwrap();
        let txid = glc_relayer::glc::hex::decode_exact::<32>(txid_hex).unwrap();
        let amount = (r["amount"].as_f64().unwrap() * 100_000_000.0).round() as u64;
        total += amount;
        observed.push(ObservedUtxo {
            txid,
            vout: r["vout"].as_i64().unwrap(),
            amount_atomic: amount,
            script_pubkey_hex: r["scriptPubKey"].as_str().unwrap().to_string(),
            confirmations: r["confirmations"].as_i64().unwrap(),
        });
    }
    db.sync_vault_utxos(&observed, 1, 1_000).unwrap();
    total
}

fn stage(path: &Path, commitment: [u8; 32], expiry: i64, note: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(
        SweepApproval {
            commitment,
            expiry_unix: expiry,
            note: note.to_string(),
        }
        .to_text()
        .as_bytes(),
    )
    .unwrap();
}

fn maybe_node() -> Option<RegtestNode> {
    let (Some(d), Some(c)) = (goldcoind_bin(), goldcoin_cli_bin()) else {
        eprintln!("SKIP: set GOLDCOIND_BIN and GOLDCOIN_CLI_BIN to rehearse against a real node");
        return None;
    };
    Some(RegtestNode::start(&d, &c))
}

/// **Runbook §5, steps 4–6, end to end against a real node.**
#[tokio::test(flavor = "multi_thread")]
async fn the_documented_compromise_response_moves_the_whole_vault() {
    let Some(node) = maybe_node() else { return };
    let miner = node.cli(&["getnewaddress"]);
    node.cli(&["generatetoaddress", "130", &miner]);

    // The vault we are escaping from, funded with three separate outputs so
    // the sweep really has to combine them.
    let old = build_vault(&node);
    // Lock each vault output as it is created: left alone the wallet happily
    // spends the vault's own output as the input to the next send and
    // consolidates all three into one. A real property of wallet-held
    // custody, documented in regtest_withdrawal.rs, not a test artifact.
    for _ in 0..3 {
        node.cli(&["sendtoaddress", &old.address, "40.0"]);
        node.cli(&["generatetoaddress", "1", &miner]);
        let listed = node.cli(&[
            "listunspent",
            "1",
            "9999999",
            &format!("[\"{}\"]", old.address),
        ]);
        let rows: serde_json::Value = serde_json::from_str(&listed).unwrap();
        let sel: Vec<serde_json::Value> = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|r| serde_json::json!({"txid": r["txid"], "vout": r["vout"]}))
            .collect();
        if !sel.is_empty() {
            node.cli(&[
                "lockunspent",
                "false",
                &serde_json::to_string(&sel).unwrap(),
            ]);
        }
    }
    node.cli(&["lockunspent", "true"]);
    node.cli(&["generatetoaddress", "3", &miner]);

    // Step 3 of the runbook: the freshly generated destination vault.
    let new = build_vault(&node);
    assert_ne!(old.address, new.address);

    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_for(&old);

    // --- step 4: every operator plans independently -----------------------
    //
    // Three separate databases, each synced from the node, so "compare the
    // commitments before anyone approves" is genuinely being exercised
    // rather than asserted about one shared value.
    let mut plans: Vec<(Db, SweepPlan)> = Vec::new();
    for i in 0..3 {
        let mut db = Db::open(&dir.path().join(format!("op{i}.sqlite"))).unwrap();
        let total = sync_vault(&mut db, &node, &old);
        assert_eq!(total, 120 * 100_000_000, "the vault holds 3 x 40 GLC");
        let utxos = db.available_utxos(1).unwrap();
        let plan = plan_sweep(
            old.hash160,
            SweepDestination::p2sh(new.hash160, new.address.clone()),
            &utxos,
            cfg.fee_rate_per_kb,
            cfg.dust_threshold_atomic,
            cfg.max_inputs_per_payout,
            glc_relayer::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .expect("the sweep plans");
        plans.push((db, plan));
    }

    let commitment = plans[0].1.commitment(PROTOCOL_VERSION);
    for (_, p) in &plans {
        assert_eq!(
            p.commitment(PROTOCOL_VERSION),
            commitment,
            "operators looking at the same vault must derive the same commitment — \
             this is the check the runbook tells them to make before approving"
        );
        assert_eq!(p.inputs.len(), 3, "a sweep takes every output");
    }
    let plan = plans[0].1.clone();
    assert_eq!(
        plan.swept_atomic + plan.fee_atomic,
        120 * 100_000_000,
        "nothing goes anywhere but the destination and the fee"
    );

    // --- the node builds the transaction, and it is verified --------------
    let rpc = node.rpc();
    let adapter = glc_relayer::withdrawal::adapter::RealPayoutRpc::new(node.rpc());
    let inputs: Vec<(String, i64)> = plan
        .inputs
        .iter()
        .map(|u| (u.txid_hex.clone(), u.vout))
        .collect();
    let unsigned_hex = {
        use glc_relayer::withdrawal::executor::PayoutRpc;
        adapter
            .create_raw_transaction(&inputs, &[(new.address.clone(), plan.swept_atomic)])
            .await
            .expect("the node builds the sweep")
    };
    let unsigned = Transaction::parse_hex(&unsigned_hex).unwrap();
    glc_relayer::withdrawal::sweep::verify_sweep_tx(&unsigned, &plan)
        .expect("the node built exactly the planned sweep");

    // --- step 5: each operator approves on their own signer ---------------
    //
    // Before approving, prove the fail-closed default is real on a live
    // transaction rather than only in unit fixtures.
    let unapproved = SweepView::new(
        cfg.clone(),
        0,
        OneKeySigner {
            rpc: node.rpc(),
            wif: old.wifs[0].clone(),
        },
        dir.path().join("nothing-staged"),
    )
    .unwrap();
    let (mut db0, _) = plans.remove(0);
    assert_eq!(
        unapproved
            .sign_sweep(&mut db0, &unsigned_hex, PROTOCOL_VERSION, 1_000)
            .await
            .unwrap_err(),
        SweepRefusal::NotApproved,
        "a signer whose operator has staged nothing must refuse a real sweep"
    );

    // Two of three approve — the threshold, not the whole set, so the
    // rehearsal proves M is genuinely sufficient.
    let mut partials: Vec<PartialSignature> = Vec::new();
    let mut dbs: Vec<Db> = vec![db0];
    for (_, p) in plans.into_iter() {
        let _ = p;
    }
    for i in 0..2usize {
        let approvals = dir.path().join(format!("sweep-approvals-{i}"));
        stage(&approvals, commitment, 9_999_999_999, "REHEARSAL: INC-0");
        let view = SweepView::new(
            cfg.clone(),
            i as u8,
            OneKeySigner {
                rpc: node.rpc(),
                wif: old.wifs[i].clone(),
            },
            approvals,
        )
        .unwrap();
        let mut db = if i == 0 {
            dbs.pop().unwrap()
        } else {
            let mut d = Db::open(&dir.path().join(format!("signer{i}.sqlite"))).unwrap();
            sync_vault(&mut d, &node, &old);
            d
        };
        let swept = view
            .sign_sweep(&mut db, &unsigned_hex, PROTOCOL_VERSION, 1_000)
            .await
            .unwrap_or_else(|e| panic!("operator {i} approved but did not sign: {e}"));
        assert_eq!(swept.partial.signatures.len(), 3, "one signature per input");
        // What the audit record will state (§13.3) must be what actually
        // leaves the vault, so it is checked against the plan here too.
        assert_eq!(swept.swept_atomic, plan.swept_atomic);
        assert_eq!(swept.inputs, plan.inputs.len());
        partials.push(PartialSignature {
            vault_pubkey: swept.partial.vault_pubkey,
            signatures: swept.partial.signatures,
        });
    }

    // --- step 6: assemble and broadcast -----------------------------------
    let signed = assemble(&unsigned, &cfg.vault, &partials).expect("2 of 3 assembles");
    let signed_hex = signed.serialize_hex();
    let outcome = rpc.send_raw_transaction(&signed_hex).await.unwrap();
    let txid = match outcome {
        BroadcastOutcome::Accepted { txid } => txid,
        other => panic!("the network rejected the rehearsed sweep: {other:?}"),
    };
    node.cli(&["generatetoaddress", "2", &miner]);

    // --- what a rehearsal is for: did the documented outcome happen? ------
    let old_left = node.cli(&[
        "listunspent",
        "1",
        "9999999",
        &format!("[\"{}\"]", old.address),
    ]);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&old_left)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0,
        "runbook §5 claims a sweep leaves nothing behind — the old vault must be empty"
    );

    let arrived: serde_json::Value = serde_json::from_str(&node.cli(&[
        "listunspent",
        "1",
        "9999999",
        &format!("[\"{}\"]", new.address),
    ]))
    .unwrap();
    let rows = arrived.as_array().unwrap();
    assert_eq!(rows.len(), 1, "a sweep pays exactly one output");
    let got = (rows[0]["amount"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    assert_eq!(
        got, plan.swept_atomic,
        "the destination received exactly what the operators approved"
    );
    assert_eq!(
        rows[0]["txid"].as_str().unwrap(),
        txid,
        "the confirmed output belongs to the broadcast sweep"
    );

    // The txid was predictable before broadcast (ADR-0013's model).
    assert_eq!(
        signed.txid_hex(),
        txid,
        "the assembled txid matched what the network accepted"
    );
}

/// The runbook tells operators to compare commitments **before** approving,
/// because differing ones mean differing views of the vault. This proves
/// that is a real condition, not a ceremonial step.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_whose_vault_view_differs_derives_a_different_commitment() {
    let Some(node) = maybe_node() else { return };
    let miner = node.cli(&["getnewaddress"]);
    node.cli(&["generatetoaddress", "130", &miner]);

    let old = build_vault(&node);
    let new = build_vault(&node);
    node.cli(&["sendtoaddress", &old.address, "40.0"]);
    node.cli(&["generatetoaddress", "2", &miner]);

    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_for(&old);
    let plan_now = |db: &Db| {
        let utxos = db.available_utxos(1).unwrap();
        plan_sweep(
            old.hash160,
            SweepDestination::p2sh(new.hash160, new.address.clone()),
            &utxos,
            cfg.fee_rate_per_kb,
            cfg.dust_threshold_atomic,
            cfg.max_inputs_per_payout,
            glc_relayer::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .expect("plans")
    };

    // Operator A syncs now; the vault then receives more; operator B syncs
    // after. Their commitments must differ — otherwise a stale approval
    // could authorise sweeping value its approver never saw.
    let mut a = Db::open(&dir.path().join("a.sqlite")).unwrap();
    sync_vault(&mut a, &node, &old);
    let commit_a = plan_now(&a).commitment(PROTOCOL_VERSION);

    node.cli(&["sendtoaddress", &old.address, "10.0"]);
    node.cli(&["generatetoaddress", "2", &miner]);
    let mut b = Db::open(&dir.path().join("b.sqlite")).unwrap();
    sync_vault(&mut b, &node, &old);
    let commit_b = plan_now(&b).commitment(PROTOCOL_VERSION);

    assert_ne!(
        commit_a, commit_b,
        "a vault that received funds between the two plans must produce a different \
         commitment — this is what the runbook's compare-before-approving step catches"
    );

    // And a signer holding A's approval refuses B's sweep outright.
    let approvals = dir.path().join("approvals");
    stage(&approvals, commit_a, 9_999_999_999, "REHEARSAL");
    let view = SweepView::new(
        cfg.clone(),
        0,
        OneKeySigner {
            rpc: node.rpc(),
            wif: old.wifs[0].clone(),
        },
        approvals,
    )
    .unwrap();

    let plan_b = plan_now(&b);
    let adapter = glc_relayer::withdrawal::adapter::RealPayoutRpc::new(node.rpc());
    let inputs: Vec<(String, i64)> = plan_b
        .inputs
        .iter()
        .map(|u| (u.txid_hex.clone(), u.vout))
        .collect();
    let unsigned_hex = {
        use glc_relayer::withdrawal::executor::PayoutRpc;
        adapter
            .create_raw_transaction(&inputs, &[(new.address.clone(), plan_b.swept_atomic)])
            .await
            .unwrap()
    };
    assert_eq!(
        view.sign_sweep(&mut b, &unsigned_hex, PROTOCOL_VERSION, 1_000)
            .await
            .unwrap_err(),
        SweepRefusal::DifferentSweepApproved,
        "the signer must refuse a sweep its operator did not approve, on a real transaction"
    );
}
