//! `glc-wallet` — the **user-facing** withdrawal tool.
//!
//! Burns wrapped GLC on Solana and creates the on-chain `WithdrawalRequest`
//! the federation pays out from. It is the only tool in this repository
//! intended for people who do not operate the bridge.
//!
//! # Separate from `glc-admin` on purpose
//!
//! `glc-admin` is for operators and touches bridge state. This holds a
//! **user's** keypair and can do exactly one thing: burn that user's own
//! tokens. It has no admin key, no validator key, no vault key, and no
//! command that affects anyone else. Keeping the two binaries apart means an
//! operator's muscle memory and a user's cannot be confused, and a user is
//! never one typo away from an operator command.
//!
//! # The one thing that can go permanently wrong
//!
//! `burn_wrapped` **cannot check the Goldcoin address** — the program has no
//! base58 decoder (ADR-0018 D2). The burn succeeds whatever is typed, and a
//! withdrawal with an undecodable destination can never be paid: there is no
//! un-burn instruction. So every check runs *before* signing, and the
//! address is validated with the very function the payout pipeline uses, so
//! this tool can never accept something the bridge would later refuse.

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Signer};
use solana_sdk::transaction::Transaction;

use glc_relayer::ops::withdraw_preflight::{self, WithdrawContext};
use glc_relayer::solana::instruction as ix;
use glc_relayer::solana::rpc::{decode_bridge_config, RealSolanaRpc, SolanaRpc};
use glc_relayer::withdrawal::discovery;

const USAGE: &str = r#"glc-wallet — withdraw wrapped GLC back to Goldcoin

  glc-wallet withdraw --amount-atomic N --glc-address ADDRESS --keypair PATH

  --amount-atomic  how much to withdraw, in atomic units.
                   1 GLC = 100000000 atomic units.
  --glc-address    the Goldcoin address to be paid.
  --keypair        your Solana keypair file. It signs, pays the fee, and
                   must be the one holding the wrapped GLC.

This burns your wrapped GLC and records a withdrawal the bridge operators
pay out from. It cannot be undone, so the address is checked first.

Reads its connection settings from the environment, the same names the
bridge itself uses:
  GLC_SOLANA_RPC_URL     e.g. https://api.mainnet-beta.solana.com
  GLC_SOLANA_COMMITMENT  e.g. confirmed
  GLC_PROGRAM_ID_HEX     the bridge program, 32 hex-encoded bytes"#;

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
            eprintln!("error: {name} is required\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| {
        anyhow::anyhow!(
            "the environment variable {name} is not set.\n\
             glc-wallet needs to know which bridge and which cluster to talk to; see \
             `glc-wallet --help`."
        )
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("withdraw") => withdraw(&args).await,
        Some("-h") | Some("--help") | Some("help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => {
            eprintln!("error: unknown command {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

async fn withdraw(args: &[String]) -> anyhow::Result<()> {
    let amount: u64 = require(args, "--amount-atomic").parse().map_err(|_| {
        anyhow::anyhow!(
            "--amount-atomic must be a whole number of atomic units.\n\
             1 GLC = 100000000, so 1.5 GLC is --amount-atomic 150000000."
        )
    })?;
    let glc_address = require(args, "--glc-address");
    let keypair_path = require(args, "--keypair");

    let user = read_keypair_file(&keypair_path).map_err(|e| {
        anyhow::anyhow!(
            "could not read your keypair at {keypair_path}: {e}\n\
             This should be a Solana keypair JSON file, like the one `solana-keygen` writes."
        )
    })?;

    let program_id = Pubkey::from(
        glc_relayer::glc::hex::decode_exact::<32>(&env_required("GLC_PROGRAM_ID_HEX")?)
            .map_err(|e| anyhow::anyhow!("GLC_PROGRAM_ID_HEX is not 32 hex bytes: {e}"))?,
    );
    let commitment =
        glc_relayer::solana::config::parse_commitment(&env_required("GLC_SOLANA_COMMITMENT")?)
            .map_err(|e| anyhow::anyhow!("invalid GLC_SOLANA_COMMITMENT: {e}"))?;
    let rpc = RealSolanaRpc::new(env_required("GLC_SOLANA_RPC_URL")?, commitment);

    // --- read the bridge's own state -------------------------------------
    let (config_pda, _) = ix::bridge_config_pda(&program_id);
    let config_account = rpc.get_account(&config_pda).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "no bridge was found at program {program_id}.\n\
             Check GLC_PROGRAM_ID_HEX and GLC_SOLANA_RPC_URL point at the right bridge \
             and cluster."
        )
    })?;
    let config = decode_bridge_config(&config_account.data)?;

    // The user's associated token account for the wrapped mint.
    let user_ata = spl_associated_token_account::get_associated_token_address(
        &user.pubkey(),
        &config.wrapped_mint,
    );
    let balance = rpc
        .get_account(&user_ata)
        .await?
        .and_then(|a| ix::token_account_amount(&a.data));

    // --- everything that could refuse, before anything is signed ----------
    let ctx = WithdrawContext {
        paused: config.paused,
        min_withdrawal: config.min_withdrawal,
        mint_configured: config.mint_is_configured(),
        balance,
    };
    let dest_hash160 = withdraw_preflight::check(&ctx, amount, &glc_address)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // The index the bridge will assign. Two users burning at the same moment
    // race for it; the loser's transaction fails because the account already
    // exists, which is the correct outcome — nothing is overwritten.
    let index = config.withdrawal_count;
    let (withdrawal_pda, _) = ix::withdrawal_request_pda(&program_id, index);

    println!(
        "About to withdraw\n  amount:      {} atomic units ({:.8} GLC)\n  to Goldcoin: {}\n  \
         from:        {}\n  withdrawal:  index {index} at {withdrawal_pda}\n",
        amount,
        withdraw_preflight::as_glc(amount),
        glc_address,
        user.pubkey()
    );

    // --- submit -----------------------------------------------------------
    let instruction = ix::burn_wrapped_instruction(
        &program_id,
        &ix::BurnWrappedAccounts {
            user: user.pubkey(),
            bridge_config: config_pda,
            wrapped_mint: config.wrapped_mint,
            user_token_account: user_ata,
            withdrawal: withdrawal_pda,
        },
        amount,
        &glc_address,
    );
    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&user.pubkey()),
        &[&user],
        blockhash,
    );
    let signature = rpc.send_transaction(&tx).await.map_err(|e| {
        anyhow::anyhow!(
            "the withdrawal was not accepted: {e}\n\
             Nothing was burned. If someone else withdrew at the same moment, index {index} \
             was taken — simply run the command again."
        )
    })?;

    // --- verify what actually landed --------------------------------------
    //
    // Reporting success without reading the record back would leave the user
    // trusting a transaction signature for something irreversible.
    //
    // `send_transaction` returns as soon as the cluster accepts the
    // transaction, not when it is confirmed, so the record is not readable
    // immediately. Polling matters more than it looks: without it the CLI
    // reports a scary failure for a withdrawal that actually succeeded, and
    // a user who then re-runs would burn a second time.
    println!("Submitted {signature} — waiting for it to confirm...");
    let mut account = None;
    for _ in 0..60 {
        if let Some(a) = rpc.get_account(&withdrawal_pda).await? {
            account = Some(a);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let account = account.ok_or_else(|| {
        anyhow::anyhow!(
            "the transaction {signature} was accepted, but the withdrawal record at \
             {withdrawal_pda} did not appear within 30 seconds.\n\
             This usually means the cluster is slow, NOT that the withdrawal failed. Check \
             {withdrawal_pda} before running this command again — running it again could burn \
             a second time."
        )
    })?;
    let record =
        discovery::decode_withdrawal(&program_id, &withdrawal_pda, &account.owner, &account.data)
            .map_err(|e| {
            anyhow::anyhow!(
                "the withdrawal record at {withdrawal_pda} could not be read: {e}\n\
                 The transaction was {signature}. Report this to the bridge operators."
            )
        })?;

    let mut mismatches = Vec::new();
    if record.amount_atomic != amount {
        mismatches.push(format!(
            "amount is {} on chain, expected {amount}",
            record.amount_atomic
        ));
    }
    if record.glc_address != glc_address {
        mismatches.push(format!(
            "destination is {:?} on chain, expected {glc_address:?}",
            record.glc_address
        ));
    }
    if record.glc_address_hash160 != dest_hash160 {
        mismatches.push("the destination decodes to a different Goldcoin address".to_string());
    }
    if record.requester != user.pubkey() {
        mismatches.push(format!(
            "requester is {} on chain, expected {}",
            record.requester,
            user.pubkey()
        ));
    }
    if record.index != index {
        mismatches.push(format!(
            "index is {} on chain, expected {index}",
            record.index
        ));
    }
    if !mismatches.is_empty() {
        anyhow::bail!(
            "the withdrawal was recorded but does NOT match what was requested:\n  - {}\n\
             Transaction {signature}. Report this to the bridge operators before doing anything \
             else.",
            mismatches.join("\n  - ")
        );
    }

    println!(
        "Withdrawal submitted and verified on chain.\n\n  \
         withdrawal index: {}\n  withdrawal PDA:   {}\n  transaction:      {}\n  \
         amount:           {} atomic units ({:.8} GLC)\n  Goldcoin address: {}\n",
        record.index,
        withdrawal_pda,
        signature,
        record.amount_atomic,
        withdraw_preflight::as_glc(record.amount_atomic),
        record.glc_address
    );
    println!(
        "Your wrapped GLC has been burned. The bridge operators will pay the Goldcoin\n\
         address above once the burn is finalized; this takes a while and needs no further\n\
         action from you. Keep the withdrawal index if you need to ask about it."
    );
    Ok(())
}
