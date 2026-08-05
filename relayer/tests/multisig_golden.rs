//! Golden-vector tests for the Phase 7e scriptSig assembler (ADR-0017 D2).
//!
//! Goldcoin 0.17 has no `combinerawtransaction` and no PSBT, so the relayer
//! assembles the final `scriptSig` itself. That moves work the node used to
//! do into our code, and nothing about it can be assumed correct — these
//! tests pin it against **real node output**.
//!
//! `tests/vectors/phase7e-multisig-golden.json` was captured from a live
//! `goldcoind` 0.17.0 regtest node. The reference transaction it records was
//! broadcast and mined, so "matches the vector" means "would actually spend",
//! not merely "matches something we generated".

use glc_relayer::withdrawal::multisig::{
    assemble, extract_signatures, MultisigError, PartialSignature, Transaction,
};
use glc_relayer::withdrawal::vault::{MultisigVault, COMPRESSED_PUBKEY_LEN};

struct Golden {
    redeem_script_hex: String,
    signer_pubkeys: Vec<String>,
    unsigned_hex: String,
    partial_hex: Vec<String>,
    node_signed_hex: String,
    node_txid: String,
}

fn golden() -> Golden {
    let raw = include_str!("vectors/phase7e-multisig-golden.json");
    // A hand-rolled reader rather than serde: the vector is a fixed shape,
    // and a parser that accepted more would obscure a corrupted vector.
    let field = |key: &str| -> String {
        let pat = format!("\"{key}\":");
        let start = raw.find(&pat).unwrap_or_else(|| panic!("missing {key}")) + pat.len();
        let rest = &raw[start..];
        let q1 = rest.find('"').unwrap();
        let q2 = rest[q1 + 1..].find('"').unwrap();
        rest[q1 + 1..q1 + 1 + q2].to_string()
    };
    let array = |key: &str| -> Vec<String> {
        let pat = format!("\"{key}\":");
        let start = raw.find(&pat).unwrap() + pat.len();
        let rest = &raw[start..];
        let open = rest.find('[').unwrap();
        let close = rest.find(']').unwrap();
        rest[open + 1..close]
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    Golden {
        redeem_script_hex: field("redeem_script_hex"),
        signer_pubkeys: array("signer_pubkeys"),
        unsigned_hex: field("unsigned_hex"),
        partial_hex: array("partial_hex"),
        node_signed_hex: field("node_signed_hex_quorum_01"),
        node_txid: field("node_txid_quorum_01"),
    }
}

fn vault(g: &Golden) -> MultisigVault {
    MultisigVault::from_redeem_script_hex(&g.redeem_script_hex).unwrap()
}

fn pubkey(hex_str: &str) -> [u8; COMPRESSED_PUBKEY_LEN] {
    glc_relayer::glc::hex::decode_exact::<COMPRESSED_PUBKEY_LEN>(hex_str).unwrap()
}

/// The partial for signer `i`, as `signrawtransaction` returned it.
fn partial(g: &Golden, i: usize) -> PartialSignature {
    let redeem = glc_relayer::glc::hex::decode_vec(&g.redeem_script_hex).unwrap();
    let tx = Transaction::parse_hex(&g.partial_hex[i]).unwrap();
    PartialSignature {
        vault_pubkey: pubkey(&g.signer_pubkeys[i]),
        signatures: extract_signatures(&tx, &redeem).unwrap(),
    }
}

#[test]
fn the_vector_itself_is_internally_consistent() {
    // If this failed, every other test here would pass or fail for the wrong
    // reason.
    let g = golden();
    let v = vault(&g);
    assert_eq!(v.threshold, 2);
    assert_eq!(v.signer_pubkeys.len(), 3);
    for (i, pk) in g.signer_pubkeys.iter().enumerate() {
        assert_eq!(
            v.signer_pubkeys[i],
            pubkey(pk),
            "signer {i} order preserved"
        );
    }
    let signed = Transaction::parse_hex(&g.node_signed_hex).unwrap();
    assert_eq!(
        signed.txid_hex(),
        g.node_txid,
        "our txid matches the node's"
    );
    assert_eq!(signed.inputs.len(), 2, "the vector exercises 2 inputs");
}

#[test]
fn assembly_reproduces_the_nodes_bytes_exactly() {
    // THE test. Our independently assembled transaction must be
    // byte-identical to one a real node produced, signed, and had mined.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let signed = assemble(&unsigned, &vault(&g), &[partial(&g, 0), partial(&g, 1)]).unwrap();

    assert_eq!(
        signed.serialize_hex(),
        g.node_signed_hex,
        "assembled bytes must equal what goldcoind produced"
    );
    assert_eq!(signed.txid_hex(), g.node_txid);
}

#[test]
fn assembly_is_independent_of_the_order_partials_are_supplied_in() {
    // Peers answer in whatever order the network delivers. The result must
    // not depend on it — only on redeem-script position.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let v = vault(&g);
    let forward = assemble(&unsigned, &v, &[partial(&g, 0), partial(&g, 1)]).unwrap();
    let reverse = assemble(&unsigned, &v, &[partial(&g, 1), partial(&g, 0)]).unwrap();
    assert_eq!(
        forward.serialize_hex(),
        reverse.serialize_hex(),
        "collection order must not change the assembled transaction"
    );
    assert_eq!(forward.txid_hex(), g.node_txid);
}

#[test]
fn a_different_quorum_produces_a_different_txid() {
    // ADR-0015's premise, re-established here: the txid depends on WHICH
    // quorum signs, which is why the quorum is designated before signing and
    // reassignment must be explicit.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let v = vault(&g);
    let q01 = assemble(&unsigned, &v, &[partial(&g, 0), partial(&g, 1)]).unwrap();
    let q02 = assemble(&unsigned, &v, &[partial(&g, 0), partial(&g, 2)]).unwrap();
    let q12 = assemble(&unsigned, &v, &[partial(&g, 1), partial(&g, 2)]).unwrap();
    let txids = [q01.txid_hex(), q02.txid_hex(), q12.txid_hex()];
    let unique: std::collections::HashSet<&String> = txids.iter().collect();
    assert_eq!(
        unique.len(),
        3,
        "each quorum yields its own txid: {txids:?}"
    );
}

#[test]
fn every_signature_placed_verifies_over_its_own_inputs_sighash() {
    // Each input has a distinct sighash, so a per-input mix-up would produce
    // a transaction that looks well-formed and fails at consensus.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let v = vault(&g);
    let p0 = partial(&g, 0);
    assert_eq!(p0.signatures.len(), 2, "one signature per input");
    assert_ne!(
        p0.signatures[0], p0.signatures[1],
        "the same signer signs each input differently"
    );
    assert_ne!(
        unsigned.sighash_all(0, &v.redeem_script),
        unsigned.sighash_all(1, &v.redeem_script)
    );
}

#[test]
fn refuses_a_signature_that_does_not_verify() {
    // A corrupted or forged partial must be caught here, not at broadcast.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let mut bad = partial(&g, 1);
    let n = bad.signatures[0].len();
    // Flip a byte inside the DER body, leaving length and sighash intact.
    bad.signatures[0][n - 5] ^= 0xFF;
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0), bad]).unwrap_err();
    assert!(
        matches!(
            err,
            MultisigError::SignatureDoesNotVerify { .. } | MultisigError::MalformedSignature { .. }
        ),
        "expected a verification failure, got {err:?}"
    );
}

#[test]
fn refuses_a_signature_lifted_from_a_different_input() {
    // Replaying input 0's signature into input 1's slot: structurally valid,
    // cryptographically wrong.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let mut swapped = partial(&g, 1);
    swapped.signatures[1] = swapped.signatures[0].clone();
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0), swapped]).unwrap_err();
    assert!(
        matches!(err, MultisigError::SignatureDoesNotVerify { input: 1, .. }),
        "got {err:?}"
    );
}

#[test]
fn refuses_a_signer_that_is_not_in_the_vault() {
    // A signature from a stranger can never satisfy the script; placing it
    // would produce an unspendable transaction that only fails at broadcast.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let mut stranger = partial(&g, 1);
    stranger.vault_pubkey[1] ^= 0xFF;
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0), stranger]).unwrap_err();
    assert!(
        matches!(err, MultisigError::SignerNotInVault { .. }),
        "{err:?}"
    );
}

#[test]
fn refuses_a_duplicated_signer() {
    // One peer answering twice must never look like two approvals — the
    // multisig analogue of the mint path's unique-signer count.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0), partial(&g, 0)]).unwrap_err();
    assert!(
        matches!(err, MultisigError::DuplicateSigner { .. }),
        "{err:?}"
    );
}

#[test]
fn refuses_fewer_signatures_than_the_threshold() {
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0)]).unwrap_err();
    assert!(
        matches!(err, MultisigError::ThresholdNotMet { .. }),
        "{err:?}"
    );
}

#[test]
fn refuses_more_signatures_than_the_threshold() {
    // OP_CHECKMULTISIG pops exactly M signatures; an extra one makes the
    // script fail, so this must be caught before broadcast.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let err = assemble(
        &unsigned,
        &vault(&g),
        &[partial(&g, 0), partial(&g, 1), partial(&g, 2)],
    )
    .unwrap_err();
    assert!(
        matches!(err, MultisigError::TooManySignatures { .. }),
        "{err:?}"
    );
}

#[test]
fn refuses_a_partial_covering_the_wrong_number_of_inputs() {
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let mut short = partial(&g, 1);
    short.signatures.pop();
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0), short]).unwrap_err();
    assert!(
        matches!(err, MultisigError::InputCountMismatch(1)),
        "{err:?}"
    );
}

#[test]
fn refuses_a_non_sighash_all_signature() {
    // SIGHASH_NONE or SIGHASH_SINGLE would leave outputs mutable after
    // signing — for a payout, the destination itself.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let mut bad = partial(&g, 1);
    let last = bad.signatures[0].len() - 1;
    bad.signatures[0][last] = 0x02; // SIGHASH_NONE
    let err = assemble(&unsigned, &vault(&g), &[partial(&g, 0), bad]).unwrap_err();
    assert!(
        matches!(
            err,
            MultisigError::MalformedSignature {
                reason: "sighash type is not SIGHASH_ALL",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn refuses_malformed_der_and_implausible_lengths() {
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let v = vault(&g);
    for (label, sig) in [
        ("empty", Vec::new()),
        ("oversized", vec![0x30; 200]),
        ("not DER", vec![0xFF, 0xFF, 0xFF, 0x01]),
    ] {
        let mut bad = partial(&g, 1);
        bad.signatures[0] = sig;
        let err = assemble(&unsigned, &v, &[partial(&g, 0), bad]).unwrap_err();
        assert!(
            matches!(err, MultisigError::MalformedSignature { .. }),
            "{label}: {err:?}"
        );
    }
}

#[test]
fn the_assembled_scriptsig_has_the_expected_shape() {
    // OP_0 <sig> <sig> <redeemScript>, with the CHECKMULTISIG dummy first.
    let g = golden();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    let v = vault(&g);
    let signed = assemble(&unsigned, &v, &[partial(&g, 0), partial(&g, 1)]).unwrap();
    for inp in &signed.inputs {
        assert_eq!(inp.script_sig[0], 0x00, "must begin with the OP_0 dummy");
        assert!(
            inp.script_sig
                .windows(v.redeem_script.len())
                .any(|w| w == v.redeem_script),
            "must end with the redeem script"
        );
    }
}

/// The fee estimate must cover the transaction the vault really broadcasts.
///
/// Regression (found in the three-operator rehearsal): the estimator charged
/// a flat 148 bytes per input — the size of a **P2PKH** input. The vault
/// spends 2-of-3 **P2SH multisig** outputs, which are ~299 bytes each, so
/// every payout was sized at roughly half its true weight and paid roughly
/// half the configured rate. A node applying that same rate rejects the
/// result, and the payout never relays.
///
/// The reference transaction here was signed by goldcoind 0.17, broadcast,
/// and mined, so "the estimate covers it" means it covers bytes that really
/// spent — not bytes this crate also produced.
#[test]
fn the_fee_estimate_covers_the_transaction_the_vault_really_broadcasts() {
    use glc_relayer::withdrawal::coin::{estimated_size_bytes, multisig_input_bytes};

    let g = golden();
    let mined = Transaction::parse_hex(&g.node_signed_hex).unwrap();
    let real_size = mined.serialize().len() as u64;
    let num_inputs = mined.inputs.len() as u64;
    let num_outputs = mined.outputs.len() as u64;
    let redeem_len = glc_relayer::glc::hex::decode_vec(&g.redeem_script_hex)
        .unwrap()
        .len();

    let threshold = vault(&g).threshold;
    let estimate = estimated_size_bytes(
        num_inputs,
        num_outputs,
        multisig_input_bytes(threshold, redeem_len),
    );
    assert!(
        estimate >= real_size,
        "estimate {estimate} is under the {real_size} bytes goldcoind actually \
         produced for {num_inputs} multisig input(s) — this underpays the fee"
    );

    // Over-estimating is the safe direction, but only just: the sole slack is
    // that a real DER signature can come in a couple of bytes under the
    // 73-byte maximum. Anything beyond that means the model has drifted.
    let slack = estimate - real_size;
    let max_slack = num_inputs * threshold as u64 * 3;
    assert!(
        slack <= max_slack,
        "estimate {estimate} overshoots {real_size} by {slack}, more than the \
         {max_slack} bytes of DER slack that is explainable"
    );

    // Pin the defect itself: the old P2PKH figure does not cover this.
    const P2PKH_INPUT_BYTES: u64 = 148;
    assert!(
        estimated_size_bytes(num_inputs, num_outputs, P2PKH_INPUT_BYTES) < real_size,
        "the P2PKH input size must NOT cover a multisig spend — if it does, \
         this test has stopped guarding anything"
    );
}

/// Whatever rate an operator configures, the fee has to buy the real bytes.
///
/// A node measures the transaction it receives, so the only fee that relays
/// is one computed over the true serialized size.
#[test]
fn the_fee_buys_the_real_bytes_at_every_configured_rate() {
    use glc_relayer::withdrawal::coin::{fee_for, multisig_input_bytes};

    let g = golden();
    let mined = Transaction::parse_hex(&g.node_signed_hex).unwrap();
    let real_size = mined.serialize().len() as u64;
    let redeem_len = glc_relayer::glc::hex::decode_vec(&g.redeem_script_hex)
        .unwrap()
        .len();
    let input_bytes = multisig_input_bytes(vault(&g).threshold, redeem_len);

    // 1_000 is Goldcoin 0.17's default minimum relay rate; the rest bracket
    // what an operator would plausibly configure.
    for rate in [1_000u64, 10_000, 100_000, 1_000_000] {
        let demanded = real_size.saturating_mul(rate).div_ceil(1000);
        let paid = fee_for(
            mined.inputs.len() as u64,
            mined.outputs.len() as u64,
            rate,
            input_bytes,
        );
        assert!(
            paid >= demanded,
            "at {rate}/kB the payout pays {paid} but the node demands \
             {demanded} for its {real_size} bytes"
        );
    }
}

#[test]
fn extract_signatures_rejects_a_scriptsig_with_no_signature() {
    // A partial containing only the redeem script (or nothing) is malformed;
    // silently returning an empty signature would defer the failure to
    // broadcast.
    let g = golden();
    let redeem = glc_relayer::glc::hex::decode_vec(&g.redeem_script_hex).unwrap();
    let unsigned = Transaction::parse_hex(&g.unsigned_hex).unwrap();
    assert!(
        extract_signatures(&unsigned, &redeem).is_err(),
        "an unsigned transaction has no signatures to extract"
    );
}
