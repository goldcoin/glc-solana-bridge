//! Vault sweep: moving the entire vault to a new vault (Phase 7i-0).
//!
//! ADR-0014 §8.7 makes "pause → rotate → sweep" the response to a suspected
//! vault-key compromise. The first two steps were executable; the third had
//! no implementation anywhere. A documented incident response whose final
//! step cannot be performed is worse than none, because it is believed.
//!
//! # Why a sweep is not a payout
//!
//! Everything else this bridge signs is *derivable*. A payout corresponds to
//! a burn on Solana; a completion corresponds to a confirmed Goldcoin
//! transaction. A signer can therefore check a request against facts and
//! refuse anything that does not match.
//!
//! A sweep corresponds to **nothing on chain**. It spends the whole vault to
//! an address chosen by a human, for a reason — suspected compromise — that
//! exists only in the operators' heads. No amount of chain observation can
//! tell a signer whether a sweep should happen.
//!
//! That makes it the most dangerous operation in the system: a signer that
//! signed sweeps on request would hand the vault to anyone holding a
//! federation transport identity. So the authorisation model is the same one
//! governance uses (`p2p::governance_view`): each operator stages the exact
//! sweep out of band, and their signer signs that one sweep and nothing
//! else. M signatures then mean M humans each decided, which is the only
//! meaning worth having here.
//!
//! # What this module is
//!
//! The pure half: planning a sweep from a UTXO set, committing to it
//! canonically, and verifying that a proposed transaction realises exactly
//! the plan. No keys, no network, no database — so every signer can run the
//! identical check, which is the point.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::glc::withdrawal_db::VaultUtxo;
use crate::withdrawal::coin::fee_for;
use crate::withdrawal::multisig::Transaction;

/// Domain tag for the sweep commitment. Distinct from every other tag in
/// the system, so a sweep approval can never be replayed as a payout intent
/// or a governance parameter set.
pub const SWEEP_DOMAIN_TAG: &[u8; 16] = b"GLC_BRIDGE_SWEEP";

/// A sweep is a single-output transaction: everything, minus fee, to one
/// destination. There is deliberately no change output — a partial sweep
/// that leaves value under a possibly-compromised key is not a sweep.
pub const SWEEP_OUTPUT_COUNT: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SweepError {
    #[error("the vault holds no spendable outputs at the required confirmation depth")]
    NothingToSweep,
    #[error("total vault value {total} does not cover the {fee} fee")]
    FeeExceedsValue { total: u64, fee: u64 },
    #[error("sweeping {swept} would leave a dust output below the {dust} threshold")]
    ResultIsDust { swept: u64, dust: u64 },
    #[error("the sweep would need {needed} inputs, more than the {max} cap")]
    TooManyInputs { needed: usize, max: usize },
    #[error("the destination is the vault being swept — a sweep must move funds elsewhere")]
    DestinationIsSource,
    #[error("the proposed transaction has {found} inputs, the plan has {expected}")]
    InputCountMismatch { expected: usize, found: usize },
    #[error("proposed input {index} is {found}, the plan has {expected}")]
    InputMismatch {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("the proposed transaction has {0} outputs; a sweep has exactly one")]
    NotSingleOutput(usize),
    #[error("the sweep pays {found_hex}, not the planned destination {expected_hex}")]
    WrongDestination {
        expected_hex: String,
        found_hex: String,
    },
    #[error("the sweep pays {found}, the plan pays {expected}")]
    WrongAmount { expected: u64, found: u64 },
    #[error("the proposed transaction is already signed: input {0} carries a scriptSig")]
    AlreadySigned(usize),
}

/// A fully specified sweep. Every field a signer must agree with before it
/// will contribute a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepPlan {
    /// The vault being emptied, as its P2SH script hash — pinned so an
    /// approval for sweeping vault A can never authorise sweeping vault B.
    pub source_hash160: [u8; 20],
    /// Where the funds go. A hash160 plus the script it must appear as, so
    /// verification never has to decode base58 (which the on-chain program
    /// cannot do either — see ADR-0018 D2).
    pub dest_hash160: [u8; 20],
    /// The exact `scriptPubKey` the single output must carry. Supplied
    /// rather than derived because a destination may be P2SH (a new
    /// multisig vault) or P2PKH (cold storage), and guessing which would be
    /// exactly the kind of assumption that loses funds.
    pub dest_script_pubkey: Vec<u8>,
    pub dest_address: String,
    pub fee_atomic: u64,
    /// What the destination receives: total input value minus fee.
    pub swept_atomic: u64,
    /// Every input, in the order they must appear in the transaction.
    pub inputs: Vec<VaultUtxo>,
}

impl SweepPlan {
    pub fn total_in(&self) -> u64 {
        self.inputs.iter().map(|u| u.amount_atomic).sum()
    }

    /// The canonical bytes an operator approves and every signer recomputes.
    ///
    /// Semantic rather than byte-level, matching the ADR-0015 payout intent:
    /// it commits to what the sweep *means* (this vault, this destination,
    /// this fee, these exact outpoints and amounts), so a signer recomputes
    /// it from its own view instead of hashing bytes it was handed.
    ///
    /// Layout: tag(16) ‖ version(1) ‖ source_hash160(20) ‖ dest_hash160(20)
    /// ‖ dest_script_len(2 LE) ‖ dest_script ‖ fee(8 LE) ‖ swept(8 LE)
    /// ‖ input_count(4 LE) ‖ [ txid(32, **display order** — the bytes
    /// `VaultUtxo` stores) ‖ vout(4 LE) ‖ amount(8 LE) ] …
    ///
    /// Display order, not internal, because that is what every operator's
    /// `vault_utxos` row holds; the choice is arbitrary but must be stated,
    /// since the two differ by a reversal and a silent disagreement would
    /// make two honest operators derive different commitments.
    pub fn canonical_intent(&self, protocol_version: u8) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(80 + self.dest_script_pubkey.len() + self.inputs.len() * 44);
        out.extend_from_slice(SWEEP_DOMAIN_TAG);
        out.push(protocol_version);
        out.extend_from_slice(&self.source_hash160);
        out.extend_from_slice(&self.dest_hash160);
        out.extend_from_slice(&(self.dest_script_pubkey.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.dest_script_pubkey);
        out.extend_from_slice(&self.fee_atomic.to_le_bytes());
        out.extend_from_slice(&self.swept_atomic.to_le_bytes());
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for u in &self.inputs {
            out.extend_from_slice(&u.txid);
            out.extend_from_slice(&(u.vout as u32).to_le_bytes());
            out.extend_from_slice(&u.amount_atomic.to_le_bytes());
        }
        out
    }

    /// The 32-byte commitment an operator stages and a signer compares.
    pub fn commitment(&self, protocol_version: u8) -> [u8; 32] {
        Sha256::digest(self.canonical_intent(protocol_version)).into()
    }
}

/// Where a sweep sends the vault. Grouped so the three fields that describe
/// one destination travel together and cannot be mismatched at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepDestination {
    pub hash160: [u8; 20],
    pub script_pubkey: Vec<u8>,
    pub address: String,
}

impl SweepDestination {
    /// A P2SH destination — a new multisig vault.
    pub fn p2sh(hash160: [u8; 20], address: String) -> Self {
        SweepDestination {
            script_pubkey: p2sh_script_pubkey(&hash160),
            hash160,
            address,
        }
    }
}

/// Builds a sweep of **every** supplied output.
///
/// Takes the UTXO set rather than fetching one, so the caller decides what
/// "the vault" means (which confirmation depth, which node) and this stays
/// a pure function every signer can rerun.
///
/// Inputs are used in the order given; callers pass them in the canonical
/// `vault_utxos` order so two operators planning the same sweep produce the
/// same transaction.
#[allow(clippy::too_many_arguments)]
pub fn plan_sweep(
    source_hash160: [u8; 20],
    dest: SweepDestination,
    utxos: &[VaultUtxo],
    fee_rate_per_kb: u64,
    dust_threshold_atomic: u64,
    max_inputs: usize,
    // Bytes per signed vault input (`coin::multisig_input_bytes`): a sweep
    // spends the same P2SH multisig outputs a payout does.
    input_bytes: u64,
) -> Result<SweepPlan, SweepError> {
    let SweepDestination {
        hash160: dest_hash160,
        script_pubkey: dest_script_pubkey,
        address: dest_address,
    } = dest;
    if utxos.is_empty() {
        return Err(SweepError::NothingToSweep);
    }
    if dest_hash160 == source_hash160 {
        // Sweeping a vault to itself spends every output and returns the
        // funds to the same possibly-compromised key, having paid a fee for
        // the privilege. Always a mistake, so it is refused rather than
        // performed.
        return Err(SweepError::DestinationIsSource);
    }
    if utxos.len() > max_inputs {
        return Err(SweepError::TooManyInputs {
            needed: utxos.len(),
            max: max_inputs,
        });
    }

    let total: u64 = utxos.iter().map(|u| u.amount_atomic).sum();
    let fee = fee_for(
        utxos.len() as u64,
        SWEEP_OUTPUT_COUNT,
        fee_rate_per_kb,
        input_bytes,
    );
    let swept = total
        .checked_sub(fee)
        .ok_or(SweepError::FeeExceedsValue { total, fee })?;
    if swept == 0 {
        return Err(SweepError::FeeExceedsValue { total, fee });
    }
    if swept < dust_threshold_atomic {
        return Err(SweepError::ResultIsDust {
            swept,
            dust: dust_threshold_atomic,
        });
    }

    Ok(SweepPlan {
        source_hash160,
        dest_hash160,
        dest_script_pubkey,
        dest_address,
        fee_atomic: fee,
        swept_atomic: swept,
        inputs: utxos.to_vec(),
    })
}

/// Verifies that a proposed unsigned transaction realises exactly `plan`.
///
/// Run by every signer before it contributes, over the bytes it is actually
/// being asked to sign. The commitment check proves the operator approved
/// *this plan*; this proves the transaction *is* that plan. Both are needed:
/// a matching commitment over a different transaction would authorise a
/// signature over bytes nobody approved.
pub fn verify_sweep_tx(tx: &Transaction, plan: &SweepPlan) -> Result<(), SweepError> {
    if tx.inputs.len() != plan.inputs.len() {
        return Err(SweepError::InputCountMismatch {
            expected: plan.inputs.len(),
            found: tx.inputs.len(),
        });
    }
    for (i, (got, want)) in tx.inputs.iter().zip(&plan.inputs).enumerate() {
        // An unsigned transaction carries empty scriptSigs. A populated one
        // means someone is asking for a signature over a transaction that
        // has already been partly assembled, which is not a shape this path
        // produces and not one it will sign.
        if !got.script_sig.is_empty() {
            return Err(SweepError::AlreadySigned(i));
        }
        // The transaction carries internal order; the plan carries what the
        // node displayed. Converting is mandatory — see `internal_txid`.
        if got.prev_txid != internal_txid(&want.txid)
            || u64::from(got.prev_vout) != want.vout as u64
        {
            return Err(SweepError::InputMismatch {
                index: i,
                expected: format!("{}:{}", want.txid_hex, want.vout),
                found: format!(
                    "{}:{}",
                    crate::glc::hex::encode(&internal_txid(&got.prev_txid)),
                    got.prev_vout
                ),
            });
        }
    }

    if tx.outputs.len() != 1 {
        // Two outputs would mean part of the vault went somewhere the plan
        // does not describe — the exact failure a sweep exists to prevent.
        return Err(SweepError::NotSingleOutput(tx.outputs.len()));
    }
    let out = &tx.outputs[0];
    if out.script_pubkey != plan.dest_script_pubkey {
        return Err(SweepError::WrongDestination {
            expected_hex: crate::glc::hex::encode(&plan.dest_script_pubkey),
            found_hex: crate::glc::hex::encode(&out.script_pubkey),
        });
    }
    if out.value != plan.swept_atomic {
        return Err(SweepError::WrongAmount {
            expected: plan.swept_atomic,
            found: out.value,
        });
    }
    Ok(())
}

/// A stored (display-order) txid as it appears **inside a transaction**.
///
/// Goldcoin serializes an input's previous-output txid in internal order,
/// which is the byte reversal of the hex a node displays and of what
/// `VaultUtxo::txid` holds (decoded straight from `listunspent`). The two
/// must be converted, never compared directly.
///
/// This cost a real defect: [`verify_sweep_tx`] and the signer's input
/// lookup originally compared them as-is. Every unit fixture built both
/// sides from the same array, so the tests agreed with each other and with
/// nothing else — `sweep-execute` would have refused every genuine sweep
/// with `UnknownInput`. Found by the Phase 7j rehearsal against a real node,
/// which is precisely what ADR-0014 §8.7 asks a rehearsal to catch.
pub fn internal_txid(display_order: &[u8; 32]) -> [u8; 32] {
    let mut t = *display_order;
    t.reverse();
    t
}

/// The `scriptPubKey` for a P2SH destination: `OP_HASH160 <20> OP_EQUAL`.
///
/// A new vault is always P2SH, so the compromise-response path builds its
/// destination script here rather than trusting one off the wire.
pub fn p2sh_script_pubkey(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20
    s.extend_from_slice(hash160);
    s.push(0x87); // OP_EQUAL
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::multisig::{TxInput, TxOutput};

    const SRC: [u8; 20] = [0x11; 20];
    const DST: [u8; 20] = [0x22; 20];
    const RATE: u64 = 10_000;
    const DUST: u64 = 5_400;

    fn utxo(seed: u8, amount: u64) -> VaultUtxo {
        // Deliberately NOT `[seed; 32]`: a uniform array is a palindrome, so
        // display and internal order would coincide and every byte-order
        // assertion in this module would prove nothing.
        let mut txid = [seed; 32];
        txid[0] = seed.wrapping_add(1);
        txid[31] = seed.wrapping_add(2);
        VaultUtxo {
            txid,
            txid_hex: crate::glc::hex::encode(&txid),
            vout: 0,
            amount_atomic: amount,
            script_pubkey_hex: crate::glc::hex::encode(&p2sh_script_pubkey(&SRC)),
            confirmations: 10,
        }
    }

    fn plan(utxos: &[VaultUtxo]) -> SweepPlan {
        plan_sweep(
            SRC,
            SweepDestination::p2sh(DST, "Qdest".into()),
            utxos,
            RATE,
            DUST,
            20,
            crate::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .expect("plan")
    }

    fn tx_for(p: &SweepPlan) -> Transaction {
        Transaction {
            version: 1,
            inputs: p
                .inputs
                .iter()
                .map(|u| TxInput {
                    // Internal order, as a real transaction carries it.
                    prev_txid: internal_txid(&u.txid),
                    prev_vout: u.vout as u32,
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                })
                .collect(),
            outputs: vec![TxOutput {
                value: p.swept_atomic,
                script_pubkey: p.dest_script_pubkey.clone(),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn a_sweep_takes_every_output_and_pays_one_destination() {
        let utxos = vec![utxo(1, 500_000), utxo(2, 700_000), utxo(3, 100_000)];
        let p = plan(&utxos);
        assert_eq!(p.inputs.len(), 3, "a sweep leaves nothing behind");
        assert_eq!(p.total_in(), 1_300_000);
        assert_eq!(
            p.swept_atomic + p.fee_atomic,
            p.total_in(),
            "no value goes anywhere but the destination and the fee"
        );
        verify_sweep_tx(&tx_for(&p), &p).expect("the built transaction realises the plan");
    }

    #[test]
    fn sweeping_a_vault_to_itself_is_refused() {
        // It would spend everything, pay a fee, and leave the funds under
        // the same key the sweep exists to escape.
        let err = plan_sweep(
            SRC,
            SweepDestination::p2sh(SRC, "Qsame".into()),
            &[utxo(1, 500_000)],
            RATE,
            DUST,
            20,
            crate::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .unwrap_err();
        assert_eq!(err, SweepError::DestinationIsSource);
    }

    #[test]
    fn an_empty_vault_cannot_be_swept() {
        let err = plan_sweep(
            SRC,
            SweepDestination::p2sh(DST, "Q".into()),
            &[],
            RATE,
            DUST,
            20,
            crate::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .unwrap_err();
        assert_eq!(err, SweepError::NothingToSweep);
    }

    #[test]
    fn a_vault_worth_less_than_its_fee_is_refused_rather_than_underflowing() {
        let err = plan_sweep(
            SRC,
            SweepDestination::p2sh(DST, "Q".into()),
            &[utxo(1, 10)],
            RATE,
            DUST,
            20,
            crate::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .unwrap_err();
        assert!(
            matches!(err, SweepError::FeeExceedsValue { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_sweep_that_would_produce_dust_is_refused() {
        // fee for 1-in/1-out at RATE is 1_920; 7_000 - 1_920 = 5_080 < DUST.
        let err = plan_sweep(
            SRC,
            SweepDestination::p2sh(DST, "Q".into()),
            &[utxo(1, 7_000)],
            RATE,
            DUST,
            20,
            crate::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .unwrap_err();
        assert!(
            matches!(err, SweepError::ResultIsDust { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn the_input_cap_is_enforced() {
        let utxos: Vec<VaultUtxo> = (0..25).map(|i| utxo(i, 500_000)).collect();
        let err = plan_sweep(
            SRC,
            SweepDestination::p2sh(DST, "Q".into()),
            &utxos,
            RATE,
            DUST,
            20,
            crate::withdrawal::coin::multisig_input_bytes(2, 105),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SweepError::TooManyInputs {
                needed: 25,
                max: 20
            }
        );
    }

    #[test]
    fn the_commitment_changes_with_the_destination() {
        // The load-bearing property: an approval to sweep to A must not
        // authorise a sweep to B.
        let utxos = vec![utxo(1, 500_000)];
        let a = plan(&utxos);
        let mut b = a.clone();
        b.dest_hash160 = [0x33; 20];
        b.dest_script_pubkey = p2sh_script_pubkey(&[0x33; 20]);
        assert_ne!(a.commitment(1), b.commitment(1));
    }

    #[test]
    fn the_commitment_changes_with_the_source_vault() {
        let utxos = vec![utxo(1, 500_000)];
        let a = plan(&utxos);
        let mut b = a.clone();
        b.source_hash160 = [0x44; 20];
        assert_ne!(a.commitment(1), b.commitment(1));
    }

    #[test]
    fn the_commitment_changes_with_the_input_set() {
        // Otherwise an approval could be reused after the vault received
        // more funds, sweeping value the operator never saw.
        let a = plan(&[utxo(1, 500_000)]);
        let b = plan(&[utxo(1, 500_000), utxo(2, 500_000)]);
        assert_ne!(a.commitment(1), b.commitment(1));
    }

    #[test]
    fn the_commitment_changes_with_input_order() {
        // Order determines the txid, so two orderings are two different
        // transactions and must not share an approval.
        let a = plan(&[utxo(1, 500_000), utxo(2, 700_000)]);
        let b = plan(&[utxo(2, 700_000), utxo(1, 500_000)]);
        assert_ne!(a.commitment(1), b.commitment(1));
    }

    #[test]
    fn the_commitment_changes_with_the_protocol_version() {
        let p = plan(&[utxo(1, 500_000)]);
        assert_ne!(p.commitment(1), p.commitment(2));
    }

    #[test]
    fn the_commitment_is_domain_separated() {
        let p = plan(&[utxo(1, 500_000)]);
        assert!(p.canonical_intent(1).starts_with(SWEEP_DOMAIN_TAG));
    }

    #[test]
    fn the_commitment_is_stable_for_the_same_plan() {
        let utxos = vec![utxo(1, 500_000), utxo(2, 700_000)];
        assert_eq!(plan(&utxos).commitment(1), plan(&utxos).commitment(1));
    }

    #[test]
    fn a_transaction_paying_a_different_destination_is_rejected() {
        let p = plan(&[utxo(1, 500_000)]);
        let mut tx = tx_for(&p);
        tx.outputs[0].script_pubkey = p2sh_script_pubkey(&[0x99; 20]);
        assert!(
            matches!(
                verify_sweep_tx(&tx, &p).unwrap_err(),
                SweepError::WrongDestination { .. }
            ),
            "a redirected sweep must never be signed"
        );
    }

    #[test]
    fn a_transaction_paying_a_different_amount_is_rejected() {
        let p = plan(&[utxo(1, 500_000)]);
        let mut tx = tx_for(&p);
        tx.outputs[0].value -= 1;
        assert!(matches!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::WrongAmount { .. }
        ));
    }

    #[test]
    fn a_second_output_is_rejected() {
        // A "sweep" with a change output is a partial sweep: value stays
        // under the key the sweep exists to abandon.
        let p = plan(&[utxo(1, 500_000)]);
        let mut tx = tx_for(&p);
        tx.outputs.push(TxOutput {
            value: 1,
            script_pubkey: p2sh_script_pubkey(&SRC),
        });
        assert_eq!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::NotSingleOutput(2)
        );
    }

    #[test]
    fn a_transaction_carrying_display_order_txids_is_rejected() {
        // THE regression. Goldcoin serializes an input's txid in internal
        // order; `VaultUtxo` stores display order. The first version of this
        // module compared them directly and every unit fixture built both
        // sides from one array, so the tests agreed with each other and with
        // nothing else — `sweep-execute` would have refused every genuine
        // sweep. Found by the Phase 7j real-node rehearsal.
        //
        // This pins the convention against a KNOWN WRONG value rather than
        // against the fixture, so making both sides drift together cannot
        // make it pass again.
        let p = plan(&[utxo(1, 500_000), utxo(2, 700_000)]);
        let mut tx = tx_for(&p);
        for (inp, want) in tx.inputs.iter_mut().zip(&p.inputs) {
            inp.prev_txid = want.txid; // display order — the bug
        }
        assert!(
            matches!(
                verify_sweep_tx(&tx, &p).unwrap_err(),
                SweepError::InputMismatch { .. }
            ),
            "a transaction whose inputs are in display order is not the planned sweep"
        );
    }

    #[test]
    fn the_two_txid_orders_are_genuinely_different() {
        // Guards the test above from becoming vacuous: if `utxo()` ever
        // produced a palindromic txid, display and internal order would
        // coincide and the regression test would pass for the wrong reason.
        let u = utxo(1, 500_000);
        assert_ne!(
            internal_txid(&u.txid),
            u.txid,
            "the fixture txid must not be a palindrome, or the order test proves nothing"
        );
        assert_eq!(
            internal_txid(&internal_txid(&u.txid)),
            u.txid,
            "reversal is its own inverse"
        );
    }

    #[test]
    fn a_substituted_input_is_rejected() {
        let p = plan(&[utxo(1, 500_000), utxo(2, 700_000)]);
        let mut tx = tx_for(&p);
        tx.inputs[1].prev_txid = internal_txid(&[0xEE; 32]);
        assert!(matches!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::InputMismatch { index: 1, .. }
        ));
    }

    #[test]
    fn a_reordered_input_set_is_rejected() {
        // Reordering changes the txid, so the transaction is not the one
        // that was approved even though it spends the same outputs.
        let p = plan(&[utxo(1, 500_000), utxo(2, 700_000)]);
        let mut tx = tx_for(&p);
        tx.inputs.swap(0, 1);
        assert!(matches!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::InputMismatch { .. }
        ));
    }

    #[test]
    fn a_dropped_input_is_rejected() {
        let p = plan(&[utxo(1, 500_000), utxo(2, 700_000)]);
        let mut tx = tx_for(&p);
        tx.inputs.pop();
        assert_eq!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::InputCountMismatch {
                expected: 2,
                found: 1
            }
        );
    }

    #[test]
    fn an_extra_input_is_rejected() {
        let p = plan(&[utxo(1, 500_000)]);
        let mut tx = tx_for(&p);
        tx.inputs.push(TxInput {
            prev_txid: [0x77; 32],
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        });
        assert_eq!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::InputCountMismatch {
                expected: 1,
                found: 2
            }
        );
    }

    #[test]
    fn a_pre_signed_transaction_is_rejected() {
        let p = plan(&[utxo(1, 500_000)]);
        let mut tx = tx_for(&p);
        tx.inputs[0].script_sig = vec![0x00, 0x47];
        assert_eq!(
            verify_sweep_tx(&tx, &p).unwrap_err(),
            SweepError::AlreadySigned(0)
        );
    }

    #[test]
    fn the_p2sh_script_has_the_shape_consensus_requires() {
        let s = p2sh_script_pubkey(&DST);
        assert_eq!(s.len(), 23);
        assert_eq!(s[0], 0xa9);
        assert_eq!(s[1], 0x14);
        assert_eq!(&s[2..22], &DST);
        assert_eq!(s[22], 0x87);
    }
}
