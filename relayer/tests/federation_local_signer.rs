//! The local signer must be reachable, or payouts stall forever.
//!
//! # The defect this covers
//!
//! A payout's signing quorum is designated from the **withdrawal index**
//! (ADR-0015), not from who happens to be reachable, and it contains exactly
//! `threshold` members — no slack. `GLC_FEDERATION_PEERS` means *the other
//! operators*, and `glc-relayer` refuses to start if this operator appears in
//! it. So whenever the designated quorum included this operator, the
//! collector could not resolve that member to any endpoint, recorded it
//! `Unavailable("designated signer is not a configured peer")`, and collected
//! at most `threshold - 1` partials. The withdrawal never left `Signing`, and
//! because the designation is deterministic, every retry failed identically.
//!
//! It was not an edge case. `designate_quorum` starts the quorum at
//! `index % signer_count`, and `OperatorAssignment::designated_for` picks the
//! builder with the same expression — so **the operator designated to build a
//! payout is always a member of that payout's own quorum**.
//!
//! These tests are deliberately in-process and fast. The full proof — three
//! real `signer-server` processes, three Goldcoin nodes and a validator,
//! deposit through payout — is `rehearsal_three_operator_payout`.

use glc_relayer::p2p::collector::{DesignatedSigner, GrpcCollector};
use glc_relayer::p2p::identity::{parse_peers, with_local_signer, IdentityError, PeerEndpoint};
use glc_relayer::withdrawal::assignment::{designate_quorum, OperatorAssignment};
use glc_relayer::withdrawal::federation::VaultSignerMap;
use glc_relayer::withdrawal::vault::MultisigVault;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

const SIGNERS: usize = 3;
const THRESHOLD: usize = 2;

fn vault() -> MultisigVault {
    let keys: Vec<[u8; 33]> = (0..SIGNERS)
        .map(|i| {
            let mut k = [0u8; 33];
            k[0] = 0x02;
            k[32] = i as u8 + 1;
            k
        })
        .collect();
    MultisigVault::new(THRESHOLD, keys).unwrap()
}

fn identities() -> Vec<Pubkey> {
    (0..SIGNERS).map(|_| Keypair::new().pubkey()).collect()
}

/// The peer list an operator is *allowed* to configure: everyone but itself.
fn peers_excluding(ids: &[Pubkey], me: usize) -> Vec<PeerEndpoint> {
    ids.iter()
        .enumerate()
        .filter(|(i, _)| *i != me)
        .map(|(i, pk)| PeerEndpoint {
            validator_pubkey: *pk,
            uri: format!("https://10.0.0.{}:9000", i + 1),
        })
        .collect()
}

fn resolve(map: &VaultSignerMap, vault: &MultisigVault, quorum: &[u8]) -> Vec<DesignatedSigner> {
    quorum
        .iter()
        .map(|&i| DesignatedSigner {
            validator_pubkey: map.validator_at(i).expect("mapped validator"),
            vault_pubkey: vault.signer_pubkeys[i as usize],
        })
        .collect()
}

/// Which designated members this collector could actually resolve to an
/// endpoint. Anything it cannot resolve contributes no partial, whatever the
/// network then does.
fn reachable(collector: &GrpcCollector, designated: &[DesignatedSigner]) -> Vec<Pubkey> {
    designated
        .iter()
        .filter(|d| {
            collector
                .peers()
                .iter()
                .any(|p| p.validator_pubkey == d.validator_pubkey)
        })
        .map(|d| d.validator_pubkey)
        .collect()
}

// ---------------------------------------------------------------------------
// The defect itself
// ---------------------------------------------------------------------------

#[test]
fn the_designated_builder_is_always_in_its_own_quorum() {
    // This is why the stall was total rather than occasional, and it is
    // arithmetic rather than opinion: both expressions are `index % count`.
    for index in 0..12i64 {
        let quorum = designate_quorum(index, SIGNERS, THRESHOLD);
        let assignment = OperatorAssignment::new(0, SIGNERS, 120, 60).unwrap();
        let builder = assignment.designated_for(index as u64);
        assert!(
            quorum.contains(&(builder as u8)),
            "withdrawal {index}: builder {builder} is absent from its own quorum {quorum:?}"
        );
    }
}

#[test]
fn a_quorum_containing_this_operator_is_unreachable_without_a_local_endpoint() {
    // The regression, stated at the layer where it bit: peers alone cannot
    // satisfy a quorum that includes this operator.
    let ids = identities();
    let v = vault();
    let map = VaultSignerMap::parse(
        &ids.iter()
            .enumerate()
            .map(|(i, pk)| format!("{i}:{pk}"))
            .collect::<Vec<_>>()
            .join(","),
        &v,
    )
    .unwrap();

    let me = 0usize;
    let quorum = designate_quorum(0, SIGNERS, THRESHOLD);
    assert!(
        quorum.contains(&(me as u8)),
        "precondition: quorum includes us"
    );
    let designated = resolve(&map, &v, &quorum);

    let peers_only = GrpcCollector::insecure_without_tls(peers_excluding(&ids, me));
    let got = reachable(&peers_only, &designated);
    assert_eq!(
        got.len(),
        THRESHOLD - 1,
        "with peers alone the quorum can never reach threshold {THRESHOLD}"
    );
    assert!(!got.contains(&ids[me]), "our own signer has no endpoint");

    // With the local signer configured, every designated member resolves.
    let with_local = GrpcCollector::insecure_without_tls(
        with_local_signer(peers_excluding(&ids, me), ids[me], "https://127.0.0.1:9000").unwrap(),
    );
    let got = reachable(&with_local, &designated);
    assert_eq!(got.len(), THRESHOLD, "the full quorum is now reachable");
    assert!(got.contains(&ids[me]), "including our own signer");
}

#[test]
fn a_remote_only_quorum_is_unaffected_by_the_fix() {
    // Adding the local endpoint must not perturb quorums that never
    // contained this operator — those always worked.
    let ids = identities();
    let v = vault();
    let map = VaultSignerMap::parse(
        &ids.iter()
            .enumerate()
            .map(|(i, pk)| format!("{i}:{pk}"))
            .collect::<Vec<_>>()
            .join(","),
        &v,
    )
    .unwrap();

    let me = 0usize;
    // Withdrawal 1 designates [1, 2] — the two remote operators.
    let quorum = designate_quorum(1, SIGNERS, THRESHOLD);
    assert!(
        !quorum.contains(&(me as u8)),
        "precondition: we are not in it"
    );
    let designated = resolve(&map, &v, &quorum);

    let before = GrpcCollector::insecure_without_tls(peers_excluding(&ids, me));
    let after = GrpcCollector::insecure_without_tls(
        with_local_signer(peers_excluding(&ids, me), ids[me], "https://127.0.0.1:9000").unwrap(),
    );
    assert_eq!(reachable(&before, &designated).len(), THRESHOLD);
    assert_eq!(
        reachable(&before, &designated),
        reachable(&after, &designated),
        "a remote-only quorum resolves to exactly the same signers"
    );
}

#[test]
fn the_fix_never_substitutes_an_undesignated_signer() {
    // ADR-0015: the txid depends on which quorum signs, so a shortfall must
    // force an explicit, audited reassignment — never a quiet substitution
    // of whoever happens to be up. Operator 2 is reachable and idle, and
    // must still never appear in withdrawal 0's quorum.
    let ids = identities();
    let v = vault();
    let map = VaultSignerMap::parse(
        &ids.iter()
            .enumerate()
            .map(|(i, pk)| format!("{i}:{pk}"))
            .collect::<Vec<_>>()
            .join(","),
        &v,
    )
    .unwrap();

    let quorum = designate_quorum(0, SIGNERS, THRESHOLD);
    let designated = resolve(&map, &v, &quorum);
    let collector = GrpcCollector::insecure_without_tls(
        with_local_signer(peers_excluding(&ids, 0), ids[0], "https://127.0.0.1:9000").unwrap(),
    );

    assert_eq!(
        designated.len(),
        THRESHOLD,
        "exactly threshold-many, no spares"
    );
    let got = reachable(&collector, &designated);
    assert!(
        !got.contains(&ids[2]),
        "operator 2 is reachable but undesignated, and must not be asked"
    );
}

// ---------------------------------------------------------------------------
// Configuration is validated, not assumed
// ---------------------------------------------------------------------------

#[test]
fn an_operator_may_still_not_list_itself_among_its_peers() {
    // The fix must not become a way to smuggle self into the peer list,
    // which would count one operator as two.
    let ids = identities();
    let raw = format!("{}@https://10.0.0.1:9000", ids[0]);
    assert!(matches!(
        parse_peers(&raw, Some(&ids[0])),
        Err(IdentityError::SelfInPeerList(_))
    ));
}

#[test]
fn a_duplicate_validator_identity_is_refused() {
    let ids = identities();
    let raw = format!(
        "{}@https://10.0.0.1:9000,{}@https://10.0.0.2:9000",
        ids[1], ids[1]
    );
    assert!(matches!(
        parse_peers(&raw, Some(&ids[0])),
        Err(IdentityError::DuplicatePeer(_))
    ));
}

#[test]
fn the_local_endpoint_may_not_be_a_peers_endpoint() {
    let ids = identities();
    let shared = "https://10.0.0.2:9000";
    let peers = vec![PeerEndpoint {
        validator_pubkey: ids[1],
        uri: shared.to_string(),
    }];
    assert!(matches!(
        with_local_signer(peers, ids[0], shared),
        Err(IdentityError::DuplicateEndpoint { .. })
    ));
}

#[test]
fn a_missing_local_endpoint_stops_the_relayer_rather_than_stalling_it() {
    // Before the fix this configuration ran happily and lost every payout.
    // Now it refuses to start, and says which variable to set.
    let ids = identities();
    let e = with_local_signer(peers_excluding(&ids, 0), ids[0], "").unwrap_err();
    assert!(matches!(e, IdentityError::MissingLocalSigner));
    assert!(e.to_string().contains("GLC_RELAYER_LOCAL_SIGNER_URI"));
}
