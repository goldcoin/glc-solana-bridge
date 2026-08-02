//! Peer signature collection over mTLS gRPC (Phase 7c/7d, ADR-0016).
//!
//! Implements [`SignatureCollector`] by asking federation peers, over
//! mutually-authenticated TLS, for signatures over a canonical message.
//!
//! # What this layer decides, and what it does not
//!
//! It decides *who to ask*, *how long to wait*, and *when a round is done*
//! ([`super::aggregation`]). It does not decide what should be signed: peers
//! independently re-derive every message and sign only what they derived
//! ([`super::policy`]). Only signatures cross the network.
//!
//! # Every response is checked twice
//!
//! mTLS proves the peer holds a certificate issued by the federation's own
//! CA. That is not sufficient on its own, so each response is additionally
//! checked against the **on-chain ed25519 identity** the endpoint is
//! registered as, and its signature must verify over the message actually
//! requested. A stolen certificate therefore cannot impersonate a validator,
//! and a peer cannot contribute another member's signature, nor one over
//! different bytes.
//!
//! # Falling short is normal; a refusal is not
//!
//! Missing threshold is an ordinary tick outcome the orchestrator retries
//! later, never an error that strands a deposit. A *refusal*, though, means
//! that peer independently disagreed about what should be signed — an alarm,
//! and not something a retry will fix.

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::orchestrator::SignatureCollector;
use crate::p2p::aggregation::{ask_order, PeerOutcome, Round, PER_PEER_TIMEOUT, ROUND_TIMEOUT};
use crate::p2p::identity::{PeerEndpoint, TlsMaterial};
use crate::p2p::service::pb::federation_signer_client::FederationSignerClient;
use crate::p2p::service::{mint_request, payout_request, pb, REQUEST_TTL_SECONDS};
use crate::withdrawal::multisig::PartialSignature;
use crate::withdrawal::vault::COMPRESSED_PUBKEY_LEN;

pub struct GrpcCollector {
    peers: Vec<PeerEndpoint>,
    /// `None` means no transport authentication at all — see
    /// [`GrpcCollector::insecure_without_tls`].
    tls: Option<TlsMaterial>,
    /// The name peer certificates must be issued for. Pinned by
    /// configuration rather than taken from the URI, so a peer cannot
    /// present a certificate for a name it merely happens to control.
    tls_domain: String,
}

impl GrpcCollector {
    /// Production constructor: mutual TLS against the federation's own CA.
    pub fn new(peers: Vec<PeerEndpoint>, tls: TlsMaterial, tls_domain: String) -> Self {
        GrpcCollector {
            peers,
            tls: Some(tls),
            tls_domain,
        }
    }

    /// The endpoints this collector can reach.
    ///
    /// A designated signer absent from here contributes no partial, whatever
    /// the network does — which is exactly how payouts stalled before the
    /// local signer had an address.
    pub fn peers(&self) -> &[PeerEndpoint] {
        &self.peers
    }

    /// Plaintext transport, for loopback and tests.
    ///
    /// Deliberately named so its use is conspicuous in review and in
    /// configuration: a deployment reaching for this has no transport
    /// authentication whatsoever, and rests entirely on the application-layer
    /// identity check in [`GrpcCollector::accept`].
    pub fn insecure_without_tls(peers: Vec<PeerEndpoint>) -> Self {
        GrpcCollector {
            peers,
            tls: None,
            tls_domain: String::new(),
        }
    }

    fn next_request_id() -> Vec<u8> {
        // Unique per request so a retry is distinguishable from a fresh ask.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        nanos.to_le_bytes().to_vec()
    }

    async fn connect(&self, uri: &str) -> Result<FederationSignerClient<Channel>, String> {
        let mut endpoint = Channel::from_shared(uri.to_string())
            .map_err(|e| format!("bad peer uri: {e}"))?
            .connect_timeout(PER_PEER_TIMEOUT)
            .timeout(PER_PEER_TIMEOUT);

        if let Some(tls) = &self.tls {
            let cfg = ClientTlsConfig::new()
                // Pin the federation CA. The public web PKI is deliberately
                // NOT trusted here: otherwise any publicly-issued
                // certificate for a matching name would be accepted.
                .ca_certificate(Certificate::from_pem(tls.ca_pem.clone()))
                .domain_name(self.tls_domain.clone())
                // Present our own certificate, so the peer authenticates us
                // exactly as we authenticate it.
                .identity(Identity::from_pem(
                    tls.cert_pem.clone(),
                    tls.key_pem.clone(),
                ));
            endpoint = endpoint
                .tls_config(cfg)
                .map_err(|e| format!("tls configuration rejected: {e}"))?;
        }

        endpoint
            .connect()
            .await
            .map(FederationSignerClient::new)
            .map_err(|e| format!("connect failed: {e}"))
    }

    /// Accepts a response only if it is internally consistent.
    ///
    /// Both checks matter and neither implies the other: the identity check
    /// stops a peer answering as somebody else, the signature check stops it
    /// contributing a signature over bytes other than the ones we asked
    /// about.
    fn accept(
        expected: &Pubkey,
        message: &[u8],
        resp: pb::SignResponse,
    ) -> Result<(Pubkey, Signature), String> {
        let pubkey = Pubkey::try_from(resp.validator_pubkey.as_slice())
            .map_err(|_| "response carried a malformed validator pubkey".to_string())?;
        if pubkey != *expected {
            return Err(format!(
                "endpoint registered as {expected} answered as {pubkey}"
            ));
        }
        let sig = Signature::try_from(resp.signature.as_slice())
            .map_err(|_| "response carried a malformed signature".to_string())?;
        if !sig.verify(pubkey.as_ref(), message) {
            return Err("signature does not verify over the requested message".to_string());
        }
        Ok((pubkey, sig))
    }

    /// Asks one peer, bounded by [`PER_PEER_TIMEOUT`] at both connect and
    /// call, so one unresponsive peer cannot stall the round.
    async fn ask(&self, peer: &PeerEndpoint, req: pb::SignRequest, message: &[u8]) -> PeerOutcome {
        let mut client = match self.connect(&peer.uri).await {
            Ok(c) => c,
            Err(e) => return PeerOutcome::Unavailable(e),
        };
        match tokio::time::timeout(PER_PEER_TIMEOUT, client.sign(req)).await {
            Err(_) => PeerOutcome::Unavailable("per-peer timeout".to_string()),
            Ok(Err(status)) => {
                // `failed_precondition` is what `SignerService` returns for a
                // policy refusal. Kept distinct from unavailability because a
                // retry will get the same answer.
                if status.code() == tonic::Code::FailedPrecondition {
                    PeerOutcome::Refused(status.message().to_string())
                } else {
                    PeerOutcome::Unavailable(status.to_string())
                }
            }
            Ok(Ok(resp)) => {
                match Self::accept(&peer.validator_pubkey, message, resp.into_inner()) {
                    Ok((_, sig)) => PeerOutcome::Signed(sig),
                    // An inconsistent response counts as unavailability rather
                    // than refusal: the peer did not decline, it answered
                    // wrongly — a bug or an attack, but not a disagreement about
                    // what should be signed.
                    Err(why) => PeerOutcome::Unavailable(why),
                }
            }
        }
    }

    /// Runs one collection round, stopping as soon as `threshold` distinct
    /// signatures are in hand.
    ///
    /// Bounded by [`ROUND_TIMEOUT`] overall as well as per peer, so a
    /// pathological set of slow peers cannot stall a tick indefinitely.
    pub async fn collect(
        &self,
        threshold: usize,
        seed: u64,
        message: &[u8],
        build: impl Fn(Vec<u8>) -> pb::SignRequest,
    ) -> Round {
        let identities: Vec<Pubkey> = self.peers.iter().map(|p| p.validator_pubkey).collect();
        let mut round = Round::new();
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;

        for pubkey in ask_order(&identities, seed) {
            if round.reached(threshold) {
                break;
            }
            let Some(peer) = self.peers.iter().find(|p| p.validator_pubkey == pubkey) else {
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }
            let outcome = self
                .ask(peer, build(Self::next_request_id()), message)
                .await;
            if let PeerOutcome::Refused(why) = &outcome {
                tracing::warn!(
                    peer = %pubkey,
                    reason = %why,
                    "peer refused to sign — its view of the chain disagrees with ours"
                );
            }
            round.record(pubkey, outcome);
        }
        round
    }

    /// Collects payout signatures from an **explicitly designated** quorum.
    ///
    /// Only the designated members are asked, and the request carries the
    /// `quorum_attempt`, so ADR-0015's determinism survives: falling short
    /// here must lead to an explicit, audited quorum reassignment, never an
    /// implicit substitution of some other available signer — the txid
    /// depends on which quorum signs.
    pub async fn collect_payout_signatures(
        &self,
        epoch: u64,
        message: &[u8],
        withdrawal_index: u64,
        quorum_attempt: u32,
        designated: &[Pubkey],
    ) -> Round {
        let mut round = Round::new();
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;
        for pubkey in designated {
            let Some(peer) = self.peers.iter().find(|p| p.validator_pubkey == *pubkey) else {
                round.record(
                    *pubkey,
                    PeerOutcome::Unavailable(
                        "designated signer is not a configured peer".to_string(),
                    ),
                );
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    *pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }
            let req = payout_request(
                Self::next_request_id(),
                epoch,
                message.to_vec(),
                withdrawal_index,
                quorum_attempt,
            );
            let outcome = self.ask(peer, req, message).await;
            if let PeerOutcome::Refused(why) = &outcome {
                tracing::warn!(
                    peer = %pubkey,
                    withdrawal_index,
                    quorum_attempt,
                    reason = %why,
                    "designated payout signer refused"
                );
            }
            round.record(*pubkey, outcome);
        }
        tracing::info!(
            withdrawal_index,
            quorum_attempt,
            summary = %round.summary(),
            "payout signature collection round"
        );
        round
    }
}

/// A designated signer's endpoint plus the vault key it must answer with
/// (Phase 7e, ADR-0017 E1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesignatedSigner {
    pub validator_pubkey: Pubkey,
    pub vault_pubkey: [u8; COMPRESSED_PUBKEY_LEN],
}

/// The outcome of collecting vault partials from a designated quorum.
#[derive(Debug, Clone)]
pub struct PartialRound {
    pub partials: Vec<PartialSignature>,
    pub round: Round,
}

impl GrpcCollector {
    /// Collects **Goldcoin partial signatures** from an explicitly
    /// designated quorum (Phase 7e, ADR-0017).
    ///
    /// Only the designated members are asked, and only they may contribute:
    /// the txid depends on which quorum signs, so an unavailable designated
    /// signer must produce a shortfall requiring explicit, audited
    /// reassignment — never an implicit substitution (ADR-0015).
    ///
    /// A returned partial is checked against the vault key that signer is
    /// registered as holding. The signature itself is verified later, during
    /// assembly, against that input's sighash — which is where a forged or
    /// corrupted partial is actually caught.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect_payout_partials(
        &self,
        epoch: u64,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        designated: &[DesignatedSigner],
        proposer_index: u32,
    ) -> PartialRound {
        let mut round = Round::new();
        let mut partials = Vec::with_capacity(designated.len());
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;

        for d in designated {
            let Some(peer) = self
                .peers
                .iter()
                .find(|p| p.validator_pubkey == d.validator_pubkey)
            else {
                round.record(
                    d.validator_pubkey,
                    PeerOutcome::Unavailable(
                        "designated signer is not a configured peer".to_string(),
                    ),
                );
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    d.validator_pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }

            let req = pb::PayoutSignRequest {
                request_id: Self::next_request_id(),
                epoch,
                withdrawal_index,
                quorum_attempt,
                canonical_intent: canonical_intent.to_vec(),
                unsigned_tx_hex: unsigned_tx_hex.to_string(),
                expiry_unix: crate::p2p::service::now_unix() + REQUEST_TTL_SECONDS,
                proposer_index,
            };

            match self.ask_payout(peer, req, d).await {
                Ok(partial) => {
                    // A synthetic marker: `Round` counts approvals by
                    // federation identity, and the real cryptographic check
                    // happens during assembly.
                    round.record(
                        d.validator_pubkey,
                        PeerOutcome::Signed(Signature::default()),
                    );
                    partials.push(partial);
                }
                Err(outcome) => {
                    if let PeerOutcome::Refused(why) = &outcome {
                        tracing::warn!(
                            peer = %d.validator_pubkey,
                            withdrawal_index,
                            quorum_attempt,
                            reason = %why,
                            "designated payout signer refused — its view of the Goldcoin chain disagrees with ours"
                        );
                    }
                    round.record(d.validator_pubkey, outcome);
                }
            }
        }

        tracing::info!(
            withdrawal_index,
            quorum_attempt,
            summary = %round.summary(),
            "payout partial-signature collection round"
        );
        PartialRound { partials, round }
    }

    /// Collects **vault sweep partials** from the federation (Phase 7i-0).
    ///
    /// Unlike a payout, a sweep has no designated quorum: it is not derived
    /// from a withdrawal index, so there is nothing to designate from. Every
    /// vault signer is asked, and the first `threshold` that answer are the
    /// quorum — which is sound here because the operators, not the protocol,
    /// decide a sweep, and any M of them suffice.
    ///
    /// Refusals are **ordinary**, as with governance: a signer whose
    /// operator has not staged this exact sweep is behaving as designed.
    pub async fn collect_sweep_partials(
        &self,
        epoch: u64,
        unsigned_tx_hex: &str,
        signers: &[DesignatedSigner],
        threshold: usize,
    ) -> PartialRound {
        let mut round = Round::new();
        let mut partials = Vec::with_capacity(threshold);
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;

        for d in signers {
            if partials.len() >= threshold {
                break;
            }
            let Some(peer) = self
                .peers
                .iter()
                .find(|p| p.validator_pubkey == d.validator_pubkey)
            else {
                round.record(
                    d.validator_pubkey,
                    PeerOutcome::Unavailable("vault signer is not a configured peer".to_string()),
                );
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    d.validator_pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }

            let req = pb::SweepSignRequest {
                request_id: Self::next_request_id(),
                epoch,
                unsigned_tx_hex: unsigned_tx_hex.to_string(),
                expiry_unix: crate::p2p::service::now_unix() + REQUEST_TTL_SECONDS,
            };
            match self.ask_sweep(peer, req, d).await {
                Ok(partial) => {
                    round.record(
                        d.validator_pubkey,
                        PeerOutcome::Signed(Signature::default()),
                    );
                    partials.push(partial);
                }
                Err(outcome) => {
                    if let PeerOutcome::Refused(why) = &outcome {
                        tracing::info!(
                            peer = %d.validator_pubkey,
                            reason = %why,
                            "peer has not approved this vault sweep"
                        );
                    }
                    round.record(d.validator_pubkey, outcome);
                }
            }
        }

        tracing::warn!(
            collected = partials.len(),
            threshold,
            summary = %round.summary(),
            "VAULT SWEEP partial-signature collection round"
        );
        PartialRound { partials, round }
    }

    async fn ask_sweep(
        &self,
        peer: &PeerEndpoint,
        req: pb::SweepSignRequest,
        signer: &DesignatedSigner,
    ) -> Result<PartialSignature, PeerOutcome> {
        let mut client = self
            .connect(&peer.uri)
            .await
            .map_err(PeerOutcome::Unavailable)?;

        let resp = match tokio::time::timeout(PER_PEER_TIMEOUT, client.sign_sweep(req)).await {
            Err(_) => return Err(PeerOutcome::Unavailable("per-peer timeout".to_string())),
            Ok(Err(status)) => {
                return Err(if status.code() == tonic::Code::FailedPrecondition {
                    PeerOutcome::Refused(status.message().to_string())
                } else {
                    PeerOutcome::Unavailable(status.to_string())
                })
            }
            Ok(Ok(r)) => r.into_inner(),
        };

        // The same two-cryptosystem identity check the payout path makes, by
        // reusing its acceptor: the response shapes are identical, and a
        // second copy of this logic is a second place for it to drift.
        Self::accept_payout(
            &peer.validator_pubkey,
            signer,
            pb::PayoutSignResponse {
                request_id: resp.request_id,
                validator_pubkey: resp.validator_pubkey,
                vault_pubkey: resp.vault_pubkey,
                signatures: resp.signatures,
            },
        )
        .map_err(PeerOutcome::Unavailable)
    }

    /// Collects **completion attestations** from the federation (Phase 7f,
    /// ADR-0018).
    ///
    /// Unlike a payout, completion has no designated quorum: any M
    /// validators who have independently confirmed the payout may attest,
    /// because the on-chain proof does not depend on *which* M signed. So
    /// this asks everyone, with Phase 7d's ordering, timeouts, and failover
    /// unchanged.
    pub async fn collect_completion_signatures(
        &self,
        epoch: u64,
        withdrawal_index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
        message: &[u8],
    ) -> Round {
        let identities: Vec<Pubkey> = self.peers.iter().map(|p| p.validator_pubkey).collect();
        let mut round = Round::new();
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;
        let threshold = self.peers.len();
        let seed =
            withdrawal_index ^ u64::from_le_bytes(payout_txid[..8].try_into().unwrap_or([0u8; 8]));

        for pubkey in ask_order(&identities, seed) {
            if round.reached(threshold) {
                break;
            }
            let Some(peer) = self.peers.iter().find(|p| p.validator_pubkey == pubkey) else {
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }
            let req = pb::CompletionSignRequest {
                request_id: Self::next_request_id(),
                epoch,
                withdrawal_index,
                payout_txid: payout_txid.to_vec(),
                payout_height,
                expiry_unix: crate::p2p::service::now_unix() + REQUEST_TTL_SECONDS,
            };
            let outcome = self.ask_completion(peer, req, message).await;
            if let PeerOutcome::Refused(why) = &outcome {
                tracing::warn!(
                    peer = %pubkey,
                    withdrawal_index,
                    reason = %why,
                    "peer refused to attest completion — it has not confirmed this payout"
                );
            }
            round.record(pubkey, outcome);
        }
        tracing::info!(
            withdrawal_index,
            summary = %round.summary(),
            "completion attestation collection round"
        );
        round
    }

    /// Collects **governance signatures** from the federation (Phase 7i-0).
    ///
    /// Asks everyone, because governance has no designated quorum: any M
    /// operators who have each staged an approval may authorise the action.
    /// Refusals here are ordinary — a validator whose operator has not
    /// approved this specific proposal is *supposed* to say no.
    pub async fn collect_governance_signatures(
        &self,
        epoch: u64,
        action: u8,
        params_commitment: &[u8; 32],
        message: &[u8],
    ) -> Round {
        let identities: Vec<Pubkey> = self.peers.iter().map(|p| p.validator_pubkey).collect();
        let mut round = Round::new();
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;
        let threshold = self.peers.len();
        let seed = u64::from(action)
            ^ u64::from_le_bytes(params_commitment[..8].try_into().unwrap_or([0u8; 8]));

        for pubkey in ask_order(&identities, seed) {
            if round.reached(threshold) {
                break;
            }
            let Some(peer) = self.peers.iter().find(|p| p.validator_pubkey == pubkey) else {
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }
            let req = pb::GovernanceSignRequest {
                request_id: Self::next_request_id(),
                epoch,
                action: u32::from(action),
                params_commitment: params_commitment.to_vec(),
                expiry_unix: crate::p2p::service::now_unix() + REQUEST_TTL_SECONDS,
            };
            let outcome = self.ask_governance(peer, req, message).await;
            if let PeerOutcome::Refused(why) = &outcome {
                // NOT an alarm here, unlike everywhere else: a validator
                // whose operator has not approved this proposal is behaving
                // exactly as designed.
                tracing::info!(
                    peer = %pubkey,
                    action,
                    reason = %why,
                    "peer has not approved this governance action"
                );
            }
            round.record(pubkey, outcome);
        }
        tracing::info!(
            action,
            summary = %round.summary(),
            "governance signature collection round"
        );
        round
    }

    async fn ask_governance(
        &self,
        peer: &PeerEndpoint,
        req: pb::GovernanceSignRequest,
        message: &[u8],
    ) -> PeerOutcome {
        let mut client = match self.connect(&peer.uri).await {
            Ok(c) => c,
            Err(e) => return PeerOutcome::Unavailable(e),
        };
        match tokio::time::timeout(PER_PEER_TIMEOUT, client.sign_governance(req)).await {
            Err(_) => PeerOutcome::Unavailable("per-peer timeout".to_string()),
            Ok(Err(status)) => {
                if status.code() == tonic::Code::FailedPrecondition {
                    PeerOutcome::Refused(status.message().to_string())
                } else {
                    PeerOutcome::Unavailable(status.to_string())
                }
            }
            Ok(Ok(resp)) => {
                let r = resp.into_inner();
                let as_sign = pb::SignResponse {
                    request_id: r.request_id,
                    validator_pubkey: r.validator_pubkey,
                    signature: r.signature,
                };
                match Self::accept(&peer.validator_pubkey, message, as_sign) {
                    Ok((_, sig)) => PeerOutcome::Signed(sig),
                    Err(why) => PeerOutcome::Unavailable(why),
                }
            }
        }
    }

    async fn ask_completion(
        &self,
        peer: &PeerEndpoint,
        req: pb::CompletionSignRequest,
        message: &[u8],
    ) -> PeerOutcome {
        let mut client = match self.connect(&peer.uri).await {
            Ok(c) => c,
            Err(e) => return PeerOutcome::Unavailable(e),
        };
        match tokio::time::timeout(PER_PEER_TIMEOUT, client.sign_completion(req)).await {
            Err(_) => PeerOutcome::Unavailable("per-peer timeout".to_string()),
            Ok(Err(status)) => {
                if status.code() == tonic::Code::FailedPrecondition {
                    PeerOutcome::Refused(status.message().to_string())
                } else {
                    PeerOutcome::Unavailable(status.to_string())
                }
            }
            Ok(Ok(resp)) => {
                let r = resp.into_inner();
                // Reuses the mint path's acceptance check verbatim: the
                // response must come from the registered identity AND its
                // signature must verify over the message we asked about.
                let as_sign = pb::SignResponse {
                    request_id: r.request_id,
                    validator_pubkey: r.validator_pubkey,
                    signature: r.signature,
                };
                match Self::accept(&peer.validator_pubkey, message, as_sign) {
                    Ok((_, sig)) => PeerOutcome::Signed(sig),
                    Err(why) => PeerOutcome::Unavailable(why),
                }
            }
        }
    }

    async fn ask_payout(
        &self,
        peer: &PeerEndpoint,
        req: pb::PayoutSignRequest,
        designated: &DesignatedSigner,
    ) -> Result<PartialSignature, PeerOutcome> {
        let mut client = self
            .connect(&peer.uri)
            .await
            .map_err(PeerOutcome::Unavailable)?;

        let resp = match tokio::time::timeout(PER_PEER_TIMEOUT, client.sign_payout(req)).await {
            Err(_) => return Err(PeerOutcome::Unavailable("per-peer timeout".to_string())),
            Ok(Err(status)) => {
                return Err(if status.code() == tonic::Code::FailedPrecondition {
                    PeerOutcome::Refused(status.message().to_string())
                } else {
                    PeerOutcome::Unavailable(status.to_string())
                })
            }
            Ok(Ok(r)) => r.into_inner(),
        };

        Self::accept_payout(&peer.validator_pubkey, designated, resp)
            .map_err(PeerOutcome::Unavailable)
    }

    /// Accepts a payout response only if it is internally consistent.
    ///
    /// Two separate identity checks, in two different cryptosystems, and
    /// neither implies the other:
    ///
    /// - the **federation** ed25519 identity must match the endpoint, as on
    ///   the mint path;
    /// - the **vault** secp256k1 key must be the one this signer was
    ///   designated to hold (ADR-0017 E1). A peer answering with some other
    ///   vault key — even its own, at a different position — would produce a
    ///   signature that cannot satisfy the designated quorum, and would
    ///   change the txid if it did.
    ///
    /// The signature itself is verified later, during assembly, against the
    /// input's sighash. That is where a forged or corrupted partial is
    /// actually caught; this is only about *who* answered.
    fn accept_payout(
        expected_validator: &Pubkey,
        designated: &DesignatedSigner,
        resp: pb::PayoutSignResponse,
    ) -> Result<PartialSignature, String> {
        let answered = Pubkey::try_from(resp.validator_pubkey.as_slice())
            .map_err(|_| "response carried a malformed validator pubkey".to_string())?;
        if answered != *expected_validator {
            return Err(format!(
                "endpoint registered as {expected_validator} answered as {answered}"
            ));
        }

        let vault_pubkey: [u8; COMPRESSED_PUBKEY_LEN] = resp
            .vault_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| "response carried a malformed vault pubkey".to_string())?;
        if vault_pubkey != designated.vault_pubkey {
            return Err(format!(
                "designated signer {expected_validator} answered with a vault key it was not \
                 designated for"
            ));
        }

        if resp.signatures.is_empty() {
            return Err("response carried no signatures".to_string());
        }
        if resp.signatures.iter().any(|s| s.is_empty()) {
            return Err("response carried an empty signature".to_string());
        }

        Ok(PartialSignature {
            vault_pubkey,
            signatures: resp.signatures,
        })
    }
}

impl SignatureCollector for GrpcCollector {
    async fn collect_mint_signatures(
        &self,
        epoch: u64,
        message: &[u8],
        txid: [u8; 32],
        vout: u32,
    ) -> Vec<(Pubkey, Signature)> {
        // Ask everyone rather than caching a threshold here: the on-chain
        // ValidatorSet is the authority on threshold, and the orchestrator
        // re-reads it before aggregating. A threshold cached at this layer
        // could go stale across a rotation and silently under-collect.
        let threshold = self.peers.len();
        let seed = u64::from_le_bytes(txid[..8].try_into().unwrap_or([0u8; 8])) ^ u64::from(vout);
        let msg = message.to_vec();
        let round = self
            .collect(threshold, seed, message, move |id| {
                mint_request(id, epoch, msg.clone(), txid, vout)
            })
            .await;
        tracing::info!(summary = %round.summary(), "mint signature collection round");
        round.signatures
    }
}

/// ⚠️ **TEST-ONLY.** Signs in-process with locally held keys.
///
/// This deliberately reintroduces the very property Phase 7c exists to
/// remove — one process holding several validator identities — so that
/// end-to-end tests can reach threshold without standing up N signer
/// processes and a network between them.
///
/// It must never be constructed by a deployed relayer. Production wiring
/// (`main.rs`) uses [`GrpcCollector`] exclusively, and the orchestrator
/// itself has no key parameter at all, so reaching for this in production
/// would be a deliberate act rather than an accident.
pub struct InProcessCollector {
    keys: Vec<solana_sdk::signature::Keypair>,
}

impl InProcessCollector {
    pub fn new(keys: Vec<solana_sdk::signature::Keypair>) -> Self {
        InProcessCollector { keys }
    }
}

impl SignatureCollector for InProcessCollector {
    async fn collect_mint_signatures(
        &self,
        _epoch: u64,
        message: &[u8],
        _txid: [u8; 32],
        _vout: u32,
    ) -> Vec<(Pubkey, Signature)> {
        use solana_sdk::signature::Signer;
        self.keys
            .iter()
            .map(|k| (k.pubkey(), k.sign_message(message)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};
    use std::time::Duration;

    fn resp(kp: &Keypair, message: &[u8]) -> pb::SignResponse {
        pb::SignResponse {
            request_id: vec![1],
            validator_pubkey: kp.pubkey().to_bytes().to_vec(),
            signature: kp.sign_message(message).as_ref().to_vec(),
        }
    }

    /// An endpoint whose port refuses connections immediately.
    fn dead_peer(port: u16) -> PeerEndpoint {
        PeerEndpoint {
            validator_pubkey: Keypair::new().pubkey(),
            uri: format!("http://127.0.0.1:{port}"),
        }
    }

    #[test]
    fn accepts_a_correct_response() {
        let kp = Keypair::new();
        let msg = b"canonical";
        assert!(GrpcCollector::accept(&kp.pubkey(), msg, resp(&kp, msg)).is_ok());
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        let kp = Keypair::new();
        // Correctly signed by the right validator, but over other bytes.
        let err = GrpcCollector::accept(&kp.pubkey(), b"canonical", resp(&kp, b"other"))
            .expect_err("a signature must verify over the message we actually asked about");
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn rejects_a_response_claiming_another_validators_identity() {
        // mTLS alone cannot catch this: a peer holding a valid federation
        // certificate must still not be able to answer as somebody else.
        let kp = Keypair::new();
        let impostor = Keypair::new();
        let msg = b"canonical";
        let err = GrpcCollector::accept(&impostor.pubkey(), msg, resp(&kp, msg))
            .expect_err("a peer must not contribute another validator's signature");
        assert!(err.contains("answered as"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_signature_or_pubkey() {
        let kp = Keypair::new();
        let mut r = resp(&kp, b"canonical");
        r.signature = vec![0u8; 10];
        assert!(GrpcCollector::accept(&kp.pubkey(), b"canonical", r).is_err());

        let mut r2 = resp(&kp, b"canonical");
        r2.validator_pubkey = vec![0u8; 5];
        assert!(GrpcCollector::accept(&kp.pubkey(), b"canonical", r2).is_err());
    }

    #[test]
    fn request_ids_are_unique_across_calls() {
        let a = GrpcCollector::next_request_id();
        std::thread::sleep(Duration::from_nanos(1));
        let b = GrpcCollector::next_request_id();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn an_unreachable_peer_is_bounded_and_classified_unavailable() {
        // The point is not that it fails, but that it fails *promptly* and
        // as unavailability rather than refusal — only unavailability
        // justifies a retry.
        let peer = dead_peer(1);
        let c = GrpcCollector::insecure_without_tls(vec![peer.clone()]);
        let started = std::time::Instant::now();
        let outcome = c
            .ask(
                &peer,
                mint_request(vec![1], 0, b"m".to_vec(), [0u8; 32], 0),
                b"m",
            )
            .await;
        assert!(
            matches!(outcome, PeerOutcome::Unavailable(_)),
            "got {outcome:?}"
        );
        assert!(
            started.elapsed() < PER_PEER_TIMEOUT + Duration::from_secs(2),
            "an unreachable peer must be bounded by the per-peer timeout"
        );
    }

    #[tokio::test]
    async fn a_round_of_unreachable_peers_completes_and_reports_a_retriable_shortfall() {
        let c = GrpcCollector::insecure_without_tls(vec![dead_peer(1), dead_peer(2)]);
        let round = c
            .collect(2, 0, b"m", |id| {
                mint_request(id, 0, b"m".to_vec(), [0u8; 32], 0)
            })
            .await;
        assert_eq!(round.unique_signers(), 0);
        assert_eq!(round.unavailable.len(), 2, "both peers were tried");
        assert!(!round.reached(2));
        assert!(
            round.retry_could_help(2),
            "unreachable peers may come back, so a later tick should try again"
        );
    }

    fn designated(vault_key: u8) -> (Pubkey, DesignatedSigner) {
        let validator = Keypair::new().pubkey();
        let mut vault_pubkey = [0u8; 33];
        vault_pubkey[0] = 0x02;
        vault_pubkey[32] = vault_key;
        (
            validator,
            DesignatedSigner {
                validator_pubkey: validator,
                vault_pubkey,
            },
        )
    }

    fn payout_resp(validator: &Pubkey, vault_pubkey: [u8; 33]) -> pb::PayoutSignResponse {
        pb::PayoutSignResponse {
            request_id: vec![1],
            validator_pubkey: validator.to_bytes().to_vec(),
            vault_pubkey: vault_pubkey.to_vec(),
            signatures: vec![vec![0x30, 0x44, 0x01]],
        }
    }

    #[test]
    fn accepts_a_consistent_payout_response() {
        let (v, d) = designated(7);
        let r = payout_resp(&v, d.vault_pubkey);
        let p = GrpcCollector::accept_payout(&v, &d, r).unwrap();
        assert_eq!(p.vault_pubkey, d.vault_pubkey);
        assert_eq!(p.signatures.len(), 1);
    }

    #[test]
    fn rejects_a_payout_response_from_the_wrong_federation_identity() {
        let (v, d) = designated(7);
        let impostor = Keypair::new().pubkey();
        let r = payout_resp(&impostor, d.vault_pubkey);
        let err = GrpcCollector::accept_payout(&v, &d, r).unwrap_err();
        assert!(err.contains("answered as"), "{err}");
    }

    #[test]
    fn rejects_a_vault_key_the_signer_was_not_designated_for() {
        // The second, independent binding (ADR-0017 E1): a peer with the
        // right federation identity answering with a different vault key
        // would produce a signature that cannot satisfy the designated
        // quorum — and the txid depends on which quorum signs.
        let (v, d) = designated(7);
        let mut other = d.vault_pubkey;
        other[32] = 9;
        let err = GrpcCollector::accept_payout(&v, &d, payout_resp(&v, other)).unwrap_err();
        assert!(
            err.contains("not \n                 designated for") || err.contains("designated for"),
            "{err}"
        );
    }

    #[test]
    fn rejects_malformed_or_empty_payout_responses() {
        let (v, d) = designated(7);

        let mut r = payout_resp(&v, d.vault_pubkey);
        r.vault_pubkey = vec![0u8; 5];
        assert!(GrpcCollector::accept_payout(&v, &d, r).is_err());

        let mut r = payout_resp(&v, d.vault_pubkey);
        r.validator_pubkey = vec![0u8; 5];
        assert!(GrpcCollector::accept_payout(&v, &d, r).is_err());

        let mut r = payout_resp(&v, d.vault_pubkey);
        r.signatures = Vec::new();
        assert!(
            GrpcCollector::accept_payout(&v, &d, r).is_err(),
            "a response with no signatures contributes nothing and must be refused"
        );

        let mut r = payout_resp(&v, d.vault_pubkey);
        r.signatures = vec![Vec::new()];
        assert!(
            GrpcCollector::accept_payout(&v, &d, r).is_err(),
            "an empty signature would be placed into a scriptSig as a zero-length push"
        );
    }

    #[tokio::test]
    async fn a_designated_payout_signer_that_is_not_a_configured_peer_is_a_shortfall() {
        // ADR-0015 forbids substituting a different signer, because the txid
        // depends on which quorum signs. This must surface as a shortfall,
        // never be quietly filled from the available peers.
        let stranger = Keypair::new().pubkey();
        let c = GrpcCollector::insecure_without_tls(vec![dead_peer(1)]);
        let round = c
            .collect_payout_signatures(0, b"m", 4, 0, &[stranger])
            .await;
        assert_eq!(round.unique_signers(), 0);
        assert_eq!(round.unavailable.len(), 1);
        assert!(
            round.unavailable[0].1.contains("not a configured peer"),
            "{:?}",
            round.unavailable
        );
        assert_eq!(
            round.unavailable[0].0, stranger,
            "the shortfall is attributed to the designated signer"
        );
    }

    #[tokio::test]
    async fn payout_collection_asks_only_the_designated_quorum() {
        // A non-designated peer must not be asked at all, even when it is
        // configured and the designated one is down.
        let designated = dead_peer(1);
        let other = dead_peer(2);
        let c = GrpcCollector::insecure_without_tls(vec![designated.clone(), other.clone()]);
        let round = c
            .collect_payout_signatures(0, b"m", 4, 0, &[designated.validator_pubkey])
            .await;
        assert_eq!(round.unavailable.len(), 1, "only the designated peer");
        assert_eq!(round.unavailable[0].0, designated.validator_pubkey);
        assert!(
            !round
                .unavailable
                .iter()
                .any(|(pk, _)| *pk == other.validator_pubkey),
            "a non-designated peer must never be substituted in"
        );
    }
}
