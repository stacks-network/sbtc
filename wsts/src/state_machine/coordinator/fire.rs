use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use crate::{
    common::{check_public_shares, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::{
        point::{Point, G},
        scalar::Scalar,
    },
    net::{
        DkgBegin, DkgEnd, DkgEndBegin, DkgFailure, DkgPrivateBegin, DkgPrivateShares,
        DkgPublicShares, DkgStatus, Message, NonceRequest, NonceResponse, SignatureShareRequest,
        SignatureType,
    },
    state_machine::{
        coordinator::{Config, Coordinator as CoordinatorTrait, Error, SignRoundInfo, State},
        DkgError, OperationResult, SignError, StateMachine,
    },
    taproot::SchnorrProof,
    util::{decrypt, make_shared_secret_from_key},
    v2,
};

/// The coordinator for the FIRE algorithm
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator {
    /// common config fields
    config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    pub current_sign_id: u64,
    /// current signing iteration ID
    pub current_sign_iter_id: u64,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    dkg_end_messages: BTreeMap<u32, DkgEnd>,
    /// the current view of a successful DKG's participants' commitments
    pub party_polynomials: HashMap<u32, PolyCommitment>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on for DKG
    pub dkg_wait_signer_ids: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: v2::Aggregator,
    malicious_signer_ids: HashSet<u32>,
    malicious_dkg_signer_ids: HashSet<u32>,
}

impl Coordinator {
    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        message: &Message,
    ) -> Result<(Option<Message>, Option<OperationResult>), Error> {
        loop {
            match self.state.clone() {
                State::Idle => {
                    // Did we receive a coordinator message?
                    if let Message::DkgBegin(dkg_begin) = message {
                        if self.current_dkg_id >= dkg_begin.dkg_id {
                            // We have already processed this DKG round
                            return Ok((None, None));
                        }
                        // Set the current sign id to one before the current message to ensure
                        // that we start the next round at the correct id. (Do this rather
                        // than overwriting afterwards to ensure logging is accurate)
                        self.current_dkg_id = dkg_begin.dkg_id.wrapping_sub(1);
                        let message = self.start_dkg_round()?;
                        return Ok((Some(message), None));
                    } else if let Message::NonceRequest(nonce_request) = message {
                        if self.current_sign_id >= nonce_request.sign_id {
                            // We have already processed this sign round
                            return Ok((None, None));
                        }
                        // Set the current sign id to one before the current message to ensure
                        // that we start the next round at the correct id. (Do this rather
                        // than overwriting afterwards to ensure logging is accurate)
                        self.current_sign_id = nonce_request.sign_id.wrapping_sub(1);
                        self.current_sign_iter_id = nonce_request.sign_iter_id.wrapping_sub(1);
                        let message = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.signature_type,
                        )?;
                        return Ok((Some(message), None));
                    }
                    return Ok((None, None));
                }
                State::DkgPublicDistribute => {
                    let message = self.start_public_shares()?;
                    return Ok((Some(message), None));
                }
                State::DkgPublicGather => {
                    self.gather_public_shares(message)?;
                    if self.state == State::DkgPublicGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgPrivateDistribute => {
                    let packet = self.start_private_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPrivateGather => {
                    self.gather_private_shares(message)?;
                    if self.state == State::DkgPrivateGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgEndDistribute => {
                    let packet = self.start_dkg_end()?;
                    return Ok((Some(packet), None));
                }
                State::DkgEndGather => {
                    if let Err(error) = self.gather_dkg_end(message) {
                        if let Error::DkgFailure(dkg_failures) = error {
                            return Ok((
                                None,
                                Some(OperationResult::DkgError(DkgError::DkgEndFailure(
                                    dkg_failures,
                                ))),
                            ));
                        } else {
                            return Err(error);
                        }
                    }
                    if self.state == State::DkgEndGather {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        return Ok((
                            None,
                            Some(OperationResult::Dkg(
                                self.aggregate_public_key
                                    .ok_or(Error::MissingAggregatePublicKey)?,
                            )),
                        ));
                    }
                }
                State::NonceRequest(signature_type) => {
                    let packet = self.request_nonces(signature_type)?;
                    return Ok((Some(packet), None));
                }
                State::NonceGather(signature_type) => {
                    self.gather_nonces(message, signature_type)?;
                    if self.state == State::NonceGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::SigShareRequest(signature_type) => {
                    let packet = self.request_sig_shares(signature_type)?;
                    return Ok((Some(packet), None));
                }
                State::SigShareGather(signature_type) => {
                    if let Err(e) = self.gather_sig_shares(message, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
                    }
                    if self.state == State::SigShareGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        if let SignatureType::Taproot = signature_type {
                            if let Some(schnorr_proof) = &self.schnorr_proof {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignTaproot(SchnorrProof {
                                        r: schnorr_proof.r,
                                        s: schnorr_proof.s,
                                    })),
                                ));
                            } else {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(SignError::Coordinator(
                                        Error::MissingSchnorrProof,
                                    ))),
                                ));
                            }
                        } else if let SignatureType::Schnorr = signature_type {
                            if let Some(schnorr_proof) = &self.schnorr_proof {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignSchnorr(SchnorrProof {
                                        r: schnorr_proof.r,
                                        s: schnorr_proof.s,
                                    })),
                                ));
                            } else {
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(SignError::Coordinator(
                                        Error::MissingSchnorrProof,
                                    ))),
                                ));
                            }
                        } else if let Some(signature) = &self.signature {
                            return Ok((
                                None,
                                Some(OperationResult::Sign(Signature {
                                    R: signature.R,
                                    z: signature.z,
                                })),
                            ));
                        } else {
                            return Ok((
                                None,
                                Some(OperationResult::SignError(SignError::Coordinator(
                                    Error::MissingSignature,
                                ))),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Message, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.dkg_wait_signer_ids = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Public Share Distribution"
        );
        let dkg_begin = DkgBegin { dkg_id: self.current_dkg_id };

        self.move_to(State::DkgPublicGather)?;
        Ok(Message::DkgBegin(dkg_begin))
    }

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Message, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_public_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Private Share Distribution"
        );

        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_public_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
        self.move_to(State::DkgPrivateGather)?;
        Ok(Message::DkgPrivateBegin(dkg_begin))
    }

    /// Ask signers to compute shares and send DKG end
    pub fn start_dkg_end(&mut self) -> Result<Message, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_private_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting DkgEnd Distribution"
        );

        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
        self.move_to(State::DkgEndGather)?;
        Ok(Message::DkgEndBegin(dkg_end_begin))
    }

    fn gather_public_shares(&mut self, message: &Message) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = message {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.signer_public_keys;
            if !signer_public_keys.contains_key(&dkg_public_shares.signer_id) {
                warn!(signer_id = %dkg_public_shares.signer_id, "No public key in config");
                return Ok(());
            };

            self.dkg_wait_signer_ids
                .remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.public_shares_gathered()?;
        }
        Ok(())
    }

    fn public_shares_gathered(&mut self) -> Result<(), Error> {
        self.move_to(State::DkgPrivateDistribute)?;
        Ok(())
    }

    fn gather_private_shares(&mut self, message: &Message) -> Result<(), Error> {
        if let Message::DkgPrivateShares(dkg_private_shares) = message {
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.signer_public_keys;
            if !signer_public_keys.contains_key(&dkg_private_shares.signer_id) {
                warn!(signer_id = %dkg_private_shares.signer_id, "No public key in config");
                return Ok(());
            };

            self.dkg_wait_signer_ids
                .remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                dkg_id = %dkg_private_shares.dkg_id,
                signer_id = %dkg_private_shares.signer_id,
                "DkgPrivateShares received"
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.private_shares_gathered()?;
        }
        Ok(())
    }

    fn private_shares_gathered(&mut self) -> Result<(), Error> {
        self.move_to(State::DkgEndDistribute)?;
        Ok(())
    }

    fn gather_dkg_end(&mut self, message: &Message) -> Result<(), Error> {
        debug!(
            "DKG Round {}: waiting for Dkg End from signers {:?}",
            self.current_dkg_id, self.dkg_wait_signer_ids
        );
        if let Message::DkgEnd(dkg_end) = message {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            if self.dkg_wait_signer_ids.contains(&dkg_end.signer_id) {
                self.dkg_wait_signer_ids.remove(&dkg_end.signer_id);
                self.dkg_end_messages
                    .insert(dkg_end.signer_id, dkg_end.clone());
                debug!(
                    dkg_id = %dkg_end.dkg_id,
                    signer_id = %dkg_end.signer_id,
                    waiting = ?self.dkg_wait_signer_ids,
                    "DkgEnd received"
                );
            } else {
                warn!(
                    dkg_id = %dkg_end.dkg_id,
                    signer_id = %dkg_end.signer_id,
                    "Got DkgEnd from signer who we weren't waiting on"
                );
            }
        }

        let mut dkg_failures = HashMap::new();
        let threshold: usize = self.config.threshold.try_into().unwrap();
        if self.dkg_wait_signer_ids.is_empty() {
            // if there are any errors, mark signers malicious and retry
            for (signer_id, dkg_end) in &self.dkg_end_messages {
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    warn!(%signer_id, ?dkg_failure, "DkgEnd failure");
                    match dkg_failure {
                        DkgFailure::BadState => {
                            // signer should not be in a bad state so treat as malicious
                            self.malicious_dkg_signer_ids.insert(*signer_id);
                            dkg_failures.insert(*signer_id, dkg_failure.clone());
                        }
                        DkgFailure::Threshold => {
                            dkg_failures.insert(*signer_id, dkg_failure.clone());
                        }
                        DkgFailure::BadPublicShares(bad_shares) => {
                            // bad_shares is a set of signer_ids
                            for bad_signer_id in bad_shares {
                                // verify public shares are bad
                                let dkg_public_shares = &self.dkg_public_shares[bad_signer_id];
                                let mut bad_party_ids = Vec::new();
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(comm, threshold) {
                                        bad_party_ids.push(party_id);
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if bad_party_ids.is_empty() {
                                    warn!("Signer {} reported BadPublicShares from {} but the shares were valid, mark {} as malicious", signer_id, bad_signer_id, signer_id);
                                    self.malicious_dkg_signer_ids.insert(*signer_id);
                                } else {
                                    warn!("Signer {} reported BadPublicShares from {}, mark {} as malicious", signer_id, bad_signer_id, bad_signer_id);
                                    self.malicious_dkg_signer_ids.insert(*bad_signer_id);

                                    // save legitimate failures to return to caller
                                    dkg_failures.insert(*signer_id, dkg_failure.clone());
                                }
                            }
                        }
                        DkgFailure::BadPrivateShares(bad_shares) => {
                            // bad_shares is a map of signer_id to BadPrivateShare
                            for (bad_signer_id, bad_private_share) in bad_shares {
                                // verify the DH tuple proof first so we know the shared key is correct
                                let signer_public_key = &self.config.signer_public_keys[signer_id];
                                let bad_signer_public_key =
                                    &self.config.signer_public_keys[bad_signer_id];
                                let mut is_bad = false;

                                if bad_private_share.tuple_proof.verify(
                                    signer_public_key,
                                    bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
                                    // verify at least one bad private share for one of signer_id's key_ids
                                    let shared_secret =
                                        make_shared_secret_from_key(&bad_private_share.shared_key);

                                    let dkg_public_shares = &self.dkg_public_shares[bad_signer_id]
                                        .comms
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<u32, PolyCommitment>>();
                                    let dkg_private_shares =
                                        &self.dkg_private_shares[bad_signer_id];
                                    let signer_key_ids = &self.config.signer_key_ids[signer_id];

                                    for (src_party_id, key_shares) in &dkg_private_shares.shares {
                                        let poly = &dkg_public_shares[src_party_id];
                                        for key_id in signer_key_ids {
                                            let bytes = &key_shares[key_id];
                                            match decrypt(&shared_secret, bytes) {
                                                Ok(plain) => match Scalar::try_from(&plain[..]) {
                                                    Ok(private_eval) => {
                                                        let poly_eval = match compute::poly(
                                                            &compute::id(*key_id),
                                                            poly.poly(),
                                                        ) {
                                                            Ok(p) => p,
                                                            Err(e) => {
                                                                warn!("Failed to evaluate public poly from signer_id {} to key_id {}: {:?}", bad_signer_id, key_id, e);
                                                                is_bad = true;
                                                                break;
                                                            }
                                                        };

                                                        if private_eval * G != poly_eval {
                                                            warn!("Invalid dkg private share from signer_id {} to key_id {}", bad_signer_id, key_id);

                                                            is_bad = true;
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to parse Scalar for dkg private share from signer_id {} to key_id {}: {:?}", bad_signer_id, key_id, e);

                                                        is_bad = true;
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    warn!("Failed to decrypt dkg private share from signer_id {} to key_id {}: {:?}", bad_signer_id, key_id, e);
                                                    is_bad = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if !is_bad {
                                    warn!("Signer {} reported BadPrivateShare from {} but the shares were valid, mark {} as malicious", signer_id, bad_signer_id, signer_id);
                                    self.malicious_dkg_signer_ids.insert(*signer_id);
                                } else {
                                    warn!("Signer {} reported BadPrivateShare from {}, mark {} as malicious", signer_id, bad_signer_id, bad_signer_id);
                                    self.malicious_dkg_signer_ids.insert(*bad_signer_id);

                                    // save legitimate failures to return to caller
                                    dkg_failures.insert(*signer_id, dkg_failure.clone());
                                }
                            }
                        }
                        DkgFailure::MissingPublicShares(_) => {
                            dkg_failures.insert(*signer_id, dkg_failure.clone());
                        }
                        DkgFailure::MissingPrivateShares(_) => {
                            dkg_failures.insert(*signer_id, dkg_failure.clone());
                        }
                    }
                }
            }
            if dkg_failures.is_empty() {
                info!("no dkg failures");
                self.dkg_end_gathered()?;
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure(dkg_failures));
            }
        }
        Ok(())
    }

    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.constant_term());

        info!("Aggregate public key: {}", key);
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }

    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Message, Error> {
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
        info!(
            sign_id = %self.current_sign_id,
            sign_iter_id = %self.current_sign_iter_id,
            "Requesting Nonces"
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
        };
        self.move_to(State::NonceGather(signature_type))?;

        Ok(Message::NonceRequest(nonce_request))
    }

    fn gather_nonces(
        &mut self,
        message: &Message,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = message {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.signer_public_keys;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self.config.signer_key_ids.get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }

            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    sign_id = %nonce_response.sign_id,
                    sign_iter_id = %nonce_response.sign_iter_id,
                    signer_id = %nonce_response.signer_id,
                    "Received malicious NonceResponse"
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
                return Ok(());
            }

            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();
            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());

            // ignore the passed key_ids
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                recv_keys = %nonce_info.nonce_recv_key_ids.len(),
                threshold = %self.config.threshold,
                "Received NonceResponse"
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {}", aggregate_nonce);

                self.move_to(State::SigShareRequest(signature_type))?;
            }
        }
        Ok(())
    }

    fn request_sig_shares(&mut self, signature_type: SignatureType) -> Result<Message, Error> {
        self.signature_shares.clear();
        info!(
            sign_id = %self.current_sign_id,
            "Requesting Signature Shares"
        );
        let nonce_responses = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?
            .public_nonces
            .values()
            .cloned()
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
        };
        self.move_to(State::SigShareGather(signature_type))?;

        Ok(Message::SignatureShareRequest(sig_share_request))
    }

    fn gather_sig_shares(
        &mut self,
        message: &Message,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::SignatureShareResponse(sig_share_response) = message {
            if sig_share_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    sig_share_response.dkg_id,
                    self.current_dkg_id,
                ));
            }
            if sig_share_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    sig_share_response.sign_id,
                    self.current_sign_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.signer_public_keys;
            if !signer_public_keys.contains_key(&sig_share_response.signer_id) {
                warn!(signer_id = %sig_share_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .signer_key_ids
                .get(&sig_share_response.signer_id)
            else {
                warn!(signer_id = %sig_share_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let mut sig_share_response_key_ids = HashSet::new();
            for sig_share in &sig_share_response.signature_shares {
                for key_id in &sig_share.key_ids {
                    sig_share_response_key_ids.insert(*key_id);
                }
            }

            if *signer_key_ids != sig_share_response_key_ids {
                warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
                return Ok(());
            }

            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
            let response_info = self.message_nonces.entry(self.message.clone()).or_default();
            if response_info
                .sign_wait_signer_ids
                .contains(&sig_share_response.signer_id)
            {
                response_info
                    .sign_wait_signer_ids
                    .remove(&sig_share_response.signer_id);
                for sig_share in &sig_share_response.signature_shares {
                    for key_id in &sig_share.key_ids {
                        response_info.sign_recv_key_ids.insert(*key_id);
                    }
                }

                debug!(
                    "Sign round {} SignatureShareResponse from signer {} ({}/{} key_ids). Waiting on {:?}",
                    sig_share_response.sign_id,
                    sig_share_response.signer_id,
                    response_info.sign_recv_key_ids.len(),
                    response_info.nonce_recv_key_ids.len(),
                    response_info.sign_wait_signer_ids
                );
            } else {
                warn!(
                    "Sign round {} SignatureShareResponse from signer {} not in the wait list",
                    sig_share_response.sign_id, sig_share_response.signer_id,
                );
            }
        }
        let message_nonce = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?;
        if message_nonce.sign_wait_signer_ids.is_empty() {
            // Calculate the aggregate signature
            let nonce_responses = message_nonce
                .public_nonces
                .values()
                .cloned()
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                "aggregator.sign({}, {}, {}, {})",
                hex::encode(&self.message),
                nonces.len(),
                shares.len(),
                self.party_polynomials.len(),
            );

            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    &shares,
                    &key_ids,
                    None,
                )?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, &shares, &key_ids)?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, &shares, &key_ids)?;
                debug!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }

            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn compute_aggregate_nonce(&self) -> Point {
        // XXX this needs to be key_ids for v1 and signer_ids for v2
        let public_nonces = self
            .message_nonces
            .get(&self.message)
            .cloned()
            .unwrap_or_default()
            .public_nonces;
        let party_ids = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.key_ids)
            .collect::<Vec<u32>>();
        let nonces = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.nonces)
            .collect::<Vec<PublicNonce>>();
        let (_, R) = compute::intermediate(&self.message, &party_ids, &nonces);

        R
    }
}

impl StateMachine<State, Error> for Coordinator {
    fn move_to(&mut self, state: State) -> Result<(), Error> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => prev_state == &State::Idle,
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => {
                prev_state == &State::DkgPrivateDistribute || prev_state == &State::DkgPrivateGather
            }
            State::DkgEndDistribute => prev_state == &State::DkgPrivateGather,
            State::DkgEndGather => prev_state == &State::DkgEndDistribute,
            State::NonceRequest(signature_type) => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgEndGather
                    || prev_state == &State::SigShareGather(*signature_type)
            }
            State::NonceGather(signature_type) => {
                prev_state == &State::NonceRequest(*signature_type)
                    || prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareRequest(signature_type) => {
                prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareGather(signature_type) => {
                prev_state == &State::SigShareRequest(*signature_type)
                    || prev_state == &State::SigShareGather(*signature_type)
            }
        };
        if accepted {
            debug!("state change from {:?} to {:?}", prev_state, state);
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{:?} to {:?}",
                prev_state, state
            )))
        }
    }
}

impl CoordinatorTrait for Coordinator {
    /// Create a new coordinator
    fn new(config: Config) -> Self {
        Self {
            aggregator: v2::Aggregator::new(config.num_keys, config.threshold),
            config,
            current_dkg_id: 0,
            current_sign_id: 0,
            current_sign_iter_id: 0,
            dkg_public_shares: Default::default(),
            dkg_private_shares: Default::default(),
            dkg_end_messages: Default::default(),
            party_polynomials: Default::default(),
            message_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            dkg_wait_signer_ids: Default::default(),
            state: State::Idle,
            malicious_signer_ids: Default::default(),
            malicious_dkg_signer_ids: Default::default(),
        }
    }

    /// Retrieve the config
    fn get_config(&self) -> Config {
        self.config.clone()
    }

    /// Set the aggregate key and polynomial commitments used to form that key.
    ///  Check if the polynomial commitments match the key
    fn set_key_and_party_polynomials(
        &mut self,
        aggregate_key: Point,
        party_polynomials: Vec<(u32, PolyCommitment)>,
    ) -> Result<(), Error> {
        let computed_key = party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.constant_term());
        if computed_key != aggregate_key {
            return Err(Error::AggregateKeyPolynomialMismatch(
                computed_key,
                aggregate_key,
            ));
        }
        let party_polynomials_len = party_polynomials.len();
        let party_polynomials = HashMap::from_iter(party_polynomials);
        if party_polynomials.len() != party_polynomials_len {
            return Err(Error::DuplicatePartyId);
        }
        self.aggregate_public_key = Some(aggregate_key);
        self.party_polynomials = party_polynomials;
        Ok(())
    }

    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        messages: &[Message],
    ) -> Result<(Vec<Message>, Vec<OperationResult>), Error> {
        let mut outbound_messages = vec![];
        let mut operation_results = vec![];
        for message in messages {
            let (outbound_message, operation_result) = self.process_message(message)?;
            outbound_messages.extend(outbound_message);
            operation_results.extend(operation_result);
        }

        Ok((outbound_messages, operation_results))
    }

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point> {
        self.aggregate_public_key
    }

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>) {
        self.aggregate_public_key = aggregate_public_key;
    }

    /// Retrieve the current message bytes being signed
    fn get_message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// Retrive the current state
    fn get_state(&self) -> State {
        self.state.clone()
    }

    /// Start a DKG round
    fn start_dkg_round(&mut self) -> Result<Message, Error> {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    /// Start a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        signature_type: SignatureType,
    ) -> Result<Message, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.message = message.to_vec();
        self.current_sign_id = self.current_sign_id.wrapping_add(1);
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(signature_type))?;
        self.request_nonces(signature_type)
    }

    // Reset internal state
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_end_messages.clear();
        self.party_polynomials.clear();
        self.message_nonces.clear();
        self.signature_shares.clear();
        self.dkg_wait_signer_ids.clear();
    }
}

#[cfg(test)]
/// Test module for coordinator functionality
pub mod test {
    use crate::{
        common::PolyCommitment,
        curve::{point::Point, scalar::Scalar},
        net::{
            DkgBegin, DkgFailure, DkgPrivateShares, DkgPublicShares, Message, NonceRequest,
            SignatureType,
        },
        state_machine::{
            coordinator::{
                fire::Coordinator as FireCoordinator,
                test::{
                    bad_signature_share_request, check_signature_shares, coordinator_state_machine,
                    empty_private_shares, empty_public_shares, feedback_messages,
                    feedback_mutated_messages, gen_nonces, invalid_nonce, new_coordinator,
                    run_dkg_sign, setup, start_dkg_round,
                },
                Config, Coordinator as CoordinatorTrait, State,
            },
            signer::Signer,
            DkgError, OperationResult,
        },
        util::create_rng,
        v2,
    };
    use std::collections::HashMap;

    #[test]
    fn new_coordinator_v2() {
        new_coordinator::<FireCoordinator>();
    }

    #[test]
    fn coordinator_state_machine_v2() {
        coordinator_state_machine::<FireCoordinator>();
    }

    #[test]
    fn start_dkg_round_v2() {
        start_dkg_round::<FireCoordinator>();
    }

    #[test]
    fn start_public_shares() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FireCoordinator::new(config);

        coordinator.state = State::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result, Message::DkgBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn start_private_shares() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FireCoordinator::new(config);

        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn run_dkg_sign_v2() {
        for _ in 0..4 {
            run_dkg_sign::<FireCoordinator>(5, 2);
        }
    }

    #[test]
    fn check_signature_shares_v2() {
        check_signature_shares::<FireCoordinator>(5, 2, SignatureType::Frost, vec![0]);
        check_signature_shares::<FireCoordinator>(5, 2, SignatureType::Schnorr, vec![0]);
        check_signature_shares::<FireCoordinator>(5, 2, SignatureType::Taproot, vec![0]);
    }

    #[test]
    fn all_signers_dkg_v2() {
        all_signers_dkg(5, 2);
    }

    fn all_signers_dkg(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator>, Vec<Signer>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinators
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        // Successfully got an Aggregate Public Key...
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }
        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                for coordinator in coordinators.iter() {
                    assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
                    assert_eq!(coordinator.get_state(), State::Idle);
                }
            }
            _ => panic!("Expected Dkg Operation result"),
        }
        (coordinators, signers)
    }

    #[test]
    fn missing_public_keys_dkg_v2() {
        let num_signers = 10;
        let keys_per_signer = 1;
        let (mut coordinators, signers) = setup::<FireCoordinator>(num_signers, keys_per_signer);

        // Start a DKG round where we will not allow all signers to recv DkgBegin, so they will not respond with DkgPublicShares
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        let mut minimum_coordinators = coordinators.clone();
        let mut minimum_signers = signers.clone();

        // Let us also remove that signers public key from the config including all of its key ids
        let mut removed_signer = minimum_signers.pop().expect("Failed to pop signer");
        let public_key = removed_signer
            .public_keys
            .signers
            .remove(&removed_signer.signer_id)
            .expect("Failed to remove public key");
        removed_signer
            .public_keys
            .key_ids
            .retain(|_k, pk| pk.to_bytes() != public_key.to_bytes());

        for signer in minimum_signers.iter_mut() {
            // Overwrite all other signers to use the new public keys missing the removed signers public key
            signer.public_keys = removed_signer.public_keys.clone();
        }

        // Send the DKG Begin message to minimum signers and gather responses by sharing with signers and coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut minimum_coordinators,
            &mut minimum_signers,
            std::slice::from_ref(&message),
        );

        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());
        assert!(minimum_coordinators
            .iter()
            .all(|coordinator| coordinator.state == State::DkgPublicGather));
    }

    #[test]
    fn malicious_signers_dkg_v2() {
        malicious_signers_dkg(5, 2);
    }

    fn malicious_signers_dkg(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator>, Vec<Signer>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinators
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }
        // Send the DKG Private Begin message to all signers and share their responses with the coordinators and signers, but mutate one signer's DkgPrivateShares so it is marked malicious
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &outbound_messages,
            |signer, msgs| {
                if signer.signer_id == 0 {
                    msgs.iter()
                        .map(|message| {
                            if let Message::DkgPrivateShares(shares) = &message {
                                // mutate one of the shares
                                let sshares: Vec<(u32, HashMap<u32, Vec<u8>>)> = shares
                                    .shares
                                    .iter()
                                    .map(|(src_party_id, share_map)| {
                                        (
                                            *src_party_id,
                                            share_map
                                                .iter()
                                                .map(|(dst_key_id, bytes)| {
                                                    let mut bytes = bytes.clone();
                                                    bytes.insert(0, 234);
                                                    (*dst_key_id, bytes)
                                                })
                                                .collect(),
                                        )
                                    })
                                    .collect();

                                Message::DkgPrivateShares(DkgPrivateShares {
                                    dkg_id: shares.dkg_id,
                                    signer_id: shares.signer_id,
                                    shares: sshares.clone(),
                                })
                            } else {
                                message.clone()
                            }
                        })
                        .collect()
                } else {
                    msgs
                }
            },
        );
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::DkgError(dkg_error) => {
                // we mutated the private shares themselves, so we should see a BadPrivateShares from signer_id 0
                match dkg_error {
                    DkgError::DkgEndFailure(failure_map) => {
                        for dkg_failure in failure_map.values() {
                            match dkg_failure {
                                DkgFailure::BadPrivateShares(bad_share_map) => {
                                    for bad_signer_id in bad_share_map.keys() {
                                        assert_eq!(*bad_signer_id, 0u32);
                                    }
                                }
                                _ => panic!("Expected DkgFailure::BadPrivateShares"),
                            }
                        }
                    }
                    _ => panic!("Expected DkgError::DkgEndFailure"),
                }
            }
            _ => panic!("Expected OperationResult::DkgError"),
        }
        (coordinators, signers)
    }

    #[test]
    fn bad_poly_length_dkg_v2() {
        bad_poly_length_dkg(5, 2);
    }

    fn bad_poly_length_dkg(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator>, Vec<Signer>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DkgBegin message to all signers and share their responses with the coordinators and signers, but mutate two signers' DkgPublicShares: make one polynomial larger than the threshold, and the other smaller
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &[message],
            |signer, msgs| {
                if signer.signer_id == 0 || signer.signer_id == 1 {
                    msgs.iter()
                        .map(|message| {
                            if let Message::DkgPublicShares(shares) = &message {
                                let comms = shares
                                    .comms
                                    .iter()
                                    .map(|(party_id, comm)| {
                                        let mut c = comm.clone();
                                        let (id, mut poly) = c.into_parts();
                                        if signer.signer_id == 0 {
                                            poly.push(Point::new());
                                        } else {
                                            poly.pop();
                                        }
                                        c = PolyCommitment::new(id, poly)
                                            .expect("polynomial should still be valid");
                                        (*party_id, c)
                                    })
                                    .collect();
                                Message::DkgPublicShares(DkgPublicShares {
                                    dkg_id: shares.dkg_id,
                                    signer_id: shares.signer_id,
                                    comms,
                                })
                            } else {
                                message.clone()
                            }
                        })
                        .collect()
                } else {
                    msgs
                }
            },
        );

        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::DkgError(dkg_error) => {
                // we mutated the public shares themselves, so we should see a BadPublicShares from signer_ids 0 and 1
                match dkg_error {
                    DkgError::DkgEndFailure(failure_map) => {
                        for dkg_failure in failure_map.values() {
                            match dkg_failure {
                                DkgFailure::BadPublicShares(bad_shares) => {
                                    for bad_signer_id in bad_shares {
                                        assert!(*bad_signer_id == 0u32 || *bad_signer_id == 1u32);
                                    }
                                }
                                _ => panic!("Expected DkgFailure::BadPublicShares"),
                            }
                        }
                    }
                    _ => panic!("Expected DkgError::DkgEndFailure"),
                }
            }
            _ => panic!("Expected OperationResult::DkgError"),
        }
        (coordinators, signers)
    }

    #[test]
    fn all_signers_sign() {
        let (mut coordinators, mut signers) = all_signers_dkg(5, 2);

        // We have started a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
                for coordinator in &coordinators {
                    assert_eq!(coordinator.state, State::Idle);
                }
            }
            _ => panic!("Expected Signature Operation result"),
        }
    }

    #[test]
    fn minimum_signers_sign() {
        let num_signers = 10;
        let keys_per_signer = 2;

        let (mut coordinators, mut signers) = all_signers_dkg(num_signers, keys_per_signer);
        let config = coordinators.first().unwrap().get_config();

        // Figure out how many signers we can remove and still be above the threshold
        let num_keys = config.num_keys as f64;
        let threshold = config.threshold as f64;
        let mut num_signers_to_remove =
            ((num_keys - threshold) / keys_per_signer as f64).floor() as usize;
        if num_signers as usize > signers.len() {
            num_signers_to_remove -= (num_signers - signers.len() as u32) as usize;
        }
        for _ in 0..num_signers_to_remove {
            signers.pop();
        }

        // Start a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::Idle);
        }
    }

    #[test]
    fn missing_public_keys_sign() {
        let num_signers = 10;
        let keys_per_signer = 2;

        let (mut coordinators, mut signers) = all_signers_dkg(num_signers, keys_per_signer);

        // Let us also remove that signers public key from the config including all of its key ids
        let mut removed_signer = signers.pop().expect("Failed to pop signer");
        let public_key = removed_signer
            .public_keys
            .signers
            .remove(&removed_signer.signer_id)
            .expect("Failed to remove public key");
        removed_signer
            .public_keys
            .key_ids
            .retain(|_k, pk| pk.to_bytes() != public_key.to_bytes());

        for signer in signers.iter_mut() {
            signer.public_keys = removed_signer.public_keys.clone();
        }

        // Start a signing round
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }
        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &msg
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::Idle);
        }
    }

    #[test]
    fn multiple_nonce_request_messages() {
        let num_signers = 12;
        let keys_per_signer = 1;
        let (mut coordinators, mut signers) = all_signers_dkg(num_signers, keys_per_signer);

        // Start a signing round
        let orig_msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&orig_msg, signature_type)
            .unwrap();

        let mut alt_packet = message.clone();
        assert_eq!(
            coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the original message to the first 1/4 of the signers and gather responses by sharing with the rest of the signers and the coordinators
        let signers_len = signers.len();
        let (outbound_messages, operation_results) = feedback_messages(
            &mut coordinators,
            &mut signers[0..signers_len / 4],
            &[message],
        );

        let alt_message = "It was many and many a year ago, in a kingdom by the hill"
            .as_bytes()
            .to_vec();
        match &mut alt_packet {
            Message::NonceRequest(nonce_request) => {
                nonce_request.message = alt_message.clone();
            }
            _ => panic!("Expected NonceRequest message"),
        };

        // Send the alternative message to the last 3/4 of signers and gather responses by sharing with the rest of the signers and the coordinators
        let (alt_outbound_messages, alt_operation_results) = feedback_messages(
            &mut coordinators,
            &mut signers[signers_len / 4..],
            &[alt_packet],
        );

        assert!(operation_results.is_empty());
        assert!(alt_operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }
        // Assert that the first 1/4 signers did not receive a result
        assert!(outbound_messages.is_empty());
        assert_eq!(alt_outbound_messages.len(), 1);
        match &alt_outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &alt_outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                // Verify that the winning message was the alternative message that had majority vote
                assert!(sig.verify(
                    &coordinators
                        .first()
                        .unwrap()
                        .aggregate_public_key
                        .expect("No aggregate public key set!"),
                    &alt_message
                ));
            }
            _ => panic!("Expected Signature Operation result"),
        }

        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::Idle);
        }
    }

    #[test]
    fn old_round_ids_are_ignored() {
        let (mut coordinators, _) = setup::<FireCoordinator>(3, 10);
        for coordinator in &mut coordinators {
            let id: u64 = 10;
            let old_id = id.saturating_sub(1);
            coordinator.current_dkg_id = id;
            coordinator.current_sign_id = id;
            // Attempt to start an old DKG round
            let (packets, results) = coordinator
                .process_inbound_messages(&[Message::DkgBegin(DkgBegin { dkg_id: old_id })])
                .unwrap();
            assert!(packets.is_empty());
            assert!(results.is_empty());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_dkg_id, id);

            // Attempt to start the same DKG round
            let (packets, results) = coordinator
                .process_inbound_messages(&[Message::DkgBegin(DkgBegin { dkg_id: id })])
                .unwrap();
            assert!(packets.is_empty());
            assert!(results.is_empty());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_dkg_id, id);

            // Attempt to start an old Sign round
            let (packets, results) = coordinator
                .process_inbound_messages(&[Message::NonceRequest(NonceRequest {
                    dkg_id: id,
                    sign_id: old_id,
                    message: vec![],
                    sign_iter_id: id,
                    signature_type: SignatureType::Frost,
                })])
                .unwrap();
            assert!(packets.is_empty());
            assert!(results.is_empty());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_sign_id, id);

            // Attempt to start the same Sign round
            let (packets, results) = coordinator
                .process_inbound_messages(&[Message::NonceRequest(NonceRequest {
                    dkg_id: id,
                    sign_id: id,
                    message: vec![],
                    sign_iter_id: id,
                    signature_type: SignatureType::Frost,
                })])
                .unwrap();
            assert!(packets.is_empty());
            assert!(results.is_empty());
            assert_eq!(coordinator.state, State::Idle);
            assert_eq!(coordinator.current_sign_id, id);
        }
    }

    #[test]
    fn gen_nonces_v2() {
        gen_nonces::<FireCoordinator>(5, 1);
    }

    #[test]
    fn bad_signature_share_request_v2() {
        bad_signature_share_request::<FireCoordinator>(5, 2);
    }

    #[test]
    fn invalid_nonce_v2() {
        invalid_nonce::<FireCoordinator>(5, 2);
    }

    #[test]
    fn one_signer_bad_threshold() {
        let mut rng = create_rng();
        let (mut coordinators, mut signers) = setup::<FireCoordinator>(10, 1);

        // persist one signer, change the threshold, reset polys
        let mut state = signers[0].signer.save();

        state.threshold -= 1;
        signers[0].threshold -= 1;
        signers[0].signer = v2::Party::load(&state);

        signers[0].signer.reset_polys(&mut rng);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::DkgError(DkgError::DkgEndFailure(failure_map)) => {
                for i in 1..10 {
                    match failure_map.get(&i) {
                        Some(DkgFailure::BadPublicShares(set)) => {
                            if set.len() != 1 {
                                panic!(
                                    "signer {} should have reported a single BadPublicShares",
                                    i
                                );
                            } else if !set.contains(&0) {
                                panic!(
                                    "signer {} should have reported BadPublicShares from signer 0",
                                    i
                                );
                            }
                        }
                        Some(failure) => {
                            panic!("signer {} should have reported BadPublicShares, instead reported {:?}", i, failure);
                        }
                        None => {
                            panic!("signer {} should have reported BadPublicShares", i);
                        }
                    }
                }

                if let Some(failure) = failure_map.get(&0) {
                    panic!("Coordinator should not have passed along incorrect failure {:?} from signer 0", failure);
                }
            }
            result => panic!(
                "Expected OperationResult::DkgError(DkgError::DkgEndFailure), got {:?}",
                &result
            ),
        }
    }

    #[test]
    fn bad_dkg_threshold() {
        let (mut coordinators, mut signers) = setup::<FireCoordinator>(10, 1);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // alter the DkgEndBegin message
        let mut message = outbound_messages[0].clone();
        if let Message::DkgEndBegin(ref mut dkg_end_begin) = message {
            dkg_end_begin.signer_ids = vec![0u32];
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::DkgError(DkgError::DkgEndFailure(failure_map)) => {
                for (signer_id, failure) in failure_map {
                    if !matches!(failure, DkgFailure::Threshold) {
                        panic!("{signer_id} had wrong failure {:?}", failure);
                    }
                }
            }
            result => {
                panic!("Expected DkgEndFailure got {:?}", result);
            }
        }
    }

    #[test]
    fn empty_public_shares_v2() {
        empty_public_shares::<FireCoordinator>(5, 2);
    }

    #[test]
    fn empty_private_shares_v2() {
        empty_private_shares::<FireCoordinator>(5, 2);
    }
}
