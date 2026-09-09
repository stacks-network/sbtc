use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use crate::{
    common::{PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::point::Point,
    net::{
        DkgBegin, DkgEnd, DkgEndBegin, DkgPrivateBegin, DkgPrivateShares, DkgPublicShares,
        DkgStatus, Message, NonceRequest, NonceResponse, SignatureShareRequest, SignatureType,
    },
    state_machine::{
        coordinator::{Config, Coordinator as CoordinatorTrait, Error, State},
        DkgError, OperationResult, SignError, StateMachine,
    },
    taproot::SchnorrProof,
    v2,
};

/// The coordinator for the FROST algorithm
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator {
    /// common config fields
    config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    current_sign_id: u64,
    /// current signing iteration ID
    current_sign_iter_id: u64,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    dkg_end_messages: BTreeMap<u32, DkgEnd>,
    party_polynomials: HashMap<u32, PolyCommitment>,
    public_nonces: BTreeMap<u32, NonceResponse>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on
    pub ids_to_await: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: v2::Aggregator,
}

impl Coordinator {
    /// Process the given message
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
                        // then overwriting afterwards to ensure logging is accurate)
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
                        // then overwriting afterwards to ensure logging is accurate)
                        self.current_sign_id = nonce_request.sign_id.wrapping_sub(1);
                        self.current_sign_iter_id = nonce_request.sign_iter_id;
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
                    let message = self.start_private_shares()?;
                    return Ok((Some(message), None));
                }
                State::DkgPrivateGather => {
                    self.gather_private_shares(message)?;
                    if self.state == State::DkgPrivateGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgEndDistribute => {
                    let message = self.start_dkg_end()?;
                    return Ok((Some(message), None));
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
                    let message = self.request_nonces(signature_type)?;
                    return Ok((Some(message), None));
                }
                State::NonceGather(signature_type) => {
                    self.gather_nonces(message, signature_type)?;
                    if self.state == State::NonceGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::SigShareRequest(signature_type) => {
                    let message = self.request_sig_shares(signature_type)?;
                    return Ok((Some(message), None));
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
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignTaproot(SchnorrProof {
                                    r: schnorr_proof.r,
                                    s: schnorr_proof.s,
                                })),
                            ));
                        } else if let SignatureType::Schnorr = signature_type {
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignSchnorr(SchnorrProof {
                                    r: schnorr_proof.r,
                                    s: schnorr_proof.s,
                                })),
                            ));
                        } else {
                            let signature =
                                self.signature.as_ref().ok_or(Error::MissingSignature)?;
                            return Ok((
                                None,
                                Some(OperationResult::Sign(Signature {
                                    R: signature.R,
                                    z: signature.z,
                                })),
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
        self.ids_to_await = (0..self.config.num_signers).collect();
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
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Private Share Distribution"
        );
        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (1..self.config.num_keys + 1).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
        self.move_to(State::DkgPrivateGather)?;
        Ok(Message::DkgPrivateBegin(dkg_begin))
    }

    /// Ask signers to compute secrets and send DKG end
    pub fn start_dkg_end(&mut self) -> Result<Message, Error> {
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting DKG End Distribution"
        );
        let dkg_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (0..self.config.num_keys).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
        self.move_to(State::DkgEndGather)?;
        Ok(Message::DkgEndBegin(dkg_begin))
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

            self.ids_to_await.remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }

            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgPrivateDistribute)?;
        }
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

            self.ids_to_await.remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                dkg_id = %dkg_private_shares.dkg_id,
                signer_id = %dkg_private_shares.signer_id,
                "DkgPrivateShares received"
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgEndDistribute)?;
        }
        Ok(())
    }

    fn gather_dkg_end(&mut self, message: &Message) -> Result<(), Error> {
        debug!(
            dkg_id = %self.current_dkg_id,
            waiting = ?self.ids_to_await,
            "Waiting for Dkg End from signers"
        );
        if let Message::DkgEnd(dkg_end) = message {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            if self.ids_to_await.contains(&dkg_end.signer_id) {
                self.ids_to_await.remove(&dkg_end.signer_id);
                self.dkg_end_messages
                    .insert(dkg_end.signer_id, dkg_end.clone());
                debug!(
                    dkg_id = %dkg_end.dkg_id,
                    signer_id = %dkg_end.signer_id,
                    waiting = ?self.ids_to_await,
                    "DkgEnd received"
                );
            }
        }

        if self.ids_to_await.is_empty() {
            let mut dkg_failures = HashMap::new();

            for (signer_id, dkg_end) in &self.dkg_end_messages {
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    warn!(%signer_id, ?dkg_failure, "DkgEnd failure");
                    dkg_failures.insert(*signer_id, dkg_failure.clone());
                }
            }

            if dkg_failures.is_empty() {
                self.dkg_end_gathered()?;
            } else {
                return Err(Error::DkgFailure(dkg_failures));
            }
        }
        Ok(())
    }

    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            let Some(dkg_public_shares) = self.dkg_public_shares.get(signer_id) else {
                warn!(%signer_id, "no DkgPublicShares");
                return Err(Error::BadStateChange(format!("Should not have transitioned to DkgEndGather since we were missing DkgPublicShares from signer {signer_id}")));
            };
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .party_polynomials
            .values()
            .fold(Point::default(), |s, comm| s + comm.constant_term());

        info!(
            %key,
            "Aggregate public key"
        );
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }

    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Message, Error> {
        self.public_nonces.clear();
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
        self.ids_to_await = (0..self.config.num_signers).collect();
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

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.ids_to_await.remove(&nonce_response.signer_id);
            debug!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                waiting = ?self.ids_to_await,
                "NonceResponse received"
            );
        }
        if self.ids_to_await.is_empty() {
            let aggregate_nonce = self.compute_aggregate_nonce();
            info!(
                %aggregate_nonce,
                "Aggregate nonce"
            );

            self.move_to(State::SigShareRequest(signature_type))?;
        }
        Ok(())
    }

    fn request_sig_shares(&mut self, signature_type: SignatureType) -> Result<Message, Error> {
        self.signature_shares.clear();
        info!(
            sign_id = %self.current_sign_id,
            "Requesting Signature Shares"
        );
        let nonce_responses = (0..self.config.num_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
        };
        self.ids_to_await = (0..self.config.num_signers).collect();
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
            self.ids_to_await.remove(&sig_share_response.signer_id);
            debug!(
                sign_id = %sig_share_response.sign_id,
                signer_id = %sig_share_response.signer_id,
                waiting = ?self.ids_to_await,
                "SignatureShareResponse received"
            );
        }
        if self.ids_to_await.is_empty() {
            // Calculate the aggregate signature
            let nonce_responses = (0..self.config.num_signers)
                .map(|i| self.public_nonces[&i].clone())
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = &self
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                nonces_len = %nonces.len(),
                shares_len = %shares.len(),
                "aggregator.sign"
            );

            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_taproot(&self.message, &nonces, shares, &key_ids, None)?;
                debug!(
                    r = %schnorr_proof.r,
                    s = %schnorr_proof.s,
                    "SchnorrProof"
                );
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, shares, &key_ids)?;
                debug!(
                    r = %schnorr_proof.r,
                    s = %schnorr_proof.s,
                    "SchnorrProof"
                );
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, shares, &key_ids)?;
                debug!(
                    R = %signature.R,
                    z = %signature.z,
                    "Signature"
                );
                self.signature = Some(signature);
            }

            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn compute_aggregate_nonce(&self) -> Point {
        // XXX this needs to be key_ids for v1 and signer_ids for v2
        let party_ids = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.key_ids.clone())
            .collect::<Vec<u32>>();
        let nonces = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.nonces.clone())
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
            State::NonceRequest(_) => {
                prev_state == &State::Idle || prev_state == &State::DkgEndGather
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
            public_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            ids_to_await: Default::default(),
            state: State::Idle,
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
            if let Some(outbound_message) = outbound_message {
                outbound_messages.push(outbound_message);
            }
            if let Some(operation_result) = operation_result {
                operation_results.push(operation_result);
            }
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
        self.party_polynomials.clear();
        self.public_nonces.clear();
        self.signature_shares.clear();
        self.ids_to_await = (0..self.config.num_signers).collect();
    }
}

#[cfg(test)]
/// Test module for coordinator functionality
pub mod test {
    use crate::{
        curve::scalar::Scalar,
        net::{DkgBegin, Message, NonceRequest, SignatureType},
        state_machine::coordinator::{
            frost::Coordinator as FrostCoordinator,
            test::{
                bad_signature_share_request, check_signature_shares, coordinator_state_machine,
                empty_private_shares, empty_public_shares, invalid_nonce, new_coordinator,
                run_dkg_sign, start_dkg_round,
            },
            Config, Coordinator as CoordinatorTrait, State,
        },
        util::create_rng,
    };

    #[test]
    fn new_coordinator_v2() {
        new_coordinator::<FrostCoordinator>();
    }

    #[test]
    fn coordinator_state_machine_v2() {
        coordinator_state_machine::<FrostCoordinator>();
    }

    #[test]
    fn start_dkg_round_v2() {
        start_dkg_round::<FrostCoordinator>();
    }

    #[test]
    fn start_public_shares() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::new(config);

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
        let mut coordinator = FrostCoordinator::new(config);

        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn run_dkg_sign_v2() {
        run_dkg_sign::<FrostCoordinator>(5, 2);
    }

    #[test]
    fn check_signature_shares_v2() {
        check_signature_shares::<FrostCoordinator>(5, 2, SignatureType::Frost, vec![0]);
        check_signature_shares::<FrostCoordinator>(5, 2, SignatureType::Schnorr, vec![0]);
        check_signature_shares::<FrostCoordinator>(5, 2, SignatureType::Taproot, vec![0]);
    }

    #[test]
    fn bad_signature_share_request_v2() {
        bad_signature_share_request::<FrostCoordinator>(5, 2);
    }

    #[test]
    fn invalid_nonce_v2() {
        invalid_nonce::<FrostCoordinator>(5, 2);
    }

    #[test]
    fn process_inbound_messages_v2() {
        run_dkg_sign::<FrostCoordinator>(5, 2);
    }

    #[test]
    fn old_round_ids_are_ignored() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::new(config);
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

    #[test]
    fn empty_public_shares_v2() {
        empty_public_shares::<FrostCoordinator>(5, 2);
    }

    #[test]
    fn empty_private_shares_v2() {
        empty_private_shares::<FrostCoordinator>(5, 2);
    }
}
