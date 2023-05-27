use crate::{
    cds::{verify_cds_proof, CDSProver},
    schnorr::projective_to_elements,
    utils::ecc,
};
use winterfell::{
    math::{
        curves::curve_f63::{AffinePoint, ProjectivePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement,
    },
    ByteReader, ByteWriter, Deserializable, DeserializationError, Prover, ProverError,
    Serializable, SliceReader,
};

use super::{build_options, constants::*};

/// Encrypted vote submitted by a registered voter
#[derive(Debug, Clone, Copy)]
pub struct EncryptedVote {
    voter_index: usize,
    encrypted_vote: ProjectivePoint,
    proof_points: [ProjectivePoint; PROOF_NUM_POINTS],
    proof_scalars: [Scalar; PROOF_NUM_SCALARS],
}

/// Errors raised by VoteCollector
#[derive(Debug, PartialEq)]
pub enum CollectorError {
    /// This error occurs when submitted encrypted vote is invalid
    InvalidEncryptedVote,
    /// This error occurs when not all voters have submitted
    /// valid encrypted votes
    NotEnoughEncryptedVotes,
    /// Wrapper for errors raised by CDSProver
    Prover(ProverError),
}

/// Compact public inputs sent to on-chain verifier
/// to minimize the cost of calldata
#[derive(Debug)]
pub struct CompactPublicInputs {
    /// encrypted votes
    encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// truncated CDS proofs
    cds_proofs: Vec<[BaseElement; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH]>,
    /// output of CDS proof validation
    outputs: Vec<[BaseElement; AFFINE_POINT_WIDTH * 5]>,
}

impl Serializable for CompactPublicInputs {
    fn write_into<W: winterfell::ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.encrypted_votes.len() as u32);
        for encrypted_vote in self.encrypted_votes.iter() {
            Serializable::write_batch_into(encrypted_vote, target);
        }
        for cds_proof in self.cds_proofs.iter() {
            Serializable::write_batch_into(cds_proof, target);
        }
        for output in self.outputs.iter() {
            Serializable::write_batch_into(output, target);
        }
    }
}

impl Deserializable for CompactPublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut encrypted_vote = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
        let mut cds_proof = [BaseElement::ZERO; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH];
        let mut output = [BaseElement::ZERO; AFFINE_POINT_WIDTH * 5];

        let num_proofs = source.read_u32()? as usize;
        let mut encrypted_votes = Vec::with_capacity(num_proofs);
        let mut cds_proofs = Vec::with_capacity(num_proofs);
        let mut outputs = Vec::with_capacity(num_proofs);

        for _ in 0..num_proofs {
            encrypted_vote
                .copy_from_slice(&BaseElement::read_batch_from(source, AFFINE_POINT_WIDTH)?);
            encrypted_votes.push(encrypted_vote);
        }

        for _ in 0..num_proofs {
            cds_proof.copy_from_slice(&BaseElement::read_batch_from(
                source,
                PROOF_NUM_POINTS * AFFINE_POINT_WIDTH,
            )?);
            cds_proofs.push(cds_proof);
        }

        for _ in 0..num_proofs {
            output.copy_from_slice(&BaseElement::read_batch_from(
                source,
                AFFINE_POINT_WIDTH * 5,
            )?);
            outputs.push(output);
        }

        Ok(Self {
            encrypted_votes,
            cds_proofs,
            outputs,
        })
    }
}

/// Type that encapsulates all data and functionalities of
/// aggregator during vote casting phase
#[derive(Debug, Clone)]
pub struct VoteCollector {
    /// Voting keys of registered voters
    pub voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// Blinding keys of registered voters
    /// computed based on self.voting_keys
    pub blinding_keys: Vec<ProjectivePoint>,
    /// Encrypted votes submitted by registered voters
    /// Is equal to None if voter has not submitted a valid encrypted vote
    pub encrypted_votes: Vec<Option<[BaseElement; AFFINE_POINT_WIDTH]>>,
    /// Points in CDS proof
    pub proof_points: Vec<Option<[BaseElement; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH]>>,
    /// Scalars in CDS proof
    pub proof_scalars: Vec<Option<[Scalar; PROOF_NUM_SCALARS]>>,

    /// Number of valid encrypted votes received
    num_valid_votes: usize,
    /// Cached proof
    serialized_proof: Vec<u8>,
}

impl VoteCollector {
    /// Create an object of type VoteCollector given a list of voting keys
    /// Number of voting_keys must be a power of two.
    pub fn new(voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>) -> Self {
        // compute blinding keys
        let blinding_keys = Self::compute_blinding_keys(&voting_keys);
        let num_voters = voting_keys.len();

        Self {
            voting_keys,
            blinding_keys,
            encrypted_votes: vec![None; num_voters],
            proof_points: vec![None; num_voters],
            proof_scalars: vec![None; num_voters],
            num_valid_votes: 0,
            serialized_proof: vec![],
        }
    }

    /// Compute list of blinding keys given list of voting keys
    #[inline]
    pub fn compute_blinding_keys(
        voting_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    ) -> Vec<ProjectivePoint> {
        let num_voters = voting_keys.len();
        assert!(num_voters > 1, "Number of voters must be greater than 1.");
        assert!(
            num_voters.is_power_of_two(),
            "Number of voters must be a power of two."
        );
        let mut blinding_keys = Vec::with_capacity(num_voters);
        let mut blinding_key = ecc::IDENTITY;

        // Compute blinding keys
        for voting_key in voting_keys.iter().skip(1) {
            ecc::compute_add_mixed(&mut blinding_key, &ecc::compute_negation_affine(voting_key));
        }
        for i in 0..num_voters - 1 {
            blinding_keys.push(ProjectivePoint::from_raw_coordinates(blinding_key));

            ecc::compute_add_mixed(
                &mut blinding_key,
                &ecc::compute_negation_affine(&voting_keys[i]),
            );
            ecc::compute_add_mixed(
                &mut blinding_key,
                &ecc::compute_negation_affine(&voting_keys[i + 1]),
            );
        }
        blinding_keys.push(ProjectivePoint::from_raw_coordinates(blinding_key));
        blinding_keys
    }

    /// Reconstruct an object of type Self from a sequence of bytes
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        let mut source = SliceReader::new(source);
        Self::read_from(&mut source)
    }

    /// Dump self to an output stream
    pub fn dump_to<W: std::io::Write>(&self, target: &mut W) -> Result<usize, std::io::Error> {
        target.write(&self.to_bytes())
    }

    /// Process new encrypted vote submitted by voter
    /// Return Ok if encrypted vote is processed successfully.
    pub fn add_encrypted_vote(
        &mut self,
        encrypted_vote: EncryptedVote,
    ) -> Result<(), CollectorError> {
        // Check CDS proof validation result
        let voter_index = encrypted_vote.voter_index;
        let voting_key = ProjectivePoint::from(AffinePoint::from_raw_coordinates(
            self.voting_keys[voter_index],
        ));

        if verify_cds_proof(
            voter_index,
            voting_key,
            self.blinding_keys[voter_index],
            encrypted_vote.encrypted_vote,
            &encrypted_vote.proof_points,
            &encrypted_vote.proof_scalars,
        ) {
            return Err(CollectorError::InvalidEncryptedVote);
        }

        // Return InvalidEncryptedVote if a voter submits twice to
        // avoid information leak
        if self.encrypted_votes[voter_index].is_some() {
            return Err(CollectorError::InvalidEncryptedVote);
        }

        self.add_encrypted_vote_unchecked(encrypted_vote);

        Ok(())
    }

    /// Generate STARK proofs for verification of encrypted votes
    /// Public inputs and proofs are serialized and returned as
    /// a single sequenece of bytes
    pub fn get_cast_proof(&mut self) -> Result<Vec<u8>, CollectorError> {
        if self.num_valid_votes != self.voting_keys.len() {
            return Err(CollectorError::NotEnoughEncryptedVotes);
        }

        if self.serialized_proof.len() > 0 {
            return Ok(self.serialized_proof.clone());
        }

        let encrypted_votes = self
            .encrypted_votes
            .iter()
            .map(|&x| x.unwrap())
            .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();
        let proof_points = self
            .proof_points
            .iter()
            .map(|&x| x.unwrap())
            .collect::<Vec<[BaseElement; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH]>>();
        let proof_scalars = self
            .proof_scalars
            .iter()
            .map(|&x| x.unwrap())
            .collect::<Vec<[Scalar; PROOF_NUM_SCALARS]>>();

        let cds_prover = CDSProver::new(
            build_options(1),
            self.voting_keys.clone(),
            encrypted_votes,
            proof_points,
            proof_scalars,
        );
        let cds_trace = cds_prover.build_trace();
        let cds_pub_inputs = cds_prover.get_pub_inputs(&cds_trace);
        let cds_proof = cds_prover.prove(cds_trace);
        if cds_proof.is_err() {
            return Err(CollectorError::Prover(cds_proof.unwrap_err()));
        }
        let cds_proof = cds_proof.unwrap();

        let compact_pub_inputs = CompactPublicInputs {
            encrypted_votes: cds_pub_inputs.encrypted_votes,
            cds_proofs: cds_pub_inputs.cds_proofs,
            outputs: cds_pub_inputs.outputs,
        };
        let mut serialized_proof = vec![];
        CompactPublicInputs::write_into(&compact_pub_inputs, &mut serialized_proof);
        serialized_proof.write_u8_slice(&cds_proof.to_bytes());

        Ok(serialized_proof)
    }

    fn add_encrypted_vote_unchecked(&mut self, encrypted_vote: EncryptedVote) {
        let voter_index = encrypted_vote.voter_index;
        self.encrypted_votes[voter_index] =
            Some(projective_to_elements(encrypted_vote.encrypted_vote));

        let mut points = [BaseElement::ZERO; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH];
        points[..AFFINE_POINT_WIDTH]
            .copy_from_slice(&projective_to_elements(encrypted_vote.proof_points[0]));
        points[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2]
            .copy_from_slice(&projective_to_elements(encrypted_vote.proof_points[1]));
        points[AFFINE_POINT_WIDTH * 2..AFFINE_POINT_WIDTH * 3]
            .copy_from_slice(&projective_to_elements(encrypted_vote.proof_points[2]));
        points[AFFINE_POINT_WIDTH * 3..AFFINE_POINT_WIDTH * 4]
            .copy_from_slice(&projective_to_elements(encrypted_vote.proof_points[3]));

        self.proof_points[voter_index] = Some(points);
        self.proof_scalars[voter_index] = Some(encrypted_vote.proof_scalars);
        self.num_valid_votes += 1;
    }

    #[cfg(test)]
    pub fn get_example(num_proofs: usize) -> Self {
        use crate::cds::CDSExample;

        let (example, _) = CDSExample::new(build_options(1), num_proofs);
        let encrypted_votes = example
            .encrypted_votes
            .iter()
            .map(|&x| Some(x))
            .collect::<Vec<Option<[BaseElement; AFFINE_POINT_WIDTH]>>>();
        let proof_points = example
            .proof_points
            .iter()
            .map(|&x| Some(x))
            .collect::<Vec<Option<[BaseElement; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH]>>>();
        let proof_scalars = example
            .proof_scalars
            .iter()
            .map(|&x| Some(x))
            .collect::<Vec<Option<[Scalar; PROOF_NUM_SCALARS]>>>();
        let blinding_keys = Self::compute_blinding_keys(&example.voting_keys);

        Self {
            voting_keys: example.voting_keys,
            blinding_keys,
            encrypted_votes,
            proof_points,
            proof_scalars,
            num_valid_votes: num_proofs,
            serialized_proof: vec![],
        }
    }

    #[cfg(test)]
    pub fn get_cast_proof_wrong_pub_inputs(&mut self) -> Result<Vec<u8>, CollectorError> {
        use rand_core::{OsRng, RngCore};

        let mut serialized_proof = self.get_cast_proof()?;
        let pub_inputs_nbytes =
            self.num_valid_votes * (2 * 5 * AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT);
        let fault_position = 4 + ((OsRng.next_u32() as usize) % pub_inputs_nbytes);
        serialized_proof[fault_position] ^= 1;

        Ok(serialized_proof)
    }

    #[cfg(test)]
    pub fn get_cast_proof_wrong_stark_proof(&mut self) -> Result<Vec<u8>, CollectorError> {
        use rand_core::{OsRng, RngCore};

        let mut serialized_proof = self.get_cast_proof()?;
        let pub_inputs_nbytes =
            self.num_valid_votes * (2 * 5 * AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT);
        let proof_nbytes = serialized_proof.len() - 4 - pub_inputs_nbytes;
        let fault_position = 4 + pub_inputs_nbytes + ((OsRng.next_u32() as usize) % proof_nbytes);
        serialized_proof[fault_position] ^= 1;

        Ok(serialized_proof)
    }
}

impl Serializable for VoteCollector {
    fn write_into<W: winterfell::ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.voting_keys.len() as u32);
        for i in 0..self.voting_keys.len() {
            Serializable::write_batch_into(&self.voting_keys[i], target);
            if self.encrypted_votes[i].is_some() {
                Serializable::write_batch_into(&self.encrypted_votes[i].unwrap(), target);
                Serializable::write_batch_into(&self.proof_points[i].unwrap(), target);
                Serializable::write_batch_into(&self.proof_scalars[i].unwrap(), target);
            } else {
                target.write_u8_slice(&[0u8; BYTES_PER_CDS_PROOF]);
            }
        }
    }
}

impl Deserializable for VoteCollector {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut voting_key = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
        let mut encrypted_vote = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
        let mut points = [BaseElement::ZERO; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH];
        let mut scalars = [Scalar::zero(); PROOF_NUM_SCALARS];
        let mut num_valid_votes: usize = 0;

        let num_voters = source.read_u32()? as usize;
        let mut voting_keys = Vec::with_capacity(num_voters);
        let mut encrypted_votes = Vec::with_capacity(num_voters);
        let mut proof_points = Vec::with_capacity(num_voters);
        let mut proof_scalars = Vec::with_capacity(num_voters);

        for _ in 0..num_voters {
            voting_key.copy_from_slice(&BaseElement::read_batch_from(source, AFFINE_POINT_WIDTH)?);
            voting_keys.push(voting_key);
            encrypted_vote
                .copy_from_slice(&BaseElement::read_batch_from(source, AFFINE_POINT_WIDTH)?);
            if encrypted_vote.iter().all(|&x| x == BaseElement::ZERO) {
                // encrypted vote is None
                encrypted_votes.push(None);
                proof_points.push(None);
                proof_scalars.push(None);
                continue;
            }
            num_valid_votes += 1;
            points.copy_from_slice(&BaseElement::read_batch_from(
                source,
                PROOF_NUM_POINTS * AFFINE_POINT_WIDTH,
            )?);
            scalars.copy_from_slice(&Scalar::read_batch_from(source, PROOF_NUM_SCALARS)?);
            encrypted_votes.push(Some(encrypted_vote));
            proof_points.push(Some(points));
            proof_scalars.push(Some(scalars));
        }

        let blinding_keys = Self::compute_blinding_keys(&voting_keys);

        Ok(Self {
            voting_keys,
            blinding_keys,
            encrypted_votes,
            proof_points,
            proof_scalars,
            num_valid_votes,
            serialized_proof: vec![],
        })
    }
}
