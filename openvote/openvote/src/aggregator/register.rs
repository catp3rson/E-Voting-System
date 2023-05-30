use crate::{
    aggregator::build_options,
    merkle::{verify_merlke_proof, MerkleProver},
    schnorr::{verify_signature, SchnorrProver},
};
use log::debug;
use web3::types::Address;
use winterfell::{
    math::{curves::curve_f63::Scalar, fields::f63::BaseElement, FieldElement},
    ByteReader, ByteWriter, Deserializable, DeserializationError, Prover, ProverError,
    Serializable, SliceReader,
};

use super::constants::*;

/// registration of a voter
#[derive(Debug, Clone, Copy)]
pub struct Registration {
    /// Voting key
    pub voting_key: [BaseElement; AFFINE_POINT_WIDTH],
    /// Merkle branch
    pub merkle_branch: [BaseElement; TREE_DEPTH * DIGEST_SIZE],
    /// Merkle branch index
    pub hash_index: usize,
    /// Schnorr signature of (voting_key, address)
    pub signature: ([BaseElement; POINT_COORDINATE_WIDTH], Scalar),
    /// Ethereum address
    pub address: Address,
}

/// Errors raised by VoterRegistar
#[derive(Debug, PartialEq)]
pub enum RegistarError {
    /// This error occurs when an Ethereum address is registered under
    /// two different voting keys
    DuplicatedEthAddress,
    /// This error occurs when Merkle proof of membership is invalid
    InvalidMerkleProof,
    /// This error occurs when Schnorr signature is invalid
    InvalidSchnorrSig,
    /// This error occurs when the number of registrations
    /// exceeds the number eligible voters
    TooManyRegistrations,
}

/// Compact public inputs sent to on-chain verifier
/// to minimize the cost of calldata
#[derive(Debug)]
pub struct CompactPublicInputs {
    /// voting keys
    pub voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// Ethereum addresses
    pub addresses: Vec<Address>,
    /// signatures
    pub signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
}

impl Serializable for CompactPublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.voting_keys.len() as u32);
        for voting_key in self.voting_keys.iter() {
            Serializable::write_batch_into(voting_key, target);
        }
        for address in self.addresses.iter() {
            target.write_u8_slice(address.as_bytes());
        }
        for signature in self.signatures.iter() {
            Serializable::write_batch_into(&signature.0, target);
            target.write(signature.1);
        }
    }
}

/// Type that encapsulates all data and functionalities of
/// aggregator during voter registration phase
#[derive(Debug)]
pub struct VoterRegistar {
    /// Merkle root of tree built from list of eligible voters
    pub elg_root: [BaseElement; DIGEST_SIZE],
    /// Number of eligible voters
    pub num_elg_voters: usize,
    /// voting keys
    pub voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// sibling nodes on the branch from leaf to root
    /// in Merkle proof of membership
    pub merkle_branches: Vec<[BaseElement; TREE_DEPTH * DIGEST_SIZE]>,
    /// branch index in Merkle proof of membership
    pub hash_indices: Vec<usize>,
    /// Schnorr signatures
    pub signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
    /// Ethereum addresses of voters
    pub addresses: Vec<Address>,

    /// Set to true if cached proof is outdated
    pub dirty_flag: bool,
    /// Cached proof
    pub serialized_proof: Vec<u8>,
}

impl VoterRegistar {
    /// Create an object of type VoterRegistar
    /// Initially, dirty_flag is not set
    pub fn new(elg_root: [BaseElement; DIGEST_SIZE], num_elg_voters: usize) -> Self {
        Self {
            elg_root,
            num_elg_voters,
            voting_keys: Vec::with_capacity(num_elg_voters),
            merkle_branches: Vec::with_capacity(num_elg_voters),
            hash_indices: Vec::with_capacity(num_elg_voters),
            signatures: Vec::with_capacity(num_elg_voters),
            addresses: Vec::with_capacity(num_elg_voters),
            dirty_flag: false,
            serialized_proof: vec![],
        }
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

    /// Process new registration submitted by voter
    /// Return Ok if registration is processed successfully.
    pub fn add_registration(&mut self, registration: Registration) -> Result<(), RegistarError> {
        // Two voters cannot share one Ethereum address
        if self.addresses.contains(&registration.address) {
            let idx = self
                .addresses
                .iter()
                .position(|&a| a == registration.address)
                .unwrap();
            if self.voting_keys[idx] != registration.voting_key {
                return Err(RegistarError::DuplicatedEthAddress);
            }
        }

        // Check if Merkle proof of membership is valid
        if !verify_merlke_proof(
            &self.elg_root,
            &registration.voting_key,
            &registration.merkle_branch,
            registration.hash_index,
        ) {
            return Err(RegistarError::InvalidMerkleProof);
        }

        // Check if Schnorr signature is valid
        if !verify_signature(
            registration.voting_key,
            registration.address,
            registration.signature,
        ) {
            return Err(RegistarError::InvalidSchnorrSig);
        }

        // If this voter has already submitted a registration
        // replace their old registration with this registration
        let idx = self
            .voting_keys
            .iter()
            .position(|&vk| vk == registration.voting_key);
        self.add_registration_unchecked(registration, idx)
    }

    /// Bulk process new registrations submitted by voters
    /// Return vector of boolean values to indicate which
    /// registration is processed successfully.
    pub fn add_registrations(
        &mut self,
        registrations: &[Registration],
    ) -> Vec<Result<(), RegistarError>> {
        registrations
            .iter()
            .map(|&registration| self.add_registration(registration))
            .collect::<Vec<Result<(), RegistarError>>>()
    }

    /// Add registration without validating
    fn add_registration_unchecked(
        &mut self,
        registration: Registration,
        idx: Option<usize>,
    ) -> Result<(), RegistarError> {
        if idx.is_some() {
            let idx = idx.unwrap();
            self.voting_keys[idx] = registration.voting_key;
            self.merkle_branches[idx] = registration.merkle_branch;
            self.hash_indices[idx] = registration.hash_index;
            self.signatures[idx] = registration.signature;
            self.addresses[idx] = registration.address;
        } else {
            if self.voting_keys.len() + 1 > self.num_elg_voters {
                return Err(RegistarError::TooManyRegistrations);
            }
            self.voting_keys.push(registration.voting_key);
            self.merkle_branches.push(registration.merkle_branch);
            self.hash_indices.push(registration.hash_index);
            self.signatures.push(registration.signature);
            self.addresses.push(registration.address);
        }
        self.dirty_flag = true;
        Ok(())
    }

    /// Get compact public inputs to submit to
    /// on-chain verifier
    pub fn get_pub_inputs(&self) -> CompactPublicInputs {
        CompactPublicInputs {
            voting_keys: self.voting_keys.clone(),
            addresses: self.addresses.clone(),
            signatures: self.signatures.clone(),
        }
    }

    /// Generate STARK proofs for verification of registrations
    /// Public inputs and proofs are serialized and returned as
    /// a single sequenece of bytes
    pub fn get_register_proof(&mut self) -> Result<Vec<u8>, ProverError> {
        if !self.dirty_flag {
            return Ok(self.serialized_proof.clone());
        }

        // generate proof for verification of Merkle proofs
        let merkle_prover = MerkleProver::new(
            build_options(1),
            self.elg_root.clone(),
            self.voting_keys.clone(),
        );
        let merkle_trace =
            merkle_prover.build_trace(self.merkle_branches.clone(), self.hash_indices.clone());
        let merkle_proof = merkle_prover.prove(merkle_trace)?;

        // generate proof for verification of Schnorr signatures
        let schnorr_prover = SchnorrProver::new(
            build_options(1),
            self.voting_keys.clone(),
            self.addresses.clone(),
            self.signatures.clone(),
        );
        let schnorr_trace = schnorr_prover.build_trace();
        let schnorr_proof = schnorr_prover.prove(schnorr_trace)?;

        // serialize public inputs and proofs
        let compact_pub_inputs = self.get_pub_inputs();
        let mut serialized_proof = vec![];
        compact_pub_inputs.write_into(&mut serialized_proof);
        // Serialize STARK proof for merkle
        let merkle_proof_bytes = merkle_proof.to_bytes();
        serialized_proof.write_u32(merkle_proof_bytes.len() as u32);
        serialized_proof.write_u8_slice(&merkle_proof_bytes);
        // Serialize STARK proof for schnorr
        let schnorr_proof_bytes = &schnorr_proof.to_bytes();
        serialized_proof.write_u8_slice(&schnorr_proof_bytes);

        debug!("Generated serialized STARK proof of size {} bytes for verification of {} registrations.",
            serialized_proof.len(),
            self.voting_keys.len()
        );

        // Cache serialized STARK proof
        self.serialized_proof = serialized_proof.clone();
        self.dirty_flag = false;

        Ok(serialized_proof)
    }

    /// Randomly generate an object of type Self
    #[cfg(test)]
    pub fn get_example(num_regs: usize) -> Self {
        use crate::{merkle::build_merkle_tree_from, schnorr::SchnorrExample};

        assert!(
            num_regs > 1,
            "Number of registrations must be greater than 1."
        );
        assert!(
            num_regs.is_power_of_two(),
            "Number of registrations must be a power of two."
        );

        let schnorr = SchnorrExample::new(build_options(1), num_regs);
        let (elg_root, merkle_branches, hash_indices) =
            build_merkle_tree_from(&schnorr.voting_keys);

        Self {
            elg_root,
            num_elg_voters: num_regs,
            voting_keys: schnorr.voting_keys,
            merkle_branches,
            hash_indices,
            signatures: schnorr.signatures,
            addresses: schnorr.addresses,
            dirty_flag: true,
            serialized_proof: vec![],
        }
    }

    /// Proof generation with fault in public inputs
    #[cfg(test)]
    pub fn get_register_proof_wrong_pub_inputs(&mut self) -> Result<Vec<u8>, ProverError> {
        use rand_core::{OsRng, RngCore};

        let mut serialized_proof = self.get_register_proof()?;
        let pub_inputs_nbytes =
            self.voting_keys.len() * (BYTES_PER_AFFINE + BYTES_PER_ADDRESS + BYTES_PER_SIGNATURE);
        let fault_position = 4 + ((OsRng.next_u32() as usize) % pub_inputs_nbytes);
        serialized_proof[fault_position] ^= 1;

        Ok(serialized_proof)
    }

    /// Proof generation with fault in STARK proofs
    #[cfg(test)]
    pub fn get_register_proof_wrong_stark_proof(&mut self) -> Result<Vec<u8>, ProverError> {
        use rand_core::{OsRng, RngCore};

        let mut serialized_proof = self.get_register_proof()?;
        let pub_inputs_nbytes =
            self.voting_keys.len() * (BYTES_PER_AFFINE + BYTES_PER_ADDRESS + BYTES_PER_SIGNATURE);
        let proof_nbytes = serialized_proof.len() - 4 - pub_inputs_nbytes;
        let fault_position = 4 + pub_inputs_nbytes + ((OsRng.next_u32() as usize) % proof_nbytes);
        serialized_proof[fault_position] ^= 1;

        Ok(serialized_proof)
    }
}

impl Serializable for VoterRegistar {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.num_elg_voters as u32);
        Serializable::write_batch_into(&self.elg_root, target);
        target.write_u32(self.voting_keys.len() as u32);
        for i in 0..self.voting_keys.len() {
            Serializable::write_batch_into(&self.voting_keys[i], target);
            Serializable::write_batch_into(&self.merkle_branches[i], target);
            target.write_u64(self.hash_indices[i] as u64);
            Serializable::write_batch_into(&self.signatures[i].0, target);
            target.write(self.signatures[i].1);
            target.write_u8_slice(&self.addresses[i].as_bytes());
        }
    }
}

impl Deserializable for VoterRegistar {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_elg_voters = source.read_u32()? as usize;
        let mut elg_root = [BaseElement::ZERO; DIGEST_SIZE];
        elg_root.copy_from_slice(&BaseElement::read_batch_from(source, DIGEST_SIZE)?);

        let num_regs = source.read_u32()? as usize;
        let mut voting_keys = Vec::with_capacity(num_regs);
        let mut merkle_branches = Vec::with_capacity(num_regs);
        let mut hash_indices = Vec::with_capacity(num_regs);
        let mut signatures = Vec::with_capacity(num_regs);
        let mut messages = Vec::with_capacity(num_regs);
        let mut addresses = Vec::with_capacity(num_regs);

        let mut voting_key = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
        let mut merkle_branch = [BaseElement::ZERO; TREE_DEPTH * DIGEST_SIZE];
        let mut signature_r = [BaseElement::ZERO; POINT_COORDINATE_WIDTH];
        let mut message = [BaseElement::ZERO; MSG_LENGTH];

        for _ in 0..num_regs {
            voting_key.copy_from_slice(&BaseElement::read_batch_from(source, AFFINE_POINT_WIDTH)?);
            merkle_branch.copy_from_slice(&BaseElement::read_batch_from(
                source,
                TREE_DEPTH * DIGEST_SIZE,
            )?);
            let hash_index = source.read_u64()? as usize;
            signature_r.copy_from_slice(&BaseElement::read_batch_from(
                source,
                POINT_COORDINATE_WIDTH,
            )?);
            let signature_s = Scalar::read_from(source)?;
            message.copy_from_slice(&BaseElement::read_batch_from(source, MSG_LENGTH)?);
            let address = Address::from_slice(&source.read_u8_vec(Address::len_bytes())?);

            voting_keys.push(voting_key);
            merkle_branches.push(merkle_branch);
            hash_indices.push(hash_index);
            signatures.push((signature_r, signature_s));
            messages.push(message);
            addresses.push(address);
        }

        Ok(Self {
            elg_root,
            num_elg_voters,
            voting_keys,
            merkle_branches,
            hash_indices,
            signatures,
            addresses,
            dirty_flag: num_regs > 0,
            serialized_proof: vec![],
        })
    }
}
