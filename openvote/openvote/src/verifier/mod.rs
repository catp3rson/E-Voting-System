use self::constants::*;
use crate::{
    cds::{CDSAir, PublicInputs as CDSPublicInputs},
    merkle::{MerkleAir, PublicInputs as MerklePublicInputs},
    schnorr::{PublicInputs as SchnorrPublicInputs, SchnorrAir},
};
use winterfell::{
    math::{
        curves::curve_f63::{AffinePoint, ProjectivePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement,
    },
    verify, Deserializable, DeserializationError, SliceReader, StarkProof,
};

/// constants for verifier
pub mod constants;

/// Verify register proof submitted by off-chain aggregator in voter registration phase
/// elg_root_bytes should be stored on smart contract
pub fn verify_register_proof(
    elg_root_bytes: &[u8],
    register_proof: &[u8],
) -> Result<bool, DeserializationError> {
    // Deserialize Merkle public inputs
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&register_proof[..4]);
    let num_regs = u32::from_le_bytes(tmp) as usize;
    let mut bound = 4 + BYTES_PER_VOTING_KEY * num_regs;
    let merkle_pub_inputs_bytes = [&elg_root_bytes, &register_proof[..bound]].concat();
    let merkle_pub_inputs = MerklePublicInputs::from_bytes(&merkle_pub_inputs_bytes)?;
    // Deserialize Schnorr public inputs
    bound += (BYTES_PER_ADDRESS + BYTES_PER_SIGNATURE) * num_regs;
    let schnorr_pub_inputs = SchnorrPublicInputs::from_bytes(&register_proof[..bound])?;
    // Deserialize proofs
    tmp.copy_from_slice(&register_proof[bound..bound + 4]);
    let merkle_proof_nbytes = u32::from_le_bytes(tmp) as usize;
    bound += 4;
    let merkle_proof = StarkProof::from_bytes(&register_proof[bound..bound + merkle_proof_nbytes])?;
    let schnorr_proof = StarkProof::from_bytes(&register_proof[bound + merkle_proof_nbytes..])?;

    // Verify STARK proofs
    Ok(verify::<MerkleAir>(merkle_proof, merkle_pub_inputs).is_ok()
        && verify::<SchnorrAir>(schnorr_proof, schnorr_pub_inputs).is_ok())
}

/// voting_keys should be stored on smart contract
/// First 4 bytes of voting_keys are little-endian representation of voting_keys.len()
pub fn verify_cast_proof(
    voting_keys: &[u8],
    cast_proof: &[u8],
) -> Result<bool, DeserializationError> {
    // Deserialize CDS public inputs and proof
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&cast_proof[..4]);
    let num_proofs = u32::from_le_bytes(tmp) as usize;
    tmp.copy_from_slice(&voting_keys[..4]);
    if num_proofs != (u32::from_le_bytes(tmp) as usize) {
        return Err(DeserializationError::InvalidValue(String::from(
            "Number of CDS proofs submitted does not match number of voting keys.",
        )));
    }
    let cds_pub_inputs = CDSPublicInputs::from_bytes(&[voting_keys, &cast_proof[4..]].concat())?;
    let bound = 4 + num_proofs * (2 * 5 * AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT);
    let cds_proof = StarkProof::from_bytes(&cast_proof[bound..])?;

    // Verify STARK proof
    Ok(verify::<CDSAir>(cds_proof, cds_pub_inputs).is_ok())
}

/// encrypted_votes should be stored on smart contract
pub fn verify_tally_result(
    encrypted_votes: &[u8],
    tally_result: u32,
) -> Result<bool, DeserializationError> {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&encrypted_votes[..4]);
    let num_votes = u32::from_le_bytes(tmp);

    let diff = if tally_result * 2 > num_votes {
        Scalar::from(tally_result * 2 - num_votes)
    } else {
        -Scalar::from(num_votes - tally_result * 2)
    };
    let expected = ProjectivePoint::generator() * diff;
    let mut actual = ProjectivePoint::identity();

    let mut encrypted_vote = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
    let mut encrypted_votes = SliceReader::new(&encrypted_votes[4..]);

    for _ in 0..num_votes {
        encrypted_vote.copy_from_slice(&BaseElement::read_batch_from(
            &mut encrypted_votes,
            AFFINE_POINT_WIDTH,
        )?);
        actual += AffinePoint::from_raw_coordinates(encrypted_vote);
    }

    Ok(expected == actual)
}
