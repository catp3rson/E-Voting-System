// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bitvec::{order::Lsb0, view::AsBits};
use rand_core::{OsRng, RngCore};
use unroll::unroll_for_loops;
use winterfell::{
    crypto::Hasher,
    math::{
        curves::curve_f63::{AffinePoint, ProjectivePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement,
    },
    FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, VerifierError,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(feature = "std")]
use winterfell::{math::log2, Trace};

use self::constants::{HASH_MSG_LENGTH, PROOF_NUM_POINTS, PROOF_NUM_SCALARS};

use super::utils::{
    ecc::{self, AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH},
    field,
    rescue::{self, Rescue63, RATE_WIDTH as HASH_RATE_WIDTH},
};

pub(crate) mod constants;
mod trace;

mod air;
use air::{CDSAir, PublicInputs};

mod prover;
pub(crate) use prover::CDSProver;

#[cfg(test)]
mod tests;

// SCHNORR SIGNATURE EXAMPLE
// ================================================================================================

/// Outputs a new `SchnorrExample` with `num_signatures` signatures on random messages.
pub fn get_example(
    num_proofs: usize,
) -> (
    CDSExample,
    (
        Vec<ProjectivePoint>,
        Vec<ProjectivePoint>,
        Vec<[Scalar; PROOF_NUM_SCALARS]>,
        Vec<[ProjectivePoint; PROOF_NUM_POINTS]>,
    ),
) {
    CDSExample::new(
        ProofOptions::new(
            42,
            8,
            0,
            HashFunction::Blake3_192,
            FieldExtension::None,
            4,
            256,
        ),
        num_proofs,
    )
}

/// A struct to perform Schnorr signature valid
/// verification proof among a set of signed messages.
#[derive(Clone, Debug)]
pub struct CDSExample {
    options: ProofOptions,
    voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    proof_points: Vec<[BaseElement; AFFINE_POINT_WIDTH * PROOF_NUM_POINTS]>,
    proof_scalars: Vec<[Scalar; PROOF_NUM_SCALARS]>,
}

impl CDSExample {
    /// Outputs a new `SchnorrExample` with `num_signatures` signatures on random messages.
    pub fn new(
        options: ProofOptions,
        num_proofs: usize,
    ) -> (
        CDSExample,
        (
            Vec<ProjectivePoint>,
            Vec<ProjectivePoint>,
            Vec<[Scalar; PROOF_NUM_SCALARS]>,
            Vec<[ProjectivePoint; PROOF_NUM_POINTS]>,
        ),
    ) {
        let mut rng = OsRng;
        let mut secret_keys = Vec::with_capacity(num_proofs);
        let mut voting_keys = Vec::with_capacity(num_proofs);
        let mut blinding_keys = Vec::with_capacity(num_proofs);
        let mut votes = Vec::with_capacity(num_proofs);

        // prepare secret keys and public keys
        for _ in 0..num_proofs {
            let secret_key = Scalar::random(&mut rng);
            let voting_key = ProjectivePoint::generator() * secret_key;
            secret_keys.push(secret_key);
            voting_keys.push(voting_key);
        }

        // prepare blinding keys and random votes
        let mut blinding_key = ProjectivePoint::identity();
        for &voting_key in voting_keys.iter().skip(1) {
            blinding_key -= voting_key;
        }

        for i in 0..num_proofs {
            blinding_keys.push(blinding_key);
            votes.push(rng.next_u32() % 2 == 1);
            if i + 1 < num_proofs {
                blinding_key += voting_keys[i];
                blinding_key += voting_keys[i + 1];
            }
        }

        // compute the CDS proofs
        #[cfg(feature = "std")]
        let now = Instant::now();
        let (encrypted_votes, proof_scalars, proof_points) = encrypt_votes_and_compute_proofs(
            num_proofs,
            &secret_keys,
            &voting_keys,
            &blinding_keys,
            &votes,
        );

        #[cfg(feature = "std")]
        debug!(
            "Computed {} CDS proofs in {} ms",
            num_proofs,
            now.elapsed().as_millis(),
        );

        // verify the CDS proofs
        #[cfg(feature = "std")]
        let now = Instant::now();

        assert!(naive_verify_cds_proofs(
            &voting_keys,
            &encrypted_votes,
            &proof_scalars,
            &proof_points
        ));

        #[cfg(feature = "std")]
        debug!(
            "Verified {} CDS proofs in {} ms",
            num_proofs,
            now.elapsed().as_millis(),
        );

        let extra_data = (
            voting_keys.clone(),
            encrypted_votes.clone(),
            proof_scalars.clone(),
            proof_points.clone(),
        );

        let voting_keys = voting_keys
            .into_iter()
            .map(|p| projective_to_elements(p))
            .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();

        let encrypted_votes = encrypted_votes
            .into_iter()
            .map(|p| projective_to_elements(p))
            .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();

        let proof_points = proof_points
            .iter()
            .map(|ps| concat_proof_points(ps))
            .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH * PROOF_NUM_POINTS]>>();

        (
            CDSExample {
                options,
                voting_keys,
                encrypted_votes,
                proof_points,
                proof_scalars,
            },
            extra_data,
        )
    }

    /// Proves the validity of a sequence of Schnorr signatures
    pub fn prove(&self) -> (PublicInputs, StarkProof) {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating proofs for verifying {} CDS proofs\n\
            ---------------------",
            self.voting_keys.len(),
        );

        let prover = CDSProver::new(
            self.options.clone(),
            self.voting_keys.clone(),
            self.encrypted_votes.clone(),
            self.proof_points.clone(),
            self.proof_scalars.clone(),
        );

        // generate the execution trace
        #[cfg(feature = "std")]
        let now = Instant::now();
        let trace = prover.build_trace();
        #[cfg(feature = "std")]
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace.length()),
            now.elapsed().as_millis()
        );

        // generate the proof
        (prover.get_pub_inputs(&trace), prover.prove(trace).unwrap())
    }

    /// Verifies the validity of a proof of correct Schnorr signature verification
    pub fn verify(&self, proof: StarkProof, pub_inputs: PublicInputs) -> Result<(), VerifierError> {
        winterfell::verify::<CDSAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_proof(
        &self,
        proof: StarkProof,
        pub_inputs: PublicInputs,
    ) -> Result<(), VerifierError> {
        let mut pub_inputs = pub_inputs;
        let mut rng = OsRng;
        let fault_index = (rng.next_u32() as usize) % (pub_inputs.proofs.len());
        let fault_position = (rng.next_u32() as usize) % (pub_inputs.proofs[0].len());
        pub_inputs.proofs[fault_index][fault_position] += BaseElement::ONE;
        winterfell::verify::<CDSAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_output(
        &self,
        proof: StarkProof,
        pub_inputs: PublicInputs,
    ) -> Result<(), VerifierError> {
        let mut pub_inputs = pub_inputs;
        let mut rng = OsRng;
        let fault_index = (rng.next_u32() as usize) % (pub_inputs.outputs.len());
        let fault_position = (rng.next_u32() as usize) % (pub_inputs.outputs[0].len());
        pub_inputs.outputs[fault_index][fault_position] += BaseElement::ONE;
        winterfell::verify::<CDSAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Encrypt votes and compute CDS proofs
pub(crate) fn encrypt_votes_and_compute_proofs(
    num_proofs: usize,
    secret_keys: &[Scalar],
    voting_keys: &[ProjectivePoint],
    blinding_keys: &[ProjectivePoint],
    votes: &[bool],
) -> (
    Vec<ProjectivePoint>,
    Vec<[Scalar; PROOF_NUM_SCALARS]>,
    Vec<[ProjectivePoint; PROOF_NUM_POINTS]>,
) {
    assert!(
        secret_keys.len() == num_proofs
            && voting_keys.len() == num_proofs
            && blinding_keys.len() == num_proofs
            && votes.len() == num_proofs,
        "Inconsistent length."
    );
    let rng = OsRng;
    let mut ws = Vec::with_capacity(num_proofs);
    let mut encrypted_votes = Vec::with_capacity(num_proofs);
    let mut proof_scalars = Vec::with_capacity(num_proofs);
    let mut proof_points = Vec::with_capacity(num_proofs);

    // compute the encrypted votes
    for i in 0..num_proofs {
        let encrypted_vote = if votes[i] {
            blinding_keys[i] * secret_keys[i] + ProjectivePoint::generator()
        } else {
            blinding_keys[i] * secret_keys[i] - ProjectivePoint::generator()
        };
        encrypted_votes.push(encrypted_vote);
    }

    //compute the proof points (a1, b1, a2, b2)
    for i in 0..num_proofs {
        let w = Scalar::random(rng);
        ws.push(w);

        if votes[i] {
            let r1 = Scalar::random(rng);
            let d1 = Scalar::random(rng);
            let a1 = ProjectivePoint::generator() * r1 + voting_keys[i] * d1;
            let b1 =
                blinding_keys[i] * r1 + (encrypted_votes[i] + ProjectivePoint::generator()) * d1;
            let a2 = ProjectivePoint::generator() * w;
            let b2 = blinding_keys[i] * w;
            proof_points.push([a1, b1, a2, b2]);
            proof_scalars.push([d1, Scalar::zero(), r1, Scalar::zero()])
        } else {
            let r2 = Scalar::random(rng);
            let d2 = Scalar::random(rng);
            let a2 = ProjectivePoint::generator() * r2 + voting_keys[i] * d2;
            let b2 =
                blinding_keys[i] * r2 + (encrypted_votes[i] - ProjectivePoint::generator()) * d2;
            let a1 = ProjectivePoint::generator() * w;
            let b1 = blinding_keys[i] * w;
            proof_points.push([a1, b1, a2, b2]);
            proof_scalars.push([Scalar::zero(), d2, Scalar::zero(), r2])
        }
    }

    // compute the challenge and proof scalars
    for i in 0..num_proofs {
        let hash_message =
            points_to_hash_message(i, voting_keys[i], encrypted_votes[i], &proof_points[i]);
        let c_bytes = hash_message_bytes(&hash_message);
        let c_bits = c_bytes.as_bits::<Lsb0>();
        let c_scalar = Scalar::from_bits(c_bits);

        if votes[i] {
            let d2 = c_scalar - proof_scalars[i][0];
            proof_scalars[i][1] = d2;
            let r2 = ws[i] - secret_keys[i] * d2;
            proof_scalars[i][3] = r2;
        } else {
            let d1 = c_scalar - proof_scalars[i][1];
            proof_scalars[i][0] = d1;
            let r1 = ws[i] - secret_keys[i] * d1;
            proof_scalars[i][2] = r1;
        }
    }

    assert!(
        encrypted_votes.len() == num_proofs
            && proof_scalars.len() == num_proofs
            && proof_points.len() == num_proofs,
        "Inconsistent length."
    );

    (encrypted_votes, proof_scalars, proof_points)
}

/// Naively varify CDS proofs
pub fn naive_verify_cds_proofs(
    voting_keys: &[ProjectivePoint],
    encrypted_votes: &[ProjectivePoint],
    proof_scalars: &[[Scalar; PROOF_NUM_SCALARS]],
    proof_points: &[[ProjectivePoint; PROOF_NUM_POINTS]],
) -> bool {
    // compute blinding keys
    let num_proofs = voting_keys.len();
    let mut blinding_keys = Vec::with_capacity(num_proofs);
    let mut blinding_key = ProjectivePoint::identity();
    for i in 1..num_proofs {
        blinding_key -= voting_keys[i];
    }
    for i in 0..num_proofs {
        blinding_keys.push(blinding_key);
        if i + 1 < num_proofs {
            blinding_key += voting_keys[i];
            blinding_key += voting_keys[i + 1];
        }
    }

    for (i, (scalars, points)) in proof_scalars.iter().zip(proof_points.iter()).enumerate() {
        let d1 = scalars[0];
        let d2 = scalars[1];
        let r1 = scalars[2];
        let r2 = scalars[3];

        let a1 = points[0];
        let b1 = points[1];
        let a2 = points[2];
        let b2: ProjectivePoint = points[3];

        let hash_message = points_to_hash_message(i, voting_keys[i], encrypted_votes[i], points);
        let c_bytes = hash_message_bytes(&hash_message);
        let c_bits = c_bytes.as_bits::<Lsb0>();
        let c_scalar = Scalar::from_bits(c_bits);
        if (c_scalar != d1 + d2)
            || (a1 != ProjectivePoint::generator() * r1 + voting_keys[i] * d1)
            || (b1
                != blinding_keys[i] * r1 + (encrypted_votes[i] + ProjectivePoint::generator()) * d1)
            || (a2 != ProjectivePoint::generator() * r2 + voting_keys[i] * d2)
            || (b2
                != blinding_keys[i] * r2 + (encrypted_votes[i] - ProjectivePoint::generator()) * d2)
        {
            return false;
        }
    }

    true
}

#[inline]
fn projective_to_elements(point: ProjectivePoint) -> [BaseElement; AFFINE_POINT_WIDTH] {
    let mut result = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
    result[..POINT_COORDINATE_WIDTH].copy_from_slice(&AffinePoint::from(point).get_x());
    result[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH]
        .copy_from_slice(&AffinePoint::from(point).get_y());
    result
}

#[inline]
fn concat_proof_points(
    proof_points: &[ProjectivePoint; PROOF_NUM_POINTS],
) -> [BaseElement; AFFINE_POINT_WIDTH * PROOF_NUM_POINTS] {
    let mut result = [BaseElement::ZERO; AFFINE_POINT_WIDTH * PROOF_NUM_POINTS];
    let proof_points = proof_points.map(|p| projective_to_elements(p)).concat();
    result.copy_from_slice(&proof_points);
    result
}

#[inline]
fn points_to_hash_message(
    voter_index: usize,
    voting_key: ProjectivePoint,
    encrypted_vote: ProjectivePoint,
    proof_points: &[ProjectivePoint; PROOF_NUM_POINTS],
) -> [BaseElement; HASH_MSG_LENGTH] {
    let mut hash_message = [BaseElement::ZERO; HASH_MSG_LENGTH];
    let proof_points = concat_proof_points(proof_points);
    hash_message[0] = BaseElement::from(voter_index as u8);
    hash_message[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2]
        .copy_from_slice(&projective_to_elements(voting_key));
    hash_message[AFFINE_POINT_WIDTH * 2..AFFINE_POINT_WIDTH * 3]
        .copy_from_slice(&projective_to_elements(encrypted_vote));
    hash_message[AFFINE_POINT_WIDTH * 3..AFFINE_POINT_WIDTH * (PROOF_NUM_POINTS + 3)]
        .copy_from_slice(&proof_points);
    hash_message
}

#[unroll_for_loops]
#[inline]
fn hash_message_bytes(message: &[BaseElement; HASH_MSG_LENGTH]) -> [u8; 32] {
    debug_assert!(
        HASH_MSG_LENGTH % HASH_RATE_WIDTH == 0,
        "Length of hash message must be divisible by rate width."
    );
    let mut h = Rescue63::digest(&message[..HASH_RATE_WIDTH]);
    let mut message_chunk;
    for i in (HASH_RATE_WIDTH..HASH_MSG_LENGTH).step_by(HASH_RATE_WIDTH) {
        message_chunk = rescue::Hash::new(
            message[i],
            message[i + 1],
            message[i + 2],
            message[i + 3],
            message[i + 4],
            message[i + 5],
            message[i + 6],
        );
        h = Rescue63::merge(&[h, message_chunk]);
    }
    let h = h.to_elements();
    let mut h_bytes = [0u8; 32];
    for (i, h_word) in h.iter().enumerate().take(4) {
        h_bytes[8 * i..8 * i + 8].copy_from_slice(&h_word.to_bytes());
    }
    h_bytes
}

#[unroll_for_loops]
#[inline]
fn diff_registers<const NREGS: usize>(
    a: &[BaseElement],
    b: &[BaseElement],
) -> [BaseElement; NREGS] {
    let mut result = [BaseElement::ZERO; NREGS];
    for i in 0..NREGS {
        result[i] = a[i] - b[i];
    }
    result
}
