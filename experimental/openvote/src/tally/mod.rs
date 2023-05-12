// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ecc::PROJECTIVE_POINT_WIDTH;
use rand_core::{OsRng, RngCore};
use winterfell::{
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

use crate::utils::ecc::IDENTITY;

use super::utils::ecc::{self, AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH};

pub(crate) mod constants;

mod air;
use air::{PublicInputs, TallyAir};

mod prover;
pub(crate) use prover::TallyProver;

#[cfg(test)]
mod tests;

// SCHNORR SIGNATURE EXAMPLE
// ================================================================================================

/// Outputs a new `TallyExample` with `num_signatures` signatures on random messages.
pub fn get_example(num_signatures: usize) -> TallyExample {
    TallyExample::new(
        // TODO: make it customizable
        ProofOptions::new(
            42,
            8,
            0,
            HashFunction::Blake3_192,
            FieldExtension::None,
            4,
            256,
        ),
        num_signatures,
    )
}

/// A struct to perform Tally signature valid
/// verification proof among a set of signed messages.
#[derive(Clone, Debug)]
pub struct TallyExample {
    options: ProofOptions,
    encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    tally_result: u64,
}

impl TallyExample {
    /// Outputs a new `TallyExample` with `num_signatures` signatures on random messages.
    pub fn new(options: ProofOptions, num_votes: usize) -> TallyExample {
        // compute the encrypted votes
        let mut rng = OsRng;
        let tally_result = rng.next_u64() % ((num_votes + 1) as u64);
        let mut encrypted_votes = Vec::with_capacity(num_votes);

        let d = Scalar::from(tally_result).double() - Scalar::from(num_votes as u64);
        let mut s_sum = Scalar::zero();

        for _ in 0..num_votes - 1 {
            let s = Scalar::random(rng);
            s_sum += s;
            let encrypted_vote = AffinePoint::generator() * s;
            encrypted_votes.push(projective_to_elements(encrypted_vote))
        }

        let encrypted_vote = AffinePoint::generator() * (d - s_sum);
        encrypted_votes.push(projective_to_elements(encrypted_vote));

        // verify the tally result
        #[cfg(feature = "std")]
        let now = Instant::now();

        assert!(naive_verify_tally_result(&encrypted_votes, tally_result));

        #[cfg(feature = "std")]
        debug!(
            "Verified tally result with {} in {} ms",
            num_votes,
            now.elapsed().as_millis(),
        );

        TallyExample {
            options,
            encrypted_votes,
            tally_result,
        }
    }

    /// Proves the validity of a sequence of Tally signatures
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating proof for verifying tally result with {} encrypted votes\n\
            ---------------------",
            self.encrypted_votes.len(),
        );

        let prover = TallyProver::new(
            self.options.clone(),
            self.encrypted_votes.clone(),
            self.tally_result,
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
        prover.prove(trace).unwrap()
    }

    /// Verifies the validity of a proof of correct Tally signature verification
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            encrypted_votes: self.encrypted_votes.clone(),
            tally_result: self.tally_result,
        };
        winterfell::verify::<TallyAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let num_votes = self.encrypted_votes.len();
        let mut rng = OsRng;
        let mut pub_inputs = PublicInputs {
            encrypted_votes: self.encrypted_votes.clone(),
            tally_result: self.tally_result,
        };

        if rng.next_u32() % 2 == 1 {
            // wrong encrypted vote
            let fault_idx = (rng.next_u32() as usize) % num_votes;
            let fault_position = (rng.next_u32() as usize) % self.encrypted_votes[0].len();
            pub_inputs.encrypted_votes[fault_idx][fault_position] += BaseElement::ONE;
        } else {
            // wrong tally result
            while pub_inputs.tally_result == self.tally_result {
                pub_inputs.tally_result = rng.next_u64() % ((num_votes + 1) as u64);
            }
        }

        winterfell::verify::<TallyAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline]
/// Naively verify the tally result
pub(crate) fn naive_verify_tally_result(
    encrypted_votes: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    tally_result: u64,
) -> bool {
    let num_votes = encrypted_votes.len();
    let mut encrypted_sum = IDENTITY;
    let expected_sum = AffinePoint::generator()
        * (Scalar::from(tally_result).double() - Scalar::from(num_votes as u64));

    for encrypted_vote in encrypted_votes {
        ecc::compute_add_mixed(&mut encrypted_sum, encrypted_vote);
    }

    if expected_sum.is_identity() {
        let mut result = true;
        for i in AFFINE_POINT_WIDTH..PROJECTIVE_POINT_WIDTH {
            result = result && (encrypted_sum[i] == BaseElement::ZERO);
        }
        result
    } else {
        let expected_sum = projective_to_elements(expected_sum);
        let encrypted_sum = ecc::reduce_to_affine(&encrypted_sum);
        encrypted_sum == expected_sum
    }
}

#[inline]
/// Convert ProjectivePoint to AffinePoint then convert AffinePoint to array of BaseElement
fn projective_to_elements(point: ProjectivePoint) -> [BaseElement; AFFINE_POINT_WIDTH] {
    let mut result = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
    result[..POINT_COORDINATE_WIDTH].copy_from_slice(&AffinePoint::from(point).get_x());
    result[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH]
        .copy_from_slice(&AffinePoint::from(point).get_y());
    result
}
