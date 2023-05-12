use super::constants::*;
use crate::utils::ecc;
use ecc::POINT_COORDINATE_WIDTH;
use winterfell::{
    math::{
        curves::curve_f63::{AffinePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement, StarkField,
    },
    ProofOptions, Prover, TraceTable,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use super::PublicInputs;
use super::TallyAir;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// TALLY PROVER
// ================================================================================================

pub struct TallyProver {
    options: ProofOptions,
    encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    // number of "yes" votes
    tally_result: u64,
}

impl TallyProver {
    pub fn new(
        options: ProofOptions,
        encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
        tally_result: u64,
    ) -> Self {
        Self {
            options,
            encrypted_votes,
            tally_result,
        }
    }

    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        // the number of valid encrypted votes is supposed
        // to be a power of two (checked in cds)
        let num_votes = self.encrypted_votes.len() as u64;
        debug_assert!(num_votes >= 2, "Number of proofs cannot be less than 2.");
        debug_assert!(
            num_votes.is_power_of_two(),
            "Number of valid encrypted voted should be a power of two."
        );
        debug_assert!(
            num_votes < BaseElement::MODULUS,
            "Number of votes cannot be greater than base field modulus."
        );
        debug_assert!(self.tally_result <= num_votes, "Invalid tally result");

        // allocate memory to hold the trace table
        let mut trace = TraceTable::new(TRACE_WIDTH, num_votes as usize);

        trace.fill(
            |state| {
                let neg_d = Scalar::from(num_votes) - Scalar::from(self.tally_result).double();
                let neg_d_g = AffinePoint::from(AffinePoint::generator() * neg_d);
                // start with -d * g
                state[..POINT_COORDINATE_WIDTH].copy_from_slice(&neg_d_g.get_x());
                state[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH].copy_from_slice(&neg_d_g.get_y());
                if !neg_d_g.is_identity() {
                    state[AFFINE_POINT_WIDTH] = BaseElement::ONE;
                }
            },
            |step, state| {
                if (step as u64) < num_votes - 2 {
                    ecc::compute_add_mixed(state, &self.encrypted_votes[step]);
                } else {
                    ecc::compute_add_mixed(state, &self.encrypted_votes[step]);
                    let reduced = ecc::reduce_to_affine(&state[..PROJECTIVE_POINT_WIDTH]);
                    state[..AFFINE_POINT_WIDTH].copy_from_slice(&reduced);
                }
            },
        );

        trace
    }
}

impl Prover for TallyProver {
    type BaseField = BaseElement;
    type Air = TallyAir;
    type Trace = TraceTable<BaseElement>;

    // This method should use the existing trace to extract the public inputs to be given
    // to the verifier. As the Tally sub-AIR program is not intended to be used as a
    // standalone AIR program, we bypass this here by storing directly the messages and signatures
    // in the TallyProver struct. This is not used in the complete state transition Air program
    // where only initial and final Merkle roots are provided to the verifier.
    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        PublicInputs {
            encrypted_votes: self.encrypted_votes.clone(),
            tally_result: self.tally_result,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
