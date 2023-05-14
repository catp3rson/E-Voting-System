// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::ecc;
use super::{constants::*, projective_to_elements};
use crate::utils::not;
use ecc::POINT_COORDINATE_WIDTH;
use winterfell::math::curves::curve_f63::AffinePoint;
use winterfell::{
    math::{curves::curve_f63::Scalar, fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// TALLY AIR
// ================================================================================================

pub struct PublicInputs {
    pub encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    pub tally_result: u64,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for encrypted_vote in self.encrypted_votes.iter() {
            Serializable::write_batch_into(encrypted_vote, target);
        }
        target.write(Scalar::from(self.tally_result));
    }
}

pub struct TallyAir {
    context: AirContext<BaseElement>,
    encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    tally_result: u64,
}

impl Air for TallyAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees();
        assert_eq!(TRACE_WIDTH, trace_info.width());

        TallyAir {
            context: AirContext::new(trace_info, degrees, options),
            encrypted_votes: pub_inputs.encrypted_votes,
            tally_result: pub_inputs.tally_result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Expected state width is TRACE_WIDTH field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // Split periodic values
        let final_reduction_flag = periodic_values[0];
        let encrypted_vote = &periodic_values[1..AFFINE_POINT_WIDTH + 1];

        // sum of encrypted votes
        ecc::enforce_point_addition_mixed_unchecked(
            &mut result[..PROJECTIVE_POINT_WIDTH],
            &current[..PROJECTIVE_POINT_WIDTH],
            &next[..PROJECTIVE_POINT_WIDTH],
            encrypted_vote,
            not(final_reduction_flag),
        );

        ecc::enforce_point_addition_mixed_reduce_affine(
            &mut result[..PROJECTIVE_POINT_WIDTH],
            &current[..PROJECTIVE_POINT_WIDTH],
            &next[..PROJECTIVE_POINT_WIDTH],
            encrypted_vote,
            final_reduction_flag,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert starting and ending values
        let mut assertions = vec![];
        let num_votes = self.encrypted_votes.len();
        let neg_d = Scalar::from(num_votes as u64) - Scalar::from(self.tally_result).double();
        let neg_d_g = AffinePoint::generator() * neg_d;
        let neg_d_g_elements = projective_to_elements(neg_d_g);

        // START OF TRACE
        for i in 0..AFFINE_POINT_WIDTH {
            assertions.push(Assertion::single(i, 0, neg_d_g_elements[i]));
        }
        assertions.push(Assertion::single(
            AFFINE_POINT_WIDTH,
            0,
            BaseElement::from(!neg_d_g.is_identity() as u8),
        ));
        for i in AFFINE_POINT_WIDTH + 1..PROJECTIVE_POINT_WIDTH {
            assertions.push(Assertion::single(i, 0, BaseElement::ZERO));
        }

        // END OF TRACE
        // we should end with -self.encrypted_votes[-1]
        let neg_last_vote = ecc::compute_negation_affine(&self.encrypted_votes[num_votes - 1]);
        for i in 0..AFFINE_POINT_WIDTH {
            assertions.push(Assertion::single(i, num_votes - 1, neg_last_vote[i]));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Start with empty periodic columns
        let num_votes = self.encrypted_votes.len();
        let mut columns = vec![vec![BaseElement::ZERO; num_votes]];
        // final_reduction_flag
        columns[0][num_votes - 2] = BaseElement::ONE;

        // encrypted votes
        let mut encrypted_votes = vec![Vec::with_capacity(num_votes); AFFINE_POINT_WIDTH];
        for i in 0..num_votes - 1 {
            let encrypted_vote = self.encrypted_votes[i];
            for j in 0..AFFINE_POINT_WIDTH {
                encrypted_votes[j].push(encrypted_vote[j])
            }
        }
        for i in 0..AFFINE_POINT_WIDTH {
            encrypted_votes[i].push(BaseElement::ZERO);
        }
        columns.append(&mut encrypted_votes);

        columns
    }
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

pub(crate) fn transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = vec![TransitionConstraintDegree::new(6); AFFINE_POINT_WIDTH];

    degrees.append(&mut vec![
        TransitionConstraintDegree::new(5);
        POINT_COORDINATE_WIDTH
    ]);

    degrees
}
