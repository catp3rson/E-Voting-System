// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::result;
use std::process::Output;

use super::super::utils::periodic_columns::stitch;
use super::constants::*;
use super::rescue::{RATE_WIDTH as HASH_RATE_WIDTH, STATE_WIDTH as HASH_STATE_WIDTH};
use super::trace::prepare_encrypted_votes;
use super::{ecc, field, rescue};
use crate::utils::ecc::GENERATOR;
use crate::utils::{are_equal, not, EvaluationResult};
use unroll::unroll_for_loops;
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// CDS AIR
// ================================================================================================

#[derive(Debug, Clone)]
pub struct PublicInputs {
    // [vk, ev, a1, b1, a2, b2]
    pub proofs: Vec<[BaseElement; AFFINE_POINT_WIDTH * 6]>,
    pub outputs: Vec<[BaseElement; AFFINE_POINT_WIDTH * 5]>,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for i in 0..self.proofs.len() {
            Serializable::write_batch_into(&self.proofs[i], target);
        }
    }
}

pub struct CDSAir {
    context: AirContext<BaseElement>,
    proofs: Vec<[BaseElement; AFFINE_POINT_WIDTH * 6]>,
    outputs: Vec<[BaseElement; AFFINE_POINT_WIDTH * 5]>,
}

impl Air for CDSAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees();
        assert_eq!(TRACE_WIDTH, trace_info.width());
        CDSAir {
            context: AirContext::new(trace_info, degrees, options),
            proofs: pub_inputs.proofs,
            outputs: pub_inputs.outputs,
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
        let global_mask = periodic_values[0];
        let phase_mask = periodic_values[1];

        let c_mult_flag = periodic_values[2];
        let scalar_mult_flag = periodic_values[3];
        let doubling_flag = periodic_values[4];

        let hash_digest_register_flag = &periodic_values[5..9];

        let voting_key = &periodic_values[9..9 + AFFINE_POINT_WIDTH];
        let blinding_key = &periodic_values[9 + AFFINE_POINT_WIDTH..9 + AFFINE_POINT_WIDTH * 2];
        let encrypted_vote =
            &periodic_values[9 + AFFINE_POINT_WIDTH * 2..9 + AFFINE_POINT_WIDTH * 3];

        let hash_flag = periodic_values[9 + AFFINE_POINT_WIDTH * 3];
        let hash_internal_inputs = &periodic_values
            [10 + AFFINE_POINT_WIDTH * 3..10 + AFFINE_POINT_WIDTH * 3 + HASH_RATE_WIDTH];
        let ark = &periodic_values[10 + AFFINE_POINT_WIDTH * 3 + HASH_RATE_WIDTH..];

        let copy_hash_flag = not(hash_flag) * global_mask;
        let final_point_addition_flag = not(scalar_mult_flag) * phase_mask;

        let c_doubling_flag = doubling_flag * c_mult_flag;
        let c_addition_flag = not(doubling_flag) * c_mult_flag;
        let c_copy_flag = not(c_mult_flag) * not(final_point_addition_flag) * global_mask;

        let addition_flag = not(doubling_flag) * scalar_mult_flag;

        evaluate_constraints(
            result,
            current,
            next,
            // Rescue round constants
            ark,
            // Points in proof
            voting_key,
            blinding_key,
            encrypted_vote,
            // Inputs to Rescue hash
            hash_internal_inputs,
            // flags
            doubling_flag,
            addition_flag,
            c_doubling_flag,
            c_addition_flag,
            c_copy_flag,
            hash_digest_register_flag,
            final_point_addition_flag,
            hash_flag,
            copy_hash_flag,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let (proof_points_a, proof_points_b, c_diff_value) =
            transpose_proof_points(&self.proofs, &self.outputs);

        // Assert starting and ending values
        let mut assertions = vec![];

        // START OF CDS CYCLE
        for i in 0..PROJECTIVE_POINT_WIDTH {
            let value = BaseElement::from((i == POINT_COORDINATE_WIDTH) as u8);
            assertions.append(&mut vec![
                // c * vk
                Assertion::periodic(i, 0, CDS_CYCLE_LENGTH, value),
                // r1 * g / r2 * g
                Assertion::periodic(i + PROJECTIVE_POINT_WIDTH + 1, 0, NROWS_PER_PHASE, value),
                // r1 * bk / r2 * bk
                Assertion::periodic(
                    i + 2 * PROJECTIVE_POINT_WIDTH + 1,
                    0,
                    NROWS_PER_PHASE,
                    value,
                ),
                // d1 * vk / d2 * vk
                Assertion::periodic(
                    i + 3 * PROJECTIVE_POINT_WIDTH + 2,
                    0,
                    NROWS_PER_PHASE,
                    value,
                ),
                // d1 * (ev + G) / d2 * (ev - G)
                Assertion::periodic(
                    i + 4 * PROJECTIVE_POINT_WIDTH + 2,
                    0,
                    NROWS_PER_PHASE,
                    value,
                ),
            ]);
        }
        // binary decompositions
        assertions.append(&mut vec![
            Assertion::periodic(
                PROJECTIVE_POINT_WIDTH,
                0,
                NROWS_PER_PHASE,
                BaseElement::ZERO,
            ),
            Assertion::periodic(
                3 * PROJECTIVE_POINT_WIDTH + 1,
                0,
                NROWS_PER_PHASE,
                BaseElement::ZERO,
            ),
            Assertion::periodic(
                5 * PROJECTIVE_POINT_WIDTH + 2,
                0,
                NROWS_PER_PHASE,
                BaseElement::ZERO,
            ),
        ]);
        // Reconstructed c
        for i in 0..4 {
            assertions.push(Assertion::periodic(
                i + 5 * PROJECTIVE_POINT_WIDTH + 3,
                0,
                CDS_CYCLE_LENGTH,
                BaseElement::ZERO,
            ));
        }
        // Rescue registers
        for i in 0..self.proofs.len() {
            assertions.push(Assertion::single(
                5 * PROJECTIVE_POINT_WIDTH + 7,
                i * CDS_CYCLE_LENGTH,
                BaseElement::from(i as u8),
            ));
        }
        for i in 1..HASH_STATE_WIDTH {
            assertions.push(Assertion::periodic(
                i + 5 * PROJECTIVE_POINT_WIDTH + 7,
                0,
                CDS_CYCLE_LENGTH,
                BaseElement::ZERO,
            ));
        }

        // END OF PHASE
        for i in 0..AFFINE_POINT_WIDTH {
            // a1, a2
            assertions.push(Assertion::sequence(
                i + PROJECTIVE_POINT_WIDTH + 1,
                SCALAR_MUL_LENGTH + 1,
                NROWS_PER_PHASE,
                proof_points_a[i].to_owned(),
            ));
            // b1, b2
            assertions.push(Assertion::sequence(
                i + 2 * PROJECTIVE_POINT_WIDTH + 1,
                SCALAR_MUL_LENGTH + 1,
                NROWS_PER_PHASE,
                proof_points_b[i].to_owned(),
            ));
        }

        // END OF CYCLE
        // (c - d1 - d2) * vk
        for i in 0..POINT_COORDINATE_WIDTH {
            assertions.push(Assertion::sequence(
                i,
                CDS_CYCLE_LENGTH - 1,
                CDS_CYCLE_LENGTH,
                c_diff_value[i].to_owned(),
            ));
            assertions.push(Assertion::sequence(
                i + AFFINE_POINT_WIDTH,
                CDS_CYCLE_LENGTH - 1,
                CDS_CYCLE_LENGTH,
                c_diff_value[i + POINT_COORDINATE_WIDTH].to_owned(),
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Start with empty periodic columns
        let mut columns = vec![Vec::new(); 3 * AFFINE_POINT_WIDTH + HASH_RATE_WIDTH + 10];
        // Stitch in the periodic columns applicable to all uses of CDS
        stitch(
            &mut columns,
            periodic_columns(),
            vec![
                (0, 0),
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 4),
                (5, 5),
                (6, 6),
                (7, 7),
                (8, 8),
                (9, 9 + 3 * AFFINE_POINT_WIDTH),
            ],
        );
        // Values to feed to the last registers of the hash state at the end of a cycle.
        // Always zero (i.e. resetting the rate) or equal to the chunks of the message.
        let trace_width = CDS_CYCLE_LENGTH * self.proofs.len();
        let mut hash_intermediate_inputs =
            vec![vec![BaseElement::ZERO; trace_width]; HASH_RATE_WIDTH];

        let mut blinding_keys = vec![vec![BaseElement::ZERO; trace_width]; AFFINE_POINT_WIDTH];

        let mut voting_keys = vec![vec![BaseElement::ZERO; trace_width]; AFFINE_POINT_WIDTH];

        let mut encrypted_votes = vec![vec![BaseElement::ZERO; trace_width]; AFFINE_POINT_WIDTH];

        let mut blinding_key = ecc::IDENTITY;
        for proof in self.proofs.iter().skip(1) {
            ecc::compute_add_mixed(
                &mut blinding_key,
                &ecc::compute_negation_affine(&proof[..AFFINE_POINT_WIDTH]),
            );
        }
        // we don't need to set hash_message[0] = BaseElement::from(voter_index)
        // because we only take hash_message[HASH_RATE_WIDTH..]
        let mut hash_message = [BaseElement::ZERO; HASH_MSG_LENGTH];

        for (voter_index, proof) in self.proofs.iter().enumerate() {
            hash_message[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 7].copy_from_slice(proof);

            let affine_blinding_key = ecc::reduce_to_affine(&blinding_key);
            let (encrypted_vote_1, encrypted_vote_2) =
                prepare_encrypted_votes(&proof[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2]);

            for i in 0..NUM_HASH_ITER - 1 {
                for (j, input) in hash_intermediate_inputs.iter_mut().enumerate() {
                    input[i * HASH_CYCLE_LENGTH
                        + NUM_HASH_ROUNDS
                        + voter_index * CDS_CYCLE_LENGTH] =
                        hash_message[j + (i + 1) * HASH_RATE_WIDTH];
                }
            }

            for i in 0..voting_keys.len() {
                blinding_keys[i]
                    [voter_index * CDS_CYCLE_LENGTH..(voter_index + 1) * CDS_CYCLE_LENGTH]
                    .fill(affine_blinding_key[i]);
                voting_keys[i]
                    [voter_index * CDS_CYCLE_LENGTH..(voter_index + 1) * CDS_CYCLE_LENGTH]
                    .fill(proof[i]);
                encrypted_votes[i][voter_index * CDS_CYCLE_LENGTH
                    ..voter_index * CDS_CYCLE_LENGTH + NROWS_PER_PHASE]
                    .fill(encrypted_vote_1[i]);
                encrypted_votes[i][voter_index * CDS_CYCLE_LENGTH + NROWS_PER_PHASE
                    ..(voter_index + 1) * CDS_CYCLE_LENGTH]
                    .fill(encrypted_vote_2[i]);
            }

            // get the blinding key of the next voter
            if voter_index + 1 < self.proofs.len() {
                ecc::compute_add_mixed(&mut blinding_key, &proof[..AFFINE_POINT_WIDTH]);
                ecc::compute_add_mixed(
                    &mut blinding_key,
                    &self.proofs[voter_index + 1][..AFFINE_POINT_WIDTH],
                )
            }
        }

        // Stitch in the above columns in the appropriate places
        stitch(
            &mut columns,
            voting_keys,
            (9..9 + AFFINE_POINT_WIDTH).enumerate().collect(),
        );
        stitch(
            &mut columns,
            blinding_keys,
            (9 + AFFINE_POINT_WIDTH..9 + 2 * AFFINE_POINT_WIDTH)
                .enumerate()
                .collect(),
        );
        stitch(
            &mut columns,
            encrypted_votes,
            (9 + 2 * AFFINE_POINT_WIDTH..9 + 3 * AFFINE_POINT_WIDTH)
                .enumerate()
                .collect(),
        );
        stitch(
            &mut columns,
            hash_intermediate_inputs,
            (10 + 3 * AFFINE_POINT_WIDTH..10 + 3 * AFFINE_POINT_WIDTH + HASH_RATE_WIDTH)
                .enumerate()
                .collect(),
        );

        // Append the rescue round constants
        columns.append(&mut rescue::get_round_constants());

        columns
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first HASH_RATE_WIDTH registers are equal to the values from the previous step
/// - the other HASH_RATE_WIDTH registers are equal to 0,
///   and add the values of internal_inputs for hash merging if any (only at last round)
fn enforce_hash_copy<E: FieldElement>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    flag: E,
    internal_inputs: &[E],
) {
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(current[i], next[i]));
    }

    // internal_inputs are either zero (no difference with original hash chain) when resetting the
    // last registers or equal to the message elements, to be fed to the hash in an iterated way.
    // See build_trace() for more info
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(
            HASH_RATE_WIDTH + i,
            flag,
            are_equal(next[HASH_RATE_WIDTH + i], internal_inputs[i]),
        );
    }
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

pub(crate) fn periodic_columns() -> Vec<Vec<BaseElement>> {
    // We are computing the values for one whole CDS trace, i.e.
    // having only 1 global period of length CDS_CYCLE_LENGTH.
    // Flag for performing hash operations
    let mut hash_flag = HASH_CYCLE_MASK.to_vec();
    for _ in 1..NUM_HASH_ITER {
        hash_flag.append(&mut HASH_CYCLE_MASK.to_vec())
    }
    hash_flag.append(&mut vec![
        BaseElement::ZERO;
        CDS_CYCLE_LENGTH - hash_flag.len()
    ]);

    // Flag for performing double-and-add steps on the 1st projective point
    let mut c_mult_flag = vec![BaseElement::ONE; SCALAR_MUL_LENGTH];
    c_mult_flag.append(&mut vec![
        BaseElement::ZERO;
        CDS_CYCLE_LENGTH - c_mult_flag.len()
    ]);

    // Flag for performing double-and-add steps on the 2nd, 3rd, 4th and 5th projective points
    let mut scalar_mult_flag = vec![BaseElement::ONE; SCALAR_MUL_LENGTH];
    scalar_mult_flag.append(&mut vec![
        BaseElement::ZERO;
        NROWS_PER_PHASE - scalar_mult_flag.len()
    ]);

    // Flag for performing doubling step in the group
    // When ZERO, compute a conditional addition step instead
    let mut point_doubling_flag = Vec::with_capacity(NROWS_PER_PHASE);
    for _ in 0..SCALAR_MUL_LENGTH / 2 {
        point_doubling_flag.append(&mut vec![BaseElement::ONE, BaseElement::ZERO]);
    }
    point_doubling_flag.append(&mut vec![
        BaseElement::ZERO;
        NROWS_PER_PHASE - point_doubling_flag.len()
    ]);

    // Flag for selecting the limb of the hash digest
    let mut hash_digest_register_flag = vec![vec![BaseElement::ZERO; CDS_CYCLE_LENGTH]; 4];
    hash_digest_register_flag[0][0..126].fill(BaseElement::ONE);
    hash_digest_register_flag[1][126..254].fill(BaseElement::ONE);
    hash_digest_register_flag[2][254..382].fill(BaseElement::ONE);
    hash_digest_register_flag[3][382..510].fill(BaseElement::ONE);

    // Mask on one phase
    let mut phase_mask = vec![BaseElement::ONE; SCALAR_MUL_LENGTH + 1];
    phase_mask.append(&mut vec![
        BaseElement::ZERO;
        NROWS_PER_PHASE - phase_mask.len()
    ]);

    // Mask on the cycle
    let mut global_mask = vec![BaseElement::ONE; CDS_CYCLE_LENGTH - 1];
    global_mask.push(BaseElement::ZERO);

    let result = vec![
        global_mask,
        phase_mask,
        c_mult_flag,
        scalar_mult_flag,
        point_doubling_flag,
        hash_digest_register_flag[0].to_owned(),
        hash_digest_register_flag[1].to_owned(),
        hash_digest_register_flag[2].to_owned(),
        hash_digest_register_flag[3].to_owned(),
        hash_flag,
    ];

    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    voting_key: &[E],
    blinding_key: &[E],
    encrypted_vote: &[E],
    hash_internal_inputs: &[E],
    doubling_flag: E,
    addition_flag: E,
    c_doubling_flag: E,
    c_addition_flag: E,
    c_copy_flag: E,
    hash_digest_register_flag: &[E],
    final_point_addition_flag: E,
    hash_flag: E,
    copy_hash_flag: E,
) {
    // Point to be used in the double-and-add operations of registers [0..PROJECTIVE_POINT_WIDTH] (s.G)
    let generator_point: Vec<E> = GENERATOR.iter().map(|&coord| coord.into()).collect();

    // Point to be used in the double-and-add operations of registers [PROJECTIVE_POINT_WIDTH + 1..PROJECTIVE_POINT_WIDTH * 2 + 1] (h.P)
    // let voting_key: Vec<E> = voting_key.to_vec();

    // When scalar_mult_flag = 1, constraints for a double-and-add
    // step are enforced on the dedicated registers for S and h.P,
    // as well as a double-and-add in the field for bin(h).

    // Enforce a step of double-and-add in the group for c * vk
    ecc::enforce_point_doubling(
        &mut result[..PROJECTIVE_POINT_WIDTH + 1],
        &current[..PROJECTIVE_POINT_WIDTH + 1],
        &next[..PROJECTIVE_POINT_WIDTH + 1],
        c_doubling_flag,
    );

    ecc::enforce_point_addition_mixed(
        &mut result[..PROJECTIVE_POINT_WIDTH + 1],
        &current[..PROJECTIVE_POINT_WIDTH + 1],
        &next[..PROJECTIVE_POINT_WIDTH + 1],
        voting_key,
        c_addition_flag,
    );

    field::enforce_copy::<PROJECTIVE_POINT_WIDTH, E>(
        &mut result[..PROJECTIVE_POINT_WIDTH],
        &current[..PROJECTIVE_POINT_WIDTH],
        &next[..PROJECTIVE_POINT_WIDTH],
        c_copy_flag,
    );

    // Enforce a step of double-and-add in the group for r1 * g
    ecc::enforce_point_doubling_bit(
        &mut result[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
        &current[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
        &next[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
        doubling_flag,
    );

    ecc::enforce_point_addition_mixed_bit(
        &mut result[PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &current[PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &next[PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &generator_point,
        2 * PROJECTIVE_POINT_WIDTH,
        addition_flag,
    );

    // Enforce a step of double-and-add in the group for r1 * bk
    ecc::enforce_point_doubling(
        &mut result[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &current[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &next[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        doubling_flag,
    );

    ecc::enforce_point_addition_mixed(
        &mut result[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &current[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        &next[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
        blinding_key,
        addition_flag,
    );

    // Enforce a step of double-and-add in the group for d1 * vk
    ecc::enforce_point_doubling_bit(
        &mut result[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
        &current[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
        &next[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
        doubling_flag,
    );

    ecc::enforce_point_addition_mixed_bit(
        &mut result[3 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        &current[3 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        &next[3 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        voting_key,
        2 * PROJECTIVE_POINT_WIDTH,
        addition_flag,
    );

    // Enforce a step of double-and-add in the group for d1 * (ev + G)
    ecc::enforce_point_doubling(
        &mut result[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        &current[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        &next[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        doubling_flag,
    );

    ecc::enforce_point_addition_mixed(
        &mut result[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        &current[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        &next[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
        encrypted_vote,
        addition_flag,
    );

    // Enforce a step of double-and-add in the field for the hash digest limbs
    for (i, &flag) in hash_digest_register_flag.iter().enumerate() {
        field::enforce_double_and_add_step_constrained(
            &mut result[PROJECTIVE_POINT_WIDTH..5 * PROJECTIVE_POINT_WIDTH + 7],
            &current[PROJECTIVE_POINT_WIDTH..5 * PROJECTIVE_POINT_WIDTH + 7],
            &next[PROJECTIVE_POINT_WIDTH..5 * PROJECTIVE_POINT_WIDTH + 7],
            4 * PROJECTIVE_POINT_WIDTH + 6 - i,
            0,
            flag * c_doubling_flag, // Do not repeat it twice
        );
    }

    // Enforce temporary accumulators copy between double-and-add steps
    field::enforce_copy::<4, E>(
        &mut result[5 * PROJECTIVE_POINT_WIDTH + 3..5 * PROJECTIVE_POINT_WIDTH + 7],
        &current[5 * PROJECTIVE_POINT_WIDTH + 3..5 * PROJECTIVE_POINT_WIDTH + 7],
        &next[5 * PROJECTIVE_POINT_WIDTH + 3..5 * PROJECTIVE_POINT_WIDTH + 7],
        c_addition_flag,
    );

    // Enforce also copy for hash digest words cells outside of double-and-add steps
    for (i, &flag) in hash_digest_register_flag.iter().enumerate() {
        result.agg_constraint(
            5 * PROJECTIVE_POINT_WIDTH + 6 - i,
            not(flag) * c_doubling_flag,
            are_equal(
                current[5 * PROJECTIVE_POINT_WIDTH + 6 - i],
                next[5 * PROJECTIVE_POINT_WIDTH + 6 - i],
            ),
        );
    }

    // When hash_flag = 1, constraints for a Rescue round
    // are enforced on the dedicated registers
    rescue::enforce_round(
        &mut result[5 * PROJECTIVE_POINT_WIDTH + 7..],
        &current[5 * PROJECTIVE_POINT_WIDTH + 7..],
        &next[5 * PROJECTIVE_POINT_WIDTH + 7..],
        ark,
        hash_flag,
    );

    // When hash_flag = 0, constraints for copying hash values to the next step
    // and updating the rate registers with self.message[i] elements are enforced.
    enforce_hash_copy(
        &mut result[5 * PROJECTIVE_POINT_WIDTH + 7..],
        &current[5 * PROJECTIVE_POINT_WIDTH + 7..],
        &next[5 * PROJECTIVE_POINT_WIDTH + 7..],
        copy_hash_flag,
        hash_internal_inputs,
    );

    // Subtract d1 * vk from c * vk, with the result stored directly in the coordinates of c * vk
    ecc::enforce_point_addition(
        &mut result[..PROJECTIVE_POINT_WIDTH],
        &current[..PROJECTIVE_POINT_WIDTH],
        &next[..PROJECTIVE_POINT_WIDTH],
        &ecc::compute_negation_projective(
            &current[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
        ),
        final_point_addition_flag,
    );

    // Add d1 * vk to r1 * g, with the result stored directly in the coordinates of r1 * g
    ecc::enforce_point_addition_reduce_affine(
        &mut result[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
        &current[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1], // r1 * g
        &next[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
        &current[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2], // d1 * vk
        final_point_addition_flag,
    );

    // Add d1 * (ev + G) to r1 * bk, with the result stored directly in the coordinates of r1 * bk
    ecc::enforce_point_addition_reduce_affine(
        &mut result[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 1],
        &current[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 1], // r1 * bk
        &next[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 1],
        &current[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 2], // d1 * (ev + G)
        final_point_addition_flag,
    );

    // Ensure that the accumulated value from the binary decomposition of c
    // matches the output of Rescue iterated hashes
    for i in 0..4 {
        result.agg_constraint(
            5 * PROJECTIVE_POINT_WIDTH + 3 + i,
            final_point_addition_flag,
            are_equal(
                current[5 * PROJECTIVE_POINT_WIDTH + 3 + i],
                current[5 * PROJECTIVE_POINT_WIDTH + 7 + i], // hash
            ),
        );
    }
}

pub(crate) fn transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    // First scalar multiplication
    let mut degrees =
        vec![
            TransitionConstraintDegree::with_cycles(5, vec![NROWS_PER_PHASE, CDS_CYCLE_LENGTH]);
            PROJECTIVE_POINT_WIDTH
        ];

    // binary decomposition
    degrees.push(TransitionConstraintDegree::with_cycles(
        2,
        vec![NROWS_PER_PHASE, CDS_CYCLE_LENGTH],
    ));

    // Second and third scalar multiplications
    // x and y coordinates have higher degrees because they also
    // store the reduced coordinates
    degrees.append(&mut vec![
        TransitionConstraintDegree::with_cycles(
            5,
            vec![NROWS_PER_PHASE, NROWS_PER_PHASE],
        );
        POINT_COORDINATE_WIDTH
    ]);
    degrees.append(&mut vec![
        TransitionConstraintDegree::with_cycles(
            4,
            vec![NROWS_PER_PHASE],
        );
        POINT_COORDINATE_WIDTH
    ]);
    degrees.append(&mut vec![
        TransitionConstraintDegree::with_cycles(
            4,
            vec![NROWS_PER_PHASE, NROWS_PER_PHASE],
        );
        POINT_COORDINATE_WIDTH
    ]);
    degrees.append(&mut vec![
        TransitionConstraintDegree::with_cycles(
            5,
            vec![NROWS_PER_PHASE, NROWS_PER_PHASE],
        );
        PROJECTIVE_POINT_WIDTH
    ]);

    // binary decomposition
    degrees.push(TransitionConstraintDegree::with_cycles(
        2,
        vec![NROWS_PER_PHASE],
    ));

    // Fourth and fifth scalar multiplications
    degrees.append(&mut vec![
        TransitionConstraintDegree::with_cycles(
            5,
            vec![NROWS_PER_PHASE, NROWS_PER_PHASE],
        );
        PROJECTIVE_POINT_WIDTH * 2
    ]);

    // binary decomposition
    degrees.push(TransitionConstraintDegree::with_cycles(
        2,
        vec![NROWS_PER_PHASE],
    ));

    // reconstructed c
    for _ in 0..4 {
        degrees.push(TransitionConstraintDegree::with_cycles(
            1,
            vec![NROWS_PER_PHASE, CDS_CYCLE_LENGTH, CDS_CYCLE_LENGTH],
        ));
    }

    // Rescue hash
    for _ in 0..HASH_STATE_WIDTH {
        degrees.push(TransitionConstraintDegree::with_cycles(
            3,
            vec![CDS_CYCLE_LENGTH],
        ));
    }

    degrees
}

#[allow(clippy::type_complexity)]
#[unroll_for_loops]
fn transpose_proof_points(
    proofs: &Vec<[BaseElement; AFFINE_POINT_WIDTH * 6]>,
    outputs: &Vec<[BaseElement; AFFINE_POINT_WIDTH * 5]>,
) -> (
    Vec<Vec<BaseElement>>,
    Vec<Vec<BaseElement>>,
    Vec<Vec<BaseElement>>,
) {
    let n = proofs.len() * 2;
    let mut result1 = vec![Vec::with_capacity(n); AFFINE_POINT_WIDTH];
    let mut result2 = vec![Vec::with_capacity(n); AFFINE_POINT_WIDTH];
    let mut result3 = vec![Vec::with_capacity(n / 2); AFFINE_POINT_WIDTH];

    for (proof, output) in proofs.iter().zip(outputs.iter()) {
        let proof_points = &proof[AFFINE_POINT_WIDTH * 2..];
        // a1, a2
        for i in 0..AFFINE_POINT_WIDTH {
            result1[i].push(proof_points[i] + output[i]);
            result1[i]
                .push(proof_points[i + 2 * AFFINE_POINT_WIDTH] + output[i + 2 * AFFINE_POINT_WIDTH])
        }
        // b1, b2
        for i in 0..AFFINE_POINT_WIDTH {
            result2[i].push(proof_points[i + AFFINE_POINT_WIDTH] + output[i + AFFINE_POINT_WIDTH]);
            result2[i].push(
                proof_points[i + 3 * AFFINE_POINT_WIDTH] + output[i + 3 * AFFINE_POINT_WIDTH],
            );
        }
        // x and z coordinates of (c - d1 - d2) * vk
        for i in 0..AFFINE_POINT_WIDTH {
            result3[i].push(output[i + 4 * AFFINE_POINT_WIDTH]);
        }
    }

    (result1, result2, result3)
}
