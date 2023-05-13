// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use crate::utils::ecc::GENERATOR;

use super::constants::*;
use super::{ecc, field, rescue};
use bitvec::{order::Lsb0, slice::BitSlice};
use core::cmp::Ordering;
use winterfell::math::{curves::curve_f63::Scalar, fields::f63::BaseElement, FieldElement};

// TRACE INITIALIZATION
// ================================================================================================

pub(crate) fn init_cds_verification_state(voter_index: usize, state: &mut [BaseElement]) {
    // initialize first state of the computation
    state[..TRACE_WIDTH].fill(BaseElement::ZERO);

    // y(c * vk) = 1
    state[POINT_COORDINATE_WIDTH] = BaseElement::ONE;

    // y(r1 * g) = y(r1 * bk) = 1
    state[PROJECTIVE_POINT_WIDTH + POINT_COORDINATE_WIDTH + 1] = BaseElement::ONE;
    state[PROJECTIVE_POINT_WIDTH * 2 + POINT_COORDINATE_WIDTH + 1] = BaseElement::ONE;

    // y(d1 * vk) = y(d1 * (ev + G)) = 1
    state[PROJECTIVE_POINT_WIDTH * 3 + POINT_COORDINATE_WIDTH + 2] = BaseElement::ONE;
    state[PROJECTIVE_POINT_WIDTH * 4 + POINT_COORDINATE_WIDTH + 2] = BaseElement::ONE;

    // copy the first RATE_WIDTH bytes of hash_msg into the registers for hashing
    state[PROJECTIVE_POINT_WIDTH * 5 + 7] = BaseElement::from(voter_index as u8);
}

// TRANSITION FUNCTION
// ================================================================================================

pub(crate) fn update_cds_verification_state(
    step: usize,
    hash_msg: &[BaseElement; HASH_MSG_LENGTH],
    voting_key: &[BaseElement; AFFINE_POINT_WIDTH],
    blinding_key: &[BaseElement; AFFINE_POINT_WIDTH],
    encrypted_vote_1: &[BaseElement; AFFINE_POINT_WIDTH],
    encrypted_vote_2: &[BaseElement; AFFINE_POINT_WIDTH],
    d1_bits: &BitSlice<Lsb0, u8>,
    d2_bits: &BitSlice<Lsb0, u8>,
    r1_bits: &BitSlice<Lsb0, u8>,
    r2_bits: &BitSlice<Lsb0, u8>,
    c_bits: &BitSlice<Lsb0, u8>,
    state: &mut [BaseElement],
) {
    // calculate Rescue hash of public params
    let bit_length = SCALAR_MUL_LENGTH / 2;
    let rescue_flag = step < TOTAL_HASH_LENGTH;
    let rescue_step = step % HASH_CYCLE_LENGTH;

    let is_phase_1 = step < NROWS_PER_PHASE;
    let mul_step = step % NROWS_PER_PHASE;

    // enforcing the three kind of rescue operations
    if rescue_flag && (rescue_step < NUM_HASH_ROUNDS) {
        // for the first NUM_HASH_ROUNDS steps in every cycle, compute a single round of Rescue hash
        rescue::apply_round(&mut state[PROJECTIVE_POINT_WIDTH * 5 + 7..], step);
    } else if rescue_flag && (step < (NUM_HASH_ITER - 1) * HASH_CYCLE_LENGTH) {
        // for the next step, insert message chunks in the state registers
        let index = (step / HASH_CYCLE_LENGTH) + 1;
        state[PROJECTIVE_POINT_WIDTH * 5 + rescue::RATE_WIDTH + 7
            ..PROJECTIVE_POINT_WIDTH * 5 + rescue::RATE_WIDTH * 2 + 7]
            .copy_from_slice(
                &hash_msg[rescue::RATE_WIDTH * index..rescue::RATE_WIDTH * (index + 1)],
            );
    } else if rescue_flag {
        // Register cells are by default copied from the previous state if no operation
        // is specified. This would conflict for here, as the "periodic" values for the
        // enforce_hash_copy() internal inputs are set to 0 at almost every step.
        // Hence we manually set them to zero for the final hash iteration, and this will
        // carry over until the end of the trace
        state[PROJECTIVE_POINT_WIDTH * 5 + rescue::RATE_WIDTH + 7
            ..PROJECTIVE_POINT_WIDTH * 5 + rescue::RATE_WIDTH * 2 + 7]
            .fill(BaseElement::ZERO);
    }

    // enforcing scalar multiplications (phase 1)
    match mul_step.cmp(&SCALAR_MUL_LENGTH) {
        Ordering::Less => {
            let real_step = mul_step / 2;
            let is_doubling_step = mul_step % 2 == 0;
            let chunk = if real_step < 63 {
                0
            } else {
                (real_step - 63) / 64 + 1
            };
            // c
            state[PROJECTIVE_POINT_WIDTH] =
                BaseElement::from((c_bits[bit_length - 1 - real_step] && is_phase_1) as u8);

            // r1 / r2
            state[PROJECTIVE_POINT_WIDTH * 3 + 1] = BaseElement::from(
                ((r1_bits[bit_length - 1 - real_step] && is_phase_1)
                    || (r2_bits[bit_length - 1 - real_step] && (!is_phase_1)))
                    as u8,
            );

            // d1 / d2
            state[5 * PROJECTIVE_POINT_WIDTH + 2] = BaseElement::from(
                ((d1_bits[bit_length - 1 - real_step] && is_phase_1)
                    || (d2_bits[bit_length - 1 - real_step] && (!is_phase_1)))
                    as u8,
            );

            if is_doubling_step {
                // double the 5 points at 5 registers
                ecc::apply_point_doubling(
                    &mut state[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
                );
                ecc::apply_point_doubling(
                    &mut state[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 1],
                );
                ecc::apply_point_doubling(
                    &mut state[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
                );
                ecc::apply_point_doubling(
                    &mut state[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 2],
                );
                if is_phase_1 {
                    ecc::apply_point_doubling(&mut state[..PROJECTIVE_POINT_WIDTH]);
                    // re-calculate c
                    field::apply_double_and_add_step(
                        &mut state[PROJECTIVE_POINT_WIDTH..5 * PROJECTIVE_POINT_WIDTH + 7],
                        4 * PROJECTIVE_POINT_WIDTH + 6 - chunk,
                        0,
                    );
                }
            } else {
                // c * vk
                ecc::apply_point_addition_mixed(
                    &mut state[..PROJECTIVE_POINT_WIDTH + 1],
                    voting_key,
                );
                // r1 * g / r2 * g
                ecc::apply_point_addition_mixed_bit(
                    &mut state[PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
                    &GENERATOR,
                    2 * PROJECTIVE_POINT_WIDTH,
                );
                // r1 * bk / r2 * bk
                ecc::apply_point_addition_mixed(
                    &mut state[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2],
                    blinding_key,
                );
                // d1 * vk / d2 * vk
                ecc::apply_point_addition_mixed_bit(
                    &mut state[3 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
                    voting_key,
                    2 * PROJECTIVE_POINT_WIDTH,
                );
                // d1 * (ev + G) / d2 * (ev - G)
                ecc::apply_point_addition_mixed(
                    &mut state[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3],
                    if is_phase_1 {
                        encrypted_vote_1
                    } else {
                        encrypted_vote_2
                    },
                );
            }
        }
        Ordering::Equal => {
            // calculate ((c - d1) * vk) / ((c - d1 - d2) * vk) and store it back into c * vk registers
            let mut rhs = [BaseElement::ZERO; PROJECTIVE_POINT_WIDTH];
            rhs.copy_from_slice(&ecc::compute_negation_projective(
                &state[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
            ));
            ecc::compute_add(&mut state[..PROJECTIVE_POINT_WIDTH], &rhs);
            // calculate (r1 * g + d1 * vk) / (r2 * g + d2 * vk) and store it back into r1 * g registers
            rhs.copy_from_slice(
                &state[3 * PROJECTIVE_POINT_WIDTH + 2..4 * PROJECTIVE_POINT_WIDTH + 2],
            );
            ecc::compute_add(
                &mut state[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
                &rhs,
            );
            // reduce (r1 * g + d1 * vk) / (r2 * g + d2 * vk)  to affine coordinates
            let reduced_point = ecc::reduce_to_affine(
                &state[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1],
            );
            state[PROJECTIVE_POINT_WIDTH + 1..PROJECTIVE_POINT_WIDTH + AFFINE_POINT_WIDTH + 1]
                .copy_from_slice(&reduced_point);

            // calculate (r1 * bk + d1 * (ev + G)) / (r2 * bk + d2 * (ev + G)) and store it back into r1 * bk registers
            rhs.copy_from_slice(
                &state[4 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 2],
            );
            ecc::compute_add(
                &mut state[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 1],
                &rhs,
            );
            // reduce (r1 * bk + d1 * (ev + G)) / (r2 * bk + d2 * (ev + G)) to affine coordinates
            let reduced_point = ecc::reduce_to_affine(
                &state[2 * PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 1],
            );
            state[2 * PROJECTIVE_POINT_WIDTH + 1
                ..2 * PROJECTIVE_POINT_WIDTH + AFFINE_POINT_WIDTH + 1]
                .copy_from_slice(&reduced_point);
        }
        _ => {
            // end of phase 1
            // reset r1 * g and r1 * bk registers
            state[PROJECTIVE_POINT_WIDTH] = BaseElement::ZERO;
            state[PROJECTIVE_POINT_WIDTH + 1..3 * PROJECTIVE_POINT_WIDTH + 2]
                .fill(BaseElement::ZERO);
            state[PROJECTIVE_POINT_WIDTH + POINT_COORDINATE_WIDTH + 1] = BaseElement::ONE;
            state[PROJECTIVE_POINT_WIDTH * 2 + POINT_COORDINATE_WIDTH + 1] = BaseElement::ONE;
            // reset d1 * vk and d1 * (ev + G) registers
            state[3 * PROJECTIVE_POINT_WIDTH + 2..5 * PROJECTIVE_POINT_WIDTH + 3]
                .fill(BaseElement::ZERO);
            state[3 * PROJECTIVE_POINT_WIDTH + POINT_COORDINATE_WIDTH + 2] = BaseElement::ONE;
            state[4 * PROJECTIVE_POINT_WIDTH + POINT_COORDINATE_WIDTH + 2] = BaseElement::ONE;
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Convert the proof scalars into bytes
#[inline]
pub(crate) fn decompose_scalars(
    proof_scalars: &[Scalar; PROOF_NUM_SCALARS],
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    (
        proof_scalars[0].to_bytes(),
        proof_scalars[1].to_bytes(),
        proof_scalars[2].to_bytes(),
        proof_scalars[3].to_bytes(),
    )
}

/// Prepare the hash message to compute the challenge
/// The hash message consists of 9 public parameters
#[inline]
pub(crate) fn prepare_hash_message(
    voter_index: usize,
    voting_key: &[BaseElement; AFFINE_POINT_WIDTH],
    encrypted_vote: &[BaseElement; AFFINE_POINT_WIDTH],
    proof_points: &[BaseElement; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH],
) -> [BaseElement; HASH_MSG_LENGTH] {
    // Message contains (i, vk, ev, a1, b1, a2, b2)
    // 4 last null bytes are for padding
    let mut hash_msg = [BaseElement::ZERO; HASH_MSG_LENGTH];
    hash_msg[0] = BaseElement::from(voter_index as u8);
    hash_msg[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2].copy_from_slice(voting_key); // x
    hash_msg[AFFINE_POINT_WIDTH * 2..AFFINE_POINT_WIDTH * 3].copy_from_slice(encrypted_vote); // y
    hash_msg[AFFINE_POINT_WIDTH * 3..AFFINE_POINT_WIDTH * (PROOF_NUM_POINTS + 3)]
        .copy_from_slice(proof_points); // a1, b1, a2, b2
    hash_msg
}

/// Calculate two points (ev + G, ev - G)
#[inline]
pub(crate) fn prepare_encrypted_votes(
    encrypted_vote: &[BaseElement],
) -> (
    [BaseElement; AFFINE_POINT_WIDTH],
    [BaseElement; AFFINE_POINT_WIDTH],
) {
    let mut result1 = [BaseElement::ZERO; PROJECTIVE_POINT_WIDTH];
    result1[AFFINE_POINT_WIDTH] = BaseElement::ONE;
    result1[..AFFINE_POINT_WIDTH].copy_from_slice(&encrypted_vote[..AFFINE_POINT_WIDTH]);
    ecc::compute_add_mixed(&mut result1, &GENERATOR);
    let mut result2 = [BaseElement::ZERO; PROJECTIVE_POINT_WIDTH];
    result2[AFFINE_POINT_WIDTH] = BaseElement::ONE;
    result2[..AFFINE_POINT_WIDTH].copy_from_slice(&encrypted_vote[..AFFINE_POINT_WIDTH]);
    ecc::compute_add_mixed(&mut result2, &ecc::compute_negation_affine(&GENERATOR));
    (
        ecc::reduce_to_affine(&result1),
        ecc::reduce_to_affine(&result2),
    )
}
