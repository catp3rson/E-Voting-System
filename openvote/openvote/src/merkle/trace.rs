use crate::schnorr::constants::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH};
// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use crate::utils::rescue::RATE_WIDTH;

use super::constants::*;
use super::rescue;
use rescue::NUM_HASH_ROUNDS;
use winterfell::math::{fields::f63::BaseElement, FieldElement};

// TRACE INITIALIZATION
// ================================================================================================

pub(crate) fn init_merkle_verification_state(
    voting_key: &[BaseElement; AFFINE_POINT_WIDTH],
    state: &mut [BaseElement],
) {
    state[..TRACE_WIDTH].fill(BaseElement::ZERO);

    // put the public key into capacity registers for hashing
    state[1..POINT_COORDINATE_WIDTH + 1].copy_from_slice(&voting_key[..POINT_COORDINATE_WIDTH]);
}

// TRANSITION FUNCTION
// ================================================================================================

pub(crate) fn update_merkle_verification_state(
    step: usize,
    hash_message: &[BaseElement; (TREE_DEPTH + 1) * RATE_WIDTH],
    hash_index: usize,
    state: &mut [BaseElement],
) {
    // calculate Rescue hash of public params
    let rescue_step = step % HASH_CYCLE_LENGTH;

    // enforcing the three kind of rescue operations
    if rescue_step < NUM_HASH_ROUNDS {
        // for the first NUM_HASH_ROUNDS steps in every cycle, compute a single round of Rescue hash
        rescue::apply_round(&mut state[1..rescue::STATE_WIDTH + 1], step);
    } else {
        // for the next step, insert message chunks in the state registers
        let index = step / HASH_CYCLE_LENGTH;
        let hash_index_bit = BaseElement::from(((hash_index >> index) & 1) as u8);

        if hash_index_bit == BaseElement::ZERO {
            // if index bit = 0, the new branch node goes into capacity registers
            state[rescue::RATE_WIDTH + 1..rescue::STATE_WIDTH + 1].copy_from_slice(
                &hash_message[rescue::RATE_WIDTH * index..rescue::RATE_WIDTH * (index + 1)],
            );
        } else {
            // if index bit = 1, the new branch node goes into state registers
            // and the accumulated hash is stored in capacity registers
            state.copy_within(1..rescue::RATE_WIDTH + 1, rescue::RATE_WIDTH + 1);
            state[1..rescue::RATE_WIDTH + 1].copy_from_slice(
                &hash_message[rescue::RATE_WIDTH * index..rescue::RATE_WIDTH * (index + 1)],
            );
        }

        state[0] = hash_index_bit;
    }
}
