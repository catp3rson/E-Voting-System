// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// CONSTANTS USED IN MERKLE PROOF VERIFICATION
// ================================================================================================

pub(crate) use crate::utils::ecc::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH};
pub(crate) use crate::utils::rescue::{
    DIGEST_SIZE, HASH_CYCLE_LENGTH, NUM_HASH_ROUNDS, RATE_WIDTH as HASH_RATE_WIDTH,
    STATE_WIDTH as HASH_STATE_WIDTH,
};

/// Total number of registers in the trace
/// Layout: | position bit | hash state |
pub const TRACE_WIDTH: usize = HASH_STATE_WIDTH + 1;

///
// pub const

/// Depth of Merkle tree (root is excluded)
/// depth = log_2(no. leaves)
#[cfg(not(test))]
pub const TREE_DEPTH: usize = 14;

#[cfg(test)]
pub const TREE_DEPTH: usize = 14;

/// Total number of steps in a verification of Merkle proof of membership
/// Two hash iterations to calculate the hash of public key
pub const MERKLE_CYCLE_LENGTH: usize = (TREE_DEPTH + 2) * HASH_CYCLE_LENGTH;
