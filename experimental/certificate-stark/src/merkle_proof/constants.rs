// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// CONSTANTS USED IN MERKLE PROOF VERIFICATION
// ================================================================================================

pub(crate) use super::rescue::{HASH_CYCLE_LENGTH, STATE_WIDTH};

/// Total number of registers in the trace
/// Layout: | position bit | hash state |
pub const TRACE_WIDTH: usize = STATE_WIDTH + 1;

/// Depth of Merkle tree (root is excluded)
/// depth = log_2(no. leaves)
#[cfg(not(test))]
pub const TREE_DEPTH: usize = 14;

#[cfg(test)]
pub const TREE_DEPTH: usize = 6;

/// Total number of steps in a verification of Merkle proof of membership
/// Two hash iterations to calculate the hash of public key
pub const MERKLE_CYCLE_LENGTH: usize = (TREE_DEPTH + 2) * HASH_CYCLE_LENGTH;
