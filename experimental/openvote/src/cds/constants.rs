// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::utils::rescue::RATE_WIDTH;

pub(crate) use super::ecc::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH, PROJECTIVE_POINT_WIDTH};
pub(crate) use super::rescue::{HASH_CYCLE_LENGTH, HASH_CYCLE_MASK, NUM_HASH_ROUNDS, STATE_WIDTH};

// CONSTANTS
// ================================================================================================

// Rescue constants

/// Number of hash iterations for hashing the public parameters and transcript
pub const NUM_HASH_ITER: usize = 12;

/// Total number of steps for the iterated hash of the message to be signed
pub const TOTAL_HASH_LENGTH: usize = HASH_CYCLE_LENGTH * NUM_HASH_ITER;

// Scalar multiplication constants

/// Number of steps during the scalar multiplication
// Equals two times 255, as double/add steps are decoupled. We purposely use 255 bits
// (instead of 254) even if the scalar field Fq is 254-bit long because we use the binary
// decomposition of the hash inside the AIR program which consists of 4 63-bit elements
// from Fp, of which we can ignore the MSB of the first limb.
pub const SCALAR_MUL_LENGTH: usize = 510;

// Periodic trace length

/// Total number of registers in the trace
// 5 points in projective coordinates, 3 binary decompositions,
// 4 field elements, 1 hash state
/// Layout: | c * pk | c_bits | r1 * g | r1 * bk | r1_bits | d1 * pk | d1 * (ev + G) | d1_bits | c0 | c1 | c2 | c3 | hash |
pub const TRACE_WIDTH: usize = 5 * PROJECTIVE_POINT_WIDTH + 3 + 4 + STATE_WIDTH;

/// Total number of steps in the trace for a single cds proof
pub const CDS_CYCLE_LENGTH: usize = 1024;

/// Number of rows in a phase. A CDS cycle consists of two phases.
pub const NROWS_PER_PHASE: usize = CDS_CYCLE_LENGTH / 2;

/// Number of ellliptic curve points contained in a CDS proof
pub const PROOF_NUM_POINTS: usize = 4;

/// Number of scalars contained in a CDS proof
pub const PROOF_NUM_SCALARS: usize = 4;

/// Length of hash message to calculate challenge
/// [i, pk, ev, a1, b1, a2, b2] (i is voter index)
pub const HASH_MSG_LENGTH: usize = NUM_HASH_ITER * RATE_WIDTH;
