pub(crate) use crate::utils::rescue::DIGEST_SIZE;

pub(crate) use crate::utils::ecc::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH};

pub(crate) use crate::merkle::constants::TREE_DEPTH;

pub(crate) use crate::schnorr::constants::MSG_LENGTH;

pub(crate) use crate::cds::constants::{PROOF_NUM_POINTS, PROOF_NUM_SCALARS};

pub(crate) use crate::verifier::constants::*;

/// Number of bytes of a CDS proof (encrypted_vote + proof_points + proof_scalars)
pub const BYTES_PER_CDS_PROOF: usize = AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT
    + PROOF_NUM_POINTS * AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT
    + PROOF_NUM_SCALARS * BYTES_PER_SCALAR;
