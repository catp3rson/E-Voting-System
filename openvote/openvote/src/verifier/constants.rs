use crate::merkle::constants::DIGEST_SIZE;
pub(crate) use crate::utils::ecc::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH};

/// Number of bytes of a serialized BaseElement
pub const BYTES_PER_ELEMENT: usize = 8;

/// Number of bytes of a serialized voting key
pub const BYTES_PER_VOTING_KEY: usize = AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT;

/// Number of bytes of an Ethereum address
pub const BYTES_PER_ADDRESS: usize = 20;

/// Number of bytes of a serialized Scalar
pub const BYTES_PER_SCALAR: usize = 32;

/// Number of bytes of a serialized Schnorr signature
pub const BYTES_PER_SIGNATURE: usize =
    POINT_COORDINATE_WIDTH * BYTES_PER_ELEMENT + BYTES_PER_SCALAR;

/// Number of bytes of a Rescue digest
pub const BYTES_PER_DIGEST: usize = DIGEST_SIZE * BYTES_PER_ELEMENT;
