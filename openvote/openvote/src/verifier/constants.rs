pub use crate::cds::constants::*;
pub use crate::merkle::constants::*;
pub use crate::schnorr::constants::*;
pub use crate::utils::ecc::*;

/// Number of bytes of a serialized BaseElement
pub const BYTES_PER_ELEMENT: usize = 8;

/// Number of bytes of a serialized voting key
pub const BYTES_PER_AFFINE: usize = AFFINE_POINT_WIDTH * BYTES_PER_ELEMENT;

/// Number of bytes of an Ethereum address
pub const BYTES_PER_ADDRESS: usize = 20;

/// Number of bytes of a serialized Scalar
pub const BYTES_PER_SCALAR: usize = 32;

/// Number of bytes of a serialized Schnorr signature
pub const BYTES_PER_SIGNATURE: usize =
    POINT_COORDINATE_WIDTH * BYTES_PER_ELEMENT + BYTES_PER_SCALAR;

/// Number of bytes of a Rescue digest
pub const BYTES_PER_DIGEST: usize = DIGEST_SIZE * BYTES_PER_ELEMENT;

/// Number of bytes of a CDS output
pub const BYTES_PER_OUTPUT: usize = BYTES_PER_AFFINE * 5;
