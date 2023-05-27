// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) use crate::utils::ecc::{
    AFFINE_POINT_WIDTH, IDENTITY, POINT_COORDINATE_WIDTH, PROJECTIVE_POINT_WIDTH,
};

// CONSTANTS
// ================================================================================================

// Periodic trace length

/// Total number of registers in the trace
// 1 point in projective coordinates
pub const TRACE_WIDTH: usize = PROJECTIVE_POINT_WIDTH;
