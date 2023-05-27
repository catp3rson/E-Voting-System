// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This crate provides an implementation of the Topos
//! state-transition AIR program.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(test)]
mod proof_size;

/// Module for off-chain aggregator
pub mod aggregator;
/// The CDS sub-AIR program
pub mod cds;
/// The Merkle proof of membership sub-AIR program
pub mod merkle;
/// The Schnorr signature sub-AIR program
pub mod schnorr;
/// The vote tallying sub-AIR program
pub mod tally;
/// Utility module
pub mod utils;
/// Module for on-chain verifier
pub mod verifier;
