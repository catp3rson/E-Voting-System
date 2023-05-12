// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn tally_test_basic_proof_verification() {
    let tally = super::TallyExample::new(build_options(1), 8);
    let proof = tally.prove();
    assert!(tally.verify(proof).is_ok());
}

#[test]
fn tally_test_basic_proof_verification_quadratic_extension() {
    let tally = Box::new(super::TallyExample::new(build_options(2), 8));
    let proof = tally.prove();
    assert!(tally.verify(proof).is_ok());
}

#[test]
fn tally_test_basic_proof_verification_cubic_extension() {
    let tally = Box::new(super::TallyExample::new(build_options(3), 8));
    let proof = tally.prove();
    assert!(tally.verify(proof).is_ok());
}

#[test]
fn tally_test_basic_proof_verification_fail() {
    let tally = super::TallyExample::new(build_options(1), 8);
    let proof = tally.prove();
    let verified = tally.verify_with_wrong_inputs(proof);
    assert!(verified.is_err());
}

fn build_options(extension: u8) -> ProofOptions {
    ProofOptions::new(
        42,
        8,
        0,
        HashFunction::Blake3_192,
        match extension {
            2 => FieldExtension::Quadratic,
            3 => FieldExtension::Cubic,
            _ => FieldExtension::None,
        },
        4,
        256,
    )
}
